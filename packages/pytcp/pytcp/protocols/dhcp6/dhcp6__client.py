################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the DHCPv6 (RFC 8415) client — the stateless
INFORMATION-REQUEST exchange (other-config: DNS, etc.) and the
stateful SOLICIT / ADVERTISE / REQUEST / REPLY exchange that leases a
non-temporary address (IA_NA). The leased address is handed to the
caller as a 'Dhcp6Lease'; the Address-API assignment + lease lifecycle
land in a later phase.

pytcp/protocols/dhcp6/dhcp6__client.py

ver 3.0.6
"""

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

from net_addr import Ip6Address, Ip6IfAddr, MacAddress
from net_proto import (
    Dhcp6Assembler,
    Dhcp6IntegrityError,
    Dhcp6MessageType,
    Dhcp6OptionClientId,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionIaNa,
    Dhcp6OptionOro,
    Dhcp6Options,
    Dhcp6OptionServerId,
    Dhcp6OptionType,
    Dhcp6Parser,
    Dhcp6SanityError,
    Dhcp6StatusCode,
)
from pytcp.lib.logger import log
from pytcp.protocols.dhcp6 import dhcp6__constants
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid, get_iaid
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem
from pytcp.socket import (
    AF_INET6,
    SO_BINDTODEVICE,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)

if TYPE_CHECKING:
    from pytcp.stack.address import AddressApi

# RFC 8415 §8 — the transaction-id is a 24-bit field.
_DHCP6__XID_MAX = 0xFFFFFF

# RFC 8415 carries no prefix length in the IA Address option; the
# on-link prefix is learned from Router Advertisements, so a leased
# address is installed as a /128 host (matching Linux dhclient -6 and
# systemd-networkd, which assign DHCPv6 addresses as /128).
_DHCP6__LEASE_PREFIX_LEN = 128


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6StatelessConfig:
    """
    The RFC 8415 §18.2.6 "other configuration" returned by a
    stateless INFORMATION-REQUEST exchange. Carries only the
    non-address parameters a stateless client asks for; today that
    is the DNS recursive name-server list (RFC 3646).
    """

    dns_servers: list[Ip6Address] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6Lease:
    """
    A negotiated DHCPv6 non-temporary-address (IA_NA) lease — the
    assigned address + its preferred / valid lifetimes, plus the
    IA_NA T1 / T2 renewal timers, the IAID, and the issuing server's
    DUID. DHCPv6 carries no prefix length in the IA Address option;
    the on-link prefix is learned from Router Advertisements, so the
    Address-API assignment installs the leased address as a /128 host.
    """

    address: Ip6Address
    preferred_lifetime: int
    valid_lifetime: int
    t1: int
    t2: int
    iaid: int
    server_duid: bytes


class Dhcp6Client(Subsystem):
    """
    DHCPv6 client (RFC 8415).

    Two invocation modes:

      - Sync: 'fetch_other_config()' / 'acquire_lease()' run one
        exchange inline in the caller's thread and return the result.
        The 'Subsystem' machinery is not engaged. Used by tests and
        operator CLI tools.
      - Daemon: 'start()' spawns the 'Subsystem' worker thread which
        blocks on a trigger 'Event'; the RA RX handler calls
        'trigger(managed=..., other=...)' on receipt of a Router
        Advertisement with the Managed / Other-config flags set, and
        the worker runs the stateful ('managed') or stateless
        ('other') exchange. Used by 'stack.start()' in production.

    Both exchanges share the §15 retransmission backoff and the
    inbound-frame validation in '_run_exchange' / '_recv_within_window'.
    """

    _subsystem_name = "DHCP6 Client"

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        interface_name: str | None = None,
        address_api: "AddressApi | None" = None,
    ) -> None:
        """
        Initialize the DHCPv6 client.

        The optional 'address_api' is the kernel/userspace Address-API
        boundary used to install a leased address. When None (the
        sync / test default) 'acquire_lease()' returns the lease
        without touching the interface's address set.
        """

        super().__init__()

        self._mac_address = mac_address
        self._interface_name = interface_name
        self._address_api = address_api

        # Trigger state. 'trigger()' (RX thread) sets the pending
        # config-mode flags under '_lock__trigger' and wakes the worker
        # via '_event__trigger'; the worker reads + clears them. The
        # debounce state ('_lease' / '_other_acquired') is worker-only
        # so a periodic RA does not re-solicit once the host is
        # configured (lease renewal is a later phase).
        self._event__trigger = threading.Event()
        self._lock__trigger = threading.Lock()
        self._pending_managed = False
        self._pending_other = False
        self._lease: Dhcp6Lease | None = None
        self._other_acquired = False

    def trigger(self, *, managed: bool, other: bool) -> None:
        """
        Record a config-mode request from an inbound Router
        Advertisement and wake the worker thread. Called from the RX
        thread; non-blocking and idempotent — the worker debounces so a
        periodic RA does not re-run a completed exchange.
        """

        with self._lock__trigger:
            self._pending_managed = self._pending_managed or managed
            self._pending_other = self._pending_other or other
        self._event__trigger.set()

    @override
    def _subsystem_loop(self) -> None:
        """
        Wait for an RA-driven trigger and run the matching exchange.

        'managed' takes precedence over 'other' (a Managed RA drives the
        full stateful address lease, which itself fetches other config
        via its Option Request); each is run at most once until the host
        is configured, so a periodic RA does not re-solicit.
        """

        if not self._event__trigger.wait(timeout=SUBSYSTEM_SLEEP_TIME__SEC):
            return
        self._event__trigger.clear()

        with self._lock__trigger:
            managed = self._pending_managed
            other = self._pending_other
            self._pending_managed = False
            self._pending_other = False

        if managed and self._lease is None:
            lease = self.acquire_lease()
            if lease is not None:
                self._lease = lease
        elif other and not self._other_acquired:
            if self.fetch_other_config() is not None:
                self._other_acquired = True

    @override
    def _stop(self) -> None:
        """
        Wake the worker out of its trigger wait so 'stop()' does not
        block for the full poll interval during teardown.
        """

        self._event__trigger.set()

    # --- message builders ---

    def _client_id_option(self) -> Dhcp6OptionClientId:
        """
        Build the Client Identifier option carrying the host DUID.
        """

        return Dhcp6OptionClientId(get_client_duid(self._mac_address))

    def _build_information_request(self, *, xid: int) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.6 INFORMATION-REQUEST carrying the
        Client Identifier (DUID), a zero Elapsed Time, and an Option
        Request listing the other-config options the client wants.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionElapsedTime(0),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.INFORMATION_REQUEST,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_solicit(self, *, xid: int) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.1 SOLICIT carrying the Client
        Identifier, an IA_NA (the client's IAID; T1 / T2 = 0 to let
        the server choose), a zero Elapsed Time, and an Option Request
        for DNS servers.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionIaNa(iaid=get_iaid(), t1=0, t2=0),
            Dhcp6OptionElapsedTime(0),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.SOLICIT,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_request(self, *, xid: int, server_duid: bytes) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.2 REQUEST addressed to the selected
        server (its DUID in the Server Identifier option), carrying the
        Client Identifier, the IA_NA, a zero Elapsed Time, and an
        Option Request for DNS servers.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionServerId(server_duid),
            Dhcp6OptionIaNa(iaid=get_iaid(), t1=0, t2=0),
            Dhcp6OptionElapsedTime(0),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.REQUEST,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _open_client_socket(self) -> socket:
        """
        Open the UDP/IPv6 socket used for the exchange, pinned to this
        client's interface via SO_BINDTODEVICE when known so the
        link-scoped multicast egress is unambiguous on a multi-homed
        host.
        """

        client_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
        if self._interface_name is not None:
            client_socket.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self._interface_name.encode())
        return client_socket

    def _multicast_target(self) -> tuple[str, int]:
        """
        Get the All_DHCP_Relay_Agents_and_Servers (address, port) the
        client transmits to.
        """

        return (
            str(dhcp6__constants.DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS),
            dhcp6__constants.DHCP6__SERVER_PORT,
        )

    # --- stateless exchange ---

    def fetch_other_config(self) -> Dhcp6StatelessConfig | None:
        """
        Run one stateless INFORMATION-REQUEST / REPLY exchange and
        return the other-configuration bundle, or None when no server
        answers within the RFC 8415 §15 retransmission budget.
        """

        xid = random.randint(0, _DHCP6__XID_MAX)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()

            def _send() -> None:
                client_socket.sendto(bytes(self._build_information_request(xid=xid)), target)

            __debug__ and log("dhcp6", f"Sending INFORMATION-REQUEST (xid={xid:#08x}) to {target[0]}")
            _send()

            reply = self._run_exchange(
                client_socket,
                xid=xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send,
                irt_ms=dhcp6__constants.DHCP6__INF_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__INF_MAX_RT_MS,
                max_attempts=dhcp6__constants.DHCP6__RETRANS_MAX_ATTEMPTS,
            )
            if reply is None:
                __debug__ and log("dhcp6", "INFORMATION-REQUEST unanswered; no other configuration obtained")
                return None

            dns_servers = reply.dns_servers or []
            __debug__ and log("dhcp6", f"Stateless config acquired: dns_servers={[str(s) for s in dns_servers]}")
            return Dhcp6StatelessConfig(dns_servers=dns_servers)
        finally:
            client_socket.close()

    # --- stateful exchange ---

    def acquire_lease(self) -> Dhcp6Lease | None:
        """
        Run the RFC 8415 §18.2.1-§18.2.2 four-message stateful exchange
        (SOLICIT → ADVERTISE → REQUEST → REPLY) and return the leased
        IA_NA address, or None when no usable lease is obtained (no
        server answered, the selected server returned no address, or
        the binding carried a non-Success Status Code).

        The first valid ADVERTISE is selected (RFC 8415 §18.2.9
        Preference-based selection is a deferred refinement).
        """

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()

            sol_xid = random.randint(0, _DHCP6__XID_MAX)

            def _send_solicit() -> None:
                client_socket.sendto(bytes(self._build_solicit(xid=sol_xid)), target)

            __debug__ and log("dhcp6", f"Sending SOLICIT (xid={sol_xid:#08x}) to {target[0]}")
            _send_solicit()

            advertise = self._run_exchange(
                client_socket,
                xid=sol_xid,
                expected_type=Dhcp6MessageType.ADVERTISE,
                resend=_send_solicit,
                irt_ms=dhcp6__constants.DHCP6__SOL_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__SOL_MAX_RT_MS,
                max_attempts=dhcp6__constants.DHCP6__RETRANS_MAX_ATTEMPTS,
            )
            if advertise is None:
                __debug__ and log("dhcp6", "SOLICIT unanswered; no lease obtained")
                return None

            server_duid = advertise.server_id
            if server_duid is None:
                __debug__ and log("dhcp6", "<WARN>ADVERTISE missing Server Identifier; no lease obtained")
                return None

            req_xid = random.randint(0, _DHCP6__XID_MAX)

            def _send_request() -> None:
                client_socket.sendto(bytes(self._build_request(xid=req_xid, server_duid=server_duid)), target)

            __debug__ and log("dhcp6", f"Sending REQUEST (xid={req_xid:#08x}) to server {server_duid.hex()}")
            _send_request()

            reply = self._run_exchange(
                client_socket,
                xid=req_xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send_request,
                irt_ms=dhcp6__constants.DHCP6__REQ_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__REQ_MAX_RT_MS,
                max_attempts=dhcp6__constants.DHCP6__REQ_MAX_RC,
            )
            if reply is None:
                __debug__ and log("dhcp6", "REQUEST unanswered; no lease obtained")
                return None

            lease = self._extract_lease(reply, server_duid=server_duid)
            if lease is not None:
                self._assign_lease(lease)
            return lease
        finally:
            client_socket.close()

    @staticmethod
    def _lease_ifaddr(lease: Dhcp6Lease) -> Ip6IfAddr:
        """
        Build the /128 interface address for a leased IA_NA address.
        """

        return Ip6IfAddr(f"{lease.address}/{_DHCP6__LEASE_PREFIX_LEN}")

    def _assign_lease(self, lease: Dhcp6Lease) -> None:
        """
        Install the leased address on the interface through the Address
        API (a no-op when no Address API was configured).
        """

        if self._address_api is None:
            return
        ifaddr = self._lease_ifaddr(lease)
        __debug__ and log("dhcp6", f"Assigning leased address {ifaddr} via the Address API")
        self._address_api.add(ifaddr=ifaddr)

    def _extract_lease(self, reply: Dhcp6Parser, *, server_duid: bytes) -> Dhcp6Lease | None:
        """
        Extract the leased IA_NA address from a REPLY. Parses the IA_NA
        sub-option block (preserved as opaque bytes by the codec) for
        the IA Address and any Status Code, returning None when the
        binding carries no address or a non-Success Status Code.
        """

        ia_na = reply.ia_na
        if ia_na is None:
            __debug__ and log("dhcp6", "<WARN>REPLY carries no IA_NA option; no lease obtained")
            return None

        try:
            Dhcp6Options.validate_integrity(frame=ia_na.options, hlen=len(ia_na.options), offset=0)
            ia_options = Dhcp6Options.from_buffer(memoryview(ia_na.options))
        except Dhcp6IntegrityError, Dhcp6SanityError:
            __debug__ and log("dhcp6", "<WARN>REPLY IA_NA sub-options malformed; no lease obtained")
            return None

        status = ia_options.status_code
        if status is not None and status.status_code != Dhcp6StatusCode.SUCCESS:
            __debug__ and log("dhcp6", f"<WARN>REPLY IA_NA Status Code {status.status_code}; no lease obtained")
            return None

        ia_addr = ia_options.ia_addr
        if ia_addr is None:
            __debug__ and log("dhcp6", "<WARN>REPLY IA_NA carries no IA Address; no lease obtained")
            return None

        lease = Dhcp6Lease(
            address=ia_addr.address,
            preferred_lifetime=ia_addr.preferred_lifetime,
            valid_lifetime=ia_addr.valid_lifetime,
            t1=ia_na.t1,
            t2=ia_na.t2,
            iaid=ia_na.iaid,
            server_duid=server_duid,
        )
        __debug__ and log(
            "dhcp6",
            f"Lease acquired: {lease.address} (preferred {lease.preferred_lifetime}s, valid {lease.valid_lifetime}s)",
        )
        return lease

    # --- shared retransmission / recv machinery ---

    def _run_exchange(
        self,
        client_socket: socket,
        *,
        xid: int,
        expected_type: Dhcp6MessageType,
        resend: Callable[[], None],
        irt_ms: int,
        mrt_ms: int,
        max_attempts: int,
    ) -> Dhcp6Parser | None:
        """
        Wait for the matching reply ('expected_type', 'xid') using the
        RFC 8415 §15 retransmission backoff seeded with the per-message
        IRT / MRT. On each per-attempt timeout the caller's 'resend'
        retransmits the request and the timeout grows (doubled, capped
        at MRT, each value randomized by RAND). Returns the parsed
        reply, or None once the attempt budget is exhausted.
        """

        rand_factor = dhcp6__constants.DHCP6__RAND_FACTOR

        rt_ms = 0.0
        for attempt in range(max_attempts):
            # RFC 8415 §15 — RT = IRT + RAND*IRT on the first attempt,
            # then RT = 2*RTprev + RAND*RTprev capped at MRT, where
            # RAND is drawn uniformly from [-0.1, +0.1].
            rand = random.uniform(-rand_factor, rand_factor)
            if attempt == 0:
                rt_ms = irt_ms + rand * irt_ms
            else:
                rt_ms = 2 * rt_ms + rand * rt_ms
                if rt_ms > mrt_ms:
                    rt_ms = mrt_ms + rand * mrt_ms
            timeout_s = max(0.001, rt_ms / 1000.0)

            result = self._recv_within_window(client_socket, xid=xid, expected_type=expected_type, timeout_s=timeout_s)
            if result is not None:
                return result

            if attempt < max_attempts - 1:
                __debug__ and log(
                    "dhcp6",
                    f"recv window expired ({timeout_s:.2f}s); retransmitting "
                    f"(attempt {attempt + 2} of {max_attempts})",
                )
                resend()

        return None

    def _recv_within_window(
        self,
        client_socket: socket,
        *,
        xid: int,
        expected_type: Dhcp6MessageType,
        timeout_s: float,
    ) -> Dhcp6Parser | None:
        """
        Wait up to 'timeout_s' seconds for a valid message of
        'expected_type' with a matching 'xid', silently dropping bogus
        packets (malformed, wrong msg-type, mismatched xid) without
        consuming the entire window. Returns the parsed message on
        success, or None if the deadline elapses with no valid response.
        """

        deadline = time.monotonic() + timeout_s
        remaining = timeout_s
        first_iter = True
        while True:
            if not first_iter:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
            first_iter = False

            try:
                packet = Dhcp6Parser(client_socket.recv__mv(timeout=remaining))
            except TimeoutError:
                return None
            except Dhcp6IntegrityError, Dhcp6SanityError:
                __debug__ and log("dhcp6", "<WARN>Dropping malformed inbound DHCPv6 frame; continuing wait window</>")
                continue

            __debug__ and log("dhcp6", f"<lg>RX</> - {packet}")

            if packet.msg_type != expected_type:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with unexpected msg-type {packet.msg_type!r}; "
                    f"expected {expected_type!r}</>",
                )
                continue
            if packet.xid != xid:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with mismatched xid (sent={xid:#08x}, got={packet.xid:#08x})</>",
                )
                continue

            return packet
