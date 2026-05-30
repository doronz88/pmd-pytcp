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
This module contains the DHCPv6 (RFC 8415) stateless client — the
INFORMATION-REQUEST / REPLY exchange that fetches "other
configuration" (DNS servers, etc.) without taking an address lease.
It is the de-risking first cut of the DHCPv6 client: it exercises the
full UDP transport + wire codec + DUID stack before the stateful
SOLICIT/REQUEST/REPLY address FSM lands.

pytcp/protocols/dhcp6/dhcp6__client.py

ver 3.0.6
"""

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Dhcp6Assembler,
    Dhcp6IntegrityError,
    Dhcp6MessageType,
    Dhcp6OptionClientId,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionOro,
    Dhcp6Options,
    Dhcp6OptionType,
    Dhcp6Parser,
    Dhcp6SanityError,
)
from pytcp.lib.logger import log
from pytcp.protocols.dhcp6 import dhcp6__constants
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid
from pytcp.socket import (
    AF_INET6,
    SO_BINDTODEVICE,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)

# RFC 8415 §8 — the transaction-id is a 24-bit field.
_DHCP6__XID_MAX = 0xFFFFFF


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6StatelessConfig:
    """
    The RFC 8415 §18.2.6 "other configuration" returned by a
    stateless INFORMATION-REQUEST exchange. Carries only the
    non-address parameters a stateless client asks for; today that
    is the DNS recursive name-server list (RFC 3646).
    """

    dns_servers: list[Ip6Address] = field(default_factory=list)


class Dhcp6Client:
    """
    DHCPv6 stateless client (RFC 8415 §18.2.6).

    Synchronous: 'fetch_other_config()' runs one INFORMATION-REQUEST
    / REPLY exchange inline in the caller's thread and returns the
    other-configuration bundle (or None when no server answers within
    the retransmission budget). No background thread is spawned — the
    daemon lifecycle and the RA Other-config (O flag) trigger land in
    a later phase.
    """

    def __init__(self, *, mac_address: MacAddress, interface_name: str | None = None) -> None:
        """
        Initialize the DHCPv6 stateless client.
        """

        self._mac_address = mac_address
        self._interface_name = interface_name

    def _build_information_request(self, *, xid: int) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.6 INFORMATION-REQUEST carrying the
        Client Identifier (DUID), a zero Elapsed Time, and an Option
        Request listing the other-config options the client wants.
        """

        options = Dhcp6Options(
            Dhcp6OptionClientId(get_client_duid(self._mac_address)),
            Dhcp6OptionElapsedTime(0),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.INFORMATION_REQUEST,
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
            target = (
                str(dhcp6__constants.DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS),
                dhcp6__constants.DHCP6__SERVER_PORT,
            )

            def _send() -> None:
                client_socket.sendto(bytes(self._build_information_request(xid=xid)), target)

            __debug__ and log("dhcp6", f"Sending INFORMATION-REQUEST (xid={xid:#08x}) to {target[0]}")
            _send()

            reply = self._recv_reply(client_socket, xid=xid, resend=_send)
            if reply is None:
                __debug__ and log("dhcp6", "INFORMATION-REQUEST unanswered; no other configuration obtained")
                return None

            dns_servers = reply.dns_servers or []
            __debug__ and log("dhcp6", f"Stateless config acquired: dns_servers={[str(s) for s in dns_servers]}")
            return Dhcp6StatelessConfig(dns_servers=dns_servers)
        finally:
            client_socket.close()

    def _recv_reply(self, client_socket: socket, *, xid: int, resend: Callable[[], None]) -> Dhcp6Parser | None:
        """
        Wait for the matching REPLY using the RFC 8415 §15
        retransmission backoff seeded with the §7.6 INFORMATION-REQUEST
        timers (IRT = INF_TIMEOUT, MRT = INF_MAX_RT). On each
        per-attempt timeout the caller's 'resend' retransmits the
        INFORMATION-REQUEST and the timeout grows (doubled, capped at
        MRT, each value randomized by RAND). Returns the parsed REPLY,
        or None once the attempt budget is exhausted.
        """

        irt_ms = dhcp6__constants.DHCP6__INF_TIMEOUT_MS
        mrt_ms = dhcp6__constants.DHCP6__INF_MAX_RT_MS
        max_attempts = dhcp6__constants.DHCP6__RETRANS_MAX_ATTEMPTS
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

            result = self._recv_within_window(client_socket, xid=xid, timeout_s=timeout_s)
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

    def _recv_within_window(self, client_socket: socket, *, xid: int, timeout_s: float) -> Dhcp6Parser | None:
        """
        Wait up to 'timeout_s' seconds for a valid REPLY, silently
        dropping bogus packets (malformed, wrong msg-type, mismatched
        xid) without consuming the entire window. Returns the parsed
        REPLY on success, or None if the deadline elapses with no
        valid response.
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

            if packet.msg_type != Dhcp6MessageType.REPLY:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with unexpected msg-type {packet.msg_type!r}; expected REPLY</>",
                )
                continue
            if packet.xid != xid:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with mismatched xid (sent={xid:#08x}, got={packet.xid:#08x})</>",
                )
                continue

            return packet
