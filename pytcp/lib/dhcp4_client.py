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
This module contains a simple DHCPv4 client used internally by the stack.

pytcp/lib/dhcp4_client.py

ver 3.0.4
"""

import random
import time
from dataclasses import dataclass
from typing import Callable

from net_addr import Ip4Address, Ip4Host, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from net_proto.protocols.dhcp4.options.dhcp4__option import Dhcp4OptionType
from net_proto.protocols.dhcp4.options.dhcp4__option__client_id import (
    Dhcp4OptionClientId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__host_name import (
    Dhcp4OptionHostName,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options
from pytcp.lib.dhcp_uid import build_client_id
from pytcp.lib.logger import log
from pytcp.protocols.dhcp4 import dhcp4__constants
from pytcp.socket import AF_INET4, SOCK_DGRAM, socket

# 'secs' is a 16-bit field in the DHCP header; cap the elapsed-
# since-acquisition seconds at UINT16_MAX so a long-lived restart
# loop cannot overflow.
_DHCP4__SECS_MAX: int = 0xFFFF


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Lease:
    """
    A negotiated DHCPv4 lease — the address+mask+gateway bundle plus
    the lease-time / server-identity / acquisition-time metadata the
    lifecycle thread needs to schedule RENEW/REBIND/RELEASE.
    """

    ip4_host: Ip4Host
    lease_time__sec: int
    server_id: Ip4Address
    acquired_at_monotonic: float


class _NakRestart:
    """
    Sentinel — DHCPNAK received in response to REQUEST; restart from
    DISCOVER (RFC 2131 §3.1 step 4).
    """


_NAK_RESTART: _NakRestart = _NakRestart()


class Dhcp4Client:
    """
    The DHCPv4 client.
    """

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        arp_dad_verifier: "Callable[[Ip4Address], bool] | None" = None,
    ) -> None:
        """
        Initialize the DHCPv4 client.

        The optional 'arp_dad_verifier' callback is invoked against
        the offered 'yiaddr' after a valid ACK; on False, 'fetch()'
        emits DHCPDECLINE per RFC 2131 §3.1 step 5 and restarts
        from DISCOVER. The packet handler wires this to its RFC 5227
        §2.1.1 probe loop; tests pass a 'MagicMock'.
        """

        self._mac_address = mac_address
        self._arp_dad_verifier = arp_dad_verifier
        # Set at the top of 'fetch()'; reused by every outbound TX in
        # this acquisition cycle to populate the DHCP header 'secs'
        # field per RFC 1542 §3.2.
        self._fetch_started_at_monotonic: float = 0.0

    @property
    def _expected_client_id(self) -> bytes:
        """
        RFC 4361 §6.1 Client Identifier — type=0xff + IAID + DUID.
        Recomputed on every access so an operator override of
        'dhcp.duid' between emissions takes effect immediately.
        """

        return build_client_id(self._mac_address)

    def fetch(self) -> Dhcp4Lease | None:
        """
        Run the DHCPv4 DISCOVER/REQUEST handshake and return the lease.

        Begins with an RFC 2131 §4.4.1 startup desynchronisation
        delay (random uniform in 'dhcp.init_delay_{min,max}_ms')
        so a fleet of hosts powered on simultaneously does not all
        DISCOVER at the same instant. The delay is bypassed entirely
        when both bounds are 0 — the canonical disable-for-tests
        configuration.

        On a DHCPNAK to the REQUEST, restart from DISCOVER up to
        'dhcp.nak_max_restarts' times before giving up. Every recv
        wait runs under the RFC 2131 §4.1 retransmission backoff
        (initial / max / attempts / jitter all sysctl-tunable).
        """

        self._initial_delay()
        self._fetch_started_at_monotonic = time.monotonic()

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            for _ in range(dhcp4__constants.DHCP4__NAK_MAX_RESTARTS + 1):
                outcome = self._discover_request_once(client_socket)
                if not isinstance(outcome, _NakRestart):
                    return outcome
            __debug__ and log(
                "dhcp4",
                "<WARN>DHCP NAK restart budget exhausted - giving up</>",
            )
            return None
        finally:
            client_socket.close()

    def _discover_request_once(self, client_socket: socket) -> Dhcp4Lease | _NakRestart | None:
        """
        Run a single DISCOVER/OFFER/REQUEST/ACK round-trip with
        retransmission backoff on each recv leg.

        Returns a 'Dhcp4Lease' on success, '_NAK_RESTART' on DHCPNAK
        (caller restarts from DISCOVER), or None on any hard failure
        (silence across the backoff window, mismatched xid/CID,
        wrong message type, missing mandatory option).
        """

        xid = random.randint(0, 0xFFFFFFFF)

        self._send_discover(client_socket, xid=xid)
        offer = self._recv_with_backoff(
            client_socket,
            expected_type=Dhcp4MessageType.OFFER,
            xid=xid,
            resend=lambda: self._send_discover(client_socket, xid=xid),
        )
        if offer is None:
            return None
        # 'allow_nak' defaults to False on the OFFER leg, so a NAK
        # would have been treated as 'wrong message type' and dropped
        # — narrow to 'Dhcp4Parser' for downstream attribute access.
        assert isinstance(offer, Dhcp4Parser)

        srv_id = offer.srv_id
        if srv_id is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Offer message - missing server identifier</>",
            )
            return None
        yiaddr = offer.yiaddr

        self._send_request(client_socket, xid=xid, srv_id=srv_id, yiaddr=yiaddr)
        ack = self._recv_with_backoff(
            client_socket,
            expected_type=Dhcp4MessageType.ACK,
            xid=xid,
            resend=lambda: self._send_request(client_socket, xid=xid, srv_id=srv_id, yiaddr=yiaddr),
            allow_nak=True,
        )
        if isinstance(ack, _NakRestart):
            return _NAK_RESTART
        if ack is None:
            return None
        # 'allow_nak' was True on the ACK leg, but the NAK case was
        # handled by the 'isinstance' branch above — narrow to
        # 'Dhcp4Parser' for downstream attribute access.
        assert isinstance(ack, Dhcp4Parser)

        if ack.subnet_mask is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Ack message - missing subnet mask</>",
            )
            return None

        if ack.lease_time is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Ack message - missing IP address lease time</>",
            )
            return None

        ip4_host = Ip4Host((ack.yiaddr, ack.subnet_mask))
        if ack.router:
            ip4_host.gateway = ack.router[0]

        # RFC 2131 §3.1 step 5 — probe the offered address before
        # claiming it. On conflict, emit DHCPDECLINE, wait at
        # least 10 s, and restart from DISCOVER via the same
        # outer-loop sentinel used by the NAK path.
        if self._arp_dad_verifier is not None and not self._arp_dad_verifier(ip4_host.address):
            __debug__ and log(
                "dhcp4",
                f"<WARN>ARP DAD reported conflict on {ip4_host.address}; sending DHCPDECLINE</>",
            )
            self._send_decline(
                client_socket,
                xid=xid,
                srv_id=srv_id,
                yiaddr=ip4_host.address,
            )
            backoff_s = dhcp4__constants.DHCP4__DECLINE_BACKOFF_MS / 1000.0
            if backoff_s > 0:
                time.sleep(backoff_s)
            return _NAK_RESTART

        return Dhcp4Lease(
            ip4_host=ip4_host,
            lease_time__sec=ack.lease_time,
            server_id=srv_id,
            acquired_at_monotonic=time.monotonic(),
        )

    def _recv_with_backoff(
        self,
        client_socket: socket,
        *,
        expected_type: Dhcp4MessageType,
        xid: int,
        resend: "Callable[[], None]",  # noqa: F821 — typing alias defined below
        allow_nak: bool = False,
    ) -> "Dhcp4Parser | _NakRestart | None":
        """
        Wait for an inbound DHCP message of 'expected_type' using the
        RFC 2131 §4.1 retransmission backoff. On each per-attempt
        timeout the caller-provided 'resend' callback retransmits the
        prior TX and the delay doubles (capped at
        'dhcp.retrans_max_ms'). Returns the parsed message on
        success, '_NAK_RESTART' if a NAK arrives and 'allow_nak' is
        True, or None when the attempt budget is exhausted.

        Bogus inbound packets (malformed, mismatched xid, mismatched
        CID echo, wrong message type) are silently dropped without
        burning the current attempt's wait window — the loop keeps
        listening until the monotonic deadline expires.
        """

        delay_ms = dhcp4__constants.DHCP4__RETRANS_INITIAL_MS
        max_ms = dhcp4__constants.DHCP4__RETRANS_MAX_MS
        max_attempts = dhcp4__constants.DHCP4__RETRANS_MAX_ATTEMPTS
        jitter_ms = dhcp4__constants.DHCP4__RETRANS_JITTER_MS

        for attempt in range(max_attempts):
            jitter_s = random.uniform(-jitter_ms / 1000.0, jitter_ms / 1000.0)
            timeout_s = max(0.001, delay_ms / 1000.0 + jitter_s)
            result = self._recv_within_window(
                client_socket,
                expected_type=expected_type,
                xid=xid,
                timeout_s=timeout_s,
                allow_nak=allow_nak,
            )
            if result is not None:
                return result
            if attempt < max_attempts - 1:
                __debug__ and log(
                    "dhcp4",
                    f"recv window expired ({timeout_s:.2f}s); retransmitting "
                    f"(attempt {attempt + 2} of {max_attempts})",
                )
                resend()
                delay_ms = min(delay_ms * 2, max_ms)
        return None

    def _recv_within_window(
        self,
        client_socket: socket,
        *,
        expected_type: Dhcp4MessageType,
        xid: int,
        timeout_s: float,
        allow_nak: bool,
    ) -> "Dhcp4Parser | _NakRestart | None":
        """
        Wait up to 'timeout_s' seconds for a valid DHCP message,
        silently dropping bogus packets (malformed, wrong type, bad
        xid, bad CID echo) without consuming the entire window.
        Returns the parsed message on success, '_NAK_RESTART' on a
        valid NAK if 'allow_nak' is True, or None if the deadline
        elapses with no valid response.

        The first 'recv__mv' call uses 'timeout_s' directly so the
        caller's intended window value reaches the socket layer
        verbatim; subsequent iterations (only entered after dropping
        a bogus packet) compute the remaining budget against a
        monotonic deadline anchored at the start of the window.
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
                packet = Dhcp4Parser(client_socket.recv__mv(timeout=remaining))
            except TimeoutError:
                return None
            except Dhcp4IntegrityError:
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Dropping malformed inbound DHCP frame; continuing wait window</>",
                )
                continue

            if allow_nak and packet.message_type == Dhcp4MessageType.NAK:
                if packet.xid != xid or not self._cid_echo_ok(packet):
                    __debug__ and log(
                        "dhcp4",
                        "<WARN>Dropping NAK with mismatched xid or CID echo</>",
                    )
                    continue
                __debug__ and log("dhcp4", "DHCP NAK received - restarting from DISCOVER")
                return _NAK_RESTART

            if packet.message_type != expected_type:
                __debug__ and log(
                    "dhcp4",
                    f"<WARN>Dropping DHCP frame with unexpected message type "
                    f"{packet.message_type!r}; expected {expected_type!r}</>",
                )
                continue
            if packet.xid != xid:
                __debug__ and log(
                    "dhcp4",
                    f"<WARN>Dropping DHCP frame with mismatched xid " f"(sent={xid:#010x}, got={packet.xid:#010x})</>",
                )
                continue
            if not self._cid_echo_ok(packet):
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Dropping DHCP frame with mismatched Client Identifier echo</>",
                )
                continue

            return packet

    def _send_discover(self, client_socket: socket, *, xid: int) -> None:
        """
        Build and send the DHCP DISCOVER packet.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _send_request(
        self,
        client_socket: socket,
        *,
        xid: int,
        srv_id: Ip4Address,
        yiaddr: Ip4Address,
    ) -> None:
        """
        Build and send the DHCP REQUEST packet.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionServerId(srv_id),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _send_decline(
        self,
        client_socket: socket,
        *,
        xid: int,
        srv_id: Ip4Address,
        yiaddr: Ip4Address,
    ) -> None:
        """
        Build and send the DHCPDECLINE packet per RFC 2131 §3.1 step
        5. The DECLINE carries Server Identifier (option 54) and
        Requested IP Address (option 50) identifying the rejected
        offer, plus the Client Identifier (RFC 2131 §2 / RFC 6842
        §3). 'ciaddr' is 0 because the address has not been
        claimed.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DECLINE),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionServerId(srv_id),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _initial_delay(self) -> None:
        """
        Sleep for an RFC 2131 §4.4.1 startup desynchronisation
        delay drawn uniformly from
        '[dhcp.init_delay_min_ms, dhcp.init_delay_max_ms]'.
        Bypassed when 'init_delay_max_ms' is 0 — the canonical
        disable-for-tests configuration.
        """

        max_ms = dhcp4__constants.DHCP4__INIT_DELAY_MAX_MS
        if max_ms == 0:
            return
        min_ms = dhcp4__constants.DHCP4__INIT_DELAY_MIN_MS
        delay_s = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
        __debug__ and log("dhcp4", f"Initial desync delay: {delay_s:.2f}s")
        time.sleep(delay_s)

    def _elapsed_secs(self) -> int:
        """
        Compute the DHCP header 'secs' field per RFC 1542 §3.2 —
        seconds elapsed since the client began the address-
        acquisition process. Capped at UINT16_MAX so a long-running
        restart loop cannot overflow the 16-bit field.
        """

        return min(
            _DHCP4__SECS_MAX,
            max(0, int(time.monotonic() - self._fetch_started_at_monotonic)),
        )

    def _cid_echo_ok(self, packet: Dhcp4Parser) -> bool:
        """
        Validate the Client Identifier echo per RFC 6842 §3 — when the
        server echoes the CID option, the value MUST match what the
        client emitted. An absent echo is acceptable (RFC 6842 says
        "if the client identifier option is present").
        """

        echoed = packet.client_id
        return echoed is None or echoed == self._expected_client_id
