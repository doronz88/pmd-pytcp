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
Tests for the ICMPv6 parser's handling of out-of-range ICMP Code
bytes on inbound ND messages. Each ND message type's Code enum
defines only the canonical zero member; an inbound frame whose
Code byte does not map to a known enum member must surface as a
graceful 'Icmp6IntegrityError', NOT an uncaught 'ValueError' that
crashes the RX subsystem.

net_proto/tests/unit/protocols/icmp6/test__icmp6__parser__nd_code_validation.py

ver 3.0.5
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address
from net_proto import (
    EthernetAssembler,
    Icmp6Assembler,
    Icmp6IntegrityError,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRedirect,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    Icmp6Parser,
    Ip6Assembler,
    PacketRx,
    inet_cksum,
)


def _build_icmp6_frame(*, message: Any, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> bytes:
    """
    Build the full Ethernet/IPv6/ICMPv6 wire frame so the
    pseudo-header checksum (and 'ip6__dlen') can be derived from
    the same underlying assembly the parser will see.
    """

    return bytes(
        EthernetAssembler(
            ethernet__payload=Ip6Assembler(
                ip6__src=ip6__src,
                ip6__dst=ip6__dst,
                ip6__hop=255,
                ip6__payload=Icmp6Assembler(icmp6__message=message),
            ),
        )
    )


def _build_packet_rx_with_bad_code(
    *,
    icmp6_frame: bytes,
    bad_code: int,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Take a freshly-assembled ICMPv6 frame, overwrite the Code
    byte to 'bad_code', recompute the checksum so the parser's
    integrity-check stage passes (which means the bad-code
    rejection happens in the message-construction stage, not the
    checksum stage), and wrap the result in a PacketRx with a
    minimal IPv6 stub.
    """

    mutated = bytearray(icmp6_frame)
    mutated[1] = bad_code
    # Zero the existing checksum so we can recompute from scratch.
    mutated[2] = 0
    mutated[3] = 0
    pshdr_sum = (
        sum(int(b) for b in bytes(ip6__src))
        + sum(int(b) for b in bytes(ip6__dst))
        + len(mutated)
        + 58  # IPPROTO_ICMPv6
    )
    cksum = inet_cksum(bytes(mutated), init=pshdr_sum)
    mutated[2] = (cksum >> 8) & 0xFF
    mutated[3] = cksum & 0xFF

    rx = PacketRx(bytes(mutated))
    rx.ip6 = cast(
        Any,
        SimpleNamespace(
            dlen=len(mutated),
            pshdr_sum=pshdr_sum,
            src=ip6__src,
            dst=ip6__dst,
            hop=255,
        ),
    )
    return rx


@parameterized_class(
    [
        {
            "_description": "NS message (type 135) with non-zero Code byte must be rejected as integrity error.",
            "_message": Icmp6NdMessageNeighborSolicitation(
                target_address=Ip6Address("fe80::1"),
                options=Icmp6NdOptions(),
            ),
            "_ip6__src": Ip6Address("fe80::99"),
            "_ip6__dst": Ip6Address("fe80::1"),
            "_expected_code_class": "Icmp6NdNeighborSolicitationCode",
        },
        {
            "_description": "NA message (type 136) with non-zero Code byte must be rejected as integrity error.",
            "_message": Icmp6NdMessageNeighborAdvertisement(
                target_address=Ip6Address("fe80::1"),
                options=Icmp6NdOptions(),
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("ff02::1"),
            "_expected_code_class": "Icmp6NdNeighborAdvertisementCode",
        },
        {
            "_description": "RS message (type 133) with non-zero Code byte must be rejected as integrity error.",
            "_message": Icmp6NdMessageRouterSolicitation(
                options=Icmp6NdOptions(),
            ),
            "_ip6__src": Ip6Address("fe80::99"),
            "_ip6__dst": Ip6Address("ff02::2"),
            "_expected_code_class": "Icmp6NdRouterSolicitationCode",
        },
        {
            "_description": "RA message (type 134) with non-zero Code byte must be rejected as integrity error.",
            "_message": Icmp6NdMessageRouterAdvertisement(
                hop=64,
                router_lifetime=1800,
                reachable_time=0,
                retrans_timer=0,
                options=Icmp6NdOptions(),
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("ff02::1"),
            "_expected_code_class": "Icmp6NdRouterAdvertisementCode",
        },
        {
            "_description": "Redirect message (type 137) with non-zero Code byte must be rejected as integrity error.",
            "_message": Icmp6NdMessageRedirect(
                target_address=Ip6Address("fe80::1"),
                destination_address=Ip6Address("2001:db8::1234"),
                options=Icmp6NdOptions(),
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("2001:db8::7"),
            "_expected_code_class": "Icmp6NdRedirectCode",
        },
    ]
)
class TestIcmp6ParserNdCodeRejection(TestCase):
    """
    Pin that an inbound ND message with a Code byte outside the
    canonical zero member surfaces as a graceful
    'Icmp6IntegrityError' rather than an uncaught 'ValueError'.
    """

    _description: str
    _message: Any
    _ip6__src: Ip6Address
    _ip6__dst: Ip6Address
    _expected_code_class: str

    def test__icmp6__parser__nd_message_bad_code_rejected_as_integrity_error(self) -> None:
        """
        Ensure an inbound ND message whose Code byte is not
        the canonical zero value is rejected by the parser via
        'Icmp6IntegrityError' — not an uncaught 'ValueError'
        from the enum-construction path inside 'from_buffer'.

        Reference: RFC 4861 §6.1.1, §6.1.2, §7.1.1, §7.1.2 (Code = 0 mandatory for ND).
        """

        ethernet_frame = _build_icmp6_frame(
            message=self._message,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )
        # Strip Ethernet (14) + IPv6 fixed header (40) to get the
        # ICMPv6 frame the parser receives.
        icmp6_frame = ethernet_frame[14 + 40 :]

        rx = _build_packet_rx_with_bad_code(
            icmp6_frame=icmp6_frame,
            bad_code=99,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )

        with self.assertRaises(Icmp6IntegrityError) as ctx:
            Icmp6Parser(rx)

        self.assertIn(
            self._expected_code_class,
            str(ctx.exception),
            msg=("The integrity-error message must surface the offending " f"enum class for case: {self._description}"),
        )
