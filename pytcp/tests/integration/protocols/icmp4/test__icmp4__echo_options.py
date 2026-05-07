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
Integration tests for the IPv4 Echo Reply options-echo path. Drives
an ICMPv4 Echo Request carrying IPv4 options through the production
RX/TX path and asserts the Echo Reply echoes the inbound options
with LSRR/SSRR reversed (RFC 1122 §3.2.2.6).

pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_options.py

ver 3.0.4
"""

from net_addr import Ip4Address, MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoRequest,
    Ip4Assembler,
    Ip4OptionEol,
    Ip4OptionLsrr,
    Ip4Options,
    Ip4OptionSsrr,
    Ip4Parser,
    PacketRx,
)
from pytcp import stack
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


def _build_echo_request(*, options: Ip4Options) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Request frame from
    HOST_A → STACK carrying the supplied IPv4 options.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=MacAddress("02:00:00:00:00:91"),
            ethernet__dst=MacAddress("02:00:00:00:00:07"),
            ethernet__payload=Ip4Assembler(
                ip4__src=Ip4Address("10.0.1.91"),
                ip4__dst=Ip4Address("10.0.1.7"),
                ip4__options=options,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(
                        id=0x1234,
                        seq=0x0001,
                        data=b"hello",
                    ),
                ),
            ),
        )
    )


class TestIcmp4EchoOptions(IcmpTestCase):
    """
    The IPv4 Echo Reply options-echo behaviour tests.
    """

    def setUp(self) -> None:
        """
        Opt into 'IP4__ACCEPT_SOURCE_ROUTE' so the inbound LSRR/SSRR
        gate does not drop the test frames before they reach the
        Echo Reply path. The default-False gate is exercised
        separately in 'test__packet_handler__ip4__rx__source_route'.
        """

        super().setUp()
        stack.IP4__ACCEPT_SOURCE_ROUTE = True

    def _parse_reply_lsrr(self, reply_frame: bytes) -> Ip4OptionLsrr | None:
        """
        Re-parse the outbound Echo Reply frame and return its LSRR
        option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.lsrr

    def _parse_reply_ssrr(self, reply_frame: bytes) -> Ip4OptionSsrr | None:
        """
        Re-parse the outbound Echo Reply frame and return its SSRR
        option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.ssrr

    def _parse_reply_options_count(self, reply_frame: bytes) -> int:
        """
        Re-parse the outbound Echo Reply frame and return the number
        of IPv4 options.
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return len(list(packet_rx.ip4.options))

    def test__icmp4__echo_options__lsrr__route_reversed_pointer_reset(self) -> None:
        """
        Ensure an inbound Echo Request carrying an LSRR option
        (route=[A, B], pointer fully consumed) produces an Echo Reply
        whose LSRR option carries the reversed route ([B, A]) with the
        pointer reset to 4 (start). This is the canonical source-route
        reversal mandate.

        Reference: RFC 1122 §3.2.2.6 (LSRR/SSRR MUST be reversed in
        Echo Reply).
        Reference: RFC 791 §3.1 (Loose Source Route wire format).
        """

        inbound_options = Ip4Options(
            Ip4OptionLsrr(
                pointer=12,
                route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            ),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Echo Request must produce exactly one Echo Reply.",
        )

        reply_lsrr = self._parse_reply_lsrr(frames_tx[0])

        self.assertIsNotNone(
            reply_lsrr,
            msg="Echo Reply must carry an LSRR option matching the request.",
        )
        assert reply_lsrr is not None  # for the type-checker
        self.assertEqual(
            reply_lsrr.route,
            [Ip4Address("10.0.1.20"), Ip4Address("10.0.1.10")],
            msg="Echo Reply LSRR route must be the inbound route reversed.",
        )
        self.assertEqual(
            reply_lsrr.pointer,
            4,
            msg="Echo Reply LSRR pointer must be reset to 4.",
        )

    def test__icmp4__echo_options__ssrr__route_reversed_pointer_reset(self) -> None:
        """
        Ensure an SSRR option in the inbound Echo Request is reversed
        the same way as LSRR — the wire format is identical, the
        semantic distinction (strict vs loose) does not affect the
        echo behaviour.

        Reference: RFC 1122 §3.2.2.6 (LSRR/SSRR MUST be reversed in
        Echo Reply).
        Reference: RFC 791 §3.1 (Strict Source Route wire format).
        """

        inbound_options = Ip4Options(
            Ip4OptionSsrr(
                pointer=12,
                route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            ),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))

        reply_ssrr = self._parse_reply_ssrr(frames_tx[0])

        self.assertIsNotNone(
            reply_ssrr,
            msg="Echo Reply must carry an SSRR option matching the request.",
        )
        assert reply_ssrr is not None  # for the type-checker
        self.assertEqual(
            reply_ssrr.route,
            [Ip4Address("10.0.1.20"), Ip4Address("10.0.1.10")],
            msg="Echo Reply SSRR route must be the inbound route reversed.",
        )
        self.assertEqual(
            reply_ssrr.pointer,
            4,
            msg="Echo Reply SSRR pointer must be reset to 4.",
        )

    def test__icmp4__echo_options__no_options__reply_unchanged(self) -> None:
        """
        Ensure an Echo Request without any IPv4 options produces an
        Echo Reply with no options either — the regression guard for
        the trivial case the Echo handler used to handle alone.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options
        — when none are present, none are emitted).
        """

        frames_tx = self._drive_rx(frame=_build_echo_request(options=Ip4Options()))

        self.assertEqual(
            self._parse_reply_options_count(frames_tx[0]),
            0,
            msg="Echo Reply must carry no options when the request had none.",
        )
