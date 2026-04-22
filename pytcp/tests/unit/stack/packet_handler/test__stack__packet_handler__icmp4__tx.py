#!/usr/bin/env python3

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
This module contains unit tests for the 'PacketHandlerIcmp4Tx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__icmp4__tx.py

ver 3.0.4
"""


from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
)
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__icmp4__tx import (
    PacketHandlerIcmp4Tx,
)

# Silence log output emitted by the handlers during tests.
stack.LOG__CHANNEL = set()


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")


class _StubHandler(PacketHandlerIcmp4Tx):
    """
    Minimal concrete subclass of 'PacketHandlerIcmp4Tx' for testing.
    """

    def __init__(self) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self.ip4_tx_calls: list[dict[str, object]] = []

    def _phtx_ip4(self, **kwargs: object) -> TxStatus:
        self.ip4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


class TestPacketHandlerIcmp4Tx(TestCase):
    """
    The 'PacketHandlerIcmp4Tx._phtx_icmp4' behaviour tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()

    def test__stack__packet_handler__icmp4__tx__echo_reply_counted_and_forwarded(self) -> None:
        """
        Ensure an Echo Reply is counted in 'icmp4__echo_reply__send'
        and forwarded to '_phtx_ip4' with the assembled ICMPv4 payload.
        """

        status = self._handler._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoReply(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._handler._packet_stats_tx.icmp4__pre_assemble, 1)
        self.assertEqual(self._handler._packet_stats_tx.icmp4__echo_reply__send, 1)
        self.assertEqual(len(self._handler.ip4_tx_calls), 1)
        call = self._handler.ip4_tx_calls[0]
        self.assertEqual(call["ip4__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip4__dst"], HOST_A__IP4)
        self.assertIsInstance(call["ip4__payload"], Icmp4Assembler)

    def test__stack__packet_handler__icmp4__tx__echo_request_counted(self) -> None:
        """
        Ensure an Echo Request is counted in 'icmp4__echo_request__send'.
        """

        self._handler._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(self._handler._packet_stats_tx.icmp4__echo_request__send, 1)

    def test__stack__packet_handler__icmp4__tx__port_unreachable_counted(self) -> None:
        """
        Ensure a Destination Unreachable (code=PORT) is counted in
        'icmp4__destination_unreachable__port__send'.
        """

        self._handler._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.PORT,
                data=b"\x00" * 20,
            ),
        )

        self.assertEqual(self._handler._packet_stats_tx.icmp4__destination_unreachable__port__send, 1)

    def test__stack__packet_handler__icmp4__tx__unsupported_type_raises(self) -> None:
        """
        Ensure an unsupported ICMPv4 message type / code combination
        raises 'ValueError' rather than silently producing an invalid
        packet. Destination Unreachable with code=NETWORK is not in
        the supported match arms.
        """

        with self.assertRaises(ValueError):
            self._handler._phtx_icmp4(
                ip4__src=STACK__IP4_ADDRESS,
                ip4__dst=HOST_A__IP4,
                icmp4__message=Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.NETWORK,
                    data=b"\x00" * 20,
                ),
            )

    def test__stack__packet_handler__icmp4__tx__send_icmp4_packet_forwards(self) -> None:
        """
        Ensure the public 'send_icmp4_packet' helper forwards its
        arguments verbatim to '_phtx_icmp4'.
        """

        status = self._handler.send_icmp4_packet(
            ip4__local_address=STACK__IP4_ADDRESS,
            ip4__remote_address=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._handler._packet_stats_tx.icmp4__echo_request__send, 1)
