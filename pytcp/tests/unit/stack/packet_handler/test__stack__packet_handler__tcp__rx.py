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
This module contains unit tests for the 'PacketHandlerTcpRx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__tcp__rx.py

ver 3.0.4
"""

from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address
from net_proto import Ip4Assembler, Ip4Parser, TcpAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__tcp__rx import (
    PacketHandlerTcpRx,
)

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")


class _StubHandler(PacketHandlerTcpRx):
    """
    Minimal concrete subclass of 'PacketHandlerTcpRx' for testing.
    """

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self.tcp_tx_calls: list[dict[str, object]] = []

    def _phtx_tcp(self, **kwargs: object) -> TxStatus:
        self.tcp_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _packet_rx_from_ip4_tcp(
    *,
    src: Ip4Address = HOST_A__IP4,
    dst: Ip4Address = STACK__IP4_ADDRESS,
    sport: int = 12345,
    dport: int = 80,
    flag_syn: bool = False,
    flag_ack: bool = False,
    flag_rst: bool = False,
    flag_fin: bool = False,
    seq: int = 0,
    ack: int = 0,
    payload: bytes = b"",
) -> PacketRx:
    """
    Build a 'PacketRx' parsed through Ip4Parser with a TCP segment
    payload matching the provided header fields.
    """

    tcp = TcpAssembler(
        tcp__sport=sport,
        tcp__dport=dport,
        tcp__seq=seq,
        tcp__ack=ack,
        tcp__flag_syn=flag_syn,
        tcp__flag_ack=flag_ack,
        tcp__flag_rst=flag_rst,
        tcp__flag_fin=flag_fin,
        tcp__payload=payload,
    )
    frame = bytes(Ip4Assembler(ip4__src=src, ip4__dst=dst, ip4__payload=tcp))
    packet_rx = PacketRx(frame)
    Ip4Parser(packet_rx)
    return packet_rx


class _TcpRxTestBase(TestCase):
    """
    Common setUp for the TCP RX tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    def tearDown(self) -> None:
        self._sockets_patch.stop()


class TestPacketHandlerTcpRxParse(_TcpRxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__tcp__rx__parse_fail_drops(self) -> None:
        """
        Ensure a TCP segment with a corrupt checksum is counted in
        'tcp__failed_parse__drop'.
        """

        # Build a valid IP+TCP frame then corrupt the TCP cksum field.
        frame = bytearray(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=TcpAssembler(tcp__sport=12345, tcp__dport=80),
            )
        )
        # TCP cksum is at offset IP4_header_len + 16. Minimum IP header is 20.
        frame[20 + 16] = 0xDE
        frame[20 + 17] = 0xAD

        packet_rx = PacketRx(bytes(frame))
        Ip4Parser(packet_rx)
        self._handler._phrx_tcp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.tcp__pre_parse,
            1,
            msg="tcp__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.tcp__failed_parse__drop,
            1,
            msg="Malformed TCP must be counted in tcp__failed_parse__drop.",
        )


class TestPacketHandlerTcpRxDispatch(_TcpRxTestBase):
    """
    The socket-match and RST-response tests.
    """

    def test__stack__packet_handler__tcp__rx__active_socket_match_forwards(self) -> None:
        """
        Ensure a TCP segment matching an active socket is forwarded to
        the socket's 'process_tcp_packet'.
        """

        fake_socket = MagicMock()

        class _MatchAllDict(dict[object, object]):
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        packet_rx = _packet_rx_from_ip4_tcp(flag_ack=True, payload=b"x")
        self._handler._phrx_tcp(packet_rx)

        fake_socket.process_tcp_packet.assert_called_once()
        self.assertEqual(
            self._handler._packet_stats_rx.tcp__socket_match_active__forward_to_socket,
            1,
            msg="Active-socket forward must increment tcp__socket_match_active__forward_to_socket.",
        )
        self.assertEqual(
            self._handler.tcp_tx_calls,
            [],
            msg="Active-socket forward must not send any RST.",
        )

    def test__stack__packet_handler__tcp__rx__rst_no_match_silently_dropped(self) -> None:
        """
        Ensure a TCP RST that doesn't match any socket is silently
        dropped and no RST is sent back (would be an amplification).
        """

        packet_rx = _packet_rx_from_ip4_tcp(flag_rst=True, flag_ack=True)
        self._handler._phrx_tcp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.tcp__no_socket_match__rst__drop,
            1,
            msg="Unmatched RST must be counted in tcp__no_socket_match__rst__drop.",
        )
        self.assertEqual(
            self._handler.tcp_tx_calls,
            [],
            msg="Unmatched RST must NOT trigger a reply.",
        )

    def test__stack__packet_handler__tcp__rx__no_match_sends_rst(self) -> None:
        """
        Ensure a TCP segment that matches no socket and is not an RST
        elicits a TCP RST+ACK reply.
        """

        packet_rx = _packet_rx_from_ip4_tcp(flag_ack=True, seq=100, payload=b"hi")
        self._handler._phrx_tcp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.tcp__no_socket_match__respond_rst,
            1,
            msg="Unmatched non-RST segment must be counted in tcp__no_socket_match__respond_rst.",
        )
        self.assertEqual(len(self._handler.tcp_tx_calls), 1)
        call = self._handler.tcp_tx_calls[0]
        self.assertEqual(call["ip__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip__dst"], HOST_A__IP4)
        self.assertEqual(call["tcp__sport"], 80)
        self.assertEqual(call["tcp__dport"], 12345)
        self.assertTrue(call["tcp__flag_rst"])
        self.assertTrue(call["tcp__flag_ack"])
        # ACK must cover the incoming seq + syn + fin + payload len (100 + 0 + 0 + 2).
        self.assertEqual(call["tcp__ack"], 102)
