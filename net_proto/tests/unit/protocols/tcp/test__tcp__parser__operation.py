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
This module contains tests for the TCP packet parser operation.

net_proto/tests/unit/protocols/tcp/test__tcp__parser__operation.py

ver 3.0.4
"""

from types import SimpleNamespace
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import PacketRx, TcpHeader, TcpOptionNop, TcpOptions, TcpParser


@parameterized_class(
    [
        {
            "_description": ("TCP packet with no payload, no options, all flags except RST/FIN set, non-zero urg."),
            # TCP wire frame (20 bytes, header-only):
            #   Bytes 0-1   : 0x3039       -> sport=12345
            #   Bytes 2-3   : 0xd431       -> dport=54321
            #   Bytes 4-7   : 0x075bcd15   -> seq=123456789
            #   Bytes 8-11  : 0x3ade68b1   -> ack=987654321
            #   Bytes 12-13 : 0x51fa       -> hlen=20, flags=NCEUAPS
            #   Bytes 14-15 : 0x2b67       -> win=11111
            #   Bytes 16-17 : 0xaf64       -> cksum=44900
            #   Bytes 18-19 : 0x56ce       -> urg=22222
            "_frame_rx": b"\x30\x39\xd4\x31\x07\x5b\xcd\x15\x3a\xde\x68\xb1\x51\xfa\x2b\x67\xaf\x64\x56\xce",
            "_results": {
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=123456789,
                    ack=987654321,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=True,
                    flag_ece=True,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=True,
                    flag_fin=False,
                    win=11111,
                    cksum=44900,
                    urg=22222,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with no payload, no options, ACK+FIN (connection close).",
            # TCP wire frame (20 bytes, header-only, ACK+FIN):
            #   Bytes 0-1   : 0x0457       -> sport=1111
            #   Bytes 2-3   : 0x08ae       -> dport=2222
            #   Bytes 4-7   : 0x00000d05   -> seq=3333
            #   Bytes 8-11  : 0x0000115c   -> ack=4444
            #   Bytes 12-13 : 0x5011       -> hlen=20, flags=AF
            #   Bytes 14-15 : 0x15b3       -> win=5555
            #   Bytes 16-17 : 0x6ed5       -> cksum=28373
            #   Bytes 18-19 : 0x0000       -> urg=0
            "_frame_rx": b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3\x6e\xd5\x00\x00",
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=True,
                    win=5555,
                    cksum=28373,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP RST packet with no payload and 8 Nop options (hlen=28).",
            # TCP wire frame (28 bytes = 20-byte header + 8-byte Nop options):
            #   Bytes 0-1   : 0x3039       -> sport=12345
            #   Bytes 2-3   : 0xd431       -> dport=54321
            #   Bytes 4-7   : 0x00000000   -> seq=0
            #   Bytes 8-11  : 0x00000000   -> ack=0
            #   Bytes 12-13 : 0x7004       -> hlen=28, flags=R
            #   Bytes 14-15 : 0x2b67       -> win=11111
            #   Bytes 16-17 : 0x5c25       -> cksum=23589
            #   Bytes 18-19 : 0x0000       -> urg=0
            #   Bytes 20-27 : 0x01 * 8     -> 8 Nop padding options
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x00\x00\x00\x00\x00\x00\x00\x70\x04\x2b\x67"
                b"\x5c\x25\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            "_results": {
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=0,
                    ack=0,
                    hlen=28,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=True,
                    flag_syn=False,
                    flag_fin=False,
                    win=11111,
                    cksum=23589,
                    urg=0,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 8)),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with 16-byte payload, 4 Nop options, no flags set.",
            # TCP wire frame (40 bytes = 20-byte header + 4 Nops + 16-byte payload):
            #   Bytes 0-1   : 0xffff       -> sport=65535
            #   Bytes 2-3   : 0xffff       -> dport=65535
            #   Bytes 4-7   : 0xffffffff   -> seq=UINT_32__MAX
            #   Bytes 8-11  : 0xffffffff   -> ack=UINT_32__MAX
            #   Bytes 12-13 : 0x6000       -> hlen=24, flags=none
            #   Bytes 14-15 : 0xffff       -> win=65535
            #   Bytes 16-17 : 0xcf26       -> cksum=53030
            #   Bytes 18-19 : 0xffff       -> urg=65535
            #   Bytes 20-23 : 0x01 0x01 0x01 0x01 -> 4 Nop options
            #   Bytes 24-39 : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x60\x00\xff\xff"
                b"\xcf\x26\xff\xff\x01\x01\x01\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": TcpHeader(
                    sport=65535,
                    dport=65535,
                    seq=4294967295,
                    ack=4294967295,
                    hlen=24,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=65535,
                    cksum=53030,
                    urg=65535,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 4)),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "TCP packet with maximum 65515-byte payload and no options (total 65535).",
            "_frame_rx": (
                b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x51\x58\x15\xb3" b"\xb5\x2d\x00\x00" + b"X" * 65515
            ),
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=False,
                    flag_ece=True,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=5555,
                    cksum=46381,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"X" * 65515,
            },
        },
        {
            "_description": "TCP packet with maximum 65475-byte payload and max 40-byte Nop options.",
            "_frame_rx": (
                b"\x04\x57\x0d\x05\x00\x00\x15\xb3\x00\x00\x1e\x61\xf0\xb8\x00\x00"
                b"\xbd\x39\x27\x0f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" + b"X" * 65475
            ),
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=3333,
                    seq=5555,
                    ack=7777,
                    hlen=60,
                    flag_ns=False,
                    flag_cwr=True,
                    flag_ece=False,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=0,
                    cksum=48441,
                    urg=9999,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 40)),
                "payload": b"X" * 65475,
            },
        },
    ]
)
class TestTcpParserOperation(TestCase):
    """
    The TCP packet parser operation tests.

    The TCP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the TCP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(self._frame_rx),
            pshdr_sum=0,
        )

    def test__tcp__parser__header(self) -> None:
        """
        Ensure the TCP packet parser decodes the 20-byte fixed header
        into the expected TcpHeader dataclass.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__tcp__parser__options(self) -> None:
        """
        Ensure the TCP packet parser decodes the options area into the
        expected TcpOptions container.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.options,
            self._results["options"],
            msg=f"Unexpected parsed options for case: {self._description}",
        )

    def test__tcp__parser__payload(self) -> None:
        """
        Ensure the TCP packet parser extracts the payload starting at
        'hlen' and ending at 'ip.payload_len'.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            bytes(tcp_parser.payload),
            self._results["payload"],
            msg=f"Unexpected parsed payload for case: {self._description}",
        )

    def test__tcp__parser__packet_rx_tcp(self) -> None:
        """
        Ensure the TCP packet parser installs itself on the PacketRx as
        'packet_rx.tcp'.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertIs(
            self._packet_rx.tcp,
            tcp_parser,
            msg=f"Parser must install itself on packet_rx.tcp for case: {self._description}",
        )

    def test__tcp__parser__packet_rx_frame_advanced_past_hlen(self) -> None:
        """
        Ensure the TCP packet parser advances 'packet_rx.frame' past the
        TCP header so the remaining bytes are the TCP payload.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"Parser must advance packet_rx.frame past hlen for case: {self._description}",
        )
        # Sanity: parser.payload and packet_rx.frame refer to the same
        # payload region after construction.
        self.assertEqual(
            bytes(self._packet_rx.frame),
            bytes(tcp_parser.payload),
            msg=f"packet_rx.frame and parser.payload must match for case: {self._description}",
        )
