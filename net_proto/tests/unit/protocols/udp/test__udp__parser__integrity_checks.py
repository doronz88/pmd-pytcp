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
Module contains tests for the UDP packet integrity checks.

net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py

ver 3.0.4
"""


from types import SimpleNamespace
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import PacketRx, UdpIntegrityError, UdpParser

# A valid 8-byte UDP frame used as the baseline for parser-integrity
# fixtures. Callers perturb exactly one aspect (payload_len, plen,
# checksum) to exercise individual integrity branches.
#
# UDP wire frame (8 bytes, header-only):
#   Bytes 0-1 : 0x3039 -> sport=12345
#   Bytes 2-3 : 0xd431 -> dport=54321
#   Bytes 4-5 : 0x0008 -> plen=8 (header-only)
#   Bytes 6-7 : 0xfb8c -> cksum (valid for init=0)
_BASELINE_FRAME = b"\x30\x39\xd4\x31\x00\x08\xfb\x8c"


@parameterized_class(
    [
        {
            "_description": "The 'ip__payload_len' is lower than UDP__HEADER__LEN.",
            "_frame_rx": _BASELINE_FRAME,
            "_ip__payload_len": 7,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, "
                "self._ip__payload_len=7, len(self._frame)=8"
            ),
        },
        {
            "_description": "The 'ip__payload_len' is higher than the frame length.",
            "_frame_rx": _BASELINE_FRAME,
            "_ip__payload_len": 9,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, "
                "self._ip__payload_len=9, len(self._frame)=8"
            ),
        },
        {
            "_description": "The header 'plen' field (7) is lower than UDP__HEADER__LEN.",
            # UDP wire frame (8 bytes, header-only, plen = 7):
            #   Bytes 0-1 : 0x3039 -> sport=12345
            #   Bytes 2-3 : 0xd431 -> dport=54321
            #   Bytes 4-5 : 0x0007 -> plen=7 (integrity violation: < 8)
            #   Bytes 6-7 : 0xfb8c -> cksum (irrelevant; plen check fires first)
            "_frame_rx": b"\x30\x39\xd4\x31\x00\x07\xfb\x8c",
            "_ip__payload_len": 8,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                "<= len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, plen=7, "
                "self._ip__payload_len=8, len(self._frame)=8"
            ),
        },
        {
            "_description": "The header 'plen' field does not match 'ip__payload_len'.",
            # UDP wire frame (10 bytes, header + 2-byte padding):
            #   Bytes 0-1 : 0x3039 -> sport=12345
            #   Bytes 2-3 : 0xd431 -> dport=54321
            #   Bytes 4-5 : 0x0008 -> plen=8 (disagrees with payload_len=9)
            #   Bytes 6-7 : 0xfb8c -> cksum
            #   Bytes 8-9 : 0x0000 -> filler past plen (makes frame longer
            #                        than plen without making plen < 8)
            "_frame_rx": b"\x30\x39\xd4\x31\x00\x08\xfb\x8c\x00\x00",
            "_ip__payload_len": 9,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                "<= len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, plen=8, "
                "self._ip__payload_len=9, len(self._frame)=10"
            ),
        },
        {
            "_description": "Packet has non-zero but incorrect checksum.",
            # UDP wire frame (24 bytes = 8-byte header + 16-byte payload):
            #   Bytes 0-1  : 0x3039       -> sport=12345
            #   Bytes 2-3  : 0xd431       -> dport=54321
            #   Bytes 4-5  : 0x0018       -> plen=24 (header + payload)
            #   Bytes 6-7  : 0xabcd       -> cksum (intentionally wrong)
            #   Bytes 8-23 : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x18\xab\xcd\x30\x31\x32\x33\x34\x35\x36\x37" b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_ip__payload_len": 24,
            "_ip__pshdr_sum": 0,
            "_error_message": "The packet checksum must be valid.",
        },
    ]
)
class TestUdpParserIntegrityChecks(TestCase):
    """
    The UDP packet parser integrity checks tests.

    The UDP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _ip__payload_len: int
    _ip__pshdr_sum: int
    _error_message: str

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the UDP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=self._ip__payload_len,
            pshdr_sum=self._ip__pshdr_sum,
        )

    def test__udp__parser__integrity_error(self) -> None:
        """
        Ensure the UDP packet parser raises UdpIntegrityError with the
        expected message for each malformed frame.
        """

        with self.assertRaises(UdpIntegrityError) as error:
            UdpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][UDP] {self._error_message}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestUdpParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the UDP parser integrity validator. Exercises the
    positive path — the shortest frame that passes every integrity check
    — so a future regression that tightens the constraint is caught as a
    test failure rather than silently masked by the parametrized
    rejection fixtures.
    """

    def test__udp__parser__integrity__baseline_accepted(self) -> None:
        """
        Ensure the baseline 8-byte frame (header-only, valid checksum)
        passes every integrity check and parses successfully.
        """

        self.assertEqual(
            len(_BASELINE_FRAME),
            8,
            msg="Baseline fixture must be exactly 8 bytes (header only).",
        )

        packet_rx = PacketRx(_BASELINE_FRAME)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(_BASELINE_FRAME),
            pshdr_sum=0,
        )

        parser = UdpParser(packet_rx)

        self.assertEqual(
            parser.sport,
            12345,
            msg="Baseline-frame parser must report sport=12345.",
        )
        self.assertEqual(
            parser.dport,
            54321,
            msg="Baseline-frame parser must report dport=54321.",
        )
        self.assertEqual(
            parser.plen,
            8,
            msg="Baseline-frame parser must report plen=8.",
        )

    def test__udp__parser__integrity__zero_cksum_skips_validation(self) -> None:
        """
        Ensure a frame with cksum=0 bypasses checksum validation even
        when the bytes would otherwise not sum to zero. RFC 768 allows a
        transmitter to set the UDP checksum to zero, in which case the
        receiver must not validate it.
        """

        # UDP wire frame (8 bytes, header-only, cksum=0):
        #   Bytes 0-1 : 0x3039 -> sport=12345
        #   Bytes 2-3 : 0xd431 -> dport=54321
        #   Bytes 4-5 : 0x0008 -> plen=8
        #   Bytes 6-7 : 0x0000 -> cksum=0 (validation skipped)
        frame = b"\x30\x39\xd4\x31\x00\x08\x00\x00"

        packet_rx = PacketRx(frame)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(frame),
            pshdr_sum=0,
        )

        parser = UdpParser(packet_rx)

        self.assertEqual(
            parser.cksum,
            0,
            msg="Zero-cksum frame must pass integrity with cksum=0 preserved on the header.",
        )
