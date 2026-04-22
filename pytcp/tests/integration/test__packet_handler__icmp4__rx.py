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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains integration tests for the Packet Handler ICMPv4 RX operations.

pytcp/tests/integration/test__packet_handler__icmp4__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/ICMPv4 Echo Request",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 106 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x005c (92 bytes)
                #   Identification  : 0x3a2f
                #   Flags / Offset  : 0x4000 (DF set)
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0xea10
                #   Source IP       : 10.0.1.91
                #   Destination IP  : 10.0.1.7
                #
                # ICMPv4
                #   Type/Code       : 8 / 0 (Echo Request)
                #   Checksum        : 0xd97d
                #   Identifier      : 0x0007
                #   Sequence        : 0x000a
                #   Payload         : 64 bytes (timestamp + pattern)
                #
                # Summary: Echo request from host A to the stack; expect an echo reply.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x5c\x3a\x2f\x40\x00\x40\x01\xea\x10\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x08\x00\xd9\x7d\x00\x07\x00\x0a\x88\x9f\xba\x60\x00\x00"
                b"\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15"
                b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25"
                b"\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 106 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x005c (92 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0x6440
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # ICMPv4
                #   Type/Code       : 0 / 0 (Echo Reply)
                #   Checksum        : 0xe17d
                #   Identifier      : 0x0007
                #   Sequence        : 0x000a
                #   Payload         : 64 bytes mirrored from request
                #
                # Summary: Echo reply to host A matching the request payload and identifiers.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x5c\x00\x00\x00\x00\x40\x01\x64\x40\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x00\x00\xe1\x7d\x00\x07\x00\x0a\x88\x9f\xba\x60\x00\x00"
                b"\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15"
                b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25"
                b"\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__echo_request__respond_echo_reply=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__echo_reply__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/ICMPv4 Echo Reply, no matching raw socket",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91 (host A), type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=ICMP, total_len=33
                # ICMPv4: type=0 (Echo Reply), code=0, cksum=0xbc1c, id=0x0007, seq=0x000a, data="hello"
                #
                # Summary: Echo reply addressed to us with no matching RAW socket installed.
                #          Bumps 'icmp4__echo_reply' and returns silently (no TX).
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x21\x00\x00\x00\x00\x40\x01\x64\x7b\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x00\x00\xbc\x1c\x00\x07\x00\x0a\x68\x65\x6c\x6c\x6f",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__echo_reply=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv4/ICMPv4 unknown type (99), classified as unknown",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91 (host A), type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=ICMP, total_len=24
                # ICMPv4: type=99 (unassigned), code=0, cksum=0x9cff, no payload
                #
                # Summary: ICMPv4 frame with an unknown type code falls through the type-match
                #          to '__phrx_icmp4__unknown' and bumps 'icmp4__unknown'.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x63\x00\x9c\xff",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__unknown=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/IPv4/ICMPv4 Destination Unreachable, valid embedded IPv4+UDP, " "no matching UDP socket"
            ),
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91 (host A), type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=ICMP, total_len=56
                # ICMPv4: type=3 (Destination Unreachable), code=3 (Port), cksum=0x8cf9
                #         data = original IPv4 (28B = 20B IPv4 + 8B UDP):
                #           IPv4: src=10.0.1.7, dst=10.0.1.91, proto=UDP, total_len=28
                #           UDP : sport=12345, dport=54321, len=8, cksum=0
                #
                # Summary: Embedded IPv4+UDP packet passes the 5-condition integrity gauntlet,
                #          but no UDP socket matches the resulting metadata. Bumps
                #          'icmp4__destination_unreachable' and returns silently.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x38\x00\x00\x00\x00\x40\x01\x64\x64\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\x03\x8c\xf9\x00\x00\x00\x00\x45\x00\x00\x1c\x00\x00"
                b"\x40\x00\x40\x11\x90\x00\x0a\x00\x01\x07\x0a\x00\x01\x5b\x30\x39"
                b"\xd4\x31\x00\x08\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__destination_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv4/ICMPv4 Destination Unreachable, embedded data fails IPv4 integrity check",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91 (host A), type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=ICMP, total_len=56
                # ICMPv4: type=3 (Destination Unreachable), code=3 (Port), cksum=0xfcfc
                #         data = 28 zero bytes (frame[0] >> 4 == 0, fails 'IPv4 version' check)
                #
                # Summary: Embedded data exists but is not a valid IPv4 packet (version nibble = 0).
                #          Integrity gauntlet rejects it; the function bumps
                #          'icmp4__destination_unreachable' and returns without UDP socket lookup.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x38\x00\x00\x00\x00\x40\x01\x64\x64\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\x03\xfc\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__destination_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv4/ICMPv4 malformed (truncated) — failed parse drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91 (host A), type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=ICMP, total_len=24
                # ICMPv4: only 4 bytes (type=8, code=0, cksum=0x0000) — truncated below the
                #         8-byte minimum the Icmp4Parser expects for an Echo Request.
                #
                # Summary: Truncated ICMPv4 message triggers Icmp4Parser to raise, bumping
                #          'icmp4__failed_parse__drop' and skipping all message-type dispatch.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x08\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerIcmp4Rx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv4 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__icmp4__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received ICMPv4
        frames as expected for each parametrized case.
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected RX packet stats for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )
