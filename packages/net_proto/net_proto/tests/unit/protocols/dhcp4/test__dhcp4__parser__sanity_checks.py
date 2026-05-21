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
This module contains tests for the DHCPv4 packet parser sanity checks.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__sanity_checks.py

ver 3.0.6
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import DHCP4__HEADER__LEN, Dhcp4Parser, Dhcp4SanityError
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__MAGIC_COOKIE

# Minimum-valid options block: DHCP Message Type = ACK + End.
# Every sanity-rejection fixture appends this so the
# RFC 2131 §3 "Message Type option MUST be present" sanity
# check (added to `_validate_sanity`) does not fire before the
# field-specific sanity assertion the test is targeting.
_DHCP4_OPTIONS_MIN_VALID = b"\x35\x01\x05\xff"


def _dhcp4_frame(
    *,
    op: int = 0x02,  # BOOTREPLY
    htype: int = 0x01,
    hlen: int = 0x06,
    hops: int = 0x00,
    xid: int = 0x12345678,
    secs: int = 0x0000,
    flags: int = 0x0000,
    ciaddr: bytes = b"\x00\x00\x00\x00",
    yiaddr: bytes = b"\x0a\x00\x01\x07",  # 10.0.1.7 (valid unicast)
    siaddr: bytes = b"\x0a\x00\x01\x01",  # 10.0.1.1 (valid unicast)
    giaddr: bytes = b"\x00\x00\x00\x00",
    chaddr_mac: bytes = b"\x02\x00\x00\x00\x00\x07",
    options: bytes = _DHCP4_OPTIONS_MIN_VALID,
) -> memoryview:
    """
    Build a minimal valid DHCPv4 frame (240-byte header + DHCP magic cookie
    + minimum-valid options block carrying a Message Type option). Callers
    override one field to provoke a sanity error; the default options block
    keeps the new RFC 2131 §3 Message Type presence check satisfied.
    """

    assert len(chaddr_mac) == 6, f"Ethernet MAC must be 6 bytes. Got: {len(chaddr_mac)}"
    chaddr = chaddr_mac + b"\x00" * (16 - 6)

    sname_bytes = b"\x00" * 64
    file_bytes = b"\x00" * 128

    frame = bytes([op, htype, hlen, hops])
    frame += xid.to_bytes(4, "big")
    frame += secs.to_bytes(2, "big") + flags.to_bytes(2, "big")
    frame += ciaddr + yiaddr + siaddr + giaddr
    frame += chaddr + sname_bytes + file_bytes + DHCP4__HEADER__MAGIC_COOKIE

    assert len(frame) == DHCP4__HEADER__LEN, f"Got frame len {len(frame)}, expected {DHCP4__HEADER__LEN}"

    return memoryview(frame + options)


_MCAST_IP = b"\xe0\x00\x00\x01"  # 224.0.0.1
_LOOPBACK_IP = b"\x7f\x00\x00\x01"  # 127.0.0.1
_LIMITED_BCAST_IP = b"\xff\xff\xff\xff"  # 255.255.255.255
_MCAST_MAC = b"\x01\x00\x5e\x00\x00\x01"  # IPv4-multicast OUI
_BCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


@parameterized_class(
    [
        {
            "_description": "The 'operation' field value is unknown (0).",
            "_args": [_dhcp4_frame(op=0)],
            "_results": {
                "error_message": "The 'operation' field value must be one of [1, 2]. Got: 0.",
            },
        },
        {
            "_description": "The 'operation' field value is unknown (3).",
            "_args": [_dhcp4_frame(op=3)],
            "_results": {
                "error_message": "The 'operation' field value must be one of [1, 2]. Got: 3.",
            },
        },
        {
            "_description": "The 'yiaddr' field is multicast.",
            "_args": [_dhcp4_frame(yiaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'yiaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'yiaddr' field is loopback.",
            "_args": [_dhcp4_frame(yiaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'yiaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'yiaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(yiaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'yiaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'ciaddr' field is multicast.",
            "_args": [_dhcp4_frame(ciaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'ciaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'ciaddr' field is loopback.",
            "_args": [_dhcp4_frame(ciaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'ciaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'ciaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(ciaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'ciaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'siaddr' field is multicast.",
            "_args": [_dhcp4_frame(siaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'siaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'siaddr' field is loopback.",
            "_args": [_dhcp4_frame(siaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'siaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'siaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(siaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'siaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'giaddr' field is multicast.",
            "_args": [_dhcp4_frame(giaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'giaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'giaddr' field is loopback.",
            "_args": [_dhcp4_frame(giaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'giaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'giaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(giaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'giaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'chaddr' field is multicast.",
            "_args": [_dhcp4_frame(chaddr_mac=_MCAST_MAC)],
            "_results": {
                "error_message": "The 'chaddr' field value 01:00:5e:00:00:01 must not be a multicast MAC address.",
            },
        },
        {
            "_description": "The 'chaddr' field is broadcast.",
            "_args": [_dhcp4_frame(chaddr_mac=_BCAST_MAC)],
            "_results": {
                "error_message": "The 'chaddr' field value ff:ff:ff:ff:ff:ff must not be a broadcast MAC address.",
            },
        },
    ]
)
class TestDhcp4ParserSanityChecks(TestCase):
    """
    The DHCPv4 packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__sanity_error(self) -> None:
        """
        Ensure the DHCPv4 packet parser raises Dhcp4SanityError on logically
        inconsistent frames and reports the expected message.

        Reference: RFC 951 §8 / RFC 2131 §2 (BOOTREQUEST=1, BOOTREPLY=2 — only defined op values).
        Reference: RFC 1122 §3.2.1.3 (forbidden IPv4 addresses for host/relay endpoints).
        Reference: RFC 2131 §2 (chaddr is the client hardware address — implicit unicast).
        """

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(*self._args)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][DHCPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )


class TestDhcp4ParserSanityHappyPath(TestCase):
    """
    Happy-path sanity tests — valid frames must pass without raising.
    """

    def test__dhcp4__parser__sanity__valid_frame_parses_cleanly(self) -> None:
        """
        Ensure a structurally valid DHCPv4 REPLY frame (unicast addresses
        across yiaddr/siaddr, zeroed ciaddr/giaddr, unicast chaddr) passes
        the sanity validator without raising.

        Reference: RFC 2131 §2 (BOOTP/DHCP packet format and field semantics).
        """

        Dhcp4Parser(_dhcp4_frame())


class TestDhcp4ParserSanityMessageTypePresence(TestCase):
    """
    The DHCPv4 parser DHCP Message Type option presence sanity
    tests. RFC 2131 §3 mandates "DHCP messages MUST contain a
    'DHCP message type' option"; a magic-cookie-bearing BOOTP
    frame without option 53 cannot be classified as a DHCP
    message and must be rejected with Dhcp4SanityError.
    """

    def test__dhcp4__parser__sanity__no_message_type_rejected(self) -> None:
        """
        Ensure a structurally valid magic-cookie-bearing frame
        whose options block does NOT carry a Message Type option
        (53) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 (DHCP messages MUST contain a Message Type option).
        Reference: RFC 2132 §9.6 (Message Type option code 53).
        """

        # Options block: just an End marker; no Message Type.
        frame = _dhcp4_frame(options=b"\xff")

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][DHCPv4] DHCP messages MUST contain a Message Type option "
            "(RFC 2131 §3 / RFC 2132 §9.6). Got: magic-cookie-bearing frame without option 53.",
            msg="Unexpected message-type-absent sanity error message.",
        )

    def test__dhcp4__parser__sanity__message_type_present_accepted(self) -> None:
        """
        Ensure a frame with the minimum-valid options block
        (Message Type + End) passes the sanity check.

        Reference: RFC 2131 §3 (Message Type presence is the canonical DHCP indicator).
        """

        # Default _dhcp4_frame() options block carries the Message Type.
        Dhcp4Parser(_dhcp4_frame())
