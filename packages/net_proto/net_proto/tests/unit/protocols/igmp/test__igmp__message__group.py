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
This module contains tests for the legacy IGMP group message.

net_proto/tests/unit/protocols/igmp/test__igmp__message__group.py

ver 3.0.6
"""

from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto.protocols.igmp.igmp__errors import IgmpSanityError
from net_proto.protocols.igmp.message.igmp__message import IgmpType
from net_proto.protocols.igmp.message.igmp__message__group import (
    IgmpMessageGroup,
)


@parameterized_class(
    [
        {
            "_description": "IGMPv2 Membership Report (type 0x16).",
            "_type": IgmpType.V2_MEMBERSHIP_REPORT,
            # IGMPv2 Membership Report (8 bytes):
            #   Byte 0    : 0x16 -> type (V2 Membership Report)
            #   Byte 1    : 0x00 -> Max Resp Time (0 in non-Query messages)
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x16\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMP V2 Membership Report group 239.1.1.1",
        },
        {
            "_description": "IGMPv2 Leave Group (type 0x17).",
            "_type": IgmpType.V2_LEAVE_GROUP,
            # IGMPv2 Leave Group (8 bytes):
            #   Byte 0    : 0x17 -> type (V2 Leave Group)
            #   Byte 1    : 0x00 -> Max Resp Time (0 in non-Query messages)
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x17\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMP V2 Leave Group group 239.1.1.1",
        },
        {
            "_description": "IGMPv1 Membership Report (type 0x12).",
            "_type": IgmpType.V1_MEMBERSHIP_REPORT,
            # IGMPv1 Membership Report (8 bytes):
            #   Byte 0    : 0x12 -> type (V1 Membership Report)
            #   Byte 1    : 0x00 -> unused
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x12\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMP V1 Membership Report group 239.1.1.1",
        },
    ]
)
class TestIgmpMessageGroup(TestCase):
    """
    The legacy IGMP group message (V2 Report / V2 Leave / V1 Report) tests.
    """

    _description: str
    _type: IgmpType
    _bytes: bytes
    _str: str

    def setUp(self) -> None:
        """
        Build the parametrized legacy IGMP group message instance.
        """

        self._message = IgmpMessageGroup(type=self._type, group_address=Ip4Address("239.1.1.1"))

    def test__igmp__group__len(self) -> None:
        """
        Ensure the legacy group message is always 8 octets.

        Reference: RFC 2236 §2 (8-octet message format).
        Reference: RFC 1112 §6 (V1 Membership Report).
        """

        self.assertEqual(
            len(self._message),
            8,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__igmp__group__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical group-message log line.

        Reference: RFC 2236 §2 (message format).
        """

        self.assertEqual(
            str(self._message),
            self._str,
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__igmp__group__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the 8-octet wire encoding with the Max
        Resp Time octet zeroed and the checksum slot left for injection.

        Reference: RFC 2236 §2 (message format).
        Reference: RFC 2236 §2.2 (Max Resp Time zero in non-Query messages).
        """

        self.assertEqual(
            bytes(self._message),
            self._bytes,
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__igmp__group__roundtrip(self) -> None:
        """
        Ensure the wire bytes round-trip through 'from_buffer()' and
        reproduce the same type and group address.

        Reference: RFC 2236 §2 (message format).
        """

        parsed = IgmpMessageGroup.from_buffer(self._bytes)

        self.assertEqual(parsed.type, self._type, msg=f"Unexpected type for case: {self._description}")
        self.assertEqual(
            parsed.group_address,
            Ip4Address("239.1.1.1"),
            msg=f"Unexpected group_address for case: {self._description}",
        )

    def test__igmp__group__sanity_accepts_multicast_group(self) -> None:
        """
        Ensure a group message naming a multicast group passes sanity.

        Reference: RFC 2236 §2.4 (Group Address holds the multicast group).
        """

        self._message.validate_sanity()


class TestIgmpMessageGroupAsserts(TestCase):
    """
    The legacy IGMP group message assertion / sanity tests.
    """

    def test__igmp__group__rejects_non_legacy_type(self) -> None:
        """
        Ensure constructing a group message with a non-legacy type (a
        Query or V3 Report type) is rejected.

        Reference: RFC 3376 §4 (type 0x11 / 0x22 are not group messages).
        """

        with self.assertRaises(AssertionError) as error:
            IgmpMessageGroup(
                type=IgmpType.MEMBERSHIP_QUERY,
                group_address=Ip4Address("239.1.1.1"),
            )

        self.assertIn("The 'type' field must be one of", str(error.exception))

    def test__igmp__group__sanity_rejects_non_multicast_group(self) -> None:
        """
        Ensure a group message whose group address is not multicast is
        rejected at sanity.

        Reference: RFC 2236 §2.4 (Group Address holds the multicast group).
        """

        message = IgmpMessageGroup(
            type=IgmpType.V2_MEMBERSHIP_REPORT,
            group_address=Ip4Address("192.0.2.1"),
        )

        with self.assertRaises(IgmpSanityError) as error:
            message.validate_sanity()

        self.assertIn("must be a multicast address", str(error.exception))
