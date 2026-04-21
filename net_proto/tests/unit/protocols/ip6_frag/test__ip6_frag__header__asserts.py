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
This module contains tests for the IPv6 Frag header fields asserts.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__header__asserts.py

ver 3.0.4
"""


from typing import Any
from unittest import TestCase

from net_proto import (
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    Ip6FragHeader,
    IpProto,
)


class TestIp6FragHeaderAsserts(TestCase):
    """
    The IPv6 Frag header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the IPv6 Frag header
        constructor so each test can override exactly one field and
        trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "next": IpProto.RAW,
            "offset": 0,
            "flag_mf": False,
            "id": 0,
        }

    def test__ip6_frag__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from masking future regressions that would
        make the baseline invalid.
        """

        header = Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            header.next,
            IpProto.RAW,
            msg="Default-constructed header must expose next=IpProto.RAW.",
        )
        self.assertEqual(
            header.offset,
            0,
            msg="Default-constructed header must expose offset=0.",
        )
        self.assertFalse(
            header.flag_mf,
            msg="Default-constructed header must expose flag_mf=False.",
        )
        self.assertEqual(
            header.id,
            0,
            msg="Default-constructed header must expose id=0.",
        )

    def test__ip6_frag__header__next__not_IpProto(self) -> None:
        """
        Ensure the constructor rejects 'next' when it is not an IpProto.
        """

        self._kwargs["next"] = value = "not an IpProto"

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'next' field must be an IpProto. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-IpProto 'next'.",
        )

    def test__ip6_frag__header__offset__under_min(self) -> None:
        """
        Ensure the constructor rejects 'offset' below UINT_13__MIN.
        """

        self._kwargs["offset"] = value = UINT_13__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'offset' under UINT_13__MIN.",
        )

    def test__ip6_frag__header__offset__over_max(self) -> None:
        """
        Ensure the constructor rejects 'offset' above UINT_13__MAX.
        """

        self._kwargs["offset"] = value = UINT_13__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'offset' over UINT_13__MAX.",
        )

    def test__ip6_frag__header__offset__not_8_byte_alligned(self) -> None:
        """
        Ensure the constructor rejects 'offset' values that fit in 13
        bits but are not 8-byte aligned. UINT_13__MAX-1 = 0xFFF7 has
        bits 0-2 set and so trips the alignment assert that runs after
        the range check.
        """

        self._kwargs["offset"] = value = UINT_13__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be 8-byte aligned. Got: {value!r}",
            msg="Unexpected assertion message for non-8-byte-aligned 'offset'.",
        )

    def test__ip6_frag__header__flag_mf__not_boolean(self) -> None:
        """
        Ensure the constructor rejects 'flag_mf' when it is not a bool.
        """

        self._kwargs["flag_mf"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_mf' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_mf'.",
        )

    def test__ip6_frag__header__id__under_min(self) -> None:
        """
        Ensure the constructor rejects 'id' below UINT_32__MIN.
        """

        self._kwargs["id"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' under UINT_32__MIN.",
        )

    def test__ip6_frag__header__id__over_max(self) -> None:
        """
        Ensure the constructor rejects 'id' above UINT_32__MAX.
        """

        self._kwargs["id"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' over UINT_32__MAX.",
        )
