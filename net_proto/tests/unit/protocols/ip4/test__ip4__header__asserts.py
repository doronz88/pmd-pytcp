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
This module contains tests for the IPv4 header fields asserts.

net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    IP4__HEADER__LEN,
    IP4__HEADER__MAX_LEN,
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    Ip4Header,
    IpProto,
)


class TestIp4HeaderAsserts(TestCase):
    """
    The IPv4 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the IPv4 header constructor
        so each test can override exactly one field and trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "hlen": IP4__HEADER__LEN,
            "dscp": 0,
            "ecn": 0,
            "plen": IP4__HEADER__LEN,
            "id": 0,
            "flag_mf": False,
            "flag_df": False,
            "offset": 0,
            "ttl": 0,
            "proto": IpProto.RAW,
            "cksum": 0,
            "src": Ip4Address(),
            "dst": Ip4Address(),
        }

    def test__ip4__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards the
        negative tests from masking future regressions that would make the
        baseline invalid.
        """

        header = Ip4Header(**self._kwargs)

        self.assertEqual(
            header.hlen,
            IP4__HEADER__LEN,
            msg="Default-constructed header must expose hlen=IP4__HEADER__LEN.",
        )

    def test__ip4__header__hlen__under_min(self) -> None:
        """
        Ensure the constructor rejects 'hlen' below IP4__HEADER__LEN
        (20 bytes).
        """

        self._kwargs["hlen"] = value = IP4__HEADER__LEN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'hlen' field must be a 4-byte-aligned integer in "
                f"[{IP4__HEADER__LEN}, {IP4__HEADER__MAX_LEN}]. Got: {value!r}"
            ),
            msg="Unexpected assertion message for 'hlen' under IP4__HEADER__LEN.",
        )

    def test__ip4__header__hlen__over_max(self) -> None:
        """
        Ensure the constructor rejects 'hlen' above IP4__HEADER__MAX_LEN
        (60 bytes; IHL=15 * 4 = 60 is the wire ceiling).
        """

        self._kwargs["hlen"] = value = IP4__HEADER__MAX_LEN + 4

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'hlen' field must be a 4-byte-aligned integer in "
                f"[{IP4__HEADER__LEN}, {IP4__HEADER__MAX_LEN}]. Got: {value!r}"
            ),
            msg="Unexpected assertion message for 'hlen' over IP4__HEADER__MAX_LEN.",
        )

    def test__ip4__header__hlen__not_4_byte_alligned(self) -> None:
        """
        Ensure the constructor rejects 'hlen' values that are in the
        [20, 60] range but not multiples of 4. The wire IHL field
        counts 4-byte words, so these values cannot round-trip.
        """

        self._kwargs["hlen"] = value = IP4__HEADER__LEN + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'hlen' field must be a 4-byte-aligned integer in "
                f"[{IP4__HEADER__LEN}, {IP4__HEADER__MAX_LEN}]. Got: {value!r}"
            ),
            msg="Unexpected assertion message for non-4-byte-aligned 'hlen'.",
        )

    def test__ip4__header__hlen__at_max_accepted(self) -> None:
        """
        Ensure the constructor accepts 'hlen' exactly at
        IP4__HEADER__MAX_LEN (boundary case).
        """

        self._kwargs["hlen"] = IP4__HEADER__MAX_LEN
        self._kwargs["plen"] = IP4__HEADER__MAX_LEN

        header = Ip4Header(**self._kwargs)

        self.assertEqual(
            header.hlen,
            IP4__HEADER__MAX_LEN,
            msg="Default-constructed header must accept hlen=IP4__HEADER__MAX_LEN.",
        )

    def test__ip4__header__dscp__under_min(self) -> None:
        """
        Ensure the constructor rejects 'dscp' below UINT_6__MIN.
        """

        self._kwargs["dscp"] = value = UINT_6__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dscp' under UINT_6__MIN.",
        )

    def test__ip4__header__dscp__over_max(self) -> None:
        """
        Ensure the constructor rejects 'dscp' above UINT_6__MAX.
        """

        self._kwargs["dscp"] = value = UINT_6__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dscp' over UINT_6__MAX.",
        )

    def test__ip4__header__ecn__under_min(self) -> None:
        """
        Ensure the constructor rejects 'ecn' below UINT_2__MIN.
        """

        self._kwargs["ecn"] = value = UINT_2__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ecn' under UINT_2__MIN.",
        )

    def test__ip4__header__ecn__over_max(self) -> None:
        """
        Ensure the constructor rejects 'ecn' above UINT_2__MAX.
        """

        self._kwargs["ecn"] = value = UINT_2__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ecn' over UINT_2__MAX.",
        )

    def test__ip4__header__plen__under_min(self) -> None:
        """
        Ensure the constructor rejects 'plen' below IP4__HEADER__LEN.
        """

        self._kwargs["plen"] = value = IP4__HEADER__LEN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer greater than or equal to 20. Got: {value!r}",
            msg="Unexpected assertion message for 'plen' under IP4__HEADER__LEN.",
        )

    def test__ip4__header__plen__over_max(self) -> None:
        """
        Ensure the constructor rejects 'plen' above UINT_16__MAX.
        """

        self._kwargs["plen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer greater than or equal to 20. Got: {value!r}",
            msg="Unexpected assertion message for 'plen' over UINT_16__MAX.",
        )

    def test__ip4__header__id__under_min(self) -> None:
        """
        Ensure the constructor rejects 'id' below UINT_16__MIN.
        """

        self._kwargs["id"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' under UINT_16__MIN.",
        )

    def test__ip4__header__id__over_max(self) -> None:
        """
        Ensure the constructor rejects 'id' above UINT_16__MAX.
        """

        self._kwargs["id"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' over UINT_16__MAX.",
        )

    def test__ip4__header__flag_df__not_boolean(self) -> None:
        """
        Ensure the constructor rejects 'flag_df' when it is not a bool.
        """

        self._kwargs["flag_df"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_df' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_df'.",
        )

    def test__ip4__header__flag_mf__not_boolean(self) -> None:
        """
        Ensure the constructor rejects 'flag_mf' when it is not a bool.
        """

        self._kwargs["flag_mf"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_mf' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_mf'.",
        )

    def test__ip4__header__offset__under_min(self) -> None:
        """
        Ensure the constructor rejects 'offset' below UINT_13__MIN.
        """

        self._kwargs["offset"] = value = UINT_13__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'offset' under UINT_13__MIN.",
        )

    def test__ip4__header__offset__over_max(self) -> None:
        """
        Ensure the constructor rejects 'offset' above UINT_13__MAX.
        """

        self._kwargs["offset"] = value = UINT_13__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'offset' over UINT_13__MAX.",
        )

    def test__ip4__header__offset__not_8_byte_alligned(self) -> None:
        """
        Ensure the constructor rejects 'offset' that is not a multiple
        of 8 bytes (UINT_13__MAX - 1 is the largest 13-bit value short
        of the aligned upper bound).
        """

        self._kwargs["offset"] = value = UINT_13__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be 8-byte aligned. Got: {value!r}",
            msg="Unexpected assertion message for non-8-byte-aligned 'offset'.",
        )

    def test__ip4__header__ttl__under_min(self) -> None:
        """
        Ensure the constructor rejects 'ttl' below UINT_8__MIN.
        """

        self._kwargs["ttl"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ttl' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ttl' under UINT_8__MIN.",
        )

    def test__ip4__header__ttl__over_max(self) -> None:
        """
        Ensure the constructor rejects 'ttl' above UINT_8__MAX.
        """

        self._kwargs["ttl"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ttl' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ttl' over UINT_8__MAX.",
        )

    def test__ip4__header__proto__not_IpProto(self) -> None:
        """
        Ensure the constructor rejects 'proto' when it is not an IpProto.
        """

        self._kwargs["proto"] = value = "not an IpProto"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'proto' field must be an IpProto. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-IpProto 'proto'.",
        )

    def test__ip4__header__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects 'cksum' below UINT_16__MIN.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' under UINT_16__MIN.",
        )

    def test__ip4__header__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects 'cksum' above UINT_16__MAX.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' over UINT_16__MAX.",
        )

    def test__ip4__header__src__not_ip4_address(self) -> None:
        """
        Ensure the constructor rejects 'src' when it is not an Ip4Address.
        """

        self._kwargs["src"] = value = 0

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip4Address 'src'.",
        )

    def test__ip4__header__dst__not_ip4_address(self) -> None:
        """
        Ensure the constructor rejects 'dst' when it is not an Ip4Address.
        """

        self._kwargs["dst"] = value = 0

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip4Address 'dst'.",
        )
