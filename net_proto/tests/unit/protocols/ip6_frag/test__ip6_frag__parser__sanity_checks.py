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
This module contains tests for the IPv6 Frag packet sanity checks.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__parser__sanity_checks.py

ver 3.0.4
"""


from types import SimpleNamespace
from unittest import TestCase

from net_proto import Ip6FragParser, Ip6FragSanityError, PacketRx

# Valid 8-byte IPv6 Frag header (no payload). Used to assert that
# '_validate_sanity()' is a no-op for well-formed frames.
#
# IPv6 Frag wire frame (8 bytes, header only):
#   Byte  0     : 0xff       -> next=IpProto.RAW (255)
#   Byte  1     : 0x00       -> reserved (must be zero)
#   Bytes 2-3   : 0x0000     -> offset=0, res=0, flag_mf=0
#   Bytes 4-7   : 0x00000000 -> id=0
_BASELINE_FRAME = b"\xff\x00\x00\x00\x00\x00\x00\x00"


class TestIp6FragParserSanityChecks(TestCase):
    """
    The IPv6 Frag packet parser sanity checks tests.

    The Ip6FragParser '_validate_sanity()' implementation is currently
    a no-op (RFC 2460 fragmentation header has no semantic constraints
    beyond the wire-format ones already covered by the integrity stage
    and dataclass asserts). This suite documents that contract: a
    well-formed frame must parse without raising Ip6FragSanityError,
    and any future sanity check should be added here as a parametrized
    negative test.
    """

    def test__ip6_frag__parser__sanity__no_op_for_baseline_frame(self) -> None:
        """
        Ensure that parsing a well-formed minimal frame does not raise
        Ip6FragSanityError. This guards against a future change that
        accidentally rejects valid frames.
        """

        packet_rx = PacketRx(_BASELINE_FRAME)
        packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(_BASELINE_FRAME),
        )

        try:
            Ip6FragParser(packet_rx)
        except Ip6FragSanityError as error:  # pragma: no cover
            self.fail(f"Baseline frame must not raise Ip6FragSanityError, got: {error!s}")

    def test__ip6_frag__sanity_error__message_prefix(self) -> None:
        """
        Ensure the Ip6FragSanityError constructor prepends the
        '[IPv6 Frag] ' protocol tag to the message, matching every
        other PacketSanityError subclass. Pinned even though the parser
        currently has no sanity checks, so the contract is enforced
        from day one for any check added later.
        """

        error = Ip6FragSanityError("dummy reason")

        self.assertEqual(
            str(error),
            "[SANITY ERROR][IPv6 Frag] dummy reason",
            msg="Ip6FragSanityError must tag messages with '[IPv6 Frag] '.",
        )
