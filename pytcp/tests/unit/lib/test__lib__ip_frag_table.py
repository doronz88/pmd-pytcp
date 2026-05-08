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
This module contains tests for the 'IpFragTable' shared flow store.

pytcp/tests/unit/lib/test__lib__ip_frag_table.py

ver 3.0.4
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import IpProto
from pytcp.lib.ip_frag import IpFragFlowId
from pytcp.lib.ip_frag_table import IpFragTable

_HOST_A__IP4 = Ip4Address("10.0.0.1")
_HOST_B__IP4 = Ip4Address("10.0.0.2")
_HOST_A__IP6 = Ip6Address("2001:db8::1")
_HOST_B__IP6 = Ip6Address("2001:db8::2")


class TestIpFragTableConstruction(TestCase):
    """
    The 'IpFragTable' construction tests.
    """

    def test__ip_frag_table__starts_empty(self) -> None:
        """
        Ensure a freshly built 'IpFragTable' exposes an empty flow
        store, regardless of timeout value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = IpFragTable(timeout=5.0)

        self.assertEqual(
            table.flows,
            {},
            msg="A freshly constructed IpFragTable must hold no flows.",
        )

    def test__ip_frag_table__flows_property_returns_live_dict(self) -> None:
        """
        Ensure 'IpFragTable.flows' returns the live underlying dict
        rather than a copy, so callers (and tests) can observe and
        mutate the store.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = IpFragTable(timeout=5.0)

        self.assertIs(
            table.flows,
            table._flows,  # pylint: disable=protected-access
            msg="IpFragTable.flows must be a live view, not a snapshot.",
        )


class TestIpFragTableAddFragmentIp4(TestCase):
    """
    The 'IpFragTable.add_fragment' tests for the IPv4-shaped flow.
    """

    def setUp(self) -> None:
        """
        Build a fresh table per test so flow state cannot leak.
        """

        self._table = IpFragTable(timeout=5.0)
        self._flow_id = IpFragFlowId(
            src=_HOST_A__IP4,
            dst=_HOST_B__IP4,
            id=42,
            proto=IpProto.UDP,
        )

    def test__ip_frag_table__add_fragment__pending_when_more_expected(self) -> None:
        """
        Ensure 'add_fragment' returns None and stores the fragment
        when the M flag is still set (more fragments to come).

        Reference: RFC 791 §3.2 (fragmented datagram still pending).
        """

        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIsNone(
            result,
            msg="A non-final fragment alone must return None.",
        )
        self.assertIn(
            self._flow_id,
            self._table.flows,
            msg="The pending fragment must be stored in the flow table.",
        )

    def test__ip_frag_table__add_fragment__contiguous_completion_returns_payload(self) -> None:
        """
        Ensure two contiguous fragments (offset 0 / MF=1, offset 8
        / MF=0) reassemble into a single joined payload and the
        flow is dropped from the store.

        Reference: RFC 791 §3.2 (reassembly on contiguous offset chain).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIsNotNone(
            result,
            msg="Final fragment of a contiguous flow must return the joined bytes.",
        )
        assert result is not None
        header_bytes, payload_bytes = result
        self.assertEqual(
            payload_bytes,
            b"\xaa" * 8 + b"\xbb" * 8,
            msg="Joined payload must be the concatenation of fragment payloads in offset order.",
        )
        self.assertEqual(
            header_bytes,
            b"\x45" + b"\x00" * 19,
            msg="Returned header must be the first-fragment header bytes verbatim.",
        )
        self.assertNotIn(
            self._flow_id,
            self._table.flows,
            msg="The flow must be removed from the store after a successful join.",
        )

    def test__ip_frag_table__add_fragment__hole_keeps_pending(self) -> None:
        """
        Ensure a flow with the last-fragment seen but a missing
        middle fragment does not yet reassemble. The completeness
        check requires a contiguous offset chain rooted at zero.

        Reference: RFC 791 §3.2 (reassembly requires contiguous coverage).
        """

        # offset 0 (MF=1) + offset 16 (MF=0) leaves an 8-byte hole at offset 8.
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=16,
            payload=b"\xcc" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIsNone(
            result,
            msg="A flow with a hole must return None even after the last fragment lands.",
        )
        self.assertIn(
            self._flow_id,
            self._table.flows,
            msg="The flow must be retained while the hole persists.",
        )


class TestIpFragTableAddFragmentIp6(TestCase):
    """
    The 'IpFragTable.add_fragment' tests for the IPv6-shaped flow
    (no proto in the key).
    """

    def test__ip_frag_table__add_fragment__ip6_flow_keyed_without_proto(self) -> None:
        """
        Ensure 'add_fragment' accepts an IPv6 flow id (proto=None,
        the default) and reassembles a contiguous two-fragment
        datagram exactly like the IPv4 path.

        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        table = IpFragTable(timeout=5.0)
        flow_id = IpFragFlowId(src=_HOST_A__IP6, dst=_HOST_B__IP6, id=99)

        table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\x00" * 8,
            flag_mf=True,
            header=b"\x60" + b"\x00" * 39,
        )
        result = table.add_fragment(
            flow_id=flow_id,
            offset=8,
            payload=b"\x11" * 8,
            flag_mf=False,
            header=b"\x60" + b"\x00" * 39,
        )

        assert result is not None
        _, payload_bytes = result
        self.assertEqual(
            payload_bytes,
            b"\x00" * 8 + b"\x11" * 8,
            msg="IPv6 flow must reassemble identically to IPv4.",
        )


class TestIpFragTableExpiry(TestCase):
    """
    The 'IpFragTable' lazy-expiry sweep tests.
    """

    def test__ip_frag_table__expired_flow_is_reaped_on_next_admit(self) -> None:
        """
        Ensure a flow whose timestamp is older than the
        configured timeout is removed from the store the next
        time 'add_fragment' is called for any flow. The reap is
        lazy / opportunistic — there is no separate timer.

        Reference: RFC 791 §3.2 (IPv4 reassembly timeout).
        Reference: RFC 8200 §4.5 (IPv6 reassembly timeout).
        Reference: RFC 8504 §16 (host buffer-hygiene requirement).
        """

        table = IpFragTable(timeout=5.0)
        stale_id = IpFragFlowId(src=_HOST_A__IP4, dst=_HOST_B__IP4, id=1, proto=IpProto.UDP)
        fresh_id = IpFragFlowId(src=_HOST_A__IP4, dst=_HOST_B__IP4, id=2, proto=IpProto.UDP)

        table.add_fragment(
            flow_id=stale_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        # Backdate the stored fragment's timestamp past the timeout.
        stale_flow = table.flows[stale_id]
        object.__setattr__(stale_flow, "timestamp", stale_flow.timestamp - 10.0)

        # Any subsequent add_fragment call triggers the cleanup.
        table.add_fragment(
            flow_id=fresh_id,
            offset=0,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertNotIn(
            stale_id,
            table.flows,
            msg="A flow older than the timeout must be reaped on the next admission.",
        )
        self.assertIn(
            fresh_id,
            table.flows,
            msg="The fresh flow must be admitted alongside the cleanup.",
        )


class TestIpFragTableIdempotence(TestCase):
    """
    The 'IpFragTable' duplicate-fragment tests.
    """

    def test__ip_frag_table__repeated_fragment_does_not_duplicate_flow(self) -> None:
        """
        Ensure re-receiving the same fragment (same offset)
        updates the stored bytes in place rather than creating a
        second flow entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = IpFragTable(timeout=5.0)
        flow_id = IpFragFlowId(src=_HOST_A__IP4, dst=_HOST_B__IP4, id=7, proto=IpProto.UDP)

        table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertEqual(
            len(table.flows),
            1,
            msg="A repeated fragment must not duplicate the flow entry.",
        )
        self.assertEqual(
            bytes(table.flows[flow_id].payload[0]),
            b"\xbb" * 8,
            msg="A repeated fragment at the same offset must overwrite the stored bytes.",
        )
