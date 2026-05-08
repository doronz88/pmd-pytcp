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
This module contains tests for the 'IpFragFlowId' and 'IpFragData' dataclasses.

pytcp/tests/unit/lib/test__lib__ip_frag.py

ver 3.0.4
"""

import time
from dataclasses import FrozenInstanceError, fields
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import IpProto
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId


class TestIpFragFlowIdIp4(TestCase):
    """
    The 'IpFragFlowId' tests covering the IPv4 address flow.
    """

    def setUp(self) -> None:
        """
        Build a canonical IPv4 'IpFragFlowId' instance for every test in
        this class.
        """

        self._src = Ip4Address("10.0.0.1")
        self._dst = Ip4Address("10.0.0.2")
        self._id = 0x1234

        self._flow_id = IpFragFlowId(
            src=self._src,
            dst=self._dst,
            id=self._id,
        )

    def test__ip_frag_flow_id__src(self) -> None:
        """
        Ensure the 'src' field stores the constructor's IPv4 source address.
        """

        self.assertEqual(
            self._flow_id.src,
            self._src,
            msg="IpFragFlowId.src must equal the IPv4 address passed to the constructor.",
        )

    def test__ip_frag_flow_id__dst(self) -> None:
        """
        Ensure the 'dst' field stores the constructor's IPv4 destination
        address.
        """

        self.assertEqual(
            self._flow_id.dst,
            self._dst,
            msg="IpFragFlowId.dst must equal the IPv4 address passed to the constructor.",
        )

    def test__ip_frag_flow_id__id(self) -> None:
        """
        Ensure the 'id' field stores the constructor's identification value.
        """

        self.assertEqual(
            self._flow_id.id,
            self._id,
            msg="IpFragFlowId.id must equal the identifier passed to the constructor.",
        )


class TestIpFragFlowIdIp6(TestCase):
    """
    The 'IpFragFlowId' tests covering the IPv6 address flow.
    """

    def test__ip_frag_flow_id__ip6_src_and_dst(self) -> None:
        """
        Ensure the 'src' / 'dst' fields accept 'Ip6Address' values — the
        type union in the source must support both IPv4 and IPv6.
        """

        src = Ip6Address("2001:db8::1")
        dst = Ip6Address("2001:db8::2")

        flow_id = IpFragFlowId(src=src, dst=dst, id=0xABCDEF12)

        self.assertEqual(
            flow_id.src,
            src,
            msg="IpFragFlowId.src must accept an IPv6 address value.",
        )
        self.assertEqual(
            flow_id.dst,
            dst,
            msg="IpFragFlowId.dst must accept an IPv6 address value.",
        )


class TestIpFragFlowIdSemantics(TestCase):
    """
    The 'IpFragFlowId' hashability / equality / immutability tests.
    """

    def setUp(self) -> None:
        """
        Build two equal and one distinct flow-id instance to exercise the
        equality and hash contracts.
        """

        self._src = Ip4Address("10.0.0.1")
        self._dst = Ip4Address("10.0.0.2")

        self._flow_a = IpFragFlowId(src=self._src, dst=self._dst, id=1)
        self._flow_b = IpFragFlowId(src=self._src, dst=self._dst, id=1)
        self._flow_c = IpFragFlowId(src=self._src, dst=self._dst, id=2)

    def test__ip_frag_flow_id__equality(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances with identical fields compare
        equal (frozen dataclass default __eq__).
        """

        self.assertEqual(
            self._flow_a,
            self._flow_b,
            msg="Two IpFragFlowId instances with identical fields must be equal.",
        )

    def test__ip_frag_flow_id__inequality(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances that differ in one field
        compare unequal.
        """

        self.assertNotEqual(
            self._flow_a,
            self._flow_c,
            msg="IpFragFlowId instances must be unequal when any field differs.",
        )

    def test__ip_frag_flow_id__hash_matches_for_equal_instances(self) -> None:
        """
        Ensure equal 'IpFragFlowId' instances produce equal hashes so they
        can be used as dict keys in the fragment store.
        """

        self.assertEqual(
            hash(self._flow_a),
            hash(self._flow_b),
            msg="Equal IpFragFlowId instances must share the same hash.",
        )

    def test__ip_frag_flow_id__usable_as_dict_key(self) -> None:
        """
        Ensure 'IpFragFlowId' works as a dict key and equal instances
        resolve to the same entry. This is the flow-id's real use site.
        """

        store: dict[IpFragFlowId, str] = {self._flow_a: "frag-bucket"}

        self.assertEqual(
            store[self._flow_b],
            "frag-bucket",
            msg="An equal IpFragFlowId must hit the same dict entry.",
        )

    def test__ip_frag_flow_id__is_frozen(self) -> None:
        """
        Ensure 'IpFragFlowId' is frozen — direct attribute mutation must
        raise 'FrozenInstanceError'.
        """

        with self.assertRaises(FrozenInstanceError):
            self._flow_a.id = 999  # type: ignore[misc]

    def test__ip_frag_flow_id__has_slots(self) -> None:
        """
        Ensure 'IpFragFlowId' uses '__slots__' (no per-instance __dict__),
        which is the in-source declaration and a memory/perf guarantee.
        """

        self.assertFalse(
            hasattr(self._flow_a, "__dict__"),
            msg="IpFragFlowId must be slotted; instances must not carry a __dict__.",
        )


class TestIpFragFlowIdFields(TestCase):
    """
    The 'IpFragFlowId' dataclass field-layout tests.
    """

    def test__ip_frag_flow_id__field_names(self) -> None:
        """
        Ensure the dataclass exposes exactly the (src, dst, id,
        proto) fields in that order; a silent rename would be a
        wire-format regression.

        Reference: RFC 791 §3.2 (IPv4 reassembly key includes protocol).
        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        self.assertEqual(
            tuple(f.name for f in fields(IpFragFlowId)),
            ("src", "dst", "id", "proto"),
            msg="IpFragFlowId must declare exactly (src, dst, id, proto) in order.",
        )


class TestIpFragFlowIdProto(TestCase):
    """
    The 'IpFragFlowId.proto' field tests.
    """

    def test__ip_frag_flow_id__proto_defaults_to_none(self) -> None:
        """
        Ensure the 'proto' field defaults to None so callers in
        the IPv6 path (whose reassembly key omits the protocol)
        can construct the flow-id without specifying it.

        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        flow = IpFragFlowId(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
            id=1,
        )

        self.assertIsNone(
            flow.proto,
            msg="IpFragFlowId.proto must default to None for the IPv6-shaped key.",
        )

    def test__ip_frag_flow_id__proto_distinguishes_equal_src_dst_id(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances that share src/dst/ID
        but differ only in 'proto' compare unequal and hash apart,
        so they occupy distinct dict entries — the IPv4 reassembly
        invariant.

        Reference: RFC 791 §3.2 (IPv4 reassembly key includes protocol).
        """

        src = Ip4Address("10.0.0.1")
        dst = Ip4Address("10.0.0.2")

        flow_udp = IpFragFlowId(src=src, dst=dst, id=42, proto=IpProto.UDP)
        flow_tcp = IpFragFlowId(src=src, dst=dst, id=42, proto=IpProto.TCP)

        self.assertNotEqual(
            flow_udp,
            flow_tcp,
            msg=(
                "Two IpFragFlowId instances differing only in 'proto' must " "be unequal (RFC 791 §3.2 reassembly key)."
            ),
        )
        self.assertNotEqual(
            hash(flow_udp),
            hash(flow_tcp),
            msg=(
                "Hashes of IpFragFlowId instances differing only in 'proto' "
                "must differ so dict lookup separates the two streams."
            ),
        )


class TestIpFragDataConstruction(TestCase):
    """
    The 'IpFragData' construction tests.
    """

    def setUp(self) -> None:
        """
        Build a canonical 'IpFragData' instance with one fragment in the
        payload dict so the tests can inspect every field.
        """

        self._header = b"\x45\x00\x00\x14"
        self._payload: dict[int, bytes] = {0: b"AAAA", 8: b"BBBB"}

        self._frag = IpFragData(header=self._header, payload=self._payload)

    def test__ip_frag_data__header(self) -> None:
        """
        Ensure the 'header' field stores the constructor's byte payload
        verbatim (used later to rebuild the reassembled packet).
        """

        self.assertEqual(
            self._frag.header,
            self._header,
            msg="IpFragData.header must equal the bytes passed to the constructor.",
        )

    def test__ip_frag_data__payload(self) -> None:
        """
        Ensure the 'payload' field stores the constructor's offset->bytes
        mapping verbatim.
        """

        self.assertEqual(
            self._frag.payload,
            self._payload,
            msg="IpFragData.payload must equal the dict passed to the constructor.",
        )

    def test__ip_frag_data__timestamp_bracketed_by_wall_clock(self) -> None:
        """
        Ensure the 'timestamp' field, populated by the dataclass
        'default_factory', lies between the wall-clock reading taken just
        before and just after construction. Guards against any change
        that would replace 'default_factory=time.time' with a constant.
        """

        before = time.time()
        frag = IpFragData(header=b"", payload={})
        after = time.time()

        self.assertGreaterEqual(
            frag.timestamp,
            before,
            msg="IpFragData.timestamp must be >= the clock reading just before construction.",
        )
        self.assertLessEqual(
            frag.timestamp,
            after,
            msg="IpFragData.timestamp must be <= the clock reading just after construction.",
        )

    def test__ip_frag_data__timestamp_default_factory_is_time_time(self) -> None:
        """
        Ensure the 'timestamp' dataclass field's 'default_factory' is
        exactly 'time.time' — this is the contract that underpins the
        wall-clock bracketing test and the fragment-reassembly TTL logic.
        """

        timestamp_field = next(f for f in fields(IpFragData) if f.name == "timestamp")

        self.assertIs(
            timestamp_field.default_factory,
            time.time,
            msg="IpFragData.timestamp default_factory must be 'time.time'.",
        )

    def test__ip_frag_data__last_defaults_to_false(self) -> None:
        """
        Ensure the 'last' flag defaults to False — a fresh fragment bucket
        has not yet received the last-fragment packet.
        """

        self.assertFalse(
            self._frag.last,
            msg="IpFragData.last must default to False on a freshly built instance.",
        )


class TestIpFragDataReceivedLastFrag(TestCase):
    """
    The 'IpFragData.received_last_frag()' tests.
    """

    def setUp(self) -> None:
        """
        Build a fresh 'IpFragData' instance per test so mutations in one
        test cannot leak into the next.
        """

        self._frag = IpFragData(header=b"hdr", payload={0: b"data"})

    def test__ip_frag_data__received_last_frag__sets_flag(self) -> None:
        """
        Ensure 'received_last_frag()' flips 'last' from False to True by
        bypassing the frozen-dataclass barrier via 'object.__setattr__'.
        """

        self.assertFalse(
            self._frag.last,
            msg="Precondition: the 'last' flag must start False.",
        )

        self._frag.received_last_frag()

        self.assertTrue(
            self._frag.last,
            msg="IpFragData.received_last_frag() must set the 'last' flag to True.",
        )

    def test__ip_frag_data__received_last_frag__idempotent(self) -> None:
        """
        Ensure calling 'received_last_frag()' a second time keeps the
        'last' flag True (flag is monotone).
        """

        self._frag.received_last_frag()
        self._frag.received_last_frag()

        self.assertTrue(
            self._frag.last,
            msg="A repeat received_last_frag() call must keep 'last' True.",
        )

    def test__ip_frag_data__direct_mutation_still_forbidden(self) -> None:
        """
        Ensure the frozen-dataclass contract still rejects direct attribute
        assignment, even though 'received_last_frag()' mutates via the
        'object.__setattr__' escape hatch.
        """

        with self.assertRaises(FrozenInstanceError):
            self._frag.last = True  # type: ignore[misc]


class TestIpFragDataFields(TestCase):
    """
    The 'IpFragData' dataclass field-layout tests.
    """

    def test__ip_frag_data__field_names(self) -> None:
        """
        Ensure the dataclass exposes exactly (timestamp, header, last,
        payload) in that order.
        """

        self.assertEqual(
            tuple(f.name for f in fields(IpFragData)),
            ("timestamp", "header", "last", "payload"),
            msg="IpFragData must declare exactly (timestamp, header, last, payload) in order.",
        )

    def test__ip_frag_data__timestamp_is_init_false(self) -> None:
        """
        Ensure the 'timestamp' field is 'init=False' so callers cannot
        inject a spoofed construction time.
        """

        timestamp_field = next(f for f in fields(IpFragData) if f.name == "timestamp")

        self.assertFalse(
            timestamp_field.init,
            msg="IpFragData.timestamp must be init=False (populated by default_factory).",
        )

    def test__ip_frag_data__last_is_init_false(self) -> None:
        """
        Ensure the 'last' field is 'init=False' — it may only be set via
        'received_last_frag()', not through the constructor.
        """

        last_field = next(f for f in fields(IpFragData) if f.name == "last")

        self.assertFalse(
            last_field.init,
            msg="IpFragData.last must be init=False (flipped via received_last_frag).",
        )

    def test__ip_frag_data__has_slots(self) -> None:
        """
        Ensure 'IpFragData' uses '__slots__' — matches the in-source
        'slots=True' declaration.
        """

        frag = IpFragData(header=b"", payload={})

        self.assertFalse(
            hasattr(frag, "__dict__"),
            msg="IpFragData must be slotted; instances must not carry a __dict__.",
        )
