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
This module contains unit tests for the 'PacketHandlerIp4Rx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ip4__rx.py

ver 3.0.4
"""

from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address
from net_proto import Ip4FragAssembler, IpProto
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.ip_frag import IpFragFlowId
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.stack.packet_handler.packet_handler__ip4__rx import (
    PacketHandlerIp4Rx,
)

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
STACK__IP4_MULTICAST = Ip4Address("224.0.0.1")
STACK__IP4_BROADCAST = Ip4Address("255.255.255.255")
STACK__IP4_NETWORK_BROADCAST = Ip4Address("10.0.1.255")
HOST_A__IP4 = Ip4Address("10.0.1.91")
OFF_NET__IP4 = Ip4Address("192.168.99.99")


class _StubHandler(PacketHandlerIp4Rx):
    """
    Minimal concrete subclass of 'PacketHandlerIp4Rx' for testing.
    """

    def __init__(
        self,
        *,
        ip4_unicast: list[Ip4Address] | None = None,
        ip4_multicast: list[Ip4Address] | None = None,
        ip4_broadcast: list[Ip4Address] | None = None,
    ) -> None:
        """
        Initialize the stub handler with spies for the upper-layer
        dispatch methods.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._ip4_multicast = ip4_multicast if ip4_multicast is not None else [STACK__IP4_MULTICAST]
        self._ip4_unicast_list = ip4_unicast if ip4_unicast is not None else [STACK__IP4_ADDRESS]
        self._ip4_broadcast_list = (
            ip4_broadcast if ip4_broadcast is not None else [STACK__IP4_NETWORK_BROADCAST, STACK__IP4_BROADCAST]
        )
        self._ip4_frag_flows = {}

        self.dispatched: list[str] = []

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Stub list of stack IPv4 unicast addresses.
        """

        return self._ip4_unicast_list

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        """
        Stub list of stack IPv4 broadcast addresses.
        """

        return self._ip4_broadcast_list

    def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("icmp4")

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("udp")

    def _phrx_tcp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("tcp")


def _ip4_frame(
    *,
    src: Ip4Address = HOST_A__IP4,
    dst: Ip4Address = STACK__IP4_ADDRESS,
    proto: IpProto = IpProto.UDP,
    payload: bytes = b"",
) -> bytes:
    """
    Build a non-fragmented IPv4 wire frame carrying the given proto in
    the header. Uses 'Ip4FragAssembler' with offset=0/flag_mf=False so
    the 'proto' field is controllable (the regular 'Ip4Assembler'
    derives the proto from the payload assembler type).
    """

    return bytes(
        Ip4FragAssembler(
            ip4_frag__src=src,
            ip4_frag__dst=dst,
            ip4_frag__proto=proto,
            ip4_frag__flag_mf=False,
            ip4_frag__offset=0,
            ip4_frag__payload=payload,
        )
    )


class _Ip4RxTestBase(TestCase):
    """
    Common setUp for the IPv4 RX tests.
    """

    def setUp(self) -> None:
        """
        Build the stub handler and isolate the stack sockets dict.
        """

        self._handler = _StubHandler()
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    def tearDown(self) -> None:
        """
        Restore the stack sockets dict.
        """

        self._sockets_patch.stop()


class TestPacketHandlerIp4RxParseAndFilter(_Ip4RxTestBase):
    """
    The parse-and-filter branches of 'PacketHandlerIp4Rx._phrx_ip4'.
    """

    def test__stack__packet_handler__ip4__rx__parse_fail_drops(self) -> None:
        """
        Ensure a malformed IPv4 frame is counted in
        'ip4__failed_parse__drop' and no dispatch happens.
        """

        self._handler._phrx_ip4(PacketRx(b"\x45\x00\x00"))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__failed_parse__drop,
            1,
            msg="Malformed IPv4 frame must be counted in ip4__failed_parse__drop.",
        )
        self.assertEqual(self._handler.dispatched, [])

    def test__stack__packet_handler__ip4__rx__unknown_dst_drops(self) -> None:
        """
        Ensure a packet addressed to an IP not in any of our address
        lists is dropped with 'ip4__dst_unknown__drop'.
        """

        frame = _ip4_frame(dst=OFF_NET__IP4)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__dst_unknown__drop,
            1,
            msg="Unknown destination must be counted in ip4__dst_unknown__drop.",
        )
        self.assertEqual(self._handler.dispatched, [])

    def test__stack__packet_handler__ip4__rx__empty_unicast_accepts_any(self) -> None:
        """
        Ensure the destination filter is bypassed when the stack has no
        configured unicast addresses — the DHCP client relies on this
        to receive OFFER / ACK packets before an IP is claimed.
        """

        handler = _StubHandler(ip4_unicast=[])
        frame = _ip4_frame(dst=OFF_NET__IP4, proto=IpProto.UDP, payload=b"\x00" * 8)
        handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            handler._packet_stats_rx.ip4__dst_unknown__drop,
            0,
            msg="Stack with no unicast must accept any destination.",
        )
        self.assertEqual(
            handler.dispatched,
            ["udp"],
            msg="Valid UDP payload must dispatch to _phrx_udp when filter is bypassed.",
        )

    def test__stack__packet_handler__ip4__rx__unicast_dst_counts(self) -> None:
        """
        Ensure a packet to the stack unicast IP increments the
        'ip4__dst_unicast' counter.
        """

        frame = _ip4_frame(dst=STACK__IP4_ADDRESS, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__dst_unicast,
            1,
            msg="Unicast dst must be counted in ip4__dst_unicast.",
        )

    def test__stack__packet_handler__ip4__rx__multicast_dst_counts(self) -> None:
        """
        Ensure a packet to a joined multicast group is counted in
        'ip4__dst_multicast'.
        """

        frame = _ip4_frame(dst=STACK__IP4_MULTICAST, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__dst_multicast,
            1,
            msg="Multicast dst must be counted in ip4__dst_multicast.",
        )

    def test__stack__packet_handler__ip4__rx__broadcast_dst_counts(self) -> None:
        """
        Ensure a packet to a broadcast IP is counted in
        'ip4__dst_broadcast'.
        """

        frame = _ip4_frame(dst=STACK__IP4_BROADCAST, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__dst_broadcast,
            1,
            msg="Broadcast dst must be counted in ip4__dst_broadcast.",
        )


class TestPacketHandlerIp4RxDispatch(_Ip4RxTestBase):
    """
    The protocol-dispatch branches of 'PacketHandlerIp4Rx._phrx_ip4'.
    """

    def test__stack__packet_handler__ip4__rx__udp_dispatches(self) -> None:
        """
        Ensure a UDP packet dispatches to '_phrx_udp'.
        """

        frame = _ip4_frame(proto=IpProto.UDP, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(self._handler.dispatched, ["udp"])

    def test__stack__packet_handler__ip4__rx__tcp_dispatches(self) -> None:
        """
        Ensure a TCP packet dispatches to '_phrx_tcp'.
        """

        frame = _ip4_frame(proto=IpProto.TCP, payload=b"\x00" * 20)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(self._handler.dispatched, ["tcp"])

    def test__stack__packet_handler__ip4__rx__icmp4_dispatches(self) -> None:
        """
        Ensure an ICMPv4 packet dispatches to '_phrx_icmp4'.
        """

        frame = _ip4_frame(proto=IpProto.ICMP4, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(self._handler.dispatched, ["icmp4"])

    def test__stack__packet_handler__ip4__rx__unsupported_proto_drops(self) -> None:
        """
        Ensure an IPv4 packet carrying an unsupported proto value is
        dropped and counted in 'ip4__no_proto_support__drop'.
        """

        frame = _ip4_frame(proto=IpProto.IP6_FRAG, payload=b"\x00" * 8)
        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__no_proto_support__drop,
            1,
            msg="Unsupported IPv4 proto must be counted in ip4__no_proto_support__drop.",
        )
        self.assertEqual(self._handler.dispatched, [])


class TestPacketHandlerIp4RxFragmentation(_Ip4RxTestBase):
    """
    The fragmentation-handling tests.
    """

    def _build_fragment(
        self,
        *,
        frag_id: int,
        offset: int,
        flag_mf: bool,
        payload: bytes,
    ) -> bytes:
        """
        Build a single IPv4 fragment frame for reassembly tests.
        """

        return bytes(
            Ip4FragAssembler(
                ip4_frag__src=HOST_A__IP4,
                ip4_frag__dst=STACK__IP4_ADDRESS,
                ip4_frag__id=frag_id,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=flag_mf,
                ip4_frag__proto=IpProto.UDP,
                ip4_frag__payload=payload,
            )
        )

    def test__stack__packet_handler__ip4__rx__fragment_first_stored(self) -> None:
        """
        Ensure the first of two fragments is stored and returns without
        dispatching to any upper-layer handler.
        """

        frag1 = self._build_fragment(
            frag_id=12345,
            offset=0,
            flag_mf=True,
            payload=b"\x00" * 8,
        )
        self._handler._phrx_ip4(PacketRx(frag1))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__frag,
            1,
            msg="First fragment must be counted in ip4__frag.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.ip4__defrag,
            0,
            msg="ip4__defrag must NOT be incremented on an incomplete set.",
        )
        self.assertEqual(self._handler.dispatched, [])
        self.assertEqual(
            len(self._handler._ip4_frag_flows),
            1,
            msg="The fragment must be stored in _ip4_frag_flows.",
        )

    def test__stack__packet_handler__ip4__rx__fragment_out_of_order_pending(self) -> None:
        """
        Ensure an out-of-order fragment sequence stays pending until
        all offsets line up.
        """

        # Send second fragment (offset=8, final) before the first.
        frag2 = self._build_fragment(
            frag_id=54321,
            offset=8,
            flag_mf=False,
            payload=b"\x11" * 8,
        )
        self._handler._phrx_ip4(PacketRx(frag2))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__defrag,
            0,
            msg="Out-of-order final fragment without offset-0 must remain pending.",
        )
        self.assertEqual(self._handler.dispatched, [])


class TestPacketHandlerIp4RxRawSocketMatch(_Ip4RxTestBase):
    """
    The RAW-socket fastpath tests.
    """

    def test__stack__packet_handler__ip4__rx__raw_socket_match_short_circuits(self) -> None:
        """
        Ensure a matching RAW socket consumes the packet and prevents
        upper-layer dispatch, incrementing 'raw__socket_match'.
        """

        from unittest.mock import MagicMock

        # Build a frame and seed a sockets dict matched by IP proto.
        frame = _ip4_frame(proto=IpProto.UDP, payload=b"\x00" * 8)

        # Install a socket that matches any of the generated socket_ids.
        fake_socket = MagicMock()

        # Replace stack.sockets with a dict-like that returns fake_socket
        # for any lookup. This guarantees the fastpath fires regardless
        # of which socket_id the metadata yields first.
        class _MatchAllDict(dict[object, object]):
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        self._handler._phrx_ip4(PacketRx(frame))

        self.assertEqual(
            self._handler._packet_stats_rx.raw__socket_match,
            1,
            msg="A matched RAW socket must increment raw__socket_match.",
        )
        fake_socket.process_raw_packet.assert_called_once()
        self.assertEqual(
            self._handler.dispatched,
            [],
            msg="Matched RAW socket must short-circuit before protocol dispatch.",
        )


class TestPacketHandlerIp4RxDefragmentFullReassembly(_Ip4RxTestBase):
    """
    The full-reassembly defragmentation path tests.
    """

    def test__stack__packet_handler__ip4__rx__reassembly_dispatches_udp(self) -> None:
        """
        Ensure a two-fragment UDP packet gets fully reassembled and
        dispatched to '_phrx_udp', with 'ip4__defrag' incremented.
        """

        # Two consecutive 8-byte UDP payload fragments that combine
        # into a 16-byte UDP datagram. Because Ip4FragAssembler fits
        # the payload as-is (no UDP framing insertion), the combined
        # payload looks like 16 bytes of raw data — still enough to be
        # parsed as a UDP header (8 bytes) + payload (8 bytes).
        udp_like = b"\x00\x00\x00\x00\x00\x10\x00\x00" + b"\x00" * 8

        frag0 = bytes(
            Ip4FragAssembler(
                ip4_frag__src=HOST_A__IP4,
                ip4_frag__dst=STACK__IP4_ADDRESS,
                ip4_frag__id=4242,
                ip4_frag__offset=0,
                ip4_frag__flag_mf=True,
                ip4_frag__proto=IpProto.UDP,
                ip4_frag__payload=udp_like[:8],
            )
        )
        frag1 = bytes(
            Ip4FragAssembler(
                ip4_frag__src=HOST_A__IP4,
                ip4_frag__dst=STACK__IP4_ADDRESS,
                ip4_frag__id=4242,
                ip4_frag__offset=8,
                ip4_frag__flag_mf=False,
                ip4_frag__proto=IpProto.UDP,
                ip4_frag__payload=udp_like[8:],
            )
        )

        self._handler._phrx_ip4(PacketRx(frag0))
        self._handler._phrx_ip4(PacketRx(frag1))

        self.assertEqual(
            self._handler._packet_stats_rx.ip4__defrag,
            1,
            msg="ip4__defrag must be incremented after the packet is fully reassembled.",
        )
        self.assertEqual(
            self._handler.dispatched,
            ["udp"],
            msg="Reassembled UDP packet must dispatch to _phrx_udp.",
        )
        self.assertEqual(
            self._handler._ip4_frag_flows,
            {},
            msg="Flow table must be empty after successful reassembly.",
        )


class TestPacketHandlerIp4RxFragmentFlowState(_Ip4RxTestBase):
    """
    The fragment-flow-state tests.
    """

    def test__stack__packet_handler__ip4__rx__same_fragment_twice_is_idempotent(self) -> None:
        """
        Ensure re-receiving the same fragment (same offset) updates
        the stored bytes in place rather than creating a duplicate
        flow entry.
        """

        frag = bytes(
            Ip4FragAssembler(
                ip4_frag__src=HOST_A__IP4,
                ip4_frag__dst=STACK__IP4_ADDRESS,
                ip4_frag__id=7777,
                ip4_frag__offset=0,
                ip4_frag__flag_mf=True,
                ip4_frag__proto=IpProto.UDP,
                ip4_frag__payload=b"\xaa" * 8,
            )
        )

        self._handler._phrx_ip4(PacketRx(frag))
        self._handler._phrx_ip4(PacketRx(frag))

        flow = IpFragFlowId(src=HOST_A__IP4, dst=STACK__IP4_ADDRESS, id=7777)
        self.assertIn(
            flow,
            self._handler._ip4_frag_flows,
            msg="Flow entry must exist after repeated fragment arrivals.",
        )
        self.assertEqual(
            len(self._handler._ip4_frag_flows),
            1,
            msg="Repeated fragment must not duplicate the flow entry.",
        )
