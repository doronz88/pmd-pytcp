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
This module contains unit tests for the 'PacketHandlerArpRx' mixin.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py

ver 3.0.5
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpAssembler, ArpOperation
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.runtime.packet_handler.packet_handler__arp__rx import (
    PacketHandlerArpRx,
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


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP4_ADDRESS = STACK__IP4_HOST.address

STACK__IP4_HOST__CANDIDATE = Ip4IfAddr("10.0.1.5/24")
STACK__IP4_ADDRESS__CANDIDATE = STACK__IP4_HOST__CANDIDATE.address

HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
HOST_B__MAC = MacAddress("02:00:00:00:00:92")
HOST_B__IP4 = Ip4Address("10.0.1.92")
OFF_NET__IP4 = Ip4Address("192.168.99.99")

MAC__BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")
MAC__UNSPEC = MacAddress()
IP4__UNSPEC = Ip4Address("0.0.0.0")


def _arp_frame(
    *,
    oper: ArpOperation,
    sha: MacAddress,
    spa: Ip4Address,
    tha: MacAddress,
    tpa: Ip4Address,
) -> bytes:
    """
    Build an ARP wire frame using 'ArpAssembler'. The handler consumes
    the frame starting at the ARP header; no Ethernet prefix is added.
    """

    return bytes(
        ArpAssembler(
            arp__oper=oper,
            arp__sha=sha,
            arp__spa=spa,
            arp__tha=tha,
            arp__tpa=tpa,
        )
    )


def _make_packet_rx(
    frame: bytes,
    *,
    ethernet_dst: MacAddress,
    ethernet_src: MacAddress = HOST_A__MAC,
) -> PacketRx:
    """
    Build a 'PacketRx' that looks like one that has already passed the
    Ethernet layer: frame starts at the ARP header and 'ethernet' is a
    SimpleNamespace carrying the src/dst MACs the parser/handler read.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ethernet = SimpleNamespace(  # type: ignore[assignment]
        dst=ethernet_dst,
        src=ethernet_src,
    )
    return packet_rx


class _StubHandler(PacketHandlerArpRx):
    """
    Minimal concrete subclass of 'PacketHandlerArpRx' for testing.
    """

    def __init__(self) -> None:
        """
        Initialize the stub handler. Spies record the arguments passed
        to the TX-side methods invoked from the RX handler.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip4_host = [STACK__IP4_HOST]
        self._ip4_host_candidate = [STACK__IP4_HOST__CANDIDATE]
        self._ip4_arp_dad__registry: DadSlotRegistry[Ip4Address] = DadSlotRegistry()
        # Install slots for every candidate so the RX path's
        # 'try_signal_conflict' has somewhere to write — mirrors
        # what '_create_stack_ip4_addressing' does at boot.
        self._ip4_arp_dad__registry.install(STACK__IP4_HOST__CANDIDATE.address)
        self._arp_defend__last_emitted: dict[Ip4Address, float] = {}
        self._arp_defend__last_conflict_at: dict[Ip4Address, float] = {}

        self.arp_replies_sent: list[dict[str, object]] = []
        self.gratuitous_arps_sent: list[Ip4Address] = []
        self.aborted_session_local_ips: list[Ip4Address] = []

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Mirror the PacketHandler's '_ip4_unicast' property helper.
        """

        return [host.address for host in self._ip4_host]

    def _send_arp_reply(self, **kwargs: object) -> None:
        """
        Record the ARP-reply TX arguments for assertions.
        """

        self.arp_replies_sent.append(kwargs)

    def _send_gratuitous_arp(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Record each gratuitous-ARP request for assertions.
        """

        self.gratuitous_arps_sent.append(ip4_unicast)


class _ArpRxTestBase(TestCase):
    """
    Common setUp for ARP RX tests.
    """

    def setUp(self) -> None:
        """
        Build the stub handler and patch the stack singletons the ARP
        handler reaches into.
        """

        self._handler = _StubHandler()

        # 'stack.arp_cache' is a bare forward declaration in
        # 'pytcp/stack/__init__.py' (no assignment until the
        # stack starts), so 'patch.object' needs 'create=True'
        # to install the mock when the unit test runs without
        # a live stack.
        self._arp_cache_patch = patch.object(stack, "arp_cache", MagicMock(), create=True)
        self._arp_cache = self._arp_cache_patch.start()

    def tearDown(self) -> None:
        """
        Restore the patched stack singletons.
        """

        self._arp_cache_patch.stop()


class TestPacketHandlerArpRxParseFail(_ArpRxTestBase):
    """
    The ARP parser-failure tests.
    """

    def test__stack__packet_handler__arp__rx__malformed_frame_drops(self) -> None:
        """
        Ensure a truncated ARP frame fails parsing and is counted in
        'arp__failed_parse__drop'.

        Reference: RFC 826 (ARP packet validation).
        """

        truncated = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )[:10]

        packet_rx = _make_packet_rx(truncated, ethernet_dst=STACK__MAC_UNICAST)
        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__pre_parse,
            1,
            msg="arp__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__failed_parse__drop,
            1,
            msg="Malformed frame must be counted in arp__failed_parse__drop.",
        )


class TestPacketHandlerArpRxRequest(_ArpRxTestBase):
    """
    The ARP-request handling tests.
    """

    def test__stack__packet_handler__arp__rx__looped_request_drop(self) -> None:
        """
        Ensure an ARP request originating from our own MAC is treated
        as a loop and dropped.

        Reference: RFC 5227 §2.1.1 (self-loopback NOTE).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=STACK__MAC_UNICAST,
            spa=STACK__IP4_ADDRESS,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(
            frame,
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=STACK__MAC_UNICAST,
        )

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__looped__drop,
            1,
            msg="Looped own-MAC ARP request must be counted in arp__op_request__looped__drop.",
        )
        self.assertEqual(
            self._handler.arp_replies_sent,
            [],
            msg="Looped ARP request must not trigger a reply.",
        )

    def test__stack__packet_handler__arp__rx__conflict_defend(self) -> None:
        """
        Ensure an ARP request claiming one of our IPv4 addresses from
        another MAC triggers gratuitous-ARP defense.

        Reference: RFC 5227 §2.4 (ongoing conflict detection).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__conflict__defend,
            1,
            msg="Conflict from another MAC must be counted in arp__op_request__conflict__defend.",
        )
        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS],
            msg="Conflict defense must send a gratuitous ARP for the stack IP.",
        )

    def test__stack__packet_handler__arp__rx__gratuitous_request(self) -> None:
        """
        Ensure a broadcast gratuitous ARP request (spa == tpa) is
        counted and populates the ARP cache.

        Reference: RFC 826 (gratuitous ARP wire shape).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__gratuitous,
            1,
            msg="Gratuitous ARP request must be counted in arp__op_request__gratuitous.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__update_arp_cache,
            1,
            msg="Gratuitous ARP request must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__gratuitous_probe_conflict_candidate(self) -> None:
        """
        Ensure a gratuitous ARP request colliding with a candidate
        address under DAD registers the probe conflict and does NOT
        learn the ARP cache entry.

        Reference: RFC 5227 §2.1.1 (probe-conflict detection).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS__CANDIDATE,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__probe_conflict__gratuitous,
            1,
            msg="Probe-conflict gratuitous request must be counted.",
        )
        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg="Probe-conflict IP must be flagged in the DAD slot registry.",
        )
        self._arp_cache.add_entry.assert_not_called()

    def test__stack__packet_handler__arp__rx__tpa_unknown(self) -> None:
        """
        Ensure an ARP request for a TPA not in our unicast list is
        counted and no reply is sent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=OFF_NET__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__tpa_unknown,
            1,
            msg="ARP request for a TPA not owned by the stack must be counted as tpa_unknown.",
        )
        self.assertEqual(
            self._handler.arp_replies_sent,
            [],
            msg="ARP request for an unknown TPA must not trigger a reply.",
        )

    def test__stack__packet_handler__arp__rx__probe(self) -> None:
        """
        Ensure an ARP probe (spa=0.0.0.0) for one of our TPAs is
        counted, a reply is sent, and the cache is NOT updated (spa
        fails the 'in host.network' test).

        Reference: RFC 5227 §2.5 (Reply to Probe Requests).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=IP4__UNSPEC,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__probe,
            1,
            msg="ARP probe request for a stack TPA must be counted.",
        )
        self.assertEqual(
            len(self._handler.arp_replies_sent),
            1,
            msg="Probe request must trigger exactly one ARP reply.",
        )
        reply = self._handler.arp_replies_sent[0]
        self.assertEqual(
            reply["arp__spa"],
            STACK__IP4_ADDRESS,
            msg="Probe reply spa must be our stack IP.",
        )
        self.assertEqual(
            reply["arp__tpa"],
            IP4__UNSPEC,
            msg="Probe reply tpa must echo the probe spa (unspecified).",
        )

    def test__stack__packet_handler__arp__rx__regular_request_replies_and_updates_cache(self) -> None:
        """
        Ensure a regular ARP request for one of our TPAs is counted,
        triggers a reply, and populates the ARP cache with spa<->sha.

        Reference: RFC 826 (ARP request → reply + cache update).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__tpa_stack,
            1,
            msg="Regular ARP request for our TPA must be counted as tpa_stack.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__respond,
            1,
            msg="Regular ARP request must trigger a respond stat.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_request__update_arp_cache,
            1,
            msg="Regular ARP request must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__unknown_operation_rejected_at_parse(self) -> None:
        """
        Ensure an ARP frame carrying an unknown operation code is
        rejected at parse time (sanity check), not by the handler's
        match-case fallthrough. The parser's sanity validation
        forbids 'is_unknown' operations.

        Reference: RFC 826 (ARP operation field).
        """

        valid = bytearray(
            _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
        )
        # Rewrite the 'oper' field (bytes 6-7) to a value neither
        # REQUEST (1) nor REPLY (2).
        valid[6:8] = (0x00FF).to_bytes(2)

        packet_rx = _make_packet_rx(bytes(valid), ethernet_dst=STACK__MAC_UNICAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__failed_parse__drop,
            1,
            msg="Unknown ARP operation must be rejected at parse time (arp__failed_parse__drop).",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_unknown__drop,
            0,
            msg="The match-case fallthrough must not fire; parser blocks unknown opers first.",
        )


class TestPacketHandlerArpRxReply(_ArpRxTestBase):
    """
    The ARP-reply handling tests.
    """

    def test__stack__packet_handler__arp__rx__looped_reply_drop(self) -> None:
        """
        Ensure an ARP reply originating from our own MAC is dropped
        as a loop.

        Reference: RFC 5227 §2.1.1 (self-loopback NOTE).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=STACK__MAC_UNICAST,
            spa=STACK__IP4_ADDRESS,
            tha=HOST_A__MAC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(
            frame,
            ethernet_dst=HOST_A__MAC,
            ethernet_src=STACK__MAC_UNICAST,
        )

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__looped__drop,
            1,
            msg="Looped own-MAC ARP reply must be counted in arp__op_reply__looped__drop.",
        )

    def test__stack__packet_handler__arp__rx__reply_conflict_defend(self) -> None:
        """
        Ensure an ARP reply claiming one of our IPv4 addresses from
        another MAC triggers gratuitous-ARP defense.

        Reference: RFC 5227 §2.4 (ongoing conflict detection on Reply).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS,
            tha=HOST_B__MAC,
            tpa=HOST_B__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=HOST_B__MAC)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__conflict__defend,
            1,
            msg="Reply conflict from another MAC must be counted in arp__op_reply__conflict__defend.",
        )
        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS],
            msg="Reply conflict defense must send a gratuitous ARP for the stack IP.",
        )

    def test__stack__packet_handler__arp__rx__reply_probe_conflict(self) -> None:
        """
        Ensure an ARP reply to our probe (tpa=0.0.0.0, ethernet.dst=our
        MAC, tha=our MAC) with spa == candidate is registered as a
        probe conflict.

        Reference: RFC 5227 §2.1.1 (probe-Reply conflict).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=STACK__MAC_UNICAST,
            tpa=IP4__UNSPEC,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__probe_conflict,
            1,
            msg="Probe-conflict reply must be counted in arp__op_reply__probe_conflict.",
        )
        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg="Probe-conflict IP must be flagged in the DAD slot registry.",
        )

    def test__stack__packet_handler__arp__rx__reply_direct_updates_cache(self) -> None:
        """
        Ensure a direct ARP reply (ethernet.dst == stack unicast MAC)
        is counted and updates the ARP cache.

        Reference: RFC 826 (cache update on Reply).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=STACK__MAC_UNICAST,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__direct,
            1,
            msg="Direct ARP reply must be counted in arp__op_reply__direct.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__update_arp_cache,
            1,
            msg="Direct ARP reply must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__reply_gratuitous(self) -> None:
        """
        Ensure a broadcast gratuitous ARP reply (spa == tpa, tha=0) is
        counted and updates the ARP cache.

        Reference: RFC 826 (gratuitous Reply wire shape).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__gratuitous,
            1,
            msg="Gratuitous ARP reply must be counted in arp__op_reply__gratuitous.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__reply_gratuitous_probe_conflict(self) -> None:
        """
        Ensure a gratuitous ARP reply claiming one of our candidate
        addresses registers the probe conflict and does NOT update the
        ARP cache.

        Reference: RFC 5227 §2.1.1 (probe-conflict via gratuitous Reply).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS__CANDIDATE,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.arp__op_reply__probe_conflict__gratuitous,
            1,
            msg="Gratuitous-reply probe conflict must be counted.",
        )
        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg="Probe-conflict IP must be flagged in the DAD slot registry.",
        )
        self._arp_cache.add_entry.assert_not_called()


class TestPacketHandlerArpRxProbeConflictPerInstanceSet(_ArpRxTestBase):
    """
    The 'PacketHandlerArpRx' probe-conflict registry-write tests.

    Pin the requirement that probe conflicts the RX handler detects
    are signalled via the per-instance
    'PacketHandler._ip4_arp_dad__registry' that the DAD claim flow
    at '_create_stack_ip4_addressing'
    (pytcp/runtime/packet_handler/__init__.py) reads via
    'has_signal()' to decide whether to admit a candidate to
    '_ip4_host'.
    """

    def test__stack__packet_handler__arp__rx__gratuitous_request_probe_conflict_writes_to_per_instance_set(
        self,
    ) -> None:
        """
        Ensure a gratuitous ARP Request whose SPA matches a
        candidate address signals the per-instance DAD slot
        registry that the DAD claim flow actually reads.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS__CANDIDATE,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg=(
                "Gratuitous-Request probe conflict must flag the candidate "
                "in the DAD slot registry; the DAD flow at "
                "'_create_stack_ip4_addressing' reads 'has_signal()' on the "
                "registry."
            ),
        )

    def test__stack__packet_handler__arp__rx__direct_reply_probe_conflict_writes_to_per_instance_set(self) -> None:
        """
        Ensure a direct unicast ARP Reply whose SPA matches a
        candidate (TPA unspecified, L2 dst == our MAC) signals
        the per-instance DAD slot registry.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=STACK__MAC_UNICAST,
            tpa=IP4__UNSPEC,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._handler._phrx_arp(packet_rx)

        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg=(
                "Direct unicast ARP Reply probe conflict must flag the "
                "candidate in the DAD slot registry; the DAD flow reads "
                "'has_signal()' on the registry."
            ),
        )

    def test__stack__packet_handler__arp__rx__gratuitous_reply_probe_conflict_writes_to_per_instance_set(self) -> None:
        """
        Ensure a gratuitous ARP Reply (broadcast L2, SPA == TPA
        matching a candidate) signals the per-instance DAD slot
        registry.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=STACK__IP4_ADDRESS__CANDIDATE,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS__CANDIDATE,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertTrue(
            self._handler._ip4_arp_dad__registry.has_signal(STACK__IP4_ADDRESS__CANDIDATE),
            msg=(
                "Gratuitous-Reply probe conflict must flag the candidate "
                "in the DAD slot registry; the DAD flow reads "
                "'has_signal()' on the registry."
            ),
        )


HOST_C__MAC = MacAddress("02:00:00:00:00:93")
STACK__IP4_HOST_2 = Ip4IfAddr("10.0.1.8/24")
STACK__IP4_ADDRESS_2 = STACK__IP4_HOST_2.address


class TestPacketHandlerArpRxDefendInterval(_ArpRxTestBase):
    """
    The 'PacketHandlerArpRx' DEFEND_INTERVAL rate-limit tests.

    Pin the requirement that defensive gratuitous ARPs are
    emitted at most once per address per DEFEND_INTERVAL
    (10 seconds). Without the rate-limit two hosts misconfigured
    with the same IP can settle into an "endless loop flooding
    the network with broadcast traffic" — each defending on
    every conflicting packet they observe, generating more
    conflicts to defend against. The rate-limit interval is
    'stack.ARP__DEFEND_INTERVAL' (10 s, matching the RFC 5227
    constant of the same name); the per-instance "last
    defended at" timestamp dict is
    'PacketHandler._arp_defend__last_emitted'.
    """

    def _drive_conflict(
        self,
        *,
        spa: Ip4Address,
        sha: MacAddress = HOST_A__MAC,
    ) -> None:
        """
        Drive a conflicting unicast ARP Reply (SPA = a stack IP,
        SHA != stack MAC) through the RX handler. Used by the
        DEFEND_INTERVAL tests to trigger the §2.4 conflict-
        defense path repeatedly.
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=sha,
            spa=spa,
            tha=STACK__MAC_UNICAST,
            tpa=spa,
        )
        packet_rx = _make_packet_rx(
            frame,
            ethernet_dst=STACK__MAC_UNICAST,
            ethernet_src=sha,
        )
        self._handler._phrx_arp(packet_rx)

    def test__stack__packet_handler__arp__rx__defend_first_conflict_emits(self) -> None:
        """
        Ensure the first conflicting ARP packet for a given IP
        emits a defensive gratuitous ARP — the rate-limit only
        gates subsequent defenses within the window, not the
        first one.

        Reference: RFC 5227 §2.4 (ongoing conflict detection and defense).
        """

        with patch("time.monotonic", return_value=1000.0):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS],
            msg="The first conflicting ARP packet must trigger a defensive gratuitous ARP.",
        )

    def test__stack__packet_handler__arp__rx__defend_second_within_interval_skipped(self) -> None:
        """
        Ensure a second conflicting ARP packet for the same IP
        within DEFEND_INTERVAL seconds of the previous defense
        does NOT emit another defensive gratuitous ARP — the
        rate-limit prevents the host from contributing to a
        broadcast storm under sustained conflict.

        Reference: RFC 5227 §2.4(c) (MUST NOT defend within DEFEND_INTERVAL).
        """

        with patch("time.monotonic", side_effect=[1000.0, 1005.0]):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS],
            msg=(
                "A second conflict within DEFEND_INTERVAL (10 s) must NOT trigger a "
                "second gratuitous ARP. Got: "
                f"{self._handler.gratuitous_arps_sent!r}"
            ),
        )

    def test__stack__packet_handler__arp__rx__defend_after_interval_re_emits(self) -> None:
        """
        Ensure a conflicting ARP packet arriving more than
        DEFEND_INTERVAL seconds after the previous defense
        re-arms the defense and emits a fresh gratuitous ARP,
        AND the re-arm correctly resets the timestamp so a
        third conflict immediately after the re-arm is
        suppressed (proving the dict was updated, not that
        the rate-limit is absent).

        Reference: RFC 5227 §2.4(c) (defense re-armed after DEFEND_INTERVAL).
        """

        with patch("time.monotonic", side_effect=[1000.0, 1010.5, 1011.0]):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS, STACK__IP4_ADDRESS],
            msg=(
                "Conflicts at t=1000 and t=1010.5 must each emit a defense (10.5 s "
                "apart, past DEFEND_INTERVAL); the third at t=1011.0 (0.5 s after "
                "the re-arm) must be suppressed. Got: "
                f"{self._handler.gratuitous_arps_sent!r}"
            ),
        )

    def test__stack__packet_handler__arp__rx__defend_per_ip_independence(self) -> None:
        """
        Ensure the rate-limit is per-IP: a defense on IP A
        does NOT suppress a defense on IP B, even within the
        same DEFEND_INTERVAL window — two hosts contending
        for two different stack IPs are independent failure
        domains. Drives a 3-packet sequence (A, A, B) so the
        no-rate-limit case [A, A, B] is distinguishable from
        the per-IP rate-limit case [A, B].

        Reference: RFC 5227 §2.4 (ongoing conflict detection and defense).
        """

        self._handler._ip4_host = [STACK__IP4_HOST, STACK__IP4_HOST_2]

        with patch("time.monotonic", side_effect=[1000.0, 1001.0, 1002.0]):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS_2, sha=HOST_C__MAC)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS, STACK__IP4_ADDRESS_2],
            msg=(
                "Conflict on IP_A at t=1000 must defend; second conflict on IP_A "
                "at t=1001 must be suppressed (within DEFEND_INTERVAL); conflict "
                "on IP_B at t=1002 must defend (separate per-IP bucket). Got: "
                f"{self._handler.gratuitous_arps_sent!r}"
            ),
        )

    def test__stack__packet_handler__arp__rx__abandon_after_second_conflict_within_interval(self) -> None:
        """
        Ensure a second conflicting ARP packet for the same IP
        within DEFEND_INTERVAL of the previous conflict
        triggers the abandon path: the IPv4 address is removed
        from '_ip4_host' and the 'arp__conflict__abandon' stat
        is incremented. The second conflict does NOT emit a
        defensive gratuitous ARP — the host is giving up the
        address rather than defending it.

        Reference: RFC 5227 §2.4(b) (MUST cease using address after second conflict).
        """

        with patch("time.monotonic", side_effect=[1000.0, 1005.0]):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS],
            msg=(
                "Second conflict within DEFEND_INTERVAL must NOT defend (host "
                "is abandoning the address per RFC 5227 §2.4(b))."
            ),
        )
        self.assertNotIn(
            STACK__IP4_HOST,
            self._handler._ip4_host,
            msg=(
                "RFC 5227 §2.4(b) MUST: the abandoned IPv4 address must be "
                "removed from '_ip4_host' so the stack stops using it."
            ),
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__conflict__abandon,
            1,
            msg="The 'arp__conflict__abandon' stat must be incremented on the abandon path.",
        )

    def test__stack__packet_handler__arp__rx__no_abandon_after_second_conflict_outside_interval(self) -> None:
        """
        Ensure two conflicts spaced MORE than DEFEND_INTERVAL
        apart do NOT trigger the abandon path — both fire
        their own defensive gratuitous ARP and the address
        stays in '_ip4_host'. The MUST in §2.4(b) is gated on
        "within DEFEND_INTERVAL"; conflicts outside that window
        are independent events.

        Reference: RFC 5227 §2.4(b) (abandon gated on within DEFEND_INTERVAL).
        """

        # 10.5 s apart — past the 10 s default DEFEND_INTERVAL.
        with patch("time.monotonic", side_effect=[1000.0, 1010.5]):
            self._drive_conflict(spa=STACK__IP4_ADDRESS)
            self._drive_conflict(spa=STACK__IP4_ADDRESS)

        self.assertEqual(
            self._handler.gratuitous_arps_sent,
            [STACK__IP4_ADDRESS, STACK__IP4_ADDRESS],
            msg="Conflicts past DEFEND_INTERVAL must each fire a defense.",
        )
        self.assertIn(
            STACK__IP4_HOST,
            self._handler._ip4_host,
            msg="Address must NOT be abandoned when conflicts are past DEFEND_INTERVAL.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.arp__conflict__abandon,
            0,
            msg="The 'arp__conflict__abandon' stat must NOT increment outside the window.",
        )

    def test__stack__packet_handler__arp__rx__abandon_aborts_bound_tcp_sessions(self) -> None:
        """
        Ensure the abandon path attempts to ABORT every
        TcpSession bound to the abandoned address. Iterates
        'pytcp.stack.sockets' and calls
        'tcp_session.tcp_fsm(syscall=SysCall.ABORT)' on every
        socket whose 'socket_id.local_address' matches.

        Reference: RFC 5227 §2.4 final (reset connections before abandon).
        """

        from pytcp.protocols.tcp.tcp__session import SysCall
        from pytcp.socket import AddressFamily, SocketType
        from pytcp.socket.socket_id import SocketId

        # Construct a fake socket with a TCP-session-shaped
        # spy on tcp_fsm.
        fake_session = MagicMock()
        fake_socket = MagicMock()
        fake_socket._tcp_session = fake_session
        socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP4_ADDRESS,
            local_port=12345,
            remote_address=HOST_A__IP4,
            remote_port=80,
        )

        with patch.dict(stack.sockets, {socket_id: fake_socket}, clear=True):
            with patch("time.monotonic", side_effect=[1000.0, 1005.0]):
                self._drive_conflict(spa=STACK__IP4_ADDRESS)
                self._drive_conflict(spa=STACK__IP4_ADDRESS)

        fake_session.tcp_fsm.assert_called_with(syscall=SysCall.ABORT)


class TestPacketHandlerArpRxPolicySysctls(_ArpRxTestBase):
    """
    The 'arp.accept' / 'arp.ignore' RX-policy sysctl tests.

    Pin that the inbound-ARP handling honours the registered
    sysctl values: 'arp.accept' gates whether off-subnet
    senders update the cache, and 'arp.ignore = 2' drops
    Requests whose sender IP is not on any of our local
    subnets (Linux's 'net.ipv4.conf.<iface>.arp_ignore' mode
    2 semantics).
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test override does not
        leak into subsequent tests' baselines.
        """

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__stack__packet_handler__arp__rx__arp_accept_default_drops_off_subnet_cache_update(self) -> None:
        """
        Ensure that with the default 'arp.accept = 0', an ARP
        Request whose sender IP is NOT on any of our local
        subnets does NOT update the ARP cache. The conservative
        default protects against trusting ARP from unknown
        networks (gratuitous-ARP cache poisoning from off-link
        attackers).

        Reference: Linux net.ipv4.conf.<iface>.arp_accept (mode 0: reject off-subnet).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=OFF_NET__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_not_called()

    def test__stack__packet_handler__arp__rx__arp_accept_one_admits_off_subnet_cache_update(self) -> None:
        """
        Ensure that with 'arp.accept = 1', an ARP Request
        whose sender IP is NOT on any of our local subnets
        DOES update the cache. Operators on multi-VLAN setups
        or behind ARP proxies may need this to learn next-hops
        outside their primary subnet.

        Reference: Linux net.ipv4.conf.<iface>.arp_accept (mode 1: admit off-subnet).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.accept", 1):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=OFF_NET__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_default_replies(self) -> None:
        """
        Ensure that with the default 'arp.ignore = 1', an ARP
        Request from an on-subnet sender for one of our
        configured IPs receives a Reply — current PyTCP
        baseline behaviour, restated against the live sysctl
        value.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 1: reply only if target configured).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            len(self._handler.arp_replies_sent),
            1,
            msg="With arp.ignore=1 (default), an on-subnet Request for our IP must trigger a Reply.",
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_drops_off_subnet_sender(self) -> None:
        """
        Ensure that with 'arp.ignore = 2', an ARP Request
        whose sender IP (SPA) is NOT on any of our local
        subnets is silently dropped without sending a Reply,
        even when its target IP IS one of ours. Linux's mode-2
        "sender-subnet-match" semantics — used to tighten
        anti-spoofing on hosts that should only answer ARPs
        from neighbours.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2: sender-subnet-match).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.ignore", 2):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler.arp_replies_sent,
            [],
            msg=(
                "With arp.ignore=2, an off-subnet sender must NOT receive an ARP "
                "Reply even when the target IP is one of ours."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_still_replies_on_subnet_sender(self) -> None:
        """
        Ensure 'arp.ignore = 2' still permits Replies when the
        sender IS on one of our local subnets — mode 2 is
        about REJECTING off-subnet senders, not about adding
        an extra rejection on legitimate neighbours.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2: on-subnet sender admitted).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.ignore", 2):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            len(self._handler.arp_replies_sent),
            1,
            msg=(
                "With arp.ignore=2, an on-subnet sender for our target IP must "
                "still receive a Reply — mode 2 only rejects off-subnet senders."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_eight_drops_all_replies(self) -> None:
        """
        Ensure 'arp.ignore = 8' (kill switch) suppresses every
        Reply regardless of sender subnet, target match, or any
        other gate — Linux's mode 8 "do not reply for all local
        addresses" semantics.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 kill-switch).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.ignore", 8):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler.arp_replies_sent,
            [],
            msg=(
                "With arp.ignore=8, even a legitimate on-subnet Request for "
                "our IP must NOT receive a Reply — kill switch is unconditional."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_still_updates_cache(self) -> None:
        """
        Ensure 'arp.ignore = 2' suppresses only the Reply and
        does NOT bypass cache learning when an off-subnet
        sender is admitted via 'arp.accept = 1'. Pins the fix
        for a latent bug where mode-2 used 'return' to drop the
        Reply, which also short-circuited the unconditional
        cache-update tail and silently ate every cache learn
        from off-subnet neighbours during anti-spoof mode.
        Linux's 'arp_ignore' affects only the reply path; cache
        behaviour is gated by 'arp_accept'.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2 affects reply path only).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.ignore", 2), sysctl_module.override("arp.accept", 1):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self.assertEqual(
            self._handler.arp_replies_sent,
            [],
            msg="arp.ignore=2 must drop the Reply when SPA is off-subnet.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=OFF_NET__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_eight_still_updates_cache(self) -> None:
        """
        Ensure 'arp.ignore = 8' suppresses only the Reply and
        does NOT bypass cache learning — mode 8's contract is
        "go silent on the wire," not "stop learning who is on
        the segment." Cache updates from inbound ARP let TCP
        reach the peer once it initiates traffic.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 affects reply path only).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.ignore", 8):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._handler._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )
