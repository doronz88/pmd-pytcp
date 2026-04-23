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

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py

ver 3.0.4
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4Host, MacAddress
from net_proto import ArpAssembler, ArpOperation
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.stack.packet_handler.packet_handler__arp__rx import (
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
STACK__IP4_HOST = Ip4Host("10.0.1.7/24")
STACK__IP4_ADDRESS = STACK__IP4_HOST.address

STACK__IP4_HOST__CANDIDATE = Ip4Host("10.0.1.5/24")
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

        self.arp_replies_sent: list[dict[str, object]] = []
        self.gratuitous_arps_sent: list[Ip4Address] = []

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

        self._arp_cache_patch = patch.object(stack, "arp_cache", MagicMock())
        self._arp_cache = self._arp_cache_patch.start()

        self._conflict_patch = patch.object(stack, "arp_probe_unicast_conflict", set[Ip4Address]())
        self._conflict_set = self._conflict_patch.start()

    def tearDown(self) -> None:
        """
        Restore the patched stack singletons.
        """

        self._arp_cache_patch.stop()
        self._conflict_patch.stop()


class TestPacketHandlerArpRxParseFail(_ArpRxTestBase):
    """
    The ARP parser-failure tests.
    """

    def test__stack__packet_handler__arp__rx__malformed_frame_drops(self) -> None:
        """
        Ensure a truncated ARP frame fails parsing and is counted in
        'arp__failed_parse__drop'.
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
        self.assertIn(
            STACK__IP4_ADDRESS__CANDIDATE,
            self._conflict_set,
            msg="Probe-conflict IP must be registered in 'arp_probe_unicast_conflict'.",
        )
        self._arp_cache.add_entry.assert_not_called()

    def test__stack__packet_handler__arp__rx__tpa_unknown(self) -> None:
        """
        Ensure an ARP request for a TPA not in our unicast list is
        counted and no reply is sent.
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
        self.assertIn(
            STACK__IP4_ADDRESS__CANDIDATE,
            self._conflict_set,
            msg="Probe-conflict IP must be registered in 'arp_probe_unicast_conflict'.",
        )

    def test__stack__packet_handler__arp__rx__reply_direct_updates_cache(self) -> None:
        """
        Ensure a direct ARP reply (ethernet.dst == stack unicast MAC)
        is counted and updates the ARP cache.
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
        self.assertIn(
            STACK__IP4_ADDRESS__CANDIDATE,
            self._conflict_set,
            msg="Probe-conflict IP must be registered in 'arp_probe_unicast_conflict'.",
        )
        self._arp_cache.add_entry.assert_not_called()
