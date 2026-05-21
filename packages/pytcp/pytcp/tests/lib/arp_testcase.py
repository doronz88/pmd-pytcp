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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration-test harness for ARP packet-handler tests.

Extends 'NetworkTestCase' with ARP-aware helpers:

  - '_build_arp_frame' / '_drive_arp' — construct an Ethernet+ARP
    frame from semantic kwargs (oper, sha, spa, tha, tpa, plus L2
    src/dst) and optionally drive it through the live packet
    handler. Replaces the hand-crafted 42-byte raw fixtures used
    by the legacy tests.

  - '_set_monotonic' / '_advance_monotonic' — control the
    'time.monotonic()' clock that the RFC 5227 §2.4(c) defense
    rate-limit reads. Lets DEFEND_INTERVAL behaviour be
    exercised deterministically.

  - '_drive_dad' — drive 'PacketHandlerL2._create_stack_ip4_addressing'
    synchronously with 'time.sleep' patched out and an optional
    per-iteration callback that can inject conflicting RX frames
    into the probe window. Lets §2.1.1 probe-conflict-aborts-claim
    behaviour be exercised end-to-end.

pytcp/tests/lib/arp_testcase.py

ver 3.0.6
"""

from __future__ import annotations

from functools import partial
from typing import Callable
from unittest.mock import patch

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_C__IP4_ADDRESS,
    IP4__BROADCAST__LIMITED,
    IP4__MULTICAST__ALL_NODES,
    IP4__UNSPECIFIED,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_GATEWAY,
    STACK__IP4_GATEWAY_MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

__all__ = (
    "ArpTestCase",
    "HOST_A__IP4_ADDRESS",
    "HOST_A__MAC_ADDRESS",
    "HOST_B__IP4_ADDRESS",
    "HOST_C__IP4_ADDRESS",
    "IP4__BROADCAST__LIMITED",
    "IP4__MULTICAST__ALL_NODES",
    "IP4__UNSPECIFIED",
    "MAC__BROADCAST",
    "MAC__UNSPECIFIED",
    "STACK__IP4_GATEWAY",
    "STACK__IP4_GATEWAY_MAC_ADDRESS",
    "STACK__IP4_HOST",
    "STACK__IP4_HOST__CANDIDATE",
    "STACK__MAC_ADDRESS",
)


class ArpTestCase(NetworkTestCase):
    """
    Base case for ARP integration tests.
    """

    _monotonic_t: float
    _dad_sleep_callbacks: list[Callable[[], None]]
    _dad_sleep_durations: list[float]

    def setUp(self) -> None:
        """
        Install the ARP-specific patches: clock control for the
        DEFEND_INTERVAL rate-limit and 'time.sleep' interception
        for the synchronous DAD driver.
        """

        super().setUp()

        # Clock for time-sensitive ARP behaviours. The harness
        # patches 'time.monotonic' in every ARP-related production
        # module so the same test-controlled clock is observed by:
        #
        #   - 'packet_handler__arp__rx._maybe_send_arp_defense'
        #     (RFC 5227 §2.4(c) DEFEND_INTERVAL)
        #   - 'arp_cache.find_entry' (RFC 1122 §2.3.2.1
        #     per-destination ARP-Request rate-limit)
        self._monotonic_t = 0.0

        def _read_monotonic() -> float:
            return self._monotonic_t

        self._monotonic_patch = patch(
            "pytcp.runtime.packet_handler.packet_handler__arp__rx.time.monotonic",
            side_effect=_read_monotonic,
        )
        self._monotonic_patch.start()
        self._arp_cache_monotonic_patch = patch(
            "pytcp.lib.neighbor.time.monotonic",
            side_effect=_read_monotonic,
        )
        self._arp_cache_monotonic_patch.start()

        # FIFO of callbacks invoked one per 'time.sleep' call from
        # 'PacketHandlerL2._create_stack_ip4_addressing'. The DAD
        # loop runs three iterations, so '_drive_dad' typically
        # populates this with three callbacks (or leaves it empty
        # for a no-injection run).
        self._dad_sleep_callbacks = []

        # Records every 'time.sleep(dur)' the patched sleep
        # observes, in order. Lets tests assert on the timing
        # pattern of the DAD flow (probe-loop intervals,
        # ANNOUNCE_INTERVAL between Announcements, ANNOUNCE_WAIT
        # post-probe quiet period, etc.).
        self._dad_sleep_durations = []

        def _patched_sleep(dur: float) -> None:
            self._dad_sleep_durations.append(dur)
            if self._dad_sleep_callbacks:
                self._dad_sleep_callbacks.pop(0)()

        self._sleep_patch = patch(
            "pytcp.runtime.packet_handler.time.sleep",
            side_effect=_patched_sleep,
        )
        self._sleep_patch.start()

    def tearDown(self) -> None:
        """
        Restore the patches installed in 'setUp', innermost first.
        """

        self._sleep_patch.stop()
        self._arp_cache_monotonic_patch.stop()
        self._monotonic_patch.stop()

        super().tearDown()

    # -- clock control ----------------------------------------------------

    def _set_monotonic(self, t: float) -> None:
        """
        Set the patched 'time.monotonic()' return value to 't'.
        """

        self._monotonic_t = t

    def _advance_monotonic(self, dt: float) -> None:
        """
        Advance the patched 'time.monotonic()' return value by
        'dt' seconds.
        """

        self._monotonic_t += dt

    # -- frame helpers ----------------------------------------------------

    @staticmethod
    def _build_arp_frame(
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper: ArpOperation,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> bytes:
        """
        Build a 42-byte Ethernet II + ARP wire frame from semantic
        kwargs. The Ethernet 'type' field is derived from the
        payload via 'EtherType.from_proto(ArpAssembler)'.

        For tests that need an unknown ArpOperation (which the
        TX-strict assembler refuses to emit on principle), use
        '_build_arp_frame_with_raw_oper' below.
        """

        return bytes(
            EthernetAssembler(
                ethernet__dst=ethernet_dst,
                ethernet__src=ethernet_src,
                ethernet__payload=ArpAssembler(
                    arp__oper=arp_oper,
                    arp__sha=arp_sha,
                    arp__spa=arp_spa,
                    arp__tha=arp_tha,
                    arp__tpa=arp_tpa,
                ),
            )
        )

    @staticmethod
    def _build_arp_frame_with_raw_oper(
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper_raw: int,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> bytes:
        """
        Build a 42-byte Ethernet II + ARP wire frame with a raw
        uint16 'oper' value bypassing the TX-strict
        ArpAssembler closed-set check.

        Used by parser sanity tests that drive an unknown
        ArpOperation through the RX path — the assembler refuses
        to construct such a frame on principle (RFC 826 /
        RFC 5494 §3), so the test builds the bytes directly.
        """

        # Ethernet II header (14 bytes) + ARP fixed payload (28 bytes).
        ether_hdr = bytes(ethernet_dst) + bytes(ethernet_src) + b"\x08\x06"
        arp_payload = (
            b"\x00\x01"  # hrtype: ETHERNET
            b"\x08\x00"  # prtype: IPv4
            b"\x06"  # hrlen
            b"\x04"  # prlen
            + arp_oper_raw.to_bytes(2)
            + bytes(arp_sha)
            + bytes(arp_spa)
            + bytes(arp_tha)
            + bytes(arp_tpa)
        )
        return ether_hdr + arp_payload

    def _drive_arp(
        self,
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper: ArpOperation,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> None:
        """
        Build an Ethernet+ARP frame from the given fields and drive
        it through the packet handler's '_phrx_ethernet' entry
        point — the same entry the production RX ring uses.
        """

        frame = self._build_arp_frame(
            ethernet_dst=ethernet_dst,
            ethernet_src=ethernet_src,
            arp_oper=arp_oper,
            arp_sha=arp_sha,
            arp_spa=arp_spa,
            arp_tpa=arp_tpa,
            arp_tha=arp_tha,
        )
        self._packet_handler._phrx_ethernet(PacketRx(frame))

    # -- DAD flow driver --------------------------------------------------

    def _drive_dad(
        self,
        *,
        on_sleep: Callable[[int], None] | None = None,
        num_sleep_callbacks: int = 3,
    ) -> None:
        """
        Drive 'PacketHandlerL2._create_stack_ip4_addressing'
        synchronously. The DAD loop runs three probe iterations
        with a 'time.sleep(random.uniform(1, 2))' between each;
        this harness patches the sleep to a no-op (or to a
        test-supplied callback).

        If 'on_sleep' is provided, it is invoked once per sleep
        with the iteration index (0, 1, 2, ...). Tests can use
        this hook to inject conflicting RX frames into the probe
        window via '_drive_arp' to exercise §2.1.1 conflict
        detection. 'num_sleep_callbacks' controls how many
        callback slots are registered — the default 3 covers
        the probe-loop iterations; tests targeting later sleeps
        (RFC 5227 §2.1.1 ANNOUNCE_WAIT post-probe quiet period
        at index 3, §2.3 ANNOUNCE_INTERVAL between Announcements
        at index 4) pass higher counts.
        """

        if on_sleep is not None:
            self._dad_sleep_callbacks = [partial(on_sleep, i) for i in range(num_sleep_callbacks)]

        self._packet_handler._create_stack_ip4_addressing()
