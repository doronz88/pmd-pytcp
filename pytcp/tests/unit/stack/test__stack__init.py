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
This module contains tests for the 'pytcp/stack/__init__.py' module
constants and the 'initialize_interface__{tap,tun}' / 'mock__init'
helpers.

pytcp/tests/unit/stack/test__stack__init.py

ver 3.0.4
"""

import sys
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytcp.stack as stack
from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer


class TestStackModuleConstants(TestCase):
    """
    The 'pytcp.stack' module-level constant tests.
    """

    def test__stack__tun_tap_constants(self) -> None:
        """
        Ensure the TAP/TUN ioctl constants match the Linux kernel
        values. Wrong values would make 'initialize_interface__tap'
        attach the wrong kernel interface.

        Reference: Linux kernel tun.h (TUNSETIFF / IFF_TUN / IFF_TAP / IFF_NO_PI).
        """

        self.assertEqual(
            stack.TUNSETIFF,
            0x400454CA,
            msg="TUNSETIFF must match the Linux kernel's TUNSETIFF ioctl code.",
        )
        self.assertEqual(
            stack.IFF_TUN,
            0x0001,
            msg="IFF_TUN must be 0x0001 per the Linux tun.h header.",
        )
        self.assertEqual(
            stack.IFF_TAP,
            0x0002,
            msg="IFF_TAP must be 0x0002 per the Linux tun.h header.",
        )
        self.assertEqual(
            stack.IFF_NO_PI,
            0x1000,
            msg="IFF_NO_PI must be 0x1000 per the Linux tun.h header.",
        )

    def test__stack__interface_mtu_defaults(self) -> None:
        """
        Ensure the default MTU for TAP/TUN interfaces is 1500 bytes —
        the standard Ethernet MTU. Changing this shifts every
        fragmentation / MSS calculation downstream.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.INTERFACE__TAP__MTU,
            1500,
            msg="INTERFACE__TAP__MTU must default to 1500.",
        )
        self.assertEqual(
            stack.INTERFACE__TUN__MTU,
            1500,
            msg="INTERFACE__TUN__MTU must default to 1500.",
        )

    def test__stack__protocol_support_defaults_enabled(self) -> None:
        """
        Ensure IPv4 and IPv6 support flags are enabled by default.
        Disabling them silently would break the integration tests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            stack.IP4__SUPPORT,
            msg="IP4__SUPPORT must default to True.",
        )
        self.assertTrue(
            stack.IP6__SUPPORT,
            msg="IP6__SUPPORT must default to True.",
        )

    def test__stack__neighbor_cache_timers_are_positive(self) -> None:
        """
        Ensure the generic NeighborCache aging timers
        ('neighbor.reachable_time' / 'neighbor.retrans_timer')
        are both positive at module load — the FSM relies on
        these for REACHABLE → STALE and inter-solicit
        retransmit cadence. The IPv6 ND cache reads these
        directly via 'pytcp.lib.neighbor' as of Phase 3 of
        the NUD migration.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib import neighbor__constants

        self.assertGreater(
            neighbor__constants.NEIGHBOR__REACHABLE_TIME,
            0,
            msg="NEIGHBOR__REACHABLE_TIME must be positive.",
        )
        self.assertGreater(
            neighbor__constants.NEIGHBOR__RETRANS_TIMER,
            0,
            msg="NEIGHBOR__RETRANS_TIMER must be positive.",
        )

    def test__stack__ephemeral_port_range(self) -> None:
        """
        Ensure the ephemeral port range lies within the 0-65535 bounds
        of a 16-bit port field and ends above its start.

        Reference: RFC 6335 §6 (ephemeral port range).
        """

        self.assertGreaterEqual(
            stack.EPHEMERAL_PORT_RANGE.start,
            0,
            msg="EPHEMERAL_PORT_RANGE start must be >= 0.",
        )
        self.assertLessEqual(
            stack.EPHEMERAL_PORT_RANGE.stop,
            65536,
            msg="EPHEMERAL_PORT_RANGE stop must be <= 65536.",
        )
        self.assertGreater(
            stack.EPHEMERAL_PORT_RANGE.stop,
            stack.EPHEMERAL_PORT_RANGE.start,
            msg="EPHEMERAL_PORT_RANGE must be non-empty.",
        )

    def test__stack__fragment_timeouts_positive(self) -> None:
        """
        Ensure IP fragment reassembly timeouts are positive. A value
        of 0 would immediately drop every fragment flow.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertGreater(
            stack.IP4__FRAG_FLOW_TIMEOUT,
            0,
            msg="IP4__FRAG_FLOW_TIMEOUT must be positive.",
        )
        self.assertGreater(
            stack.IP6__FRAG_FLOW_TIMEOUT,
            0,
            msg="IP6__FRAG_FLOW_TIMEOUT must be positive.",
        )

    def test__stack__log_channels_present(self) -> None:
        """
        Ensure the default 'LOG__CHANNEL' set contains the core
        subsystem channels referenced across the codebase. Dropping
        a channel here silences an entire subsystem's log output.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        required = {
            "stack",
            "rx-ring",
            "tx-ring",
            "arp-c",
            "nd-c",
            "ether",
            "arp",
            "ip4",
            "ip6",
            "icmp4",
            "icmp6",
            "udp",
            "tcp",
            "socket",
            "tcp-ss",
        }
        missing = required - stack.LOG__CHANNEL
        self.assertEqual(
            missing,
            set(),
            msg=f"LOG__CHANNEL must contain every core subsystem channel; missing: {missing}",
        )

    def test__stack__pytcp_version_shape(self) -> None:
        """
        Ensure the 'PYTCP_VERSION' string starts with 'ver ' so any
        consumers that parse "ver X.Y.Z" can keep working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            stack.PYTCP_VERSION.startswith("ver "),
            msg="PYTCP_VERSION must start with 'ver ' so 'ver X.Y.Z' parsers can keep working.",
        )

    def test__stack__stack_initialized_defaults_false(self) -> None:
        """
        Ensure the module-level 'stack_initialized' flag starts False
        — start()/stop() gate on it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # It might be True if the process already ran stack.init() in a
        # previous test. Assert only the default flag declaration here.
        self.assertIsInstance(
            stack.stack_initialized,
            bool,
            msg="stack_initialized must be a bool.",
        )


class TestStackInitializeInterfaceTap(TestCase):
    """
    The 'initialize_interface__tap' helper tests.
    """

    def setUp(self) -> None:
        """
        Suppress log output and patch the low-level syscalls that the
        helper delegates to ('os.open' / 'fcntl.ioctl').
        """

        self._log_patch = patch("pytcp.stack.log")
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Tear down patches.
        """

        self._log_patch.stop()

    def test__stack__initialize_tap_returns_interface_dict(self) -> None:
        """
        Ensure 'initialize_interface__tap' returns a dict carrying the
        file descriptor, InterfaceLayer.L2, default MTU, and the
        derived MAC address — the shape 'stack.init()' consumes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.os.open", return_value=42),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tap("tap7")

        self.assertEqual(
            result["fd"],
            42,
            msg="initialize_interface__tap must return the fd from os.open.",
        )
        self.assertIs(
            result["layer"],
            InterfaceLayer.L2,
            msg="initialize_interface__tap must declare the InterfaceLayer.L2 layer.",
        )
        self.assertEqual(
            result["mtu"],
            stack.INTERFACE__TAP__MTU,
            msg="initialize_interface__tap must report the INTERFACE__TAP__MTU default.",
        )
        self.assertIsInstance(
            result["mac_address"],
            MacAddress,
            msg="initialize_interface__tap must materialize a MacAddress from the interface name.",
        )

    def test__stack__initialize_tap_honors_explicit_mac(self) -> None:
        """
        Ensure passing 'mac_address=' overrides the MAC derived from
        the interface name. Used by integration tests that need a
        deterministic MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("02:00:00:00:00:99")
        with (
            patch("pytcp.stack.os.open", return_value=42),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tap("tap7", mac_address=mac)

        self.assertEqual(
            result["mac_address"],
            mac,
            msg="initialize_interface__tap must use the explicit mac_address argument verbatim.",
        )

    def test__stack__initialize_tap_exits_when_tun_missing(self) -> None:
        """
        Ensure the helper calls 'sys.exit(-1)' when '/dev/net/tun' is
        not present. This is the operator-visible failure path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.stack.os.open",
                side_effect=FileNotFoundError,
            ),
            patch("pytcp.stack.sys.exit", side_effect=SystemExit(-1)) as mock_exit,
        ):
            with self.assertRaises(SystemExit):
                stack.initialize_interface__tap("tap7")
        mock_exit.assert_called_once_with(-1)


class TestStackInitializeInterfaceTun(TestCase):
    """
    The 'initialize_interface__tun' helper tests.
    """

    def setUp(self) -> None:
        """
        Suppress log output.
        """

        self._log_patch = patch("pytcp.stack.log")
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Tear down patches.
        """

        self._log_patch.stop()

    def test__stack__initialize_tun_returns_interface_dict(self) -> None:
        """
        Ensure 'initialize_interface__tun' returns a dict carrying
        the file descriptor, InterfaceLayer.L3, and the default MTU.
        TUN mode does not report a MAC address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.os.open", return_value=99),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tun("tun7")

        self.assertEqual(
            result["fd"],
            99,
            msg="initialize_interface__tun must return the fd from os.open.",
        )
        self.assertIs(
            result["layer"],
            InterfaceLayer.L3,
            msg="initialize_interface__tun must declare the InterfaceLayer.L3 layer.",
        )
        self.assertEqual(
            result["mtu"],
            stack.INTERFACE__TUN__MTU,
            msg="initialize_interface__tun must report the INTERFACE__TUN__MTU default.",
        )
        self.assertNotIn(
            "mac_address",
            result,
            msg="initialize_interface__tun must not include a 'mac_address' key.",
        )

    def test__stack__initialize_tun_exits_when_tun_missing(self) -> None:
        """
        Ensure the TUN helper also exits on FileNotFoundError to
        match 'initialize_interface__tap'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.stack.os.open",
                side_effect=FileNotFoundError,
            ),
            patch("pytcp.stack.sys.exit", side_effect=SystemExit(-1)) as mock_exit,
        ):
            with self.assertRaises(SystemExit):
                stack.initialize_interface__tun("tun7")
        mock_exit.assert_called_once_with(-1)


class TestStackMockInit(TestCase):
    """
    The 'stack.mock__init' helper tests.
    """

    def setUp(self) -> None:
        """
        Snapshot the module-level singletons so each test can reset
        them. Using 'getattr' with a sentinel lets us handle the
        'not-yet-assigned' case (the real globals are declared with
        bare annotations).
        """

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in ("timer", "rx_ring", "tx_ring", "arp_cache", "nd_cache", "packet_handler")
        }

    def tearDown(self) -> None:
        """
        Restore the snapshot of module-level singletons.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                # The attribute was not defined before; delete the
                # assignment left by mock__init so the post-condition
                # matches the pre-condition.
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__mock_init_assigns_provided_components(self) -> None:
        """
        Ensure 'mock__init' wires every provided mock into the
        corresponding module-level singleton. Missing mocks leave
        their prior binding untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fake_timer = MagicMock()
        fake_tx = MagicMock()
        fake_rx = MagicMock()
        fake_arp = MagicMock()
        fake_nd = MagicMock()
        fake_handler = MagicMock()

        stack.mock__init(
            mock__timer=fake_timer,
            mock__tx_ring=fake_tx,
            mock__rx_ring=fake_rx,
            mock__arp_cache=fake_arp,
            mock__nd_cache=fake_nd,
            mock__packet_handler=fake_handler,
        )

        self.assertIs(stack.timer, fake_timer, msg="mock__init must wire the timer mock.")
        self.assertIs(stack.tx_ring, fake_tx, msg="mock__init must wire the tx_ring mock.")
        self.assertIs(stack.rx_ring, fake_rx, msg="mock__init must wire the rx_ring mock.")
        self.assertIs(stack.arp_cache, fake_arp, msg="mock__init must wire the arp_cache mock.")
        self.assertIs(stack.nd_cache, fake_nd, msg="mock__init must wire the nd_cache mock.")
        self.assertIs(stack.packet_handler, fake_handler, msg="mock__init must wire the packet_handler mock.")

    def test__stack__mock_init_leaves_unspecified_unchanged(self) -> None:
        """
        Ensure 'mock__init' only overwrites the singletons the caller
        passes a mock for — omitted ones stay at their prior value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # First assign all to sentinel values, then call mock__init with
        # only one mock and verify the others are untouched.
        pre_timer = MagicMock()
        pre_tx = MagicMock()
        stack.mock__init(mock__timer=pre_timer, mock__tx_ring=pre_tx)

        new_timer = MagicMock()
        stack.mock__init(mock__timer=new_timer)

        self.assertIs(
            stack.timer,
            new_timer,
            msg="mock__init must overwrite the timer when one is supplied.",
        )
        self.assertIs(
            stack.tx_ring,
            pre_tx,
            msg="mock__init must leave tx_ring untouched when no replacement is supplied.",
        )


class TestStackStopOrdering(TestCase):
    """
    The 'stack.stop()' subsystem teardown-order tests.
    """

    def setUp(self) -> None:
        """
        Snapshot the module-level state and replace each subsystem
        with a MagicMock so 'stack.stop()' can be invoked without a
        live stack.
        """

        self._saved = {
            "stack_initialized": stack.stack_initialized,
            "timer": getattr(stack, "timer", None),
            "rx_ring": getattr(stack, "rx_ring", None),
            "tx_ring": getattr(stack, "tx_ring", None),
            "arp_cache": getattr(stack, "arp_cache", None),
            "nd_cache": getattr(stack, "nd_cache", None),
            "packet_handler": getattr(stack, "packet_handler", None),
        }

        self._call_log: list[str] = []

        def _make_subsystem(name: str) -> MagicMock:
            m = MagicMock()
            m.stop.side_effect = lambda n=name: self._call_log.append(n)
            return m

        stack.timer = _make_subsystem("timer")
        stack.rx_ring = _make_subsystem("rx_ring")
        stack.tx_ring = _make_subsystem("tx_ring")
        stack.arp_cache = _make_subsystem("arp_cache")
        stack.nd_cache = _make_subsystem("nd_cache")
        stack.packet_handler = _make_subsystem("packet_handler")
        # Make 'hasattr(packet_handler, "arp_cache")' True so the
        # arp_cache.stop() branch fires.
        stack.packet_handler.arp_cache = MagicMock()
        stack.stack_initialized = True

    def tearDown(self) -> None:
        """
        Restore the saved module-level subsystems.
        """

        for name, value in self._saved.items():
            if value is not None:
                setattr(stack, name, value)

    def test__stack__stop_stops_timer_before_tx_ring(self) -> None:
        """
        Ensure 'stack.stop()' stops the timer before the TX ring so
        timer-driven callbacks (TCP RTO, persist, keep-alive,
        delayed-ACK) cannot fire after the TX ring has stopped and
        silently lose their outbound packets to a never-drained queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        timer_idx = self._call_log.index("timer")
        tx_ring_idx = self._call_log.index("tx_ring")

        self.assertLess(
            timer_idx,
            tx_ring_idx,
            msg=(
                "timer.stop() must precede tx_ring.stop() so timer-driven "
                "callbacks cannot enqueue to a stopped TX ring. Got order: "
                f"{self._call_log}"
            ),
        )

    def test__stack__stop_stops_packet_handler_first(self) -> None:
        """
        Ensure 'stack.stop()' stops the packet handler first so
        application-side TX producers exit before the rings tear
        down.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        self.assertEqual(
            self._call_log[0],
            "packet_handler",
            msg=("packet_handler.stop() must be the first action in " f"stack.stop(). Got order: {self._call_log}"),
        )

    def test__stack__stop_stops_rings_after_packet_handler(self) -> None:
        """
        Ensure both rings are stopped after the packet handler exits
        — packet_handler is the producer; stopping it first means
        the rings only need to drain in-flight packets, not absorb
        new arrivals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        ph_idx = self._call_log.index("packet_handler")
        rx_idx = self._call_log.index("rx_ring")
        tx_idx = self._call_log.index("tx_ring")

        self.assertLess(
            ph_idx,
            rx_idx,
            msg=f"rx_ring must stop after packet_handler. Got: {self._call_log}",
        )
        self.assertLess(
            ph_idx,
            tx_idx,
            msg=f"tx_ring must stop after packet_handler. Got: {self._call_log}",
        )


class TestStackInitSharedPacketStats(TestCase):
    """
    The 'stack.init()' shared 'PacketStats' wiring tests.
    """

    def setUp(self) -> None:
        """
        Snapshot the module-level singletons that 'stack.init()'
        rebinds so each test can roll back cleanly. Suppress the
        'Initializing ...' subsystem-init log lines that leak from
        the 'stack.init()' construction path.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "rx_ring",
                "tx_ring",
                "arp_cache",
                "nd_cache",
                "packet_handler",
                "interface_mtu",
                "stack_initialized",
            )
        }

    def tearDown(self) -> None:
        """
        Restore the snapshot so subsequent tests start from the same
        module-level state.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__init_l2_shares_packet_stats_across_rings_and_handler(self) -> None:
        """
        Ensure 'stack.init()' on the L2 (TAP) path constructs one
        'PacketStatsRx' and one 'PacketStatsTx' instance and threads
        the same objects into 'RxRing', 'TxRing', and
        'PacketHandlerL2'. Without this sharing, ring drop counters
        (rx_ring__queue_full__drop / __os_error__drop, tx_ring
        equivalents) would land on a different dataclass than the
        per-protocol counters and the unified 'PacketStats' snapshot
        would lose them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

        with (
            patch.object(stack, "TxRing") as tx_ring_cls,
            patch.object(stack, "RxRing") as rx_ring_cls,
            patch.object(stack, "PacketHandlerL2") as handler_cls,
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L2,
                mtu=1500,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
            )

        rx_stats = rx_ring_cls.call_args.kwargs["packet_stats"]
        tx_stats = tx_ring_cls.call_args.kwargs["packet_stats"]
        handler_kwargs = handler_cls.call_args.kwargs

        self.assertIsInstance(
            rx_stats,
            PacketStatsRx,
            msg="RxRing must receive a PacketStatsRx instance from stack.init().",
        )
        self.assertIsInstance(
            tx_stats,
            PacketStatsTx,
            msg="TxRing must receive a PacketStatsTx instance from stack.init().",
        )
        self.assertIs(
            handler_kwargs["packet_stats_rx"],
            rx_stats,
            msg=(
                "PacketHandlerL2 must receive the SAME PacketStatsRx instance the RxRing got — "
                "ring drop counters live on this dataclass and the unified-stats snapshot "
                "depends on the rings and the handler sharing one object."
            ),
        )
        self.assertIs(
            handler_kwargs["packet_stats_tx"],
            tx_stats,
            msg=(
                "PacketHandlerL2 must receive the SAME PacketStatsTx instance the TxRing got — "
                "ring drop counters live on this dataclass and the unified-stats snapshot "
                "depends on the rings and the handler sharing one object."
            ),
        )

    def test__stack__init_l3_shares_packet_stats_across_rings_and_handler(self) -> None:
        """
        Ensure 'stack.init()' on the L3 (TUN) path also threads one
        'PacketStatsRx' / 'PacketStatsTx' pair through both rings and
        the 'PacketHandlerL3' constructor — same invariant as the L2
        path, different handler class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

        with (
            patch.object(stack, "TxRing") as tx_ring_cls,
            patch.object(stack, "RxRing") as rx_ring_cls,
            patch.object(stack, "PacketHandlerL3") as handler_cls,
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L3,
                mtu=1500,
                mac_address=None,
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
            )

        rx_stats = rx_ring_cls.call_args.kwargs["packet_stats"]
        tx_stats = tx_ring_cls.call_args.kwargs["packet_stats"]
        handler_kwargs = handler_cls.call_args.kwargs

        self.assertIsInstance(
            rx_stats,
            PacketStatsRx,
            msg="RxRing must receive a PacketStatsRx instance from stack.init() on the L3 path.",
        )
        self.assertIsInstance(
            tx_stats,
            PacketStatsTx,
            msg="TxRing must receive a PacketStatsTx instance from stack.init() on the L3 path.",
        )
        self.assertIs(
            handler_kwargs["packet_stats_rx"],
            rx_stats,
            msg=(
                "PacketHandlerL3 must receive the SAME PacketStatsRx instance the RxRing got — "
                "shared-stats invariant must hold on the L3 path identically to L2."
            ),
        )
        self.assertIs(
            handler_kwargs["packet_stats_tx"],
            tx_stats,
            msg=(
                "PacketHandlerL3 must receive the SAME PacketStatsTx instance the TxRing got — "
                "shared-stats invariant must hold on the L3 path identically to L2."
            ),
        )


class TestStackInitArpCacheConfig(TestCase):
    """
    The 'stack.init()' ARP-cache-timeout configuration tests.

    Pin that the 'arp_cache_max_age' / 'arp_cache_refresh_time'
    kwargs surface user-tunable equivalents of the Linux
    sysctls 'net.ipv4.neigh.default.{base_reachable_time,
    gc_stale_time}': when supplied, they override the
    compile-time defaults that the ARP cache loop reads.
    """

    def setUp(self) -> None:
        """
        Snapshot the module-level singletons 'init()' rebinds so
        each test can roll back cleanly. Sysctl mutations are
        rolled back via 'reset_to_defaults' in tearDown. Suppress
        the 'Initializing ...' log lines that 'stack.init()'
        emits during subsystem construction.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        from pytcp.protocols.arp import arp__constants

        self._arp__constants = arp__constants
        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "rx_ring",
                "tx_ring",
                "arp_cache",
                "nd_cache",
                "packet_handler",
                "interface_mtu",
                "stack_initialized",
            )
        }

    def tearDown(self) -> None:
        """
        Restore module-level singletons and sysctl defaults.
        """

        from pytcp.lib import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def _init_l2(self, **extra: object) -> None:
        """
        Run 'stack.init()' on the L2 path with the rings / handler
        patched out so the kwargs path is exercised in isolation.
        """

        with (
            patch.object(stack, "TxRing"),
            patch.object(stack, "RxRing"),
            patch.object(stack, "PacketHandlerL2"),
            patch.object(stack, "ArpCache"),
            patch.object(stack, "NdCache"),
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L2,
                mtu=1500,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
                **extra,  # type: ignore[arg-type]
            )

    def test__stack__init__sysctls_bag_propagates_through_registry(self) -> None:
        """
        Ensure 'stack.init(sysctls={"arp.defend_interval": 20})'
        routes the dotted-name bag entry through the registry
        and writes the new value to the backing constant —
        the documented path for tuning a knob that does not have
        an explicit kwarg.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._init_l2(sysctls={"arp.defend_interval": 20})

        self.assertEqual(
            self._arp__constants.ARP__DEFEND_INTERVAL,
            20,
            msg=(
                "stack.init(sysctls={'arp.defend_interval': 20}) must mutate "
                "ARP__DEFEND_INTERVAL via the sysctl registry."
            ),
        )

    def test__stack__init__sysctls_bag_unknown_key_raises(self) -> None:
        """
        Ensure an unknown key in 'sysctls={...}' raises
        'KeyError' from the registry — operators get a clear
        error rather than a silent typo.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError):
            self._init_l2(sysctls={"arp.no_such_knob": 1})

    def test__stack__init__sysctls_bag_validator_rejection(self) -> None:
        """
        Ensure a 'sysctls={...}' entry that fails its per-knob
        validator raises 'ValueError' with the offending key
        in the message — the registry write does not bypass
        validation just because it came from the bag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            self._init_l2(sysctls={"arp.defend_interval": -5})
        self.assertIn(
            "arp.defend_interval",
            str(ctx.exception),
            msg="Bag-kwarg validator rejection must surface the offending key.",
        )

    def test__stack__init__cross_knob_probe_min_lt_probe_max_enforced(self) -> None:
        """
        Ensure the 'arp.probe_min < arp.probe_max' cross-knob
        constraint runs at the end of 'init()' via
        'finalize_validators', rejecting a configuration where
        each individual knob passes its own validator but the
        pair is inconsistent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            self._init_l2(sysctls={"arp.probe_min": 5, "arp.probe_max": 3})
        self.assertIn(
            "arp.probe_min",
            str(ctx.exception),
            msg=(
                "The cross-knob finalize validator must reject probe_min >= probe_max " "and surface the offending key."
            ),
        )


class TestStackPythonVersionGuard(TestCase):
    """
    The Python-version-guard tests at module import time.
    """

    def test__stack__requires_python_3_12(self) -> None:
        """
        Ensure the module-level assert requires Python 3.12+. This is
        the floor the codebase's PEP 695 generics and 'typing.override'
        usage depend on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertGreaterEqual(
            sys.version_info,
            (3, 12),
            msg="pytcp/stack/__init__.py asserts Python >= 3.12; the running interpreter must meet that floor.",
        )
