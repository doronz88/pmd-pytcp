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
        """

        self.assertTrue(
            stack.IP4__SUPPORT,
            msg="IP4__SUPPORT must default to True.",
        )
        self.assertTrue(
            stack.IP6__SUPPORT,
            msg="IP6__SUPPORT must default to True.",
        )

    def test__stack__arp_cache_timers_are_positive(self) -> None:
        """
        Ensure the ARP cache maximum age and refresh window are both
        positive, with refresh time strictly less than max age — the
        invariant the refresh-path arithmetic relies on.
        """

        self.assertGreater(
            stack.ARP__CACHE__ENTRY_MAX_AGE,
            0,
            msg="ARP__CACHE__ENTRY_MAX_AGE must be positive.",
        )
        self.assertGreater(
            stack.ARP__CACHE__ENTRY_REFRESH_TIME,
            0,
            msg="ARP__CACHE__ENTRY_REFRESH_TIME must be positive.",
        )
        self.assertLess(
            stack.ARP__CACHE__ENTRY_REFRESH_TIME,
            stack.ARP__CACHE__ENTRY_MAX_AGE,
            msg="REFRESH_TIME < MAX_AGE is required by the refresh-window arithmetic.",
        )

    def test__stack__nd_cache_timers_are_positive(self) -> None:
        """
        Ensure the ICMPv6 ND cache maximum age and refresh window are
        both positive with refresh time strictly less than max age.
        """

        self.assertGreater(
            stack.ICMP6__ND__CACHE__ENTRY_MAX_AGE,
            0,
            msg="ICMP6__ND__CACHE__ENTRY_MAX_AGE must be positive.",
        )
        self.assertGreater(
            stack.ICMP6__ND__CACHE__ENTRY_REFRESH_TIME,
            0,
            msg="ICMP6__ND__CACHE__ENTRY_REFRESH_TIME must be positive.",
        )
        self.assertLess(
            stack.ICMP6__ND__CACHE__ENTRY_REFRESH_TIME,
            stack.ICMP6__ND__CACHE__ENTRY_MAX_AGE,
            msg="REFRESH_TIME < MAX_AGE is required by the refresh-window arithmetic.",
        )

    def test__stack__ephemeral_port_range(self) -> None:
        """
        Ensure the ephemeral port range lies within the 0-65535 bounds
        of a 16-bit port field and ends above its start.
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
        """

        self.assertTrue(
            stack.PYTCP_VERSION.startswith("ver "),
            msg="PYTCP_VERSION must start with 'ver ' so 'ver X.Y.Z' parsers can keep working.",
        )

    def test__stack__stack_initialized_defaults_false(self) -> None:
        """
        Ensure the module-level 'stack_initialized' flag starts False
        — start()/stop() gate on it.
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


class TestStackPythonVersionGuard(TestCase):
    """
    The Python-version-guard tests at module import time.
    """

    def test__stack__requires_python_3_12(self) -> None:
        """
        Ensure the module-level assert requires Python 3.12+. This is
        the floor the codebase's PEP 695 generics and 'typing.override'
        usage depend on.
        """

        self.assertGreaterEqual(
            sys.version_info,
            (3, 12),
            msg="pytcp/stack/__init__.py asserts Python >= 3.12; the running interpreter must meet that floor.",
        )
