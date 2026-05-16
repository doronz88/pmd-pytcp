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
This module contains base testcase for PyTCP Packet Handler tests.

pytcp/tests/lib/network_testcase.py

ver 3.0.5
"""

from typing import cast
from unittest import TestCase
from unittest.mock import create_autospec, patch

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr, MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp import stack
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.protocols.ip6 import ip6__constants as ip6__constants_module
from pytcp.runtime.packet_handler import PacketHandlerL2, packet_handler__ip6_frag__tx
from pytcp.runtime.tx_ring import TxRing

# # #  IPv4
#
#           .7  10.0.1.0/24  .1          .1  10.0.2.0/24  .50
#   [STACK] ------------------- [ROUTER] -------------------- [HOST C]
#             |
#             |   .91
#             |------ [HOST A] (working arp cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working arp cache resolution)
#

# # #  IPv6
#
#        .7  2001:db8:0:1::/64  .1    .1  2001:db8:0:2::/64  .50
#        .7  fe80::/64          .1    .1  fe80::             .50
#   [STACK] ------------------- [ROUTER A] -------------------- [HOST C]
#             |
#             |    .2
#             |------ [ROUTER B] (not working nd cache resolution)
#             |
#             |   .91
#             |------ [HOST A] (working nd cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working nd cache resolution)
#

# Set the PyTCP stack candidate addressing for DAD tests.
STACK__IP4_HOST__CANDIDATE = Ip4IfAddr("10.0.1.5/24")
STACK__IP6_HOST__CANDIDATE = Ip6IfAddr("2001:db8:0:1::5/64")

# Set the PyTCP stack addressing.
STACK__MAC_ADDRESS = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK__IP4_HOST.gateway = STACK__IP4_GATEWAY
STACK__IP4_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")
STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")
STACK__IP6_GATEWAY = Ip6Address("fe80::1")
STACK__IP6_HOST.gateway = STACK__IP6_GATEWAY
STACK__IP6_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

# Set the test device's addressing.
HOST_A__MAC_ADDRESS = MacAddress("02:00:00:00:00:91")
HOST_A__IP4_ADDRESS = Ip4Address("10.0.1.91")
HOST_A__IP6_ADDRESS = Ip6Address("2001:db8:0:1::91")
HOST_B__IP4_ADDRESS = Ip4Address("10.0.1.92")
HOST_B__IP6_ADDRESS = Ip6Address("2001:db8:0:1::92")
HOST_C__IP4_ADDRESS = Ip4Address("10.0.2.50")
HOST_C__IP6_ADDRESS = Ip6Address("2001:db8:0:2::50")
ROUTER_B__IP6_ADDRESS = Ip6Address("fe80::2")

# Set common addresses.
MAC__UNSPECIFIED = MacAddress("00:00:00:00:00:00")
MAC__BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")
IP4__UNSPECIFIED = Ip4Address("0.0.0.0")
IP4__BROADCAST__LIMITED = Ip4Address("255.255.255.255")
IP4__MULTICAST__ALL_NODES = Ip4Address("224.0.0.1")
IP6__UNSPECIFIED = Ip6Address("::")
IP6__MULTICAST__ALL_NODES = Ip6Address("ff02::1")
IP6__MULTICAST__ALL_ROUTERS = Ip6Address("ff02::2")
IP6__MULTICAST__MLD2_ROUTERS = Ip6Address("ff02::16")

# Pre-populated address tables consumed by the mocked 'find_entry'
# dispatchers. Unknown lookups raise to preserve the strict-mock
# semantics the original testslide harness enforced.
_ARP_CACHE__FIND_ENTRY__TABLE: dict[Ip4Address, MacAddress | None] = {
    HOST_A__IP4_ADDRESS: HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS: None,
    STACK__IP4_GATEWAY: STACK__IP4_GATEWAY_MAC_ADDRESS,
}
_ND_CACHE__FIND_ENTRY__TABLE: dict[Ip6Address, MacAddress | None] = {
    HOST_A__IP6_ADDRESS: HOST_A__MAC_ADDRESS,
    HOST_B__IP6_ADDRESS: None,
    STACK__IP6_GATEWAY: STACK__IP6_GATEWAY_MAC_ADDRESS,
    ROUTER_B__IP6_ADDRESS: None,
}

# Stack globals that 'NetworkTestCase.setUp' patches and
# 'NetworkTestCase.tearDown' restores. Stored as a list so the
# snapshot is taken in a stable order.
_STACK__PATCHED_ATTRS: tuple[str, ...] = (
    "LOG__CHANNEL",
    "IP6__SUPPORT",
    "IP4__SUPPORT",
    "IP4__ACCEPT_SOURCE_ROUTE",
    "INTERFACE__TAP__MTU",
    "INTERFACE__TUN__MTU",
    "UDP__ECHO_NATIVE",
    "link_local",
    "stack_running",
)


class NetworkTestCase(TestCase):
    """
    Base class for all unit tests that require mock network.
    """

    _frames_tx: list[bytes]

    _packet_handler: PacketHandlerL2

    _stack__attr_snapshot: dict[str, object]
    _ip6_flow_label_generation_prior: int

    def setUp(self) -> None:
        """
        Prepare the test case.
        """

        self.maxDiff = None

        super().setUp()

        # Snapshot the stack globals we are about to mutate so
        # 'tearDown' can restore them and avoid leaking test-only
        # values (e.g. an empty 'LOG__CHANNEL') into unrelated tests.
        self._stack__attr_snapshot = {name: stack.__dict__[name] for name in _STACK__PATCHED_ATTRS}

        # Snapshot the RFC 6437 flow-label generation toggle so
        # 'tearDown' restores production behaviour (default 1 —
        # auto-emit). The harness pins it to 0 for the duration
        # of each test so existing golden-frame fixtures (which
        # encode flow=0 in their IPv6 header word) continue to
        # match without per-fixture regeneration. A dedicated
        # integration test
        # ('test__ip6__rfc6437_flow_label.py') flips this back
        # to 1 inside its own setUp to exercise the auto-wire.
        self._ip6_flow_label_generation_prior = ip6__constants_module.IP6__FLOW_LABEL_GENERATION
        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = 0

        # Patch the PyTCP stack settings to values suitable for unit tests.
        stack.__dict__.update(
            {
                "LOG__CHANNEL": set(),
                "IP6__SUPPORT": True,
                "IP4__SUPPORT": True,
                "INTERFACE__TAP__MTU": 1500,
                "INTERFACE__TUN__MTU": 1500,
                "UDP__ECHO_NATIVE": True,
            }
        )

        # Create mock Packet Handler object and prepare it for tests.

        def _mock_enqueue(packet_tx: EthernetAssembler) -> None:
            """
            Mock 'TxRing.enqueue()' method to record the assembled frames.
            """

            buffers: list[Buffer] = []
            packet_tx.assemble(buffers)
            frame_tx = b"".join(buffers)

            self.assertEqual(
                frame_tx,
                bytes(packet_tx),
                msg="TxRing mock: 'assemble()' output must equal 'bytes(packet_tx)'.",
            )

            self._frames_tx.append(frame_tx)

        # Mock the TxRing so we can record the assembled frames.
        mock_TxRing = create_autospec(TxRing, spec_set=True)
        mock_TxRing.enqueue.side_effect = _mock_enqueue

        # Mock the ArpCache so we can get predictable responses.
        def _mock_arp_find_entry(*, ip4_address: Ip4Address) -> MacAddress | None:
            """
            Mock 'ArpCache.find_entry()' — dispatch on 'ip4_address' via
            the pre-populated table; raise on unknown keys.
            """

            if ip4_address not in _ARP_CACHE__FIND_ENTRY__TABLE:
                raise AssertionError(f"Unexpected 'ArpCache.find_entry' call. Got: {ip4_address=}")

            return _ARP_CACHE__FIND_ENTRY__TABLE[ip4_address]

        mock_ArpCache = create_autospec(ArpCache, spec_set=True)
        mock_ArpCache.find_entry.side_effect = _mock_arp_find_entry
        mock_ArpCache.add_entry.return_value = None

        # Mock the NdCache so we can get predictable responses.
        def _mock_nd_find_entry(*, ip6_address: Ip6Address) -> MacAddress | None:
            """
            Mock 'NdCache.find_entry()' — dispatch on 'ip6_address' via
            the pre-populated table; raise on unknown keys.
            """

            if ip6_address not in _ND_CACHE__FIND_ENTRY__TABLE:
                raise AssertionError(f"Unexpected 'NdCache.find_entry' call. Got: {ip6_address=}")

            return _ND_CACHE__FIND_ENTRY__TABLE[ip6_address]

        mock_NdCache = create_autospec(NdCache, spec_set=True)
        mock_NdCache.find_entry.side_effect = _mock_nd_find_entry
        mock_NdCache.add_entry.return_value = None

        # Prepare PacketHandler object to be used with the tests.
        self._packet_handler = PacketHandlerL2(
            mac_address=STACK__MAC_ADDRESS,
            interface_mtu=1500,
        )

        self._packet_handler._mac_multicast = [STACK__IP6_HOST.address.solicited_node_multicast.multicast_mac]
        self._packet_handler._ip4_ifaddr = [STACK__IP4_HOST]
        self._packet_handler._ip4_multicast = [IP4__MULTICAST__ALL_NODES]
        self._packet_handler._ip6_ifaddr = [STACK__IP6_HOST]
        self._packet_handler._ip6_multicast = [
            IP6__MULTICAST__ALL_NODES,
            STACK__IP6_HOST.address.solicited_node_multicast,
        ]
        self._packet_handler._ip4_ifaddr_candidate = [STACK__IP4_HOST__CANDIDATE]
        self._packet_handler._ip6_ifaddr_candidate = [STACK__IP6_HOST__CANDIDATE]

        # Initialize the list holding the frames "sent" by mock TxRing.
        self._frames_tx = []

        stack.mock__init(
            mock__tx_ring=cast(TxRing, mock_TxRing),
            mock__arp_cache=cast(ArpCache, mock_ArpCache),
            mock__nd_cache=cast(NdCache, mock_NdCache),
            mock__packet_handler=self._packet_handler,
        )

        # Override the production RFC 7739 random Fragment ID
        # generator with a deterministic counter so fixture-
        # based fragmentation tests can assert specific
        # Identification field values. Each call returns 1, 2,
        # 3, ..., matching the legacy monotonic-counter
        # behaviour the existing fixtures were authored
        # against.
        self._frag_id_counter: list[int] = [0]

        def _det_frag_id() -> int:
            self._frag_id_counter[0] += 1
            return self._frag_id_counter[0]

        self._frag_id_patch = patch.object(
            packet_handler__ip6_frag__tx,
            "_generate_ip6_frag_id",
            side_effect=_det_frag_id,
        )
        self._frag_id_patch.start()

    def tearDown(self) -> None:
        """
        Restore the stack globals patched in 'setUp' so test-only
        values do not leak into unrelated tests run in the same
        process.
        """

        self._frag_id_patch.stop()

        stack.__dict__.update(self._stack__attr_snapshot)

        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = self._ip6_flow_label_generation_prior

        super().tearDown()
