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
This module contains unit tests for the 'PacketHandlerEthernetTx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ethernet__tx.py

ver 3.0.4
"""


from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import (
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    MacAddress,
)
from net_proto import (
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
    RawAssembler,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__ethernet__tx import (
    PacketHandlerEthernetTx,
)

# Silence log output emitted by the handlers during tests.
stack.LOG__CHANNEL = set()


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4Host("10.0.1.7/24")
STACK__IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK__IP4_HOST.gateway = STACK__IP4_GATEWAY
STACK__IP6_HOST = Ip6Host("2001:db8:0:1::7/64")
STACK__IP6_GATEWAY = Ip6Address("fe80::1")
STACK__IP6_HOST.gateway = STACK__IP6_GATEWAY

STACK__IP4_HOST__NO_GW = Ip4Host("192.168.99.7/24")
STACK__IP6_HOST__NO_GW = Ip6Host("2001:db8:0:99::7/64")
STACK__IP6_HOST__NO_GW.gateway = None

GATEWAY_MAC = MacAddress("02:00:00:00:00:01")
HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
HOST_B__IP4 = Ip4Address("10.0.1.92")  # ARP miss
HOST_B__IP6 = Ip6Address("2001:db8:0:1::92")  # ND miss
HOST_C__IP4 = Ip4Address("10.0.2.50")  # external-net
HOST_C__IP6 = Ip6Address("2001:db8:0:2::50")  # external-net


class _StubHandler(PacketHandlerEthernetTx):
    """
    Minimal concrete subclass of 'PacketHandlerEthernetTx' for testing.
    """

    def __init__(self) -> None:
        """
        Initialize the stub handler with the bare attributes the mixin reads.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip4_host = [STACK__IP4_HOST]
        self._ip6_host = [STACK__IP6_HOST]


def _build_ip4_assembler(*, src: Ip4Address, dst: Ip4Address) -> Ip4Assembler:
    """
    Build a minimal 'Ip4Assembler' fixture with the given addresses.
    """

    return Ip4Assembler(ip4__src=src, ip4__dst=dst, ip4__payload=RawAssembler())


def _build_ip6_assembler(*, src: Ip6Address, dst: Ip6Address) -> Ip6Assembler:
    """
    Build a minimal 'Ip6Assembler' fixture with the given addresses.
    """

    return Ip6Assembler(ip6__src=src, ip6__dst=dst, ip6__payload=RawAssembler())


class _EthernetTxTestBase(TestCase):
    """
    Common setUp/tearDown for the Ethernet TX unit tests.
    """

    def setUp(self) -> None:
        """
        Build the stub handler and patch stack singletons with MagicMocks.
        """

        self._handler = _StubHandler()

        self._tx_ring_patch = patch.object(stack, "tx_ring", MagicMock())
        self._arp_cache_patch = patch.object(stack, "arp_cache", MagicMock())
        self._nd_cache_patch = patch.object(stack, "nd_cache", MagicMock())

        self._tx_ring = self._tx_ring_patch.start()
        self._arp_cache = self._arp_cache_patch.start()
        self._nd_cache = self._nd_cache_patch.start()

        # Default cache responses: miss for everyone.
        self._arp_cache.find_entry.return_value = None
        self._nd_cache.find_entry.return_value = None

    def tearDown(self) -> None:
        """
        Restore the patched stack singletons.
        """

        self._tx_ring_patch.stop()
        self._arp_cache_patch.stop()
        self._nd_cache_patch.stop()


class TestPacketHandlerEthernetTxDirect(_EthernetTxTestBase):
    """
    The direct-path tests (dst already specified, no IP lookup needed).
    """

    def test__stack__packet_handler__ethernet__tx__specified_dst_sends(self) -> None:
        """
        Ensure a specified dst MAC is sent directly and neither the ARP
        cache nor the ND cache is consulted.
        """

        status = self._handler._phtx_ethernet(
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Handler must return PASSED__ETHERNET__TO_TX_RING when dst is already specified.",
        )
        self._tx_ring.enqueue.assert_called_once()
        self._arp_cache.find_entry.assert_not_called()
        self._nd_cache.find_entry.assert_not_called()
        self.assertEqual(
            self._handler._packet_stats_tx.ethernet__dst_spec__send,
            1,
            msg="ethernet__dst_spec__send must be incremented on the direct-send path.",
        )

    def test__stack__packet_handler__ethernet__tx__fills_unspecified_src(self) -> None:
        """
        Ensure an unspecified src MAC is filled with the stack unicast
        MAC and 'ethernet__src_unspec__fill' is incremented.
        """

        self._handler._phtx_ethernet(
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.src,
            STACK__MAC_UNICAST,
            msg="The enqueued packet's src MAC must be set to the stack unicast MAC.",
        )
        self.assertEqual(
            self._handler._packet_stats_tx.ethernet__src_unspec__fill,
            1,
            msg="ethernet__src_unspec__fill must be incremented when src is unspecified.",
        )

    def test__stack__packet_handler__ethernet__tx__honors_specified_src(self) -> None:
        """
        Ensure a specified src MAC is not overwritten and
        'ethernet__src_spec' is incremented.
        """

        custom_src = MacAddress("02:00:00:00:00:aa")
        self._handler._phtx_ethernet(
            ethernet__src=custom_src,
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.src,
            custom_src,
            msg="The enqueued packet's src MAC must equal the supplied src.",
        )
        self.assertEqual(
            self._handler._packet_stats_tx.ethernet__src_spec,
            1,
            msg="ethernet__src_spec must be incremented when a src MAC is supplied.",
        )

    def test__stack__packet_handler__ethernet__tx__raw_payload_unknown_proto_drops(self) -> None:
        """
        Ensure a RawAssembler payload (neither IPv4 nor IPv6) with an
        unspecified dst MAC is dropped because no resolution path applies.
        """

        status = self._handler._phtx_ethernet(ethernet__payload=RawAssembler())

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL,
            msg="Handler must return DROPED__ETHERNET__DST_RESOLUTION_FAIL for Raw payload with unspecified dst.",
        )
        self._tx_ring.enqueue.assert_not_called()
        self.assertEqual(
            self._handler._packet_stats_tx.ethernet__dst_unspec__drop,
            1,
            msg="ethernet__dst_unspec__drop must be incremented on the fallthrough drop.",
        )


class TestPacketHandlerEthernetTxIp6Lookup(_EthernetTxTestBase):
    """
    The IPv6-lookup path tests.
    """

    def test__stack__packet_handler__ethernet__tx__ip6_multicast_dst_uses_multicast_mac(self) -> None:
        """
        Ensure an IPv6 multicast destination resolves to its derived
        multicast MAC without consulting the ND cache.
        """

        ip6 = _build_ip6_assembler(
            src=STACK__IP6_HOST.address,
            dst=Ip6Address("ff02::1"),
        )

        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 multicast must resolve to multicast MAC and be enqueued.",
        )
        self._nd_cache.find_entry.assert_not_called()
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            Ip6Address("ff02::1").multicast_mac,
            msg="Destination MAC must match the IPv6 multicast MAC derivation.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_localnet_nd_cache_hit(self) -> None:
        """
        Ensure an IPv6 on-link destination resolves via the ND cache.
        """

        self._nd_cache.find_entry.return_value = HOST_A__MAC

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_A__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 localnet ND cache hit must enqueue with the cached MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            HOST_A__MAC,
            msg="Destination MAC must be the one returned by the ND cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_localnet_nd_cache_miss(self) -> None:
        """
        Ensure an IPv6 on-link destination is dropped when the ND cache
        has no matching entry.
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_B__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_ND_CACHE_MISS,
            msg="IPv6 localnet ND cache miss must drop with DST_ND_CACHE_MISS.",
        )
        self._tx_ring.enqueue.assert_not_called()

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_uses_gateway_mac(self) -> None:
        """
        Ensure an IPv6 off-link destination resolves via the gateway MAC
        from the ND cache.
        """

        self._nd_cache.find_entry.return_value = GATEWAY_MAC

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_C__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 extnet gateway ND cache hit must enqueue with the gateway MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            GATEWAY_MAC,
            msg="Destination MAC must be the gateway MAC returned by the ND cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_no_gateway(self) -> None:
        """
        Ensure an IPv6 off-link destination is dropped when the source
        host has no default gateway configured.
        """

        self._handler._ip6_host = [STACK__IP6_HOST__NO_GW]

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST__NO_GW.address, dst=Ip6Address("2001:db8:0:ffff::1"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP6,
            msg="IPv6 extnet without a gateway must drop with DST_NO_GATEWAY_IP6.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_gateway_nd_miss(self) -> None:
        """
        Ensure an IPv6 off-link destination is dropped when the gateway
        is configured but the ND cache has no entry for it.
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_C__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS,
            msg="IPv6 extnet with a gateway but ND miss must drop with DST_GATEWAY_ND_CACHE_MISS.",
        )


class TestPacketHandlerEthernetTxIp4Lookup(_EthernetTxTestBase):
    """
    The IPv4-lookup path tests.
    """

    def test__stack__packet_handler__ethernet__tx__ip4_multicast_dst(self) -> None:
        """
        Ensure an IPv4 multicast destination resolves to its derived
        multicast MAC.
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=Ip4Address("224.0.0.1"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 multicast must resolve to multicast MAC and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            Ip4Address("224.0.0.1").multicast_mac,
            msg="Destination MAC must match the IPv4 multicast MAC derivation.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_limited_broadcast(self) -> None:
        """
        Ensure an IPv4 255.255.255.255 destination resolves to the
        all-ones broadcast MAC.
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=Ip4Address("255.255.255.255"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 limited broadcast must resolve to FF:FF:FF:FF:FF:FF and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            MacAddress(0xFFFFFFFFFFFF),
            msg="Destination MAC must be FF:FF:FF:FF:FF:FF for limited broadcast.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_network_broadcast(self) -> None:
        """
        Ensure an IPv4 destination equal to the source host's network
        broadcast resolves to the all-ones broadcast MAC.
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=STACK__IP4_HOST.network.broadcast)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 network broadcast must resolve to FF:FF:FF:FF:FF:FF and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            MacAddress(0xFFFFFFFFFFFF),
            msg="Destination MAC must be FF:FF:FF:FF:FF:FF for network broadcast.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_localnet_arp_hit(self) -> None:
        """
        Ensure an IPv4 on-link destination resolves via the ARP cache.
        """

        self._arp_cache.find_entry.return_value = HOST_A__MAC

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_A__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 localnet ARP cache hit must enqueue with the cached MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            HOST_A__MAC,
            msg="Destination MAC must match the ARP cache response.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_localnet_arp_miss(self) -> None:
        """
        Ensure an IPv4 on-link destination is dropped when the ARP cache
        has no matching entry.
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_B__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_ARP_CACHE_MISS,
            msg="IPv4 localnet ARP cache miss must drop with DST_ARP_CACHE_MISS.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_uses_gateway_mac(self) -> None:
        """
        Ensure an IPv4 off-link destination resolves via the gateway MAC
        from the ARP cache.
        """

        self._arp_cache.find_entry.return_value = GATEWAY_MAC

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_C__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 extnet gateway ARP cache hit must enqueue with the gateway MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            GATEWAY_MAC,
            msg="Destination MAC must be the gateway MAC returned by the ARP cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_no_gateway(self) -> None:
        """
        Ensure an IPv4 off-link destination is dropped when the source
        host has no default gateway configured.
        """

        self._handler._ip4_host = [STACK__IP4_HOST__NO_GW]

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST__NO_GW.address, dst=Ip4Address("10.10.10.10"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP4,
            msg="IPv4 extnet without a gateway must drop with DST_NO_GATEWAY_IP4.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_gateway_arp_miss(self) -> None:
        """
        Ensure an IPv4 off-link destination is dropped when the gateway
        is configured but the ARP cache has no entry for it.
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_C__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            msg="IPv4 extnet with a gateway but ARP miss must drop with DST_GATEWAY_ARP_CACHE_MISS.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_frag_payload_routes_like_ip4(self) -> None:
        """
        Ensure an 'Ip4FragAssembler' payload goes through the same IPv4
        routing logic as a plain 'Ip4Assembler' — the handler treats
        both the same way.
        """

        self._arp_cache.find_entry.return_value = HOST_A__MAC

        frag = Ip4FragAssembler(ip4_frag__src=STACK__IP4_HOST.address, ip4_frag__dst=HOST_A__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=frag)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Ip4FragAssembler payload must route via the IPv4 ARP path.",
        )
