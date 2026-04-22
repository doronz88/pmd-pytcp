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
This module contains unit tests for the 'PacketHandlerArpTx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__tx.py

ver 3.0.4
"""


from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__arp__tx import (
    PacketHandlerArpTx,
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
STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
MAC__BROADCAST = MacAddress(0xFFFFFFFFFFFF)
MAC__UNSPEC = MacAddress()
IP4__UNSPEC = Ip4Address()


class _StubHandler(PacketHandlerArpTx):
    """
    Minimal concrete subclass of 'PacketHandlerArpTx' for testing.
    """

    def __init__(self, *, ip4_support: bool = True, ip4_unicast: list[Ip4Address] | None = None) -> None:
        """
        Initialize the stub handler and record every _phtx_ethernet call.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip4_support = ip4_support
        self._ip4_unicast_list = list(ip4_unicast) if ip4_unicast is not None else [STACK__IP4_ADDRESS]

        # Spy: record every call to _phtx_ethernet.
        self.ethernet_tx_calls: list[dict[str, object]] = []
        self.ethernet_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Return the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast_list

    def _phtx_ethernet(self, **kwargs: object) -> TxStatus:
        """
        Record the call and return the configured TxStatus.
        """

        self.ethernet_tx_calls.append(kwargs)
        return self.ethernet_tx_status


class TestPacketHandlerArpTx(TestCase):
    """
    The 'PacketHandlerArpTx._phtx_arp' behaviour tests.
    """

    def test__stack__packet_handler__arp__tx__ip4_disabled_drops(self) -> None:
        """
        Ensure the handler drops ARP packets when IPv4 is disabled and
        does not invoke the Ethernet TX path.
        """

        handler = _StubHandler(ip4_support=False)

        status = handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=MAC__UNSPEC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            status,
            TxStatus.DROPED__ARP__NO_PROTOCOL_SUPPORT,
            msg="ARP TX with IPv4 disabled must return DROPED__ARP__NO_PROTOCOL_SUPPORT.",
        )
        self.assertEqual(
            handler._packet_stats_tx.arp__no_proto_support__drop,
            1,
            msg="arp__no_proto_support__drop must be incremented on the disabled-IPv4 path.",
        )
        self.assertEqual(
            handler.ethernet_tx_calls,
            [],
            msg="IPv4-disabled drop must not hit the Ethernet TX layer.",
        )

    def test__stack__packet_handler__arp__tx__request_forwarded_to_ethernet(self) -> None:
        """
        Ensure an ARP request is counted, assembled, and forwarded to
        the Ethernet TX layer with the assembled ARP payload.
        """

        handler = _StubHandler()

        status = handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=MAC__UNSPEC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="ARP TX must return the TxStatus returned by the Ethernet TX layer.",
        )
        self.assertEqual(
            handler._packet_stats_tx.arp__pre_assemble,
            1,
            msg="arp__pre_assemble must be incremented on the TX entry.",
        )
        self.assertEqual(
            handler._packet_stats_tx.arp__op_request__send,
            1,
            msg="arp__op_request__send must be incremented on REQUEST.",
        )
        self.assertEqual(
            len(handler.ethernet_tx_calls),
            1,
            msg="Exactly one _phtx_ethernet call must have been issued.",
        )
        call = handler.ethernet_tx_calls[0]
        self.assertEqual(
            call["ethernet__src"],
            STACK__MAC_UNICAST,
            msg="Ethernet src must be passed through verbatim.",
        )
        self.assertEqual(
            call["ethernet__dst"],
            MAC__BROADCAST,
            msg="Ethernet dst must be passed through verbatim.",
        )
        self.assertIsInstance(
            call["ethernet__payload"],
            ArpAssembler,
            msg="Ethernet payload must be an ArpAssembler instance.",
        )

    def test__stack__packet_handler__arp__tx__reply_uses_reply_stat(self) -> None:
        """
        Ensure an ARP reply increments 'arp__op_reply__send' and
        forwards the assembled packet.
        """

        handler = _StubHandler()

        handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=HOST_A__MAC,
            arp__oper=ArpOperation.REPLY,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=HOST_A__MAC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            handler._packet_stats_tx.arp__op_reply__send,
            1,
            msg="arp__op_reply__send must be incremented on REPLY.",
        )
        self.assertEqual(
            handler._packet_stats_tx.arp__op_request__send,
            0,
            msg="arp__op_request__send must NOT be incremented on REPLY.",
        )


class TestPacketHandlerArpTxConvenienceHelpers(TestCase):
    """
    The convenience helper (_send_arp_announcement / _send_gratuitous_arp /
    _send_arp_probe / _send_arp_reply / send_arp_request) tests.
    """

    def setUp(self) -> None:
        """
        Build a fresh stub handler for each case.
        """

        self._handler = _StubHandler()

    def _last_call(self) -> dict[str, object]:
        """
        Return the kwargs passed to the single expected _phtx_ethernet
        call from each helper.
        """

        self.assertEqual(
            len(self._handler.ethernet_tx_calls),
            1,
            msg="Exactly one _phtx_ethernet call is expected from each ARP helper.",
        )
        return self._handler.ethernet_tx_calls[0]

    def test__stack__packet_handler__arp__tx__announcement_uses_request_with_spa_tpa_self(self) -> None:
        """
        Ensure '_send_arp_announcement' sends a REQUEST with spa == tpa
        == self IP, broadcast dst, stack src.
        """

        self._handler._send_arp_announcement(ip4_unicast=STACK__IP4_ADDRESS)

        call = self._last_call()
        self.assertEqual(call["ethernet__src"], STACK__MAC_UNICAST)
        self.assertEqual(call["ethernet__dst"], MAC__BROADCAST)
        payload = call["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.oper, ArpOperation.REQUEST)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tpa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.sha, STACK__MAC_UNICAST)
        self.assertEqual(payload.tha, MAC__UNSPEC)

    def test__stack__packet_handler__arp__tx__gratuitous_arp_uses_reply_with_spa_tpa_self(self) -> None:
        """
        Ensure '_send_gratuitous_arp' sends a REPLY with spa == tpa ==
        self IP, broadcast dst, stack src.
        """

        self._handler._send_gratuitous_arp(ip4_unicast=STACK__IP4_ADDRESS)

        payload = self._last_call()["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.oper, ArpOperation.REPLY)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tpa, STACK__IP4_ADDRESS)

    def test__stack__packet_handler__arp__tx__probe_uses_unspecified_spa(self) -> None:
        """
        Ensure '_send_arp_probe' sends a REQUEST with spa == 0.0.0.0
        per RFC 5227.
        """

        self._handler._send_arp_probe(ip4_unicast=HOST_A__IP4)

        payload = self._last_call()["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.oper, ArpOperation.REQUEST)
        self.assertEqual(payload.spa, IP4__UNSPEC)
        self.assertEqual(payload.tpa, HOST_A__IP4)

    def test__stack__packet_handler__arp__tx__reply_helper_targets_requester(self) -> None:
        """
        Ensure '_send_arp_reply' unicasts a REPLY back to the requester
        MAC with stack MAC as src.
        """

        self._handler._send_arp_reply(
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=HOST_A__MAC,
            arp__tpa=HOST_A__IP4,
        )

        call = self._last_call()
        self.assertEqual(call["ethernet__src"], STACK__MAC_UNICAST)
        self.assertEqual(call["ethernet__dst"], HOST_A__MAC)
        payload = call["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.oper, ArpOperation.REPLY)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tha, HOST_A__MAC)
        self.assertEqual(payload.tpa, HOST_A__IP4)

    def test__stack__packet_handler__arp__tx__request_uses_first_ip4_unicast(self) -> None:
        """
        Ensure 'send_arp_request' uses the first stack IPv4 unicast
        address as spa when one is configured.
        """

        self._handler.send_arp_request(arp__tpa=HOST_A__IP4)

        payload = self._last_call()["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tpa, HOST_A__IP4)

    def test__stack__packet_handler__arp__tx__request_defaults_spa_unspecified_when_empty(self) -> None:
        """
        Ensure 'send_arp_request' falls back to spa = 0.0.0.0 when the
        stack has no IPv4 unicast address.
        """

        handler = _StubHandler(ip4_unicast=[])
        handler.send_arp_request(arp__tpa=HOST_A__IP4)

        payload = handler.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            IP4__UNSPEC,
            msg="send_arp_request must fall back to spa=0.0.0.0 when no stack IPv4 is configured.",
        )
