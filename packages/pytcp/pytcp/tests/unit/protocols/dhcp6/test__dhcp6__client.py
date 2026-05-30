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
This module contains tests for the DHCPv6 stateless client in
'pytcp/protocols/dhcp6/dhcp6__client.py'.

pytcp/tests/unit/protocols/dhcp6/test__dhcp6__client.py

ver 3.0.6
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip6Address, MacAddress
from net_proto import Dhcp6MessageType, Dhcp6OptionType
from pytcp.protocols.dhcp6.dhcp6__client import Dhcp6Client, Dhcp6StatelessConfig
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid
from pytcp.socket import SO_BINDTODEVICE, SOL_SOCKET
from pytcp.stack import sysctl
from pytcp.tests.lib.dhcp6_mock_server import Dhcp6MockServer, autospec_dhcp6_socket

_DEFAULT_MAC = MacAddress("02:00:00:00:00:07")
_PINNED_XID = 0xABCDEF


class TestDhcp6ClientInit(TestCase):
    """
    The 'Dhcp6Client' constructor tests.
    """

    def test__dhcp6_client__init_stores_mac_address(self) -> None:
        """
        Ensure the constructor stores the supplied MAC address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp6Client(mac_address=_DEFAULT_MAC)

        self.assertEqual(client._mac_address, _DEFAULT_MAC, msg="The MAC address must be stored verbatim.")

    def test__dhcp6_client__init_keyword_only(self) -> None:
        """
        Ensure the constructor arguments are keyword-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            Dhcp6Client(_DEFAULT_MAC)  # type: ignore[misc]


class TestDhcp6ClientFetch(TestCase):
    """
    The 'Dhcp6Client.fetch_other_config' stateless-exchange tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock DHCPv6 server into an autospec'd socket and pin the
        transaction-id / jitter so the exchange is deterministic.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.return_value = _PINNED_XID
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))

        self._server = Dhcp6MockServer()
        self._server.wire(self._sock)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC)

    @override
    def tearDown(self) -> None:
        """
        Restore every sysctl knob mutated by a test to its default.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_client__fetch_returns_dns_servers(self) -> None:
        """
        Ensure a REPLY carrying DNS Recursive Name Server addresses is
        surfaced as the stateless other-configuration.

        Reference: RFC 8415 §18.2.6 (Creation and transmission of Information-request).
        """

        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53"), Ip6Address("2001:db8::54")])

        config = self._client.fetch_other_config()

        self.assertEqual(
            config,
            Dhcp6StatelessConfig(dns_servers=[Ip6Address("2001:db8::53"), Ip6Address("2001:db8::54")]),
            msg="fetch_other_config must surface the REPLY's DNS servers.",
        )

    def test__dhcp6_client__fetch_sends_information_request(self) -> None:
        """
        Ensure the client transmits an INFORMATION-REQUEST carrying the
        Client Identifier DUID, a zero Elapsed Time, and an Option
        Request for DNS servers, to the All_DHCP multicast group.

        Reference: RFC 8415 §18.2.6 (Information-request contents).
        """

        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        self._client.fetch_other_config()

        request = self._server.tx_log[0]
        self.assertIs(
            request.msg_type, Dhcp6MessageType.INFORMATION_REQUEST, msg="The client must send INFORMATION-REQUEST."
        )
        self.assertEqual(request.xid, _PINNED_XID, msg="The request must carry the pinned transaction-id.")
        self.assertEqual(
            request.client_id, get_client_duid(_DEFAULT_MAC), msg="The request must carry the client DUID."
        )
        self.assertEqual(request.elapsed_time, 0, msg="The first request must carry Elapsed Time 0.")
        self.assertEqual(request.oro, [Dhcp6OptionType.DNS_SERVERS], msg="The request must ORO the DNS Servers option.")

    def test__dhcp6_client__fetch_sends_to_multicast_and_binds_client_port(self) -> None:
        """
        Ensure the client binds the DHCPv6 client port and transmits to
        the All_DHCP_Relay_Agents_and_Servers group on the server port.

        Reference: RFC 8415 §7.1 / §7.2 (multicast address and UDP ports).
        """

        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        self._client.fetch_other_config()

        self._sock.bind.assert_called_once_with(("::", 546))
        self.assertEqual(
            self._sock.sendto.call_args.args[1],
            ("ff02::1:2", 547),
            msg="The client must send to ff02::1:2 port 547.",
        )
        self._sock.close.assert_called_once_with()

    def test__dhcp6_client__fetch_reply_without_dns_returns_empty(self) -> None:
        """
        Ensure a REPLY with no DNS Servers option yields an empty DNS
        list rather than None.

        Reference: RFC 8415 §18.2.6 (Information-request / Reply exchange).
        """

        self._server.enqueue_reply()

        config = self._client.fetch_other_config()

        self.assertEqual(config, Dhcp6StatelessConfig(dns_servers=[]), msg="A DNS-less REPLY must yield empty config.")

    def test__dhcp6_client__fetch_silent_server_returns_none(self) -> None:
        """
        Ensure an unanswered exchange returns None after exhausting the
        retransmission budget, having retransmitted on each timeout.

        Reference: RFC 8415 §15 (retransmission until the budget is exhausted).
        """

        config = self._client.fetch_other_config()

        self.assertIsNone(config, msg="A silent server must yield None.")
        self.assertEqual(
            self._sock.sendto.call_count,
            5,
            msg="The client must transmit retrans_max_attempts (5) times before giving up.",
        )

    def test__dhcp6_client__fetch_drops_mismatched_xid_then_succeeds(self) -> None:
        """
        Ensure a REPLY with a mismatched transaction-id is dropped and
        the client retransmits, succeeding on the next REPLY.

        Reference: RFC 8415 §16.10 (a Reply's transaction-id must match the client's).
        """

        self._server.enqueue_reply(xid=0x111111)
        self._server.enqueue_timeout()
        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        config = self._client.fetch_other_config()

        self.assertEqual(
            config,
            Dhcp6StatelessConfig(dns_servers=[Ip6Address("2001:db8::53")]),
            msg="The client must ignore the mismatched-xid REPLY and accept the next one.",
        )
        self.assertEqual(
            self._sock.sendto.call_count, 2, msg="The client must retransmit once after dropping the bogus REPLY."
        )

    def test__dhcp6_client__fetch_drops_malformed_then_succeeds(self) -> None:
        """
        Ensure a malformed inbound frame is dropped without aborting the
        exchange, and a valid REPLY on retransmit is accepted.

        Reference: RFC 8415 §16 (a client discards malformed messages).
        """

        self._server.enqueue_raw(b"\x07\x00")  # too short for the 4-byte header
        self._server.enqueue_timeout()
        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        config = self._client.fetch_other_config()

        self.assertEqual(
            config,
            Dhcp6StatelessConfig(dns_servers=[Ip6Address("2001:db8::53")]),
            msg="The client must drop the malformed frame and accept the next valid REPLY.",
        )

    def test__dhcp6_client__fetch_with_interface_pins_socket(self) -> None:
        """
        Ensure a client built with an interface name pins the socket to
        that interface via SO_BINDTODEVICE.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp6Client(mac_address=_DEFAULT_MAC, interface_name="tap7")
        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        client.fetch_other_config()

        self._sock.setsockopt.assert_called_once_with(SOL_SOCKET, SO_BINDTODEVICE, b"tap7")

    def test__dhcp6_client__fetch_drops_non_reply_message(self) -> None:
        """
        Ensure an inbound message that is not a REPLY (e.g. an
        ADVERTISE) is dropped, and a valid REPLY on retransmit is
        accepted.

        Reference: RFC 8415 §18.2.10 (a stateless client expects a Reply).
        """

        # A bare ADVERTISE (msg-type 2) header with the pinned xid.
        self._server.enqueue_raw(b"\x02\xab\xcd\xef")
        self._server.enqueue_timeout()
        self._server.enqueue_reply(dns_servers=[Ip6Address("2001:db8::53")])

        config = self._client.fetch_other_config()

        self.assertEqual(
            config,
            Dhcp6StatelessConfig(dns_servers=[Ip6Address("2001:db8::53")]),
            msg="The client must drop the non-REPLY message and accept the next valid REPLY.",
        )

    def test__dhcp6_client__retransmit_backoff_caps_at_max_rt(self) -> None:
        """
        Ensure the retransmission backoff caps the retransmission timeout
        at INF_MAX_RT once the doubled value would exceed it.

        Reference: RFC 8415 §15 (RT bounded by MRT).
        """

        # MRT below the second doubled timeout (IRT=1000 -> 2000) forces
        # the cap branch on the second retransmission.
        sysctl.set("dhcp6.inf_max_rt_ms", 1500)

        config = self._client.fetch_other_config()

        self.assertIsNone(config, msg="A silent server must still yield None with a low MRT.")
        self.assertEqual(self._sock.sendto.call_count, 5, msg="The capped backoff must not change the attempt budget.")

    def test__dhcp6_client__recv_window_deadline_exhausted(self) -> None:
        """
        Ensure the recv window returns no REPLY once its deadline has
        elapsed after dropping a bogus packet mid-window.

        Reference: RFC 8415 §15 (bounded per-attempt recv window).
        """

        sysctl.set("dhcp6.retrans_max_attempts", 1)
        mock_time = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.time"))
        # First call seeds the window deadline; the second (after the
        # bogus drop) jumps far past it so 'remaining <= 0' fires.
        mock_time.monotonic.side_effect = [1000.0, 1.0e9]

        self._server.enqueue_reply(xid=0x111111)  # mismatched xid -> dropped

        config = self._client.fetch_other_config()

        self.assertIsNone(config, msg="An exhausted recv-window deadline must yield None.")
