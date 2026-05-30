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
from unittest.mock import create_autospec, patch

from net_addr import Ip6Address, Ip6IfAddr, MacAddress
from net_proto import Dhcp6MessageType, Dhcp6Options, Dhcp6OptionType, Dhcp6StatusCode
from pytcp.protocols.dhcp6.dhcp6__client import (
    Dhcp6Client,
    Dhcp6Lease,
    Dhcp6StatelessConfig,
)
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid
from pytcp.socket import SO_BINDTODEVICE, SOL_SOCKET
from pytcp.stack import sysctl
from pytcp.stack.address import AddressApi
from pytcp.tests.lib.dhcp6_mock_server import Dhcp6MockServer, autospec_dhcp6_socket

_DEFAULT_MAC = MacAddress("02:00:00:00:00:07")
_PINNED_XID = 0xABCDEF
_SOL_XID = 0xAAAAAA
_REQ_XID = 0xBBBBBB
_SERVER_DUID = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\xfe"


class TestDhcp6ClientInit(TestCase):
    """
    The 'Dhcp6Client' constructor tests.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the Subsystem base-class init log line so the
        constructor tests do not leak 'Initializing DHCP6 Client'.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))

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
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

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


class TestDhcp6ClientAcquireLease(TestCase):
    """
    The 'Dhcp6Client.acquire_lease' stateful-exchange tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock DHCPv6 server into an autospec'd socket and pin the
        SOLICIT / REQUEST transaction-ids and jitter so the four-message
        exchange is deterministic.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.side_effect = [_SOL_XID, _REQ_XID]
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._server = Dhcp6MockServer(server_duid=_SERVER_DUID)
        self._server.wire(self._sock)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC)

    @override
    def tearDown(self) -> None:
        """
        Restore every sysctl knob mutated by a test to its default.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_client__acquire_lease_returns_lease(self) -> None:
        """
        Ensure a full SOLICIT/ADVERTISE/REQUEST/REPLY exchange returns the
        leased IA_NA address with its lifetimes, timers, and server DUID.

        Reference: RFC 8415 §18.2.1 (four-message exchange).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=3600,
            valid_lifetime=7200,
            t1=1800,
            t2=2880,
        )

        lease = self._client.acquire_lease()

        self.assertEqual(
            lease,
            Dhcp6Lease(
                address=Ip6Address("2001:db8::100"),
                preferred_lifetime=3600,
                valid_lifetime=7200,
                t1=1800,
                t2=2880,
                iaid=0,
                server_duid=_SERVER_DUID,
            ),
            msg="acquire_lease must return the leased IA_NA address bundle.",
        )

    def test__dhcp6_client__acquire_lease_solicit_contents(self) -> None:
        """
        Ensure the SOLICIT carries the Client Identifier, an IA_NA, and an
        Option Request.

        Reference: RFC 8415 §18.2.1 (Solicit message contents).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        self._client.acquire_lease()

        solicit = self._server.tx_log[0]
        self.assertIs(solicit.msg_type, Dhcp6MessageType.SOLICIT, msg="The first message must be SOLICIT.")
        self.assertEqual(solicit.xid, _SOL_XID, msg="The SOLICIT must carry the pinned SOLICIT xid.")
        self.assertEqual(solicit.client_id, get_client_duid(_DEFAULT_MAC), msg="The SOLICIT must carry the DUID.")
        self.assertIsNotNone(solicit.ia_na, msg="The SOLICIT must carry an IA_NA.")
        self.assertEqual(solicit.oro, [Dhcp6OptionType.DNS_SERVERS], msg="The SOLICIT must ORO the DNS option.")

    def test__dhcp6_client__acquire_lease_request_addresses_advertised_server(self) -> None:
        """
        Ensure the REQUEST is addressed to the server that ADVERTISEd, by
        echoing its DUID in the Server Identifier option.

        Reference: RFC 8415 §18.2.2 (Request carries the selected Server Identifier).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        self._client.acquire_lease()

        request = self._server.tx_log[1]
        self.assertIs(request.msg_type, Dhcp6MessageType.REQUEST, msg="The second message must be REQUEST.")
        self.assertEqual(request.xid, _REQ_XID, msg="The REQUEST must carry the pinned REQUEST xid.")
        self.assertEqual(request.server_id, _SERVER_DUID, msg="The REQUEST must echo the advertised Server DUID.")

    def test__dhcp6_client__acquire_lease_silent_server_returns_none(self) -> None:
        """
        Ensure an unanswered SOLICIT returns None after exhausting the
        retransmission budget.

        Reference: RFC 8415 §15 (retransmission until the budget is exhausted).
        """

        lease = self._client.acquire_lease()

        self.assertIsNone(lease, msg="A silent server must yield no lease.")
        self.assertEqual(self._sock.sendto.call_count, 5, msg="The SOLICIT must be retransmitted to budget.")

    def test__dhcp6_client__acquire_lease_advertise_without_server_id(self) -> None:
        """
        Ensure an ADVERTISE lacking a Server Identifier yields no lease.

        Reference: RFC 8415 §18.2.9 (a usable Advertise carries a Server Identifier).
        """

        self._server.enqueue_advertise(server_id=None)

        self.assertIsNone(self._client.acquire_lease(), msg="An ADVERTISE without a Server ID must yield no lease.")

    def test__dhcp6_client__acquire_lease_request_unanswered(self) -> None:
        """
        Ensure a silent server on the REQUEST leg (after a valid ADVERTISE)
        yields no lease.

        Reference: RFC 8415 §18.2.2 (Request/Reply; no Reply -> no lease).
        """

        self._server.enqueue_advertise()

        self.assertIsNone(self._client.acquire_lease(), msg="An unanswered REQUEST must yield no lease.")

    def test__dhcp6_client__acquire_lease_reply_without_ia_na(self) -> None:
        """
        Ensure a REPLY with no IA_NA option yields no lease.

        Reference: RFC 8415 §18.2.10.1 (a successful Reply carries the IA_NA binding).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_reply()  # a REPLY with Server/Client IDs but no IA_NA

        self.assertIsNone(self._client.acquire_lease(), msg="A REPLY without IA_NA must yield no lease.")

    def test__dhcp6_client__acquire_lease_reply_without_ia_address(self) -> None:
        """
        Ensure a REPLY whose IA_NA carries no IA Address yields no lease.

        Reference: RFC 8415 §18.2.10.1 (IA_NA binding carries the IA Address).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"), omit_ia_address=True)

        self.assertIsNone(self._client.acquire_lease(), msg="A REPLY IA_NA with no address must yield no lease.")

    def test__dhcp6_client__acquire_lease_reply_ia_na_status_failure(self) -> None:
        """
        Ensure a REPLY whose IA_NA carries a non-Success Status Code yields
        no lease.

        Reference: RFC 8415 §18.2.10.1 (NoAddrsAvail in the IA_NA Status Code).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            omit_ia_address=True,
            ia_status=Dhcp6StatusCode.NO_ADDRS_AVAIL,
        )

        self.assertIsNone(self._client.acquire_lease(), msg="A NoAddrsAvail IA_NA must yield no lease.")

    def test__dhcp6_client__acquire_lease_reply_ia_na_malformed_suboptions(self) -> None:
        """
        Ensure a REPLY whose IA_NA sub-option block is malformed is dropped
        without crashing the exchange.

        Reference: RFC 8415 §16 (a client discards malformed message content).
        """

        self._server.enqueue_advertise()
        # A 3-byte IA_NA sub-block — shorter than the 4-byte option header.
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"), ia_na_options_override=b"\x00\x05\x00")

        self.assertIsNone(self._client.acquire_lease(), msg="A malformed IA_NA sub-block must yield no lease.")


_REN_XID = 0xCCCCCC
_LEASE = Dhcp6Lease(
    address=Ip6Address("2001:db8::100"),
    preferred_lifetime=3600,
    valid_lifetime=7200,
    t1=1800,
    t2=2880,
    iaid=0,
    server_duid=_SERVER_DUID,
)


class TestDhcp6ClientRenewRebind(TestCase):
    """
    The 'Dhcp6Client' RENEW / REBIND lease-maintenance exchange tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock DHCPv6 server into an autospec'd socket and pin the
        RENEW / REBIND transaction-id and jitter so each exchange is
        deterministic.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.return_value = _REN_XID
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._server = Dhcp6MockServer(server_duid=_SERVER_DUID)
        self._server.wire(self._sock)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC)

    @override
    def tearDown(self) -> None:
        """
        Restore every sysctl knob mutated by a test to its default.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_client__renew_returns_updated_lease(self) -> None:
        """
        Ensure a RENEW answered with a REPLY returns the lease bundle
        carrying the server's refreshed lifetimes and timers.

        Reference: RFC 8415 §18.2.4 (Renew message and Reply processing).
        """

        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=7200,
            valid_lifetime=14400,
            t1=3600,
            t2=5760,
        )

        renewed = self._client._renew(_LEASE, deadline=1e18)

        self.assertEqual(
            renewed,
            Dhcp6Lease(
                address=Ip6Address("2001:db8::100"),
                preferred_lifetime=7200,
                valid_lifetime=14400,
                t1=3600,
                t2=5760,
                iaid=0,
                server_duid=_SERVER_DUID,
            ),
            msg="RENEW must return the refreshed lease bundle.",
        )

    def test__dhcp6_client__renew_message_contents(self) -> None:
        """
        Ensure the RENEW carries the granting server's DUID, the Client
        Identifier, and an IA_NA echoing the currently leased address.

        Reference: RFC 8415 §18.2.4 (Renew carries the Server Identifier and the IA being renewed).
        """

        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        self._client._renew(_LEASE, deadline=1e18)

        renew = self._server.tx_log[0]
        self.assertIs(renew.msg_type, Dhcp6MessageType.RENEW, msg="The maintenance message must be RENEW.")
        self.assertEqual(renew.server_id, _SERVER_DUID, msg="RENEW must address the granting server by DUID.")
        self.assertEqual(renew.client_id, get_client_duid(_DEFAULT_MAC), msg="RENEW must carry the client DUID.")
        self.assertIsNotNone(renew.ia_na, msg="RENEW must carry an IA_NA.")
        assert renew.ia_na is not None
        ia_options = Dhcp6Options.from_buffer(memoryview(renew.ia_na.options))
        assert ia_options.ia_addr is not None
        self.assertEqual(
            ia_options.ia_addr.address,
            Ip6Address("2001:db8::100"),
            msg="RENEW IA_NA must echo the currently leased address.",
        )

    def test__dhcp6_client__rebind_returns_updated_lease(self) -> None:
        """
        Ensure a REBIND answered with a REPLY returns the lease bundle
        with the responding server's DUID and refreshed lifetimes.

        Reference: RFC 8415 §18.2.5 (Rebind message and Reply processing).
        """

        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=7200,
            valid_lifetime=14400,
            t1=3600,
            t2=5760,
        )

        rebound = self._client._rebind(_LEASE, deadline=1e18)

        self.assertEqual(
            rebound,
            Dhcp6Lease(
                address=Ip6Address("2001:db8::100"),
                preferred_lifetime=7200,
                valid_lifetime=14400,
                t1=3600,
                t2=5760,
                iaid=0,
                server_duid=_SERVER_DUID,
            ),
            msg="REBIND must return the refreshed lease with the responding server's DUID.",
        )

    def test__dhcp6_client__rebind_omits_server_id(self) -> None:
        """
        Ensure the REBIND is sent without a Server Identifier so any
        server on the link may answer.

        Reference: RFC 8415 §18.2.5 (Rebind carries no Server Identifier).
        """

        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        self._client._rebind(_LEASE, deadline=1e18)

        rebind = self._server.tx_log[0]
        self.assertIs(rebind.msg_type, Dhcp6MessageType.REBIND, msg="The maintenance message must be REBIND.")
        self.assertIsNone(rebind.server_id, msg="REBIND must omit the Server Identifier.")
        self.assertIsNotNone(rebind.ia_na, msg="REBIND must carry an IA_NA.")

    def test__dhcp6_client__renew_retransmits_then_succeeds(self) -> None:
        """
        Ensure a RENEW whose first recv window times out is retransmitted
        and succeeds on the server's eventual REPLY before the deadline.

        Reference: RFC 8415 §15 (retransmission until a Reply or the MRD bound).
        """

        self._server.enqueue_timeout()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        renewed = self._client._renew(_LEASE, deadline=1e18)

        self.assertIsNotNone(renewed, msg="RENEW must succeed after one retransmission.")
        self.assertEqual(self._sock.sendto.call_count, 2, msg="RENEW must be retransmitted once before the REPLY.")

    def test__dhcp6_client__renew_gives_up_at_deadline(self) -> None:
        """
        Ensure a RENEW whose max retransmission duration (the time to T2)
        has elapsed stops retransmitting and returns None.

        Reference: RFC 8415 §18.2.4 (Renew is bounded by the time remaining until T2).
        """

        mock_time = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.time"))
        mock_time.monotonic.return_value = 100.0

        result = self._client._renew(_LEASE, deadline=100.0)

        self.assertIsNone(result, msg="RENEW must give up once the MRD deadline has elapsed.")
        self.assertEqual(self._sock.sendto.call_count, 1, msg="An expired RENEW must not retransmit past its deadline.")


class TestDhcp6ClientLifecycle(TestCase):
    """
    The 'Dhcp6Client' BOUND lease-lifecycle tests — T1 RENEW, T2 REBIND,
    valid-lifetime expiry, and the Address-API reconciliation each drives.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock server + Address API into the client and install a
        controllable monotonic clock so the T1 / T2 / valid deadlines can
        be crossed deterministically.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.return_value = _REN_XID
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.SUBSYSTEM_SLEEP_TIME__SEC", 0.0))

        self._clock = {"t": 1000.0}
        mock_time = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.time"))
        mock_time.monotonic.side_effect = lambda: self._clock["t"]

        self._address_api = create_autospec(AddressApi, spec_set=True, instance=True)

        self._server = Dhcp6MockServer(server_duid=_SERVER_DUID)
        self._server.wire(self._sock)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC, address_api=self._address_api)

    @override
    def tearDown(self) -> None:
        """
        Restore every sysctl knob mutated by a test to its default.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def _bind_lease(self) -> None:
        """
        Install '_LEASE' as the client's current lease and arm its
        timers at clock t=1000 (T1=2800, T2=3880, valid=8200).
        """

        self._client._lease = _LEASE
        self._client._arm_timers(_LEASE)

    def test__dhcp6_client__lifecycle_idle_before_t1(self) -> None:
        """
        Ensure a serviced lease whose T1 has not yet been reached emits no
        maintenance message and does not touch the Address API.

        Reference: RFC 8415 §18.2.4 (RENEW does not begin before T1).
        """

        self._bind_lease()
        self._clock["t"] = 2000.0

        self._client._service_lease()

        self.assertEqual(self._server.tx_log, [], msg="No maintenance message must be sent before T1.")
        self._address_api.replace.assert_not_called()

    def test__dhcp6_client__lifecycle_renew_at_t1(self) -> None:
        """
        Ensure crossing T1 sends a RENEW and adopts the refreshed lease
        with re-armed timers.

        Reference: RFC 8415 §18.2.4 (RENEW begins at T1).
        """

        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=3600,
            valid_lifetime=7200,
            t1=1800,
            t2=2880,
        )
        self._bind_lease()
        self._clock["t"] = 2801.0

        self._client._service_lease()

        self.assertIs(self._server.tx_log[0].msg_type, Dhcp6MessageType.RENEW, msg="Crossing T1 must send a RENEW.")
        assert self._client._lease is not None
        self.assertEqual(self._client._lease.t1, 1800, msg="The refreshed lease must replace the held one.")
        self.assertEqual(self._client._t1_deadline, 2801.0 + 1800, msg="The timers must be re-armed from the RENEW.")
        self._address_api.replace.assert_not_called()

    def test__dhcp6_client__lifecycle_rebind_at_t2(self) -> None:
        """
        Ensure crossing T2 sends a REBIND and adopts the refreshed lease.

        Reference: RFC 8415 §18.2.5 (REBIND begins at T2).
        """

        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))
        self._bind_lease()
        self._clock["t"] = 3881.0

        self._client._service_lease()

        self.assertIs(self._server.tx_log[0].msg_type, Dhcp6MessageType.REBIND, msg="Crossing T2 must send a REBIND.")

    def test__dhcp6_client__lifecycle_expiry_releases_and_resolicits(self) -> None:
        """
        Ensure crossing the valid lifetime removes the leased address and
        restarts the stateful exchange from SOLICIT.

        Reference: RFC 8415 §18.2.5 (lease expiry discards the address and restarts configuration).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::200"))
        self._bind_lease()
        self._clock["t"] = 8201.0

        self._client._service_lease()

        self._address_api.remove.assert_called_once_with(address=Ip6Address("2001:db8::100"))
        self.assertIs(self._server.tx_log[0].msg_type, Dhcp6MessageType.SOLICIT, msg="Expiry must restart at SOLICIT.")
        assert self._client._lease is not None
        self.assertEqual(
            self._client._lease.address, Ip6Address("2001:db8::200"), msg="A fresh lease must be acquired on expiry."
        )

    def test__dhcp6_client__lifecycle_renew_address_change_replaces(self) -> None:
        """
        Ensure a RENEW that returns a different address swaps it on the
        interface through the Address API.

        Reference: RFC 8415 §18.2.10.1 (server may return a new address in the IA).
        """

        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::200"))
        self._bind_lease()
        self._clock["t"] = 2801.0

        self._client._service_lease()

        self._address_api.replace.assert_called_once_with(
            old_address=Ip6Address("2001:db8::100"),
            new_ifaddr=Ip6IfAddr("2001:db8::200/128"),
        )

    def test__dhcp6_client__lifecycle_renew_failure_defers_to_rebind(self) -> None:
        """
        Ensure a RENEW that yields no usable lease keeps the current lease
        and advances T1 to T2 so the next service rebinds rather than
        re-renewing every tick.

        Reference: RFC 8415 §18.2.4 (RENEW failure escalates to REBIND at T2).
        """

        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"), omit_ia_address=True, ia_status=Dhcp6StatusCode.NO_ADDRS_AVAIL
        )
        self._bind_lease()
        self._clock["t"] = 2801.0

        self._client._service_lease()

        self.assertEqual(self._client._lease, _LEASE, msg="A failed RENEW must keep the current lease.")
        self.assertEqual(
            self._client._t1_deadline, self._client._t2_deadline, msg="A failed RENEW must not re-fire before T2."
        )
        self._address_api.replace.assert_not_called()


class TestDhcp6ClientRelease(TestCase):
    """
    The 'Dhcp6Client' RELEASE-on-shutdown tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock server + Address API into the client and pin the
        RELEASE transaction-id.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.return_value = _REN_XID
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._address_api = create_autospec(AddressApi, spec_set=True, instance=True)

        self._server = Dhcp6MockServer(server_duid=_SERVER_DUID)
        self._server.wire(self._sock)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC, address_api=self._address_api)

    def test__dhcp6_client__release_message_contents(self) -> None:
        """
        Ensure RELEASE carries the granting server's DUID, the Client
        Identifier, and an IA_NA echoing the released address.

        Reference: RFC 8415 §18.2.7 (Release message contents).
        """

        self._client.release(_LEASE)

        release = self._server.tx_log[0]
        self.assertIs(release.msg_type, Dhcp6MessageType.RELEASE, msg="The shutdown message must be RELEASE.")
        self.assertEqual(release.server_id, _SERVER_DUID, msg="RELEASE must address the granting server.")
        self.assertEqual(release.client_id, get_client_duid(_DEFAULT_MAC), msg="RELEASE must carry the client DUID.")
        assert release.ia_na is not None
        ia_options = Dhcp6Options.from_buffer(memoryview(release.ia_na.options))
        assert ia_options.ia_addr is not None
        self.assertEqual(
            ia_options.ia_addr.address,
            Ip6Address("2001:db8::100"),
            msg="RELEASE IA_NA must echo the released address.",
        )

    def test__dhcp6_client__release_is_fire_and_forget(self) -> None:
        """
        Ensure RELEASE is transmitted once and does not wait for a REPLY
        so it cannot wedge stack teardown.

        Reference: RFC 8415 §18.2.7 (Release is best-effort on shutdown).
        """

        self._client.release(_LEASE)

        self.assertEqual(self._sock.sendto.call_count, 1, msg="RELEASE must be sent exactly once.")
        self._sock.recv__mv.assert_not_called()

    def test__dhcp6_client__stop_releases_held_lease(self) -> None:
        """
        Ensure stopping the worker while a lease is held emits a RELEASE,
        removes the leased address, and clears the lease.

        Reference: RFC 8415 §18.2.7 (Release the binding on shutdown).
        """

        self._client._lease = _LEASE

        self._client._stop()

        self.assertIs(self._server.tx_log[0].msg_type, Dhcp6MessageType.RELEASE, msg="Stop must emit a RELEASE.")
        self._address_api.remove.assert_called_once_with(address=Ip6Address("2001:db8::100"))
        self.assertIsNone(self._client._lease, msg="The lease must be cleared on shutdown.")

    def test__dhcp6_client__stop_without_lease_sends_nothing(self) -> None:
        """
        Ensure stopping the worker with no held lease emits no RELEASE and
        still wakes the trigger event for prompt teardown.

        Reference: RFC 8415 §18.2.7 (no Release without a binding).
        """

        self._client._stop()

        self.assertEqual(self._server.tx_log, [], msg="No RELEASE must be sent without a held lease.")
        self._address_api.remove.assert_not_called()
        self.assertTrue(self._client._event__trigger.is_set(), msg="_stop() must still wake the trigger event.")

    def test__dhcp6_client__stop_release_socket_error_does_not_propagate(self) -> None:
        """
        Ensure a socket error while emitting the shutdown RELEASE is
        swallowed so it cannot abort the rest of stack teardown, with the
        address still removed and the lease cleared.

        Reference: RFC 8415 §18.2.7 (Release is best-effort on shutdown).
        """

        self._sock.sendto.side_effect = OSError("network down")
        self._client._lease = _LEASE

        self._client._stop()

        self._address_api.remove.assert_called_once_with(address=Ip6Address("2001:db8::100"))
        self.assertIsNone(self._client._lease, msg="The lease must be cleared even when RELEASE fails.")


class TestDhcp6ClientLeaseAssignment(TestCase):
    """
    The 'Dhcp6Client.acquire_lease' Address-API assignment tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a mock DHCPv6 server into an autospec'd socket and an
        autospec'd Address API into the client.
        """

        self._socket_factory = self.enterContext(
            patch("pytcp.protocols.dhcp6.dhcp6__client.socket", new=autospec_dhcp6_socket()),
        )
        self._sock = self._socket_factory.return_value

        self._random = self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.random"))
        self._random.randint.side_effect = [_SOL_XID, _REQ_XID]
        self._random.uniform.return_value = 0.0

        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._server = Dhcp6MockServer(server_duid=_SERVER_DUID)
        self._server.wire(self._sock)
        self._address_api = create_autospec(AddressApi, spec_set=True)
        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC, address_api=self._address_api)

    def test__dhcp6_client__acquire_lease_assigns_address_as_128(self) -> None:
        """
        Ensure a successful lease installs the leased address as a /128
        host through the Address API.

        Reference: RFC 8415 §18.2.10.1 (the client configures the assigned address).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(address=Ip6Address("2001:db8::100"))

        self._client.acquire_lease()

        self._address_api.add.assert_called_once_with(ifaddr=Ip6IfAddr("2001:db8::100/128"))

    def test__dhcp6_client__acquire_lease_failure_does_not_assign(self) -> None:
        """
        Ensure a failed lease (NoAddrsAvail) installs no address.

        Reference: RFC 8415 §18.2.10.1 (no address on a NoAddrsAvail Reply).
        """

        self._server.enqueue_advertise()
        self._server.enqueue_lease_reply(
            address=Ip6Address("2001:db8::100"),
            omit_ia_address=True,
            ia_status=Dhcp6StatusCode.NO_ADDRS_AVAIL,
        )

        self._client.acquire_lease()

        self._address_api.add.assert_not_called()


_SAMPLE_LEASE = Dhcp6Lease(
    address=Ip6Address("2001:db8::100"),
    preferred_lifetime=3600,
    valid_lifetime=7200,
    t1=1800,
    t2=2880,
    iaid=0,
    server_duid=_SERVER_DUID,
)


class TestDhcp6ClientTrigger(TestCase):
    """
    The 'Dhcp6Client' RA-driven trigger / Subsystem-loop tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a client with the SOLICIT/INFORMATION exchanges mocked and the
        trigger poll interval shortened so the worker loop runs inline.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.log"))
        self.enterContext(patch("pytcp.protocols.dhcp6.dhcp6__client.SUBSYSTEM_SLEEP_TIME__SEC", 0.0))

        self._acquire = self.enterContext(patch.object(Dhcp6Client, "acquire_lease", autospec=True))
        self._fetch = self.enterContext(patch.object(Dhcp6Client, "fetch_other_config", autospec=True))
        self._acquire.return_value = _SAMPLE_LEASE
        self._fetch.return_value = Dhcp6StatelessConfig(dns_servers=[Ip6Address("2001:db8::53")])

        self._client = Dhcp6Client(mac_address=_DEFAULT_MAC)

    def test__dhcp6_client__trigger_managed_acquires_lease(self) -> None:
        """
        Ensure a Managed trigger runs the stateful lease exchange.

        Reference: RFC 8415 §4 (Managed flag drives stateful address configuration).
        """

        self._client.trigger(managed=True, other=False)
        self._client._subsystem_loop()

        self._acquire.assert_called_once_with(self._client)
        self._fetch.assert_not_called()

    def test__dhcp6_client__trigger_other_fetches_config(self) -> None:
        """
        Ensure an Other-config trigger runs the stateless exchange.

        Reference: RFC 8415 §4 (Other-config flag drives stateless configuration).
        """

        self._client.trigger(managed=False, other=True)
        self._client._subsystem_loop()

        self._fetch.assert_called_once_with(self._client)
        self._acquire.assert_not_called()

    def test__dhcp6_client__trigger_managed_takes_precedence(self) -> None:
        """
        Ensure a trigger with both flags runs only the stateful exchange.

        Reference: RFC 8415 §4 (Managed configuration subsumes Other configuration).
        """

        self._client.trigger(managed=True, other=True)
        self._client._subsystem_loop()

        self._acquire.assert_called_once_with(self._client)
        self._fetch.assert_not_called()

    def test__dhcp6_client__trigger_managed_debounced_once_bound(self) -> None:
        """
        Ensure a second Managed trigger after a successful lease does not
        re-solicit.

        Reference: RFC 8415 §18.2.1 (no re-solicitation once an IA is bound).
        """

        self._client.trigger(managed=True, other=False)
        self._client._subsystem_loop()
        self._client.trigger(managed=True, other=False)
        self._client._subsystem_loop()

        self._acquire.assert_called_once_with(self._client)

    def test__dhcp6_client__trigger_other_debounced_once_acquired(self) -> None:
        """
        Ensure a second Other-config trigger after a successful fetch does
        not re-fetch.

        Reference: RFC 8415 §18.2.6 (other configuration fetched once per attachment).
        """

        self._client.trigger(managed=False, other=True)
        self._client._subsystem_loop()
        self._client.trigger(managed=False, other=True)
        self._client._subsystem_loop()

        self._fetch.assert_called_once_with(self._client)

    def test__dhcp6_client__trigger_managed_failure_allows_retry(self) -> None:
        """
        Ensure a failed lease leaves the client unbound so a later trigger
        retries.

        Reference: RFC 8415 §18.2.1 (retry on a failed exchange).
        """

        self._acquire.return_value = None

        self._client.trigger(managed=True, other=False)
        self._client._subsystem_loop()
        self._client.trigger(managed=True, other=False)
        self._client._subsystem_loop()

        self.assertEqual(self._acquire.call_count, 2, msg="A failed lease must allow a later retry.")

    def test__dhcp6_client__trigger_other_failure_allows_retry(self) -> None:
        """
        Ensure a failed stateless fetch leaves the client unconfigured so a
        later trigger retries.

        Reference: RFC 8415 §18.2.6 (retry on a failed exchange).
        """

        self._fetch.return_value = None

        self._client.trigger(managed=False, other=True)
        self._client._subsystem_loop()
        self._client.trigger(managed=False, other=True)
        self._client._subsystem_loop()

        self.assertEqual(self._fetch.call_count, 2, msg="A failed fetch must allow a later retry.")

    def test__dhcp6_client__loop_without_trigger_is_idle(self) -> None:
        """
        Ensure the worker loop runs no exchange when no trigger is pending.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client._subsystem_loop()

        self._acquire.assert_not_called()
        self._fetch.assert_not_called()

    def test__dhcp6_client__stop_wakes_the_trigger(self) -> None:
        """
        Ensure '_stop()' wakes the worker out of its trigger wait so
        teardown does not block.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client._stop()

        self.assertTrue(self._client._event__trigger.is_set(), msg="_stop() must set the trigger event.")
