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
This module contains tests for the 'Dhcp4Client'.

pytcp/tests/unit/lib/test__lib__dhcp4_client.py

ver 3.0.4
"""

from typing import override
from unittest import TestCase
from unittest.mock import call, patch

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from pytcp.lib.dhcp4_client import Dhcp4Client, Dhcp4Lease
from pytcp.tests.lib.dhcp4_mock_server import (
    Dhcp4MockServer,
    autospec_dhcp4_socket,
)

_DEFAULT_MAC = MacAddress("02:00:00:00:00:01")
_DEFAULT_CID = b"\x01" + bytes(_DEFAULT_MAC)
_PINNED_XID = 0xDEADBEEF


class TestDhcp4ClientInit(TestCase):
    """
    The 'Dhcp4Client' constructor tests.
    """

    def test__dhcp4_client__init_stores_mac_and_default_timeout(self) -> None:
        """
        Ensure the constructor stores the supplied MAC address and the
        default 5-second timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertEqual(
            client._mac_address,
            _DEFAULT_MAC,
            msg="Dhcp4Client._mac_address must equal the MAC passed to the constructor.",
        )
        self.assertEqual(
            client._timeout__sec,
            5,
            msg="Dhcp4Client._timeout__sec must default to 5 seconds.",
        )

    def test__dhcp4_client__init_accepts_custom_timeout(self) -> None:
        """
        Ensure the constructor honors a caller-supplied timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC, timeout__sec=30)

        self.assertEqual(
            client._timeout__sec,
            30,
            msg="Dhcp4Client._timeout__sec must equal the caller-supplied value.",
        )

    def test__dhcp4_client__init_keyword_only_arguments(self) -> None:
        """
        Ensure the constructor arguments are keyword-only — passing the
        MAC address positionally must raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            Dhcp4Client(_DEFAULT_MAC)  # type: ignore[misc]


class _Dhcp4ClientFixture(TestCase):
    """
    Shared fixture base. Subclasses build their own
    'Dhcp4MockServer', enqueue the replies the test needs, and call
    'self._fetch()' which patches the socket factory and the log
    channel for the duration of the call.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a 'Dhcp4MockServer' plus an autospec-locked socket
        factory whose return value is wired into the server. Patch
        'pytcp.lib.dhcp4_client.socket' (the factory call site) and
        the 'log' channel for the duration of every test in the
        subclass.
        """

        self._server = Dhcp4MockServer()
        self._socket_factory = autospec_dhcp4_socket()
        self._sock = self._socket_factory.return_value
        self._server.wire(self._sock)
        self.enterContext(patch("pytcp.lib.dhcp4_client.socket", self._socket_factory))
        self.enterContext(patch("pytcp.lib.dhcp4_client.log"))


class TestDhcp4ClientFetchHappyPath(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' happy-path tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the canonical lease scenario — an OFFER and ACK for
        '10.0.0.100/24' with gateway '10.0.0.1'.
        """

        super().setUp()
        self._server.enqueue_offer(router=[Ip4Address("10.0.0.1")])
        self._server.enqueue_ack(router=[Ip4Address("10.0.0.1")])

    def test__dhcp4_client__fetch_returns_lease_with_address_and_mask(self) -> None:
        """
        Ensure a valid Offer/Ack exchange yields a 'Dhcp4Lease' carrying
        an 'ip4_host' with the server-assigned address and subnet mask.

        Reference: RFC 2131 §3.1 (DHCP message exchange — DISCOVER → OFFER → REQUEST → ACK).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="Dhcp4Client.fetch() must return a Dhcp4Lease on a successful Offer/Ack exchange.",
        )
        assert result is not None
        self.assertIsInstance(
            result.ip4_host,
            Ip4Host,
            msg="Dhcp4Lease.ip4_host must be an Ip4Host.",
        )
        self.assertEqual(
            result.ip4_host.address,
            Ip4Address("10.0.0.100"),
            msg="Dhcp4Lease.ip4_host.address must equal the server-assigned yiaddr.",
        )
        self.assertEqual(
            result.ip4_host.network.mask,
            Ip4Mask("255.255.255.0"),
            msg="Dhcp4Lease.ip4_host.network.mask must equal the server-supplied subnet mask.",
        )

    def test__dhcp4_client__fetch_sets_gateway_when_router_option_present(self) -> None:
        """
        Ensure the first router address from the Router option is stored
        as the host's default gateway.

        Reference: RFC 2132 §3.5 (Router Option — option code 3).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        assert result is not None
        self.assertEqual(
            result.ip4_host.gateway,
            Ip4Address("10.0.0.1"),
            msg="Dhcp4Lease.ip4_host.gateway must equal the first router address in the DHCP Router option.",
        )

    def test__dhcp4_client__fetch_binds_and_connects_to_dhcp_ports(self) -> None:
        """
        Ensure the client binds to the canonical DHCPv4 client port 68
        on the unspecified IPv4 address and 'connects' to the broadcast
        address on port 67 before sending the Discover packet.

        Reference: RFC 2131 §4.1 (Constructing and sending DHCP messages — server port 67, client port 68).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self._sock.bind.assert_called_once_with(("0.0.0.0", 68))
        self._sock.connect.assert_called_once_with(("255.255.255.255", 67))

    def test__dhcp4_client__fetch_sends_two_packets(self) -> None:
        """
        Ensure the happy path sends exactly two packets — the initial
        Discover and the follow-up Request.

        Reference: RFC 2131 §3.1 (DHCP message exchange — DISCOVER → OFFER → REQUEST → ACK).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Happy-path fetch() must send two packets (Discover + Request).",
        )
        self.assertEqual(
            self._server.tx_log[0].message_type,
            Dhcp4MessageType.DISCOVER,
            msg="First emitted packet must be a DHCPDISCOVER.",
        )
        self.assertEqual(
            self._server.tx_log[1].message_type,
            Dhcp4MessageType.REQUEST,
            msg="Second emitted packet must be a DHCPREQUEST.",
        )

    def test__dhcp4_client__fetch_closes_socket_on_success(self) -> None:
        """
        Ensure the UDP socket is closed before 'fetch()' returns the
        negotiated lease.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self._sock.close.assert_called_once_with()

    def test__dhcp4_client__fetch_uses_configured_timeout_on_recv(self) -> None:
        """
        Ensure the per-call 'timeout' kwarg passed to 'recv__mv' matches
        the value supplied to the client constructor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC, timeout__sec=7)
        client.fetch()

        self._sock.recv__mv.assert_has_calls([call(timeout=7), call(timeout=7)])


class TestDhcp4ClientFetchNoRouter(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' 'router option absent' happy-path test.
    """

    def test__dhcp4_client__fetch_no_router_leaves_gateway_unset(self) -> None:
        """
        Ensure the host returned by 'fetch()' has no gateway set when
        the DHCP Ack lacks a Router option (the 'router is None' branch
        in the source).

        Reference: RFC 2132 §3.5 (Router Option — optional, may be absent).
        """

        self._server.enqueue_offer(router=None)
        self._server.enqueue_ack(router=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        assert result is not None
        self.assertIsNone(
            result.ip4_host.gateway,
            msg="Dhcp4Lease.ip4_host.gateway must remain None when the DHCP Ack carries no Router option.",
        )


class TestDhcp4ClientFetchOfferTimeout(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Offer-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Offer receive collapses the
        exchange: 'fetch()' returns None and the socket is closed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_timeout()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer receive times out.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchOfferWrongMessageType(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Offer-with-wrong-type failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_wrong_offer_message_type(self) -> None:
        """
        Ensure a response to the Discover with a non-OFFER message type
        aborts the exchange: 'fetch()' returns None and the socket is
        closed. Uses an ACK message type as the bogus payload to avoid
        colliding with the dedicated NAK-restart semantics exercised
        elsewhere.

        Reference: RFC 2131 §3.1 step 2 (server response to DISCOVER is DHCPOFFER).
        """

        self._server.enqueue_offer(message_type=Dhcp4MessageType.ACK)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the first response is not a DHCP Offer.",
        )
        self._sock.close.assert_called_once_with()
        self.assertEqual(
            self._sock.send.call_count,
            1,
            msg="Only the Discover must be sent when the Offer message-type check fails.",
        )


class TestDhcp4ClientFetchAckTimeout(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Ack-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Ack receive — after a valid
        Offer — aborts the exchange: 'fetch()' returns None and the
        socket is closed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_timeout()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack receive times out.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchAckWrongMessageType(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Ack-with-wrong-non-NAK-type failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_wrong_ack_message_type(self) -> None:
        """
        Ensure a response to the Request with a non-ACK, non-NAK message
        type aborts the exchange: 'fetch()' returns None and the socket
        is closed. (DHCPNAK has dedicated restart semantics covered by
        the NAK-restart test class — this case uses a stray OFFER.)

        Reference: RFC 2131 §3.1 step 4 (server response to REQUEST is DHCPACK or DHCPNAK).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(message_type=Dhcp4MessageType.OFFER)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the second response is neither an ACK nor a NAK.",
        )
        self._sock.close.assert_called_once_with()
        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Both Discover and Request must be sent before the Ack message-type check fails.",
        )


class TestDhcp4ClientFetchOfferSrvIdNone(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Offer without Server-ID.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_without_srv_id(self) -> None:
        """
        Ensure 'fetch()' returns None when the Offer omits the
        Server-ID option. The Request must not be sent and the socket
        must be closed.

        Reference: RFC 2131 §3.1 step 2 (Server identifier required in DHCPOFFER).
        """

        self._server.enqueue_offer(server_id=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer omits the Server-ID option.",
        )
        self._sock.close.assert_called_once_with()
        self.assertEqual(
            self._sock.send.call_count,
            1,
            msg="Only the Discover packet must be sent when the Offer's srv_id is missing.",
        )


class TestDhcp4ClientFetchAckMissingSubnetMask(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Ack without Subnet Mask.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_without_subnet_mask(self) -> None:
        """
        Ensure 'fetch()' returns None when the Ack omits the Subnet
        Mask option. The socket must still be closed.

        Reference: RFC 2132 §3.3 (Subnet Mask option — option code 1).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(subnet_mask=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack omits the Subnet Mask option.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchXid(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' transaction-ID generation tests.
    """

    def test__dhcp4_client__fetch_uses_random_randint_for_xid(self) -> None:
        """
        Ensure each 'fetch()' call draws a fresh xid via
        'random.randint(0, 0xFFFFFFFF)'. Pinning the PRNG call shape
        guards against accidental reseeding or range changes.

        Reference: RFC 2131 §4.1 (xid is a random 32-bit number).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=_PINNED_XID,
        ) as mock_randint:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_randint.assert_called_once_with(0, 0xFFFFFFFF)

    def test__dhcp4_client__fetch_regenerates_xid_per_call(self) -> None:
        """
        Ensure successive 'fetch()' calls draw a new xid each time so
        a stale Offer from a previous transaction cannot be matched
        against a fresh handshake.

        Reference: RFC 2131 §4.1 (each new exchange uses a fresh xid).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=_PINNED_XID,
        ) as mock_randint:
            client = Dhcp4Client(mac_address=_DEFAULT_MAC)
            client.fetch()
            client.fetch()

        self.assertEqual(
            mock_randint.call_count,
            2,
            msg="random.randint must be called once per fetch() to regenerate the xid.",
        )


class TestDhcp4ClientFetchClientIdInRequest(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Client Identifier emission in REQUEST.
    """

    def test__dhcp4_client__send_request_includes_client_id(self) -> None:
        """
        Ensure the REQUEST packet emitted in response to a valid OFFER
        carries the Client Identifier option ('\\x01' + MAC).

        Reference: RFC 2131 §2 (Client Identifier).
        Reference: RFC 2131 §4.4.1 (client SHOULD include client identifier in every message).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        request = self._server.tx_log[1]
        self.assertEqual(
            request.message_type,
            Dhcp4MessageType.REQUEST,
            msg="Sanity: the second TX must be a DHCPREQUEST.",
        )
        self.assertEqual(
            request.client_id,
            _DEFAULT_CID,
            msg="REQUEST must include the Client Identifier option carrying b'\\x01' + MAC.",
        )


class TestDhcp4ClientFetchXidMismatch(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' xid-mismatch silent-drop tests.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_xid_mismatch(self) -> None:
        """
        Ensure an OFFER whose 'xid' does not match the value the client
        sent in DISCOVER is silently dropped: 'fetch()' returns None
        and the REQUEST is not sent.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        self._server.enqueue_offer(xid=0x11111111)

        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=_PINNED_XID,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the OFFER xid does not match the DISCOVER xid.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            1,
            msg="Only DISCOVER must be sent when the OFFER xid is rejected.",
        )

    def test__dhcp4_client__fetch_returns_none_on_ack_xid_mismatch(self) -> None:
        """
        Ensure an ACK whose 'xid' does not match the value the client
        sent in REQUEST is silently dropped: 'fetch()' returns None.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(xid=0x22222222)

        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=_PINNED_XID,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK xid does not match the REQUEST xid.",
        )


class TestDhcp4ClientFetchCidEcho(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Client Identifier echo-validation tests.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_cid_mismatch(self) -> None:
        """
        Ensure an OFFER whose echoed Client Identifier does not match
        the value the client emitted is silently dropped.

        Reference: RFC 6842 §3 (client MUST compare echoed CID and silently discard mismatching messages).
        """

        self._server.enqueue_offer(
            client_id_echo=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")),
        )

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the OFFER echoes a mismatching Client Identifier.",
        )

    def test__dhcp4_client__fetch_returns_none_on_ack_cid_mismatch(self) -> None:
        """
        Ensure an ACK whose echoed Client Identifier does not match
        the value the client emitted is silently dropped.

        Reference: RFC 6842 §3 (client MUST compare echoed CID and silently discard mismatching messages).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(
            client_id_echo=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")),
        )

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK echoes a mismatching Client Identifier.",
        )

    def test__dhcp4_client__fetch_accepts_matching_cid_echo(self) -> None:
        """
        Ensure an OFFER/ACK pair whose echoed Client Identifier matches
        the client's emitted CID is accepted (regression guard against
        the new validator over-rejecting the happy path).

        Reference: RFC 6842 §3 (matching CID echo must not be discarded).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must accept matching Client Identifier echoes.",
        )


class TestDhcp4ClientFetchNakRestart(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' DHCPNAK bounded-restart tests.
    """

    def test__dhcp4_client__fetch_restarts_from_discover_on_ack_stage_nak(self) -> None:
        """
        Ensure a DHCPNAK arriving in response to the REQUEST triggers a
        restart from DISCOVER and the second exchange yields a usable
        lease. The successful round-trip after NAK confirms the
        client's bounded-restart loop, distinct from the silent-drop
        path that 'wrong message type' takes.

        Reference: RFC 2131 §3.1 step 4 (DHCPNAK → restart from DHCPDISCOVER).
        """

        self._server.enqueue_offer()
        self._server.enqueue_nak()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must restart from DISCOVER on NAK and return a lease when the retry succeeds.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            4,
            msg="NAK-restart path must send DISCOVER, REQUEST, DISCOVER, REQUEST.",
        )

    def test__dhcp4_client__fetch_returns_none_after_max_nak_restarts(self) -> None:
        """
        Ensure 'fetch()' returns None once the bounded NAK-restart
        budget is exhausted. With the default budget of 3 restarts,
        four NAK rounds (initial + 3 restarts) exhaust the loop and
        no further DISCOVER is emitted.

        Reference: RFC 2131 §3.1 step 4 (NAK → restart; bounded to avoid loops).
        """

        for _ in range(4):
            self._server.enqueue_offer()
            self._server.enqueue_nak()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None after the NAK-restart budget is exhausted.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            8,
            msg="Four DISCOVER/REQUEST round-trips must be attempted before giving up (initial + 3 restarts).",
        )


class TestDhcp4ClientFetchLeaseReturn(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Dhcp4Lease return-shape tests.
    """

    def test__dhcp4_client__fetch_returns_lease_time_from_ack(self) -> None:
        """
        Ensure 'Dhcp4Lease.lease_time__sec' equals the lease-time value
        carried by the ACK's option 51.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option — code 51).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(lease_time=7200)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.lease_time__sec,
            7200,
            msg="Dhcp4Lease.lease_time__sec must equal the ACK's option 51 value.",
        )

    def test__dhcp4_client__fetch_records_server_id_on_lease(self) -> None:
        """
        Ensure 'Dhcp4Lease.server_id' equals the Server Identifier from
        the OFFER so subsequent RENEW/REBIND/DECLINE messages can
        target the correct server.

        Reference: RFC 2131 §4.3.2 (server identifier carried into REQUEST/RENEW).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.server_id,
            Ip4Address("10.0.0.254"),
            msg="Dhcp4Lease.server_id must equal the OFFER's Server Identifier.",
        )

    def test__dhcp4_client__fetch_records_acquired_at_monotonic(self) -> None:
        """
        Ensure 'Dhcp4Lease.acquired_at_monotonic' captures a monotonic
        timestamp at lease acquisition so the lifecycle thread can
        compute T1/T2 expiries without a wall-clock dependency.

        Reference: RFC 2131 §4.4.5 (T1/T2 timing relative to lease acquisition).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch("pytcp.lib.dhcp4_client.time.monotonic", return_value=1234.5):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.acquired_at_monotonic,
            1234.5,
            msg="Dhcp4Lease.acquired_at_monotonic must equal time.monotonic() at acquisition.",
        )


class TestDhcp4ClientFetchAckMissingLeaseTime(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Ack without lease time.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_without_lease_time(self) -> None:
        """
        Ensure 'fetch()' returns None when the ACK omits the IP Address
        Lease Time option. Without a lease duration the lifecycle has
        no T1/T2 to schedule against, so the lease is unusable.

        Reference: RFC 2131 Table 3 (IP address lease time MUST be present in DHCPACK).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(lease_time=None)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK omits the IP Address Lease Time option.",
        )
