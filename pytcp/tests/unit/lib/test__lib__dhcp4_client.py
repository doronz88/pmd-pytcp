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
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from pytcp.lib import sysctl
from pytcp.lib.dhcp4_client import Dhcp4Client, Dhcp4Lease
from pytcp.lib.dhcp_uid import build_client_id
from pytcp.tests.lib.dhcp4_mock_server import (
    Dhcp4MockServer,
    autospec_dhcp4_socket,
)

_DEFAULT_MAC = MacAddress("02:00:00:00:00:01")
_DEFAULT_CID = build_client_id(_DEFAULT_MAC)
_PINNED_XID = 0xDEADBEEF


class TestDhcp4ClientInit(TestCase):
    """
    The 'Dhcp4Client' constructor tests.
    """

    def test__dhcp4_client__init_stores_mac_address(self) -> None:
        """
        Ensure the constructor stores the supplied MAC address. The
        per-recv timeout is no longer a constructor parameter — the
        Phase 1 backoff loop draws timeouts from the
        'dhcp.retrans_*' sysctl namespace instead.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertEqual(
            client._mac_address,
            _DEFAULT_MAC,
            msg="Dhcp4Client._mac_address must equal the MAC passed to the constructor.",
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
        subclass. Disable the Phase 2.1 startup desynchronisation
        delay by default so the suite does not actually sleep 1-10 s
        per 'fetch()'; tests that exercise the delay re-enable it
        via 'sysctl.override' in their own bodies.
        """

        self._server = Dhcp4MockServer()
        self._socket_factory = autospec_dhcp4_socket()
        self._sock = self._socket_factory.return_value
        self._server.wire(self._sock)
        self.enterContext(patch("pytcp.lib.dhcp4_client.socket", self._socket_factory))
        self.enterContext(patch("pytcp.lib.dhcp4_client.log"))
        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 0))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 0))


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

    def test__dhcp4_client__fetch_first_recv_uses_initial_retrans_window(self) -> None:
        """
        Ensure the first 'recv__mv' call uses a 'timeout' kwarg derived
        from 'dhcp.retrans_initial_ms' (Phase 1 backoff). With jitter
        disabled and 'retrans_initial_ms' pinned at 4000, the first
        recv must request a 4.0-second window.

        Reference: RFC 2131 §4.1 (first retransmit at 4 seconds).
        """

        with sysctl.override("dhcp.retrans_jitter_ms", 0):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        first_recv = self._sock.recv__mv.call_args_list[0]
        self.assertAlmostEqual(
            first_recv.kwargs["timeout"],
            4.0,
            places=2,
            msg="First recv__mv must use the dhcp.retrans_initial_ms-derived 4-second window.",
        )


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
        is silently dropped — under the Phase 1 backoff the bogus
        frame keeps the wait window open, the empty queue then times
        the window out, and (with the retransmit budget capped at 1
        for this test) 'fetch()' returns None without retransmitting.

        Reference: RFC 2131 §3.1 step 2 (server response to DISCOVER is DHCPOFFER).
        Reference: RFC 2131 §4.4.1 (mismatching messages silently discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
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
        Ensure a response to the Request with a non-ACK, non-NAK
        message type is silently dropped — Phase 1 keeps the wait
        window open, the empty queue then times the window out, and
        (with the retransmit budget capped at 1) 'fetch()' returns
        None without retransmitting the REQUEST.

        Reference: RFC 2131 §3.1 step 4 (server response to REQUEST is DHCPACK or DHCPNAK).
        Reference: RFC 2131 §4.4.1 (mismatching messages silently discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
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
        sent in DISCOVER is silently dropped — under Phase 1 the bogus
        frame keeps the wait window open without retransmitting; with
        the retransmit budget capped at 1 for this test, 'fetch()'
        returns None after the empty-queue timeout and the REQUEST is
        not sent.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
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


class TestDhcp4ClientFetchBackoffSilence(_Dhcp4ClientFixture):
    """
    The Phase 1 retransmission-backoff behavior under server silence.
    """

    @override
    def setUp(self) -> None:
        """
        Disable jitter for the duration of the test so the expected
        timeout sequence is deterministic, then enqueue 5 'TimeoutError'
        replies — one per backoff attempt.
        """

        super().setUp()
        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        for _ in range(5):
            self._server.enqueue_timeout()

    def test__dhcp4_client__fetch_silent_server_runs_5_attempts(self) -> None:
        """
        Ensure a fully silent server triggers exactly 5 'recv__mv'
        attempts and 5 outbound DISCOVERs (1 initial + 4 retransmits),
        then 'fetch()' returns None.

        Reference: RFC 2131 §4.1 (retransmission backoff with up to 5 attempts).
        """

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the server is silent across all retransmissions.",
        )
        self.assertEqual(
            self._sock.recv__mv.call_count,
            5,
            msg="Phase 1 backoff must make 5 recv attempts before giving up.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            5,
            msg="Phase 1 backoff must emit 5 DISCOVERs (1 initial + 4 retransmits).",
        )

    def test__dhcp4_client__fetch_silent_server_doubles_timeouts(self) -> None:
        """
        Ensure the 'timeout' kwarg passed to successive 'recv__mv'
        calls follows the doubling sequence 4 / 8 / 16 / 32 / 64
        seconds with jitter disabled.

        Reference: RFC 2131 §4.1 (retransmission delay doubled up to 64 seconds).
        """

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        timeouts = [call.kwargs["timeout"] for call in self._sock.recv__mv.call_args_list]
        self.assertEqual(
            timeouts,
            [4.0, 8.0, 16.0, 32.0, 64.0],
            msg="recv__mv timeouts must follow the 4/8/16/32/64 doubling sequence with jitter disabled.",
        )


class TestDhcp4ClientFetchBackoffEarlyExit(_Dhcp4ClientFixture):
    """
    Phase 1 backoff terminates early on the first valid OFFER.
    """

    def test__dhcp4_client__fetch_offer_on_third_attempt_returns_lease(self) -> None:
        """
        Ensure an OFFER arriving on the third attempt (after two
        timeouts) is accepted and 'fetch()' completes the exchange
        without continuing the doubling sequence.

        Reference: RFC 2131 §4.1 (retransmission loop terminates as soon as a valid reply arrives).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_timeout()
        self._server.enqueue_timeout()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease as soon as the server replies, mid-backoff.",
        )
        # Three OFFER-stage recv attempts (two timed out, third
        # succeeded) plus one ACK-stage recv = 4 total.
        self.assertEqual(
            self._sock.recv__mv.call_count,
            4,
            msg="recv__mv must be called once for each OFFER attempt plus once for the ACK.",
        )
        # Three DISCOVERs (initial + 2 retransmits) + 1 REQUEST.
        self.assertEqual(
            self._sock.send.call_count,
            4,
            msg="Send count must be 3 DISCOVERs (initial + 2 retransmits) plus 1 REQUEST.",
        )


class TestDhcp4ClientFetchBackoffBogusPacket(_Dhcp4ClientFixture):
    """
    Phase 1 backoff drops a bogus inbound packet without burning the
    current attempt's wait window.
    """

    def test__dhcp4_client__fetch_bogus_xid_in_window_does_not_burn_attempt(self) -> None:
        """
        Ensure an OFFER with a mismatching xid arriving mid-window is
        silently dropped and the client keeps waiting in the SAME
        wait window for a valid OFFER. The valid OFFER lands within
        the first 4-second window, so only one DISCOVER is emitted
        (no retransmit).

        Reference: RFC 2131 §4.4.1 (mismatched-xid messages discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_offer(xid=0x11111111)
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        # Pin random.randint so we know the DISCOVER's xid is not
        # 0x11111111 — the bogus OFFER will fail the xid gate.
        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=0xDEADBEEF,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must accept the second OFFER once the bogus first OFFER is silently dropped.",
        )
        # Two recv__mv calls during the OFFER stage (bogus + valid) +
        # one for the ACK = 3 total. NO retransmits — the bogus
        # packet did NOT trigger a new DISCOVER.
        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Bogus mid-window OFFER must NOT trigger a retransmit; only 1 DISCOVER + 1 REQUEST expected.",
        )


class TestDhcp4ClientFetchSecsField(_Dhcp4ClientFixture):
    """
    Phase 1 'secs' field advances per RFC 1542 §3.2 across the
    outbound DISCOVER / REQUEST messages within a fetch().
    """

    def test__dhcp4_client__first_discover_carries_secs_zero(self) -> None:
        """
        Ensure the very first DISCOVER carries 'secs' = 0 — the
        client has just begun the address-acquisition process so no
        time has elapsed.

        Reference: RFC 1542 §3.2 (secs field: seconds elapsed since the client began the address acquisition process).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertEqual(
            self._server.tx_log[0].secs,
            0,
            msg="First DISCOVER must carry secs=0.",
        )

    def test__dhcp4_client__retransmitted_discover_carries_advancing_secs(self) -> None:
        """
        Ensure a retransmitted DISCOVER's 'secs' field equals the
        integer number of seconds elapsed since the initial DISCOVER.
        Patches the '_elapsed_secs' helper to return 0, then 5, so
        the first DISCOVER carries secs=0 and the retransmitted
        DISCOVER (after the first window times out) carries secs=5.

        Reference: RFC 1542 §3.2 (secs field advances across retransmissions).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        # First attempt: server times out → client retransmits.
        # Second attempt: server replies with OFFER, then ACK.
        self._server.enqueue_timeout()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        # Patch the elapsed-seconds helper directly so the test is
        # decoupled from 'time.monotonic' call counts inside the
        # deadline-math loop.
        with patch.object(
            Dhcp4Client,
            "_elapsed_secs",
            side_effect=[0, 5, 5],
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertEqual(
            self._server.tx_log[0].secs,
            0,
            msg="First DISCOVER must carry secs=0.",
        )
        self.assertEqual(
            self._server.tx_log[1].secs,
            5,
            msg="Retransmitted DISCOVER must carry secs=5 after 5 s elapsed.",
        )


class TestDhcp4ClientFetchBackoffJitter(_Dhcp4ClientFixture):
    """
    Phase 1 jitter draws from a uniform ±retrans_jitter_ms window.
    """

    def test__dhcp4_client__fetch_jitter_draws_from_pm_jitter_ms(self) -> None:
        """
        Ensure 'random.uniform' is called with the symmetric
        '(-jitter_ms / 1000, +jitter_ms / 1000)' window before each
        recv attempt.

        Reference: RFC 2131 §4.1 (retransmission delay randomized by ±1 s).
        """

        self._server.enqueue_timeout()

        with patch(
            "pytcp.lib.dhcp4_client.random.uniform",
            return_value=0.0,
        ) as mock_uniform:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        # First (and only) jitter draw must use the configured
        # ±1000 ms bound expressed in seconds.
        mock_uniform.assert_any_call(-1.0, 1.0)


class TestDhcp4ClientFetchInitialDelay(_Dhcp4ClientFixture):
    """
    Phase 2.1 — RFC 2131 §4.4.1 "wait a random time between one and
    ten seconds to desynchronize the use of DHCP at startup".
    """

    def test__dhcp4_client__fetch_initial_delay_uses_default_bounds(self) -> None:
        """
        Ensure the startup desync delay draws from
        'random.uniform(1.0, 10.0)' when the
        'dhcp.init_delay_{min,max}_ms' sysctls are at their default
        values. The fixture base disables the delay by default, so
        this test restores the defaults locally before exercising
        'fetch()'.

        Reference: RFC 2131 §4.4.1 (client SHOULD wait a random time between one and ten seconds).
        """

        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 1000))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 10000))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with (
            patch("pytcp.lib.dhcp4_client.random.uniform", return_value=4.2) as mock_uniform,
            patch("pytcp.lib.dhcp4_client.time.sleep") as mock_sleep,
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_uniform.assert_any_call(1.0, 10.0)
        mock_sleep.assert_any_call(4.2)

    def test__dhcp4_client__fetch_initial_delay_honours_custom_sysctl_bounds(self) -> None:
        """
        Ensure operator overrides on 'dhcp.init_delay_min_ms' /
        'dhcp.init_delay_max_ms' propagate through to the
        'random.uniform' bounds (expressed in seconds).

        Reference: RFC 2131 §4.4.1 (the 1-10 s range is a SHOULD; tunable to fit deployment).
        """

        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 500))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 2500))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with (
            patch("pytcp.lib.dhcp4_client.random.uniform", return_value=1.0) as mock_uniform,
            patch("pytcp.lib.dhcp4_client.time.sleep"),
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        # 500 ms / 1000 = 0.5 s; 2500 ms / 1000 = 2.5 s.
        mock_uniform.assert_any_call(0.5, 2.5)

    def test__dhcp4_client__fetch_initial_delay_disabled_when_max_ms_zero(self) -> None:
        """
        Ensure the startup desync delay is bypassed entirely when
        'dhcp.init_delay_max_ms' is 0 — the canonical
        disable-for-tests configuration that the fixture base
        applies by default. 'time.sleep' must not be invoked from
        the initial-delay path on the happy-path 'fetch()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Fixture base already sets both bounds to 0; no override
        # needed here. The Phase 1 backoff path uses 'recv__mv(timeout=)'
        # rather than 'time.sleep', so 'time.sleep' should not be
        # called at all during a happy-path fetch.
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch("pytcp.lib.dhcp4_client.time.sleep") as mock_sleep:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_sleep.assert_not_called()


class TestDhcp4ClientFetchArpDad(_Dhcp4ClientFixture):
    """
    Phase 2.2 — ARP DAD verification + DHCPDECLINE on conflict.
    'Dhcp4Client.__init__' accepts an optional 'arp_dad_verifier'
    callback that 'fetch()' invokes against the leased address
    after a valid ACK; on False, the client emits DHCPDECLINE and
    restarts from DISCOVER per RFC 2131 §3.1 step 5.
    """

    def test__dhcp4_client__fetch_invokes_arp_dad_verifier_with_leased_address(self) -> None:
        """
        Ensure 'fetch()' invokes the caller-supplied
        'arp_dad_verifier' callback exactly once with the
        server-assigned 'yiaddr' after a valid ACK.

        Reference: RFC 2131 §3.1 step 5 (client SHOULD probe the offered address).
        Reference: RFC 5227 §2.1 (host MUST probe before claiming).
        """

        verifier = MagicMock(return_value=True)
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            arp_dad_verifier=verifier,
        ).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease when the verifier reports no conflict.",
        )
        verifier.assert_called_once_with(Ip4Address("10.0.0.100"))

    def test__dhcp4_client__fetch_without_verifier_returns_lease_unverified(self) -> None:
        """
        Ensure 'fetch()' returns the lease unverified when no
        'arp_dad_verifier' callback is supplied (backward
        compatibility with the Phase 0 / 1 / 2.1 invocation form).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() without a verifier must still return the lease unverified.",
        )

    def test__dhcp4_client__fetch_verifier_conflict_emits_decline_message(self) -> None:
        """
        Ensure a verifier conflict triggers a DHCPDECLINE TX whose
        message type, Server Identifier, Requested IP Address, and
        Client Identifier echo all carry the values from the offered
        lease.

        Reference: RFC 2131 §3.1 step 5 (the client MUST send a DHCPDECLINE message).
        Reference: RFC 2131 §4.4 Table 5 (DHCPDECLINE MUST carry Server ID + Requested IP).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        self.enterContext(sysctl.override("dhcp.nak_max_restarts", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        verifier = MagicMock(return_value=False)

        Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            arp_dad_verifier=verifier,
        ).fetch()

        # tx_log: [DISCOVER, REQUEST, DECLINE]
        self.assertEqual(
            len(self._server.tx_log),
            3,
            msg="DECLINE on conflict must produce exactly 3 outbound TXs (DISCOVER, REQUEST, DECLINE).",
        )
        decline = self._server.tx_log[2]
        self.assertEqual(
            decline.message_type,
            Dhcp4MessageType.DECLINE,
            msg="Third TX must carry message type DHCPDECLINE.",
        )
        self.assertEqual(
            decline.srv_id,
            Ip4Address("10.0.0.254"),
            msg="DECLINE must echo the OFFER's Server Identifier (option 54).",
        )
        self.assertEqual(
            decline.req_ip_addr,
            Ip4Address("10.0.0.100"),
            msg="DECLINE must carry the rejected yiaddr in the Requested IP Address option (50).",
        )
        self.assertEqual(
            decline.ciaddr,
            Ip4Address(),
            msg="DECLINE MUST carry ciaddr = 0 (the address has not been claimed).",
        )
        self.assertEqual(
            decline.client_id,
            _DEFAULT_CID,
            msg="DECLINE must carry the same Client Identifier as DISCOVER / REQUEST.",
        )

    def test__dhcp4_client__fetch_verifier_false_then_true_restarts_and_returns_lease(self) -> None:
        """
        Ensure a verifier that reports False once and then True on
        the retry produces a usable lease: 'fetch()' emits the
        DECLINE, restarts from DISCOVER, and succeeds on the
        second round.

        Reference: RFC 2131 §3.1 step 5 (DECLINE → restart configuration process).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        verifier = MagicMock(side_effect=[False, True])

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            arp_dad_verifier=verifier,
        ).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease when the second-round verifier reports no conflict.",
        )
        # tx_log: [DISCOVER, REQUEST, DECLINE, DISCOVER, REQUEST]
        self.assertEqual(
            len(self._server.tx_log),
            5,
            msg="DECLINE-then-restart path must emit 5 TXs (D, R, DECL, D, R).",
        )
        self.assertEqual(
            self._server.tx_log[2].message_type,
            Dhcp4MessageType.DECLINE,
            msg="Third TX must be the DECLINE bridging the two rounds.",
        )

    def test__dhcp4_client__fetch_verifier_always_false_exhausts_restart_budget(self) -> None:
        """
        Ensure a verifier that always reports conflict exhausts the
        shared restart budget ('dhcp.nak_max_restarts' = 3 means
        initial + 3 restarts = 4 rounds) and 'fetch()' returns None.
        Four DECLINEs are emitted, one per round.

        Reference: RFC 2131 §3.1 step 5 (DECLINE-and-restart is bounded to prevent infinite loops).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        for _ in range(4):
            self._server.enqueue_offer()
            self._server.enqueue_ack()

        verifier = MagicMock(return_value=False)

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            arp_dad_verifier=verifier,
        ).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the restart budget is exhausted on persistent conflict.",
        )
        # 4 rounds × 3 TXs (D, R, DECL) = 12.
        declines = [tx for tx in self._server.tx_log if tx.message_type == Dhcp4MessageType.DECLINE]
        self.assertEqual(
            len(declines),
            4,
            msg="Each restart round must emit one DECLINE; budget=3 yields 4 rounds.",
        )

    def test__dhcp4_client__fetch_decline_path_honours_decline_backoff_sleep(self) -> None:
        """
        Ensure 'fetch()' sleeps 'dhcp.decline_backoff_ms / 1000.0'
        seconds after emitting a DECLINE — the canonical
        "minimum of ten seconds" wait that prevents traffic
        floods on persistent conflict.

        Reference: RFC 2131 §3.1 step 5 (client SHOULD wait a minimum of ten seconds before restarting).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 5000))
        # Stop after the first DECLINE so only the one sleep we care
        # about is observed.
        self.enterContext(sysctl.override("dhcp.nak_max_restarts", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        verifier = MagicMock(return_value=False)

        with patch("pytcp.lib.dhcp4_client.time.sleep") as mock_sleep:
            Dhcp4Client(
                mac_address=_DEFAULT_MAC,
                arp_dad_verifier=verifier,
            ).fetch()

        # Initial-delay sleep is disabled by the fixture; only the
        # decline-backoff sleep should fire.
        mock_sleep.assert_called_once_with(5.0)


class TestDhcp4ClientFetchRfc4361Cid(_Dhcp4ClientFixture):
    """
    Phase 3 — Client Identifier emission and echo validation use
    the RFC 4361 form (type 0xff + IAID + DUID-LL) rather than the
    legacy RFC 2131 type-0x01 + MAC form.
    """

    def test__dhcp4_client__fetch_emits_rfc4361_client_id_in_discover_and_request(self) -> None:
        """
        Ensure both the DISCOVER and the REQUEST emitted by
        'fetch()' carry the RFC 4361 13-byte Client Identifier
        (type 0xff + 4-byte IAID + 8-byte DUID-LL) rather than
        the legacy RFC 2131 7-byte type-0x01 + MAC form.

        Reference: RFC 4361 §6.1 (new clients SHOULD use the type-0xff + IAID + DUID Client Identifier form).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        discover_cid = self._server.tx_log[0].client_id
        request_cid = self._server.tx_log[1].client_id

        self.assertEqual(
            discover_cid,
            build_client_id(_DEFAULT_MAC),
            msg="DISCOVER's Client Identifier must equal the RFC 4361 13-byte form.",
        )
        self.assertEqual(
            request_cid,
            discover_cid,
            msg="REQUEST's Client Identifier must equal DISCOVER's (stable across the exchange).",
        )

    def test__dhcp4_client__fetch_honours_dhcp_duid_sysctl_override(self) -> None:
        """
        Ensure setting 'dhcp.duid' to an operator-supplied hex
        string overrides the MAC-derived DUID portion of the
        emitted Client Identifier.

        Reference: RFC 4361 §6.1 (client MAY use an externally configured DUID).
        """

        override_duid_hex = "00:03:00:01:de:ad:be:ef:ca:fe"
        override_duid_bytes = bytes.fromhex(override_duid_hex.replace(":", ""))
        self.enterContext(sysctl.override("dhcp.duid", override_duid_hex))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        discover_cid = self._server.tx_log[0].client_id
        assert discover_cid is not None
        self.assertEqual(
            discover_cid[0:1],
            b"\xff",
            msg="RFC 4361 type prefix MUST be 0xff regardless of DUID override.",
        )
        self.assertEqual(
            discover_cid[5:],
            override_duid_bytes,
            msg="DUID portion of the Client Identifier must match the 'dhcp.duid' sysctl override.",
        )

    def test__dhcp4_client__fetch_emits_same_cid_across_two_fetches(self) -> None:
        """
        Ensure two consecutive 'fetch()' calls with the same MAC
        emit byte-for-byte identical Client Identifiers — DUID
        stability is required across the client's lifetime.

        Reference: RFC 4361 §6.1 (the DUID is stable across the client's life).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()
        client.fetch()

        first_cid = self._server.tx_log[0].client_id
        third_cid = self._server.tx_log[2].client_id  # 2nd fetch's DISCOVER

        self.assertEqual(
            first_cid,
            third_cid,
            msg="Two fetches with the same MAC must emit identical Client Identifiers.",
        )

    def test__dhcp4_client__fetch_rejects_server_echo_of_legacy_cid_form(self) -> None:
        """
        Ensure a server that mistakenly echoes the legacy
        RFC 2131 type-0x01 + MAC form (instead of the emitted
        type-0xff form) is silently discarded — the bytes do not
        match the emitted Client Identifier.

        Reference: RFC 6842 §3 (client MUST silently discard messages whose CID echo mismatches the sent value).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        legacy_cid = b"\x01" + bytes(_DEFAULT_MAC)
        self._server.enqueue_offer(client_id_echo=legacy_cid)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="OFFER echoing the legacy CID form must fail the RFC 6842 echo check and be discarded.",
        )
