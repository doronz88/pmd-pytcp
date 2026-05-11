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

from types import SimpleNamespace
from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from pytcp.lib.dhcp4_client import Dhcp4Client, Dhcp4Lease

_DEFAULT_MAC = MacAddress("02:00:00:00:00:01")
_DEFAULT_CID = b"\x01" + bytes(_DEFAULT_MAC)
_DEFAULT_XID = 0xDEADBEEF
_DEFAULT_LEASE_TIME = 3600


def _stub_offer(
    *,
    xid: int = _DEFAULT_XID,
    srv_id: Ip4Address | None = Ip4Address("10.0.0.254"),
    yiaddr: Ip4Address = Ip4Address("10.0.0.100"),
    subnet_mask: Ip4Mask | None = Ip4Mask("255.255.255.0"),
    router: list[Ip4Address] | None = None,
    client_id: bytes | None = None,
    lease_time: int | None = _DEFAULT_LEASE_TIME,
    message_type: Dhcp4MessageType = Dhcp4MessageType.OFFER,
) -> SimpleNamespace:
    """
    Build a 'SimpleNamespace' standing in for a parsed DHCP Offer with
    every attribute the source code reads, defaulted so that happy-path
    construction matches the canonical fixture lease '10.0.0.100/24'.
    """

    return SimpleNamespace(
        message_type=message_type,
        xid=xid,
        srv_id=srv_id,
        yiaddr=yiaddr,
        subnet_mask=subnet_mask,
        router=router,
        client_id=client_id,
        lease_time=lease_time,
    )


def _stub_ack(
    *,
    xid: int = _DEFAULT_XID,
    srv_id: Ip4Address | None = Ip4Address("10.0.0.254"),
    yiaddr: Ip4Address = Ip4Address("10.0.0.100"),
    subnet_mask: Ip4Mask | None = Ip4Mask("255.255.255.0"),
    router: list[Ip4Address] | None = None,
    client_id: bytes | None = None,
    lease_time: int | None = _DEFAULT_LEASE_TIME,
    message_type: Dhcp4MessageType = Dhcp4MessageType.ACK,
) -> SimpleNamespace:
    """
    Build a 'SimpleNamespace' standing in for a parsed DHCP Ack with
    every attribute the source code reads, defaulted so that happy-path
    construction yields a usable lease.
    """

    return SimpleNamespace(
        message_type=message_type,
        xid=xid,
        srv_id=srv_id,
        yiaddr=yiaddr,
        subnet_mask=subnet_mask,
        router=router,
        client_id=client_id,
        lease_time=lease_time,
    )


def _make_parser_factory(*responses: SimpleNamespace | Exception) -> MagicMock:
    """
    Build a 'Dhcp4Parser' replacement that returns (or raises) the
    provided sentinels on successive calls. Each variadic argument is
    one synthetic parser instance (or a 'TimeoutError' / other
    exception) consumed in order across the fetch() round-trips.
    """

    factory = MagicMock(name="Dhcp4Parser")
    factory.side_effect = list(responses)
    return factory


def _build_mock_socket(*recv_payloads: bytes | TimeoutError) -> MagicMock:
    """
    Build a socket-like 'MagicMock' whose 'recv__mv' yields the given
    byte payloads (or raises 'TimeoutError' when supplied) across
    successive calls. Any other method ('bind', 'connect', 'send',
    'close') is recorded for later inspection.
    """

    sock = MagicMock(name="socket")
    sock.recv__mv.side_effect = list(recv_payloads)
    return sock


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


class TestDhcp4ClientFetchHappyPath(TestCase):
    """
    The 'Dhcp4Client.fetch()' happy-path tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a DHCP Offer and ACK pair that produces a valid lease on
        '10.0.0.100/24' with gateway '10.0.0.1', plus the matching
        socket and parser stubs shared by every happy-path test. Patch
        the socket factory, parser class, log channel, and random xid
        for the duration of each test via 'enterContext'.
        """

        self._offer = _stub_offer(router=[Ip4Address("10.0.0.1")])
        self._ack = _stub_ack(router=[Ip4Address("10.0.0.1")])
        self._sock = _build_mock_socket(b"offer", b"ack")
        self._parser = _make_parser_factory(self._offer, self._ack)

        self.enterContext(patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock))
        self.enterContext(patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser))
        self.enterContext(patch("pytcp.lib.dhcp4_client.log"))
        self.enterContext(
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        )

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


class TestDhcp4ClientFetchNoRouter(TestCase):
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

        offer = _stub_offer(router=None)
        ack = _stub_ack(router=None)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        assert result is not None
        self.assertIsNone(
            result.ip4_host.gateway,
            msg="Dhcp4Lease.ip4_host.gateway must remain None when the DHCP Ack carries no Router option.",
        )


class TestDhcp4ClientFetchOfferTimeout(TestCase):
    """
    The 'Dhcp4Client.fetch()' Offer-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Offer receive collapses the
        exchange: 'fetch()' returns None and the socket is closed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _build_mock_socket(TimeoutError())
        parser = MagicMock(name="Dhcp4Parser")

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer receive times out.",
        )
        sock.close.assert_called_once_with()
        parser.assert_not_called()


class TestDhcp4ClientFetchOfferWrongMessageType(TestCase):
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

        bogus = _stub_offer(message_type=Dhcp4MessageType.ACK)
        sock = _build_mock_socket(b"offer")
        parser = _make_parser_factory(bogus)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the first response is not a DHCP Offer.",
        )
        sock.close.assert_called_once_with()
        self.assertEqual(
            sock.send.call_count,
            1,
            msg="Only the Discover must be sent when the Offer message-type check fails.",
        )


class TestDhcp4ClientFetchAckTimeout(TestCase):
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

        offer = _stub_offer()
        sock = _build_mock_socket(b"offer", TimeoutError())
        parser = _make_parser_factory(offer)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack receive times out.",
        )
        sock.close.assert_called_once_with()


class TestDhcp4ClientFetchAckWrongMessageType(TestCase):
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

        offer = _stub_offer()
        bogus_ack = _stub_ack(message_type=Dhcp4MessageType.OFFER)
        sock = _build_mock_socket(b"offer", b"bogus")
        parser = _make_parser_factory(offer, bogus_ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the second response is neither an ACK nor a NAK.",
        )
        sock.close.assert_called_once_with()
        self.assertEqual(
            sock.send.call_count,
            2,
            msg="Both Discover and Request must be sent before the Ack message-type check fails.",
        )


class TestDhcp4ClientFetchOfferSrvIdNone(TestCase):
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

        offer = _stub_offer(srv_id=None)
        sock = _build_mock_socket(b"offer")
        parser = _make_parser_factory(offer)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer omits the Server-ID option.",
        )
        sock.close.assert_called_once_with()
        self.assertEqual(
            sock.send.call_count,
            1,
            msg="Only the Discover packet must be sent when the Offer's srv_id is missing.",
        )


class TestDhcp4ClientFetchAckMissingSubnetMask(TestCase):
    """
    The 'Dhcp4Client.fetch()' rejection of an Ack without Subnet Mask.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_without_subnet_mask(self) -> None:
        """
        Ensure 'fetch()' returns None when the Ack omits the Subnet
        Mask option. The socket must still be closed.

        Reference: RFC 2132 §3.3 (Subnet Mask option — option code 1).
        """

        offer = _stub_offer()
        ack = _stub_ack(subnet_mask=None)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack omits the Subnet Mask option.",
        )
        sock.close.assert_called_once_with()


class TestDhcp4ClientFetchXid(TestCase):
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

        offer = _stub_offer()
        ack = _stub_ack()
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch(
                "pytcp.lib.dhcp4_client.random.randint",
                return_value=_DEFAULT_XID,
            ) as mock_randint,
        ):
            client.fetch()

        mock_randint.assert_called_once_with(0, 0xFFFFFFFF)

    def test__dhcp4_client__fetch_regenerates_xid_per_call(self) -> None:
        """
        Ensure successive 'fetch()' calls draw a new xid each time so
        a stale Offer from a previous transaction cannot be matched
        against a fresh handshake.

        Reference: RFC 2131 §4.1 (each new exchange uses a fresh xid).
        """

        sock = _build_mock_socket(b"offer-1", b"ack-1", b"offer-2", b"ack-2")
        parser = _make_parser_factory(
            _stub_offer(),
            _stub_ack(),
            _stub_offer(),
            _stub_ack(),
        )

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch(
                "pytcp.lib.dhcp4_client.random.randint",
                return_value=_DEFAULT_XID,
            ) as mock_randint,
        ):
            client.fetch()
            client.fetch()

        self.assertEqual(
            mock_randint.call_count,
            2,
            msg="random.randint must be called once per fetch() to regenerate the xid.",
        )


class TestDhcp4ClientFetchClientIdInRequest(TestCase):
    """
    The 'Dhcp4Client.fetch()' Client Identifier emission in REQUEST.
    """

    def test__dhcp4_client__send_request_includes_client_id(self) -> None:
        """
        Ensure the REQUEST packet emitted in response to a valid OFFER
        carries the Client Identifier option ('\\x01' + MAC). Parses
        the second TX payload back through the real Dhcp4Parser and
        reads its 'client_id' accessor.

        Reference: RFC 2131 §2 (Client Identifier).
        Reference: RFC 2131 §4.4.1 (client SHOULD include client identifier in every message).
        """

        offer = _stub_offer()
        ack = _stub_ack()
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            client.fetch()

        request_bytes = bytes(sock.send.call_args_list[1].args[0])
        request = Dhcp4Parser(memoryview(request_bytes))
        self.assertEqual(
            request.client_id,
            _DEFAULT_CID,
            msg="REQUEST must include the Client Identifier option carrying b'\\x01' + MAC.",
        )


class TestDhcp4ClientFetchXidMismatch(TestCase):
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

        offer = _stub_offer(xid=0x11111111)
        sock = _build_mock_socket(b"offer")
        parser = _make_parser_factory(offer)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the OFFER xid does not match the DISCOVER xid.",
        )
        self.assertEqual(
            sock.send.call_count,
            1,
            msg="Only DISCOVER must be sent when the OFFER xid is rejected.",
        )

    def test__dhcp4_client__fetch_returns_none_on_ack_xid_mismatch(self) -> None:
        """
        Ensure an ACK whose 'xid' does not match the value the client
        sent in REQUEST is silently dropped: 'fetch()' returns None.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        offer = _stub_offer()
        ack = _stub_ack(xid=0x22222222)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK xid does not match the REQUEST xid.",
        )


class TestDhcp4ClientFetchCidEcho(TestCase):
    """
    The 'Dhcp4Client.fetch()' Client Identifier echo-validation tests.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_cid_mismatch(self) -> None:
        """
        Ensure an OFFER whose echoed Client Identifier does not match
        the value the client emitted is silently dropped.

        Reference: RFC 6842 §3 (client MUST compare echoed CID and silently discard mismatching messages).
        """

        offer = _stub_offer(client_id=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")))
        sock = _build_mock_socket(b"offer")
        parser = _make_parser_factory(offer)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

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

        offer = _stub_offer()
        ack = _stub_ack(client_id=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")))
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

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

        offer = _stub_offer(client_id=_DEFAULT_CID)
        ack = _stub_ack(client_id=_DEFAULT_CID)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must accept matching Client Identifier echoes.",
        )


class TestDhcp4ClientFetchNakRestart(TestCase):
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

        offer_1 = _stub_offer()
        nak = _stub_ack(message_type=Dhcp4MessageType.NAK)
        offer_2 = _stub_offer()
        ack = _stub_ack()
        sock = _build_mock_socket(b"offer-1", b"nak", b"offer-2", b"ack")
        parser = _make_parser_factory(offer_1, nak, offer_2, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must restart from DISCOVER on NAK and return a lease when the retry succeeds.",
        )
        self.assertEqual(
            sock.send.call_count,
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

        rounds = [
            _stub_offer(),
            _stub_ack(message_type=Dhcp4MessageType.NAK),
            _stub_offer(),
            _stub_ack(message_type=Dhcp4MessageType.NAK),
            _stub_offer(),
            _stub_ack(message_type=Dhcp4MessageType.NAK),
            _stub_offer(),
            _stub_ack(message_type=Dhcp4MessageType.NAK),
        ]
        recv_payloads: list[bytes | TimeoutError] = [b"payload"] * 8
        sock = _build_mock_socket(*recv_payloads)
        parser = _make_parser_factory(*rounds)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None after the NAK-restart budget is exhausted.",
        )
        self.assertEqual(
            sock.send.call_count,
            8,
            msg="Four DISCOVER/REQUEST round-trips must be attempted before giving up (initial + 3 restarts).",
        )


class TestDhcp4ClientFetchLeaseReturn(TestCase):
    """
    The 'Dhcp4Client.fetch()' Dhcp4Lease return-shape tests.
    """

    def test__dhcp4_client__fetch_returns_lease_time_from_ack(self) -> None:
        """
        Ensure 'Dhcp4Lease.lease_time__sec' equals the lease-time value
        carried by the ACK's option 51.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option — code 51).
        """

        offer = _stub_offer()
        ack = _stub_ack(lease_time=7200)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

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

        offer = _stub_offer(srv_id=Ip4Address("10.0.0.254"))
        ack = _stub_ack()
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

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

        offer = _stub_offer()
        ack = _stub_ack()
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
            patch("pytcp.lib.dhcp4_client.time.monotonic", return_value=1234.5),
        ):
            result = client.fetch()

        assert result is not None
        self.assertEqual(
            result.acquired_at_monotonic,
            1234.5,
            msg="Dhcp4Lease.acquired_at_monotonic must equal time.monotonic() at acquisition.",
        )


class TestDhcp4ClientFetchAckMissingLeaseTime(TestCase):
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

        offer = _stub_offer()
        ack = _stub_ack(lease_time=None)
        sock = _build_mock_socket(b"offer", b"ack")
        parser = _make_parser_factory(offer, ack)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
            patch("pytcp.lib.dhcp4_client.random.randint", return_value=_DEFAULT_XID),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK omits the IP Address Lease Time option.",
        )
