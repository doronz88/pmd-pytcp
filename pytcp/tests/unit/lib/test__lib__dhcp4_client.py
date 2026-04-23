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
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from pytcp.lib.dhcp4_client import Dhcp4Client


def _make_parser_factory(
    *,
    offer: SimpleNamespace | Exception,
    ack: SimpleNamespace | Exception | None = None,
) -> MagicMock:
    """
    Build a 'Dhcp4Parser' replacement that returns (or raises) the
    provided sentinels on successive calls. The first call models the
    DHCP Offer, the second models the DHCP Ack; if 'ack' is None only
    the Offer call is expected.
    """

    responses: list[SimpleNamespace | Exception] = [offer]
    if ack is not None:
        responses.append(ack)

    factory = MagicMock(name="Dhcp4Parser")
    factory.side_effect = responses
    return factory


def _build_mock_socket(
    *,
    offer_payload: bytes | TimeoutError,
    ack_payload: bytes | TimeoutError | None = None,
) -> MagicMock:
    """
    Build a socket-like 'MagicMock' whose 'recv__mv' yields the given
    byte payloads (or raises 'TimeoutError' when supplied). Any other
    method call ('bind', 'connect', 'send', 'close') is recorded for
    later inspection.
    """

    sock = MagicMock(name="socket")

    recv_responses: list[bytes | TimeoutError] = [offer_payload]
    if ack_payload is not None:
        recv_responses.append(ack_payload)
    sock.recv__mv.side_effect = recv_responses

    return sock


class TestDhcp4ClientInit(TestCase):
    """
    The 'Dhcp4Client' constructor tests.
    """

    def test__dhcp4_client__init_stores_mac_and_default_timeout(self) -> None:
        """
        Ensure the constructor stores the supplied MAC address and the
        default 5-second timeout.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        self.assertEqual(
            client._mac_address,
            MacAddress("02:00:00:00:00:01"),
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
        """

        client = Dhcp4Client(
            mac_address=MacAddress("02:00:00:00:00:01"),
            timeout__sec=30,
        )

        self.assertEqual(
            client._timeout__sec,
            30,
            msg="Dhcp4Client._timeout__sec must equal the caller-supplied value.",
        )

    def test__dhcp4_client__init_generates_xid_in_uint32_range(self) -> None:
        """
        Ensure the transaction ID is drawn from the 32-bit unsigned
        integer range — 'random.randint(0, 0xFFFFFFFF)' in the source.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        self.assertGreaterEqual(
            client._xid,
            0,
            msg="Dhcp4Client._xid must be >= 0.",
        )
        self.assertLessEqual(
            client._xid,
            0xFFFFFFFF,
            msg="Dhcp4Client._xid must be <= 0xFFFFFFFF (UINT32 max).",
        )

    def test__dhcp4_client__init_uses_random_randint_for_xid(self) -> None:
        """
        Ensure the transaction ID is produced by 'random.randint' with
        the canonical (0, 0xFFFFFFFF) arguments. Pinning the PRNG call
        shape guards against accidental reseeding or range changes.
        """

        with patch(
            "pytcp.lib.dhcp4_client.random.randint",
            return_value=0xDEADBEEF,
        ) as mock_randint:
            client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        mock_randint.assert_called_once_with(0, 0xFFFFFFFF)
        self.assertEqual(
            client._xid,
            0xDEADBEEF,
            msg="Dhcp4Client._xid must be populated from random.randint(0, 0xFFFFFFFF).",
        )

    def test__dhcp4_client__init_keyword_only_arguments(self) -> None:
        """
        Ensure the constructor arguments are keyword-only — passing the
        MAC address positionally must raise 'TypeError'.
        """

        with self.assertRaises(TypeError):
            Dhcp4Client(MacAddress("02:00:00:00:00:01"))  # type: ignore[misc]


class TestDhcp4ClientFetchHappyPath(TestCase):
    """
    The 'Dhcp4Client.fetch()' happy-path tests.
    """

    def setUp(self) -> None:
        """
        Build a DHCP Offer and ACK pair that produces a valid
        lease on '10.0.0.100/24' with gateway '10.0.0.1', plus the
        matching socket and log patches shared by every happy-path
        test in this class.
        """

        self._offer = SimpleNamespace(
            message_type=Dhcp4MessageType.OFFER,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=[Ip4Address("10.0.0.1")],
        )
        self._ack = SimpleNamespace(
            message_type=Dhcp4MessageType.ACK,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=[Ip4Address("10.0.0.1")],
        )

        self._sock = _build_mock_socket(offer_payload=b"offer", ack_payload=b"ack")
        self._parser = _make_parser_factory(offer=self._offer, ack=self._ack)

    def test__dhcp4_client__fetch_returns_ip4_host_with_address_and_mask(self) -> None:
        """
        Ensure a valid Offer/Ack exchange yields an 'Ip4Host' carrying
        the server-assigned address and subnet mask.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        self.assertIsInstance(
            result,
            Ip4Host,
            msg="Dhcp4Client.fetch() must return an Ip4Host on a successful Offer/Ack exchange.",
        )
        assert result is not None
        self.assertEqual(
            result.address,
            Ip4Address("10.0.0.100"),
            msg="The returned Ip4Host.address must equal the server-assigned yiaddr.",
        )
        self.assertEqual(
            result.network.mask,
            Ip4Mask("255.255.255.0"),
            msg="The returned Ip4Host.network.mask must equal the server-supplied subnet mask.",
        )

    def test__dhcp4_client__fetch_sets_gateway_when_router_option_present(self) -> None:
        """
        Ensure the first router address from the Router option is stored
        as the host's default gateway.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        assert result is not None
        self.assertEqual(
            result.gateway,
            Ip4Address("10.0.0.1"),
            msg="The returned Ip4Host.gateway must equal the first router address in the DHCP Router option.",
        )

    def test__dhcp4_client__fetch_binds_and_connects_to_dhcp_ports(self) -> None:
        """
        Ensure the client binds to the canonical DHCPv4 client port 68
        on the unspecified IPv4 address and 'connects' to the broadcast
        address on port 67 before sending the Discover packet.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            client.fetch()

        self._sock.bind.assert_called_once_with(("0.0.0.0", 68))
        self._sock.connect.assert_called_once_with(("255.255.255.255", 67))

    def test__dhcp4_client__fetch_sends_two_packets(self) -> None:
        """
        Ensure the happy path sends exactly two packets — the initial
        Discover and the follow-up Request.
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
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
        """

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            client.fetch()

        self._sock.close.assert_called_once_with()

    def test__dhcp4_client__fetch_uses_configured_timeout_on_recv(self) -> None:
        """
        Ensure the per-call 'timeout' kwarg passed to 'recv__mv' matches
        the value supplied to the client constructor.
        """

        client = Dhcp4Client(
            mac_address=MacAddress("02:00:00:00:00:01"),
            timeout__sec=7,
        )

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=self._sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", self._parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
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
        """

        offer = SimpleNamespace(
            message_type=Dhcp4MessageType.OFFER,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )
        ack = SimpleNamespace(
            message_type=Dhcp4MessageType.ACK,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )

        sock = _build_mock_socket(offer_payload=b"offer", ack_payload=b"ack")
        parser = _make_parser_factory(offer=offer, ack=ack)

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        assert result is not None
        self.assertIsNone(
            result.gateway,
            msg="Ip4Host.gateway must remain None when the DHCP Ack carries no Router option.",
        )


class TestDhcp4ClientFetchOfferTimeout(TestCase):
    """
    The 'Dhcp4Client.fetch()' Offer-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Offer receive collapses the
        exchange: 'fetch()' returns None and the socket is closed.
        """

        sock = _build_mock_socket(offer_payload=TimeoutError())
        parser = MagicMock(name="Dhcp4Parser")

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
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
        closed.
        """

        bogus = SimpleNamespace(
            message_type=Dhcp4MessageType.NAK,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )

        sock = _build_mock_socket(offer_payload=b"offer")
        parser = _make_parser_factory(offer=bogus)

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
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
        """

        offer = SimpleNamespace(
            message_type=Dhcp4MessageType.OFFER,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )

        sock = _build_mock_socket(offer_payload=b"offer", ack_payload=TimeoutError())
        parser = _make_parser_factory(offer=offer)

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack receive times out.",
        )
        sock.close.assert_called_once_with()


class TestDhcp4ClientFetchAckWrongMessageType(TestCase):
    """
    The 'Dhcp4Client.fetch()' Ack-with-wrong-type failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_wrong_ack_message_type(self) -> None:
        """
        Ensure a response to the Request with a non-ACK message type
        aborts the exchange: 'fetch()' returns None and the socket is
        closed.
        """

        offer = SimpleNamespace(
            message_type=Dhcp4MessageType.OFFER,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )
        bogus_ack = SimpleNamespace(
            message_type=Dhcp4MessageType.NAK,
            srv_id=Ip4Address("10.0.0.254"),
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )

        sock = _build_mock_socket(offer_payload=b"offer", ack_payload=b"nak")
        parser = _make_parser_factory(offer=offer, ack=bogus_ack)

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the second response is not a DHCP Ack.",
        )
        sock.close.assert_called_once_with()
        self.assertEqual(
            sock.send.call_count,
            2,
            msg="Both Discover and Request must be sent before the Ack message-type check fails.",
        )


class TestDhcp4ClientFetchOfferSrvIdNone(TestCase):
    """
    The 'Dhcp4Client.fetch()' fallback for a missing Server-ID option.
    """

    def test__dhcp4_client__fetch_handles_offer_without_srv_id(self) -> None:
        """
        Ensure the happy path still yields a lease when the Offer's
        'srv_id' attribute is None; the source falls back to
        'Ip4Address()' for the Server-ID option in the outgoing Request
        ('srv_id or Ip4Address()' expression).
        """

        offer = SimpleNamespace(
            message_type=Dhcp4MessageType.OFFER,
            srv_id=None,
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )
        ack = SimpleNamespace(
            message_type=Dhcp4MessageType.ACK,
            srv_id=None,
            yiaddr=Ip4Address("10.0.0.100"),
            subnet_mask=Ip4Mask("255.255.255.0"),
            router=None,
        )

        sock = _build_mock_socket(offer_payload=b"offer", ack_payload=b"ack")
        parser = _make_parser_factory(offer=offer, ack=ack)

        client = Dhcp4Client(mac_address=MacAddress("02:00:00:00:00:01"))

        with (
            patch("pytcp.lib.dhcp4_client.socket", return_value=sock),
            patch("pytcp.lib.dhcp4_client.Dhcp4Parser", parser),
            patch("pytcp.lib.dhcp4_client.log"),
        ):
            result = client.fetch()

        assert result is not None
        self.assertEqual(
            result.address,
            Ip4Address("10.0.0.100"),
            msg="fetch() must still complete when the Offer's srv_id is None (falls back to Ip4Address()).",
        )
