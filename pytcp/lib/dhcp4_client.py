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
This module contains a simple DHCPv4 client used internally by the stack.

pytcp/lib/dhcp4_client.py

ver 3.0.3
"""

import random
from typing import override

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from net_proto.protocols.dhcp4.options.dhcp4__option import Dhcp4OptionType
from net_proto.protocols.dhcp4.options.dhcp4__option__client_id import (
    Dhcp4OptionClientId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__host_name import (
    Dhcp4OptionHostName,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options
from pytcp.lib.logger import log
from pytcp.socket import AF_INET4, SOCK_DGRAM, socket


class Dhcp4Client:
    """
    The DHCPv4 client.
    """

    @override
    def __init__(self, *, mac_address: MacAddress, timeout__sec: int = 5) -> None:
        """
        Initialize the DHCPv4 client.
        """

        self._mac_address = mac_address
        self._timeout__sec = timeout__sec

    def fetch(self) -> Ip4Host | None:
        """
        Run the DHCPv4 DISCOVER/REQUEST handshake and return the leased host.
        """

        xid = random.randint(0, 0xFFFFFFFF)

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            self._send_discover(client_socket, xid=xid)
            if (offer := self._recv_offer(client_socket)) is None:
                return None

            if offer.srv_id is None:
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Didn't receive DHCP Offer message - missing server identifier</>",
                )
                return None

            self._send_request(
                client_socket,
                xid=xid,
                srv_id=offer.srv_id,
                yiaddr=offer.yiaddr,
            )
            if (ack := self._recv_ack(client_socket)) is None:
                return None

            if ack.subnet_mask is None:
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Didn't receive DHCP Ack message - missing subnet mask</>",
                )
                return None

            ip4_host = Ip4Host((ack.yiaddr, ack.subnet_mask))
            if ack.router:
                ip4_host.gateway = ack.router[0]

            return ip4_host
        finally:
            client_socket.close()

    def _send_discover(self, client_socket: socket, *, xid: int) -> None:
        """
        Build and send the DHCP DISCOVER packet.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionClientId(b"\x01" + bytes(self._mac_address)),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _recv_offer(self, client_socket: socket) -> Dhcp4Parser | None:
        """
        Receive and validate the DHCP OFFER reply.
        """

        try:
            dhcp4_packet_rx = Dhcp4Parser(client_socket.recv__mv(timeout=self._timeout__sec))
            __debug__ and log("dhcp4", f"<lg>RX</> - {dhcp4_packet_rx}")
        except TimeoutError:
            __debug__ and log("dhcp4", "<WARN>Didn't receive DHCP Offer message - timeout</>")
            return None

        if dhcp4_packet_rx.message_type != Dhcp4MessageType.OFFER:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Offer message - message type error</>",
            )
            return None

        return dhcp4_packet_rx

    def _send_request(
        self,
        client_socket: socket,
        *,
        xid: int,
        srv_id: Ip4Address,
        yiaddr: Ip4Address,
    ) -> None:
        """
        Build and send the DHCP REQUEST packet.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionServerId(srv_id),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _recv_ack(self, client_socket: socket) -> Dhcp4Parser | None:
        """
        Receive and validate the DHCP ACK reply.
        """

        try:
            dhcp4_packet_rx = Dhcp4Parser(client_socket.recv__mv(timeout=self._timeout__sec))
            __debug__ and log("dhcp4", f"<lg>RX</> - {dhcp4_packet_rx}")
        except TimeoutError:
            __debug__ and log("dhcp4", "<WARN>Didn't receive DHCP ACK message - timeout</>")
            return None

        if dhcp4_packet_rx.message_type != Dhcp4MessageType.ACK:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP ACK message - message type error</>",
            )
            return None

        return dhcp4_packet_rx
