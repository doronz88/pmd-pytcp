#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable=expression-not-assigned

"""
Module contains simple DHCPv4 client that is used internally by the stack.

pytcp/protocols/dhcp4/client.py

ver 3.0.3
"""


import random

from net_addr import Ip4Address, Ip4Host, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from net_proto.protocols.dhcp4.options.dhcp4_option import Dhcp4OptionType
from net_proto.protocols.dhcp4.options.dhcp4_option__clt_id import (
    Dhcp4OptionCltId,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__host_name import (
    Dhcp4OptionHostName,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__srv_id import (
    Dhcp4OptionSrvId,
)
from net_proto.protocols.dhcp4.options.dhcp4_options import Dhcp4Options
from pytcp.lib.logger import log
from pytcp.socket import AF_INET4, SOCK_DGRAM, socket


class Dhcp4Client:
    """
    Class supporting DHCPv4 client operation.
    """

    def __init__(
        self, *, mac_address: MacAddress, timeout__sec: int = 5
    ) -> None:
        """
        Class constructor.
        """

        self._mac_address = mac_address
        self._timeout__sec = timeout__sec

        self._xid = random.randint(0, 0xFFFFFFFF)

    def fetch(self) -> Ip4Host | None:
        """
        IPv4 DHCP client.
        """

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        client_socket.bind(("0.0.0.0", 68))
        client_socket.connect(("255.255.255.255", 67))

        # Send DHCP Discover to broadcast address.
        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=self._xid,
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionCltId(b"\x01" + bytes(self._mac_address)),
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

        # Wait for DHCP Offer.
        try:
            dhcp4_packet_rx = Dhcp4Parser(
                client_socket.recv(timeout=self._timeout__sec)
            )
            __debug__ and log("dhcp4", f"<lg>RX</> - {dhcp4_packet_rx}")
        except TimeoutError:
            __debug__ and log(
                "dhcp4", "<WARN>Didn't receive DHCP Offer message - timeout</>"
            )
            client_socket.close()
            return None

        if dhcp4_packet_rx.message_type != Dhcp4MessageType.OFFER:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Offer message - message type errori</>",
            )
            client_socket.close()
            return None

        srv_id = dhcp4_packet_rx.srv_id
        yiaddr = dhcp4_packet_rx.yiaddr

        # Send DHCP Request packet to server.
        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=self._xid,
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
                Dhcp4OptionSrvId(srv_id or Ip4Address()),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

        # Wait for the DHCP Ack packet from server.
        try:
            dhcp4_packet_rx = Dhcp4Parser(
                client_socket.recv(timeout=self._timeout__sec)
            )
            __debug__ and log("dhcp4", f"<lg>RX</> - {dhcp4_packet_rx}")
        except TimeoutError:
            __debug__ and log(
                "dhcp4", "<WARN>Didn't receive DHCP ACK message - timeout</>"
            )
            client_socket.close()
            return None

        if dhcp4_packet_rx.message_type != Dhcp4MessageType.ACK:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP ACK message - message type error</>",
            )
            client_socket.close()
            return None

        client_socket.close()

        assert dhcp4_packet_rx.subnet_mask is not None

        ip4_host = Ip4Host(
            (
                Ip4Address(dhcp4_packet_rx.yiaddr),
                Ip4Mask(dhcp4_packet_rx.subnet_mask),
            )
        )
        if dhcp4_packet_rx.router is not None:
            ip4_host.gateway = Ip4Address(dhcp4_packet_rx.router[0])

        return ip4_host
