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
This module contains the BSD-like AF_PACKET raw link-layer socket
interface for the stack — the PyTCP equivalent of Linux
'socket(AF_PACKET, SOCK_RAW, htons(ethertype))'. Unlike the raw IP
socket ('RawSocket'), it sends and receives complete Ethernet frames
(including ARP, which is below the IP layer), keyed by an ethertype
capture / delivery filter rather than an IANA next-header value.

This is the Phase-0 skeleton: it constructs and reports its
family / type / ethertype / ifindex; RX (a per-interface tap) and TX
(verbatim frame onto the egress TxRing) arrive in later phases.

pytcp/socket/packet__socket.py

ver 3.0.6
"""

from typing import override

from net_proto.lib.enums import EtherType
from pytcp.lib.logger import log
from pytcp.socket import ETH_P_ALL, AddressFamily, SocketType, socket


class PacketSocket(socket):
    """
    The AF_PACKET raw link-layer socket.
    """

    _address_family = AddressFamily.PACKET
    _socket_type = SocketType.RAW

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily = AddressFamily.PACKET,
        type: SocketType = SocketType.RAW,
        protocol: EtherType | int | None = None,
    ) -> None:
        """
        Initialize the AF_PACKET raw link-layer socket.
        """

        # Phase 0 supports the SOCK_RAW (full-frame) flavour only; the
        # cooked SOCK_DGRAM variant lands in a later phase.
        assert type is SocketType.RAW

        super().__init__()

        # A 'None' protocol (or the coerced BSD 0 sentinel) means no
        # explicit ethertype was requested; default to the ETH_P_ALL
        # capture-all filter. An 'EtherType' member is preserved as-is
        # so the later RX tap can match against the parser-layer enum.
        self._ethertype: EtherType | int = ETH_P_ALL if protocol is None else protocol

        # ifindex 0 = unbound (every interface); set by 'bind()' later.
        self._ifindex = 0

        __debug__ and log("socket", f"<g>[{self}]</> - Created packet socket")

    @override
    def __str__(self) -> str:
        """
        Get the packet-socket log string.
        """

        return f"PACKET/RAW/0x{int(self._ethertype):04x}/if{self._ifindex}"

    @property
    def ethertype(self) -> EtherType | int:
        """
        Get the socket's ethertype capture / delivery filter.
        """

        return self._ethertype

    @property
    def ifindex(self) -> int:
        """
        Get the interface index the socket is bound to (0 = unbound).
        """

        return self._ifindex
