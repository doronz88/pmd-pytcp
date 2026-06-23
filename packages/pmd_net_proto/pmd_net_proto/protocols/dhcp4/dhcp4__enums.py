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
This module contains the DHCPv4 protocol enum classes.

pmd_net_proto/protocols/dhcp4/dhcp4__enums.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_proto.lib.proto_enum import ProtoEnumByte


class Dhcp4Operation(ProtoEnumByte):
    """
    The DHCPv4 header 'oper' field values.
    """

    REQUEST = 0x01  # RFC 2131 §2 (op field): BOOTREQUEST.
    REPLY = 0x02  # RFC 2131 §2 (op field): BOOTREPLY.


class Dhcp4HardwareType(ProtoEnumByte):
    """
    The DHCPv4 header 'htype' field values.
    """

    ETHERNET = 0x01  # RFC 2131 §2 (htype field) / IANA "ARP Hardware Types": Ethernet.


DHCP4__HARDWARE_LEN__ETHERNET = 6


class Dhcp4MessageType(ProtoEnumByte):
    """
    The DHCPv4 message type option values.
    """

    DISCOVER = 0x01  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPDISCOVER.
    OFFER = 0x02  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPOFFER.
    REQUEST = 0x03  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPREQUEST.
    DECLINE = 0x04  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPDECLINE.
    ACK = 0x05  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPACK.
    NAK = 0x06  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPNAK.
    RELEASE = 0x07  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPRELEASE.
    INFORM = 0x08  # RFC 2131 §3.1, RFC 2132 §9.6: DHCPINFORM.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        if self == Dhcp4MessageType.DISCOVER:
            name = "Discover"
        elif self == Dhcp4MessageType.OFFER:
            name = "Offer"
        elif self == Dhcp4MessageType.REQUEST:
            name = "Request"
        elif self == Dhcp4MessageType.DECLINE:
            name = "Decline"
        elif self == Dhcp4MessageType.ACK:
            name = "ACK"
        elif self == Dhcp4MessageType.NAK:
            name = "NAK"
        elif self == Dhcp4MessageType.RELEASE:
            name = "Release"
        elif self == Dhcp4MessageType.INFORM:
            name = "Inform"

        return f"{self.value}" if self.is_unknown else name
