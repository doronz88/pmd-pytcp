#!/usr/bin/env python3

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
This module contains the DHCPv4 packet assembler class.

net_proto/protocols/dhcp4/dhcp4__assembler.py

ver 3.0.4
"""


from typing import override

from net_addr.ip4_address import Ip4Address
from net_addr.mac_address import MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.protocols.dhcp4.dhcp4__base import Dhcp4
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__header import Dhcp4Header
from net_proto.protocols.dhcp4.options.dhcp4_options import Dhcp4Options


class Dhcp4Assembler(Dhcp4, ProtoAssembler):
    """
    The DHCPv4 packet assembler.
    """

    def __init__(
        self,
        *,
        dhcp4__operation: Dhcp4Operation,
        dhcp4__hops: int = 0,
        dhcp4__xid: int,
        dhcp4__secs: int = 0,
        dhcp4__flag_b: bool = False,
        dhcp4__ciaddr: Ip4Address = Ip4Address("0.0.0.0"),
        dhcp4__yiaddr: Ip4Address = Ip4Address("0.0.0.0"),
        dhcp4__siaddr: Ip4Address = Ip4Address("0.0.0.0"),
        dhcp4__giaddr: Ip4Address = Ip4Address("0.0.0.0"),
        dhcp4__chaddr: MacAddress,
        dhcp4__sname: str | None = None,
        dhcp4__file: str | None = None,
        dhcp4__options: Dhcp4Options = Dhcp4Options(),
    ) -> None:
        """
        Initialize the DHCPv4 packet assembler.
        """

        self._header = Dhcp4Header(
            operation=dhcp4__operation,
            hops=dhcp4__hops,
            xid=dhcp4__xid,
            secs=dhcp4__secs,
            flag_b=dhcp4__flag_b,
            ciaddr=dhcp4__ciaddr,
            yiaddr=dhcp4__yiaddr,
            siaddr=dhcp4__siaddr,
            giaddr=dhcp4__giaddr,
            chaddr=dhcp4__chaddr,
            sname=dhcp4__sname or "",
            file=dhcp4__file or "",
        )

        self._options = dhcp4__options

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the DHCPv4 packet.
        """

        raise NotImplementedError(
            "The 'assemble()' method is not implemented for L7 protocols. "
            "Use Sockets instead."
        )
