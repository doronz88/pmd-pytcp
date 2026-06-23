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
This module contains the Ethernet II packet assembler class.

pmd_net_proto/protocols/ethernet/ethernet__assembler.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_addr import MacAddress
from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.enums import EtherType
from pmd_net_proto.lib.proto_assembler import ProtoAssembler
from pmd_net_proto.protocols.ethernet.ethernet__base import (
    Ethernet,
    EthernetPayload,
)
from pmd_net_proto.protocols.ethernet.ethernet__header import EthernetHeader
from pmd_net_proto.protocols.raw.raw__assembler import RawAssembler
from pmd_net_proto._compat import as_buffer


class EthernetAssembler(Ethernet[EthernetPayload], ProtoAssembler):
    """
    The Ethernet packet assembler.
    """

    _payload: EthernetPayload

    def __init__(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(),
        ethernet__dst: MacAddress = MacAddress(),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> None:
        """
        Initialize the Ethernet packet assembler.
        """

        self._tracker = ethernet__payload.tracker

        self._payload = ethernet__payload

        self._header = EthernetHeader(
            dst=ethernet__dst,
            src=ethernet__src,
            type=EtherType.from_proto(self._payload),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the Ethernet packet into list of buffers.
        """

        buffers.append(as_buffer(bytearray(as_buffer(self._header))))

        self._payload.assemble(buffers)
