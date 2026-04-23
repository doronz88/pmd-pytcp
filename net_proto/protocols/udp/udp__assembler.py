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
This module contains the UDP packet assembler class.

net_proto/protocols/udp/udp__assembler.py

ver 3.0.4
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.udp.udp__base import Udp
from net_proto.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader


class UdpAssembler(Udp, ProtoAssembler):
    """
    The UDP packet assembler.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        udp__sport: int = 0,
        udp__dport: int = 0,
        udp__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the UDP packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = udp__payload

        self._header = UdpHeader(
            sport=udp__sport,
            dport=udp__dport,
            plen=UDP__HEADER__LEN + len(self._payload),
            cksum=0,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the UDP packet into list of buffers.
        """

        header = bytearray(self._header)
        header[6:8] = inet_cksum(header, self._payload, init=self.pshdr_sum).to_bytes(2)

        buffers.append(header)
        buffers.append(self._payload)
