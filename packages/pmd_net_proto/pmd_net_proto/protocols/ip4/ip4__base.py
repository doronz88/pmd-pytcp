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
This module contains the IPv4 protocol base class.

pmd_net_proto/protocols/ip4/ip4__base.py

ver 3.0.7
"""

from __future__ import annotations

import struct
from typing_extensions import TypeAliasType, override

from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.inet_cksum import inet_cksum
from pmd_net_proto.lib.proto import Proto
from pmd_net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from pmd_net_proto.protocols.igmp.igmp__assembler import IgmpAssembler
from pmd_net_proto.protocols.ip4.ip4__header import Ip4Header, Ip4HeaderProperties
from pmd_net_proto.protocols.ip4.options.ip4__options import (
    Ip4Options,
    Ip4OptionsProperties,
)
from pmd_net_proto.protocols.raw.raw__assembler import RawAssembler
from pmd_net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from pmd_net_proto.protocols.udp.udp__assembler import UdpAssembler
from typing import Generic, TypeVar, Union
from pmd_net_proto._compat import as_buffer

Ip4Payload = TypeAliasType("Ip4Payload", Union[Icmp4Assembler, IgmpAssembler, TcpAssembler, UdpAssembler, RawAssembler])


P = TypeVar("P", Ip4Payload, Buffer)
class Ip4(Proto, Ip4HeaderProperties, Ip4OptionsProperties, Generic[P]):
    """
    The IPv4 protocol base.
    """

    _header: Ip4Header
    _options: Ip4Options
    _payload: P

    @override
    def __len__(self) -> int:
        """
        Get the IPv4 packet length.
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 packet log string.
        """

        return (
            f"IPv4 {self._header.src} > {self._header.dst}, "
            f"proto {self._header.proto}, id {self._header.id}"
            f"{', DF' if self._header.flag_df else ''}"
            f"{', MF' if self._header.flag_mf else ''}, "
            f"offset {self._header.offset}, ttl {self._header.ttl}, "
            f"len {self._header.plen} "
            f"({len(self._header)}+{len(self._options)}+{len(self._payload)})"
            f"{f', opts [{self._options}]' if self._options else ''}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv4 packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, options={self._options!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 packet as a memoryview.
        """

        if isinstance(self._payload, (TcpAssembler, UdpAssembler, RawAssembler)):
            self._payload.pshdr_sum = self.pshdr_sum

        buffer = bytearray(as_buffer(self._header))
        buffer += bytearray(as_buffer(self._options))
        buffer[10:12] = inet_cksum(buffer).to_bytes(2, "big")
        buffer += bytearray(as_buffer(self._payload))

        return memoryview(buffer)
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))


    @property
    def pshdr_sum(self) -> int:
        """
        Get the IPv4 pseudo header sum used by TCP and UDP protocols
        to compute their packet checksums.
        """

        pseudo_header = struct.pack(
            "! 4s 4s BBH",
            bytes(self._header.src),
            bytes(self._header.dst),
            0,
            int(self._header.proto),
            len(self._payload),
        )

        return sum(struct.unpack("! 3L", pseudo_header))

    @property
    def header(self) -> Ip4Header:
        """
        Get the IPv4 packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Ip4Options:
        """
        Get the IPv4 packet '_options' attribute.
        """

        return self._options

    @property
    def payload(self) -> P:
        """
        Get the IPv4 packet '_payload' attribute.
        """

        return self._payload

    @property
    def payload_len(self) -> int:
        """
        Get the length of the IPv4 packet '_payload' attribute.
        """

        return len(self._payload)
