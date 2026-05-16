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
This module contains the IPv4 packet parser.

net_proto/protocols/ip4/ip4__parser.py

ver 3.0.5
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip4.ip4__base import Ip4
from net_proto.protocols.ip4.ip4__errors import (
    Ip4IntegrityError,
    Ip4SanityError,
)
from net_proto.protocols.ip4.ip4__header import (
    IP4__HEADER__LEN,
    IP4__POINTER__FLAGS_OFFSET,
    IP4__POINTER__SRC,
    IP4__POINTER__TTL,
    Ip4Header,
)
from net_proto.protocols.ip4.options.ip4__options import Ip4Options


class Ip4Parser(Ip4[Buffer], ProtoParser):
    """
    The IPv4 packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv4 packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        # Install on 'packet_rx' BEFORE the sanity stage so the
        # IPv4 RX handler can read 'packet_rx.ip4' from inside its
        # 'except Ip4SanityError' catch and emit an ICMPv4
        # Parameter Problem with the offending field's pointer
        # (RFC 1122 §3.2.2.5 / RFC 792). Frame advancement stays
        # AFTER sanity so the catch path leaves 'packet_rx.frame'
        # pointing at the original IPv4 packet bytes.
        packet_rx.ip = packet_rx.ip4 = self
        self._validate_sanity()

        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv4 packet before parsing it.
        """

        if len(self._frame) < IP4__HEADER__LEN:
            raise Ip4IntegrityError(
                "The condition 'IP4__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP4__HEADER__LEN=}, {len(self._frame)=}",
            )

        if (value := self._frame[0] >> 4) != 4:
            raise Ip4IntegrityError(
                f"The 'ver' field must be 4. Got: {value!r}",
            )

        hlen = (self._frame[0] & 0b00001111) << 2
        plen = int.from_bytes(self._frame[2:4])

        if not (IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)):
            raise Ip4IntegrityError(
                "The condition 'IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)' "
                f"must be met. Got: {IP4__HEADER__LEN=}, {hlen=}, {plen=}, {len(self._frame)=}",
            )

        if inet_cksum(self._frame[:hlen]):
            raise Ip4IntegrityError(
                "The packet checksum must be valid.",
            )

        Ip4Options.validate_integrity(frame=self._frame, hlen=hlen)

    @override
    def _parse(self) -> None:
        """
        Parse the IPv4 packet.
        """

        self._header = Ip4Header.from_buffer(self._frame)

        self._options = Ip4Options.from_buffer(self._frame[len(self._header) : self._header.hlen])

        self._payload = self._frame[self._header.hlen : self._header.plen]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv4 packet after parsing it. Each
        violation carries the canonical RFC 792 'pointer' value (byte
        offset of the offending field) so the packet handler can emit
        an ICMPv4 Parameter Problem with the correct pointer.
        """

        if (ttl := self.ttl) == 0:
            raise Ip4SanityError(
                f"The 'ttl' field must be greater than 0. Got: {ttl!r}",
                pointer=IP4__POINTER__TTL,
            )

        if (src := self.src).is_multicast:
            raise Ip4SanityError(
                f"The 'src' field must not be a multicast address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        if (src := self.src).is_reserved:
            raise Ip4SanityError(
                f"The 'src' field must not be a reserved address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        if (src := self.src).is_limited_broadcast:
            raise Ip4SanityError(
                f"The 'src' field must not be a limited broadcast address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        if self.flag_df and self.flag_mf:
            raise Ip4SanityError(
                "The 'flag_df' and 'flag_mf' flags must not be set simultaneously. "
                f"Got: {self.flag_df=}, {self.flag_mf=}",
                pointer=IP4__POINTER__FLAGS_OFFSET,
            )

        if self.flag_df and (offset := self.offset) != 0:
            raise Ip4SanityError(
                f"The 'offset' field must be 0 when the 'flag_df' flag is set. Got: {offset!r}",
                pointer=IP4__POINTER__FLAGS_OFFSET,
            )

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv4 packet header bytes.
        """

        return self._frame[: len(self._header)]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv4 packet payload bytes.
        """

        return self._payload

    @property
    def packet_bytes(self) -> Buffer:
        """
        Get the whole IPv4 packet bytes.
        """

        return self._frame[: len(self._header) + len(self._options) + len(self._payload)]
