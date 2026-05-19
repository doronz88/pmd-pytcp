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
This module contains the IPv6 Hop-by-Hop Options packet parser class.

net_proto/protocols/ip6_hbh/ip6_hbh__parser.py

ver 3.0.6
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip6_hbh.ip6_hbh__base import Ip6Hbh
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.ip6_hbh__header import (
    IP6_HBH__HEADER__LEN,
    Ip6HbhHeader,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions


class Ip6HbhParser(Ip6Hbh, ProtoParser):
    """
    The IPv6 Hop-by-Hop Options packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 HBH packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip6_hbh = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv6 HBH packet before parsing it.
        """

        if len(self._frame) < IP6_HBH__HEADER__LEN:
            raise Ip6HbhIntegrityError(
                "The condition 'IP6_HBH__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP6_HBH__HEADER__LEN=}, {len(self._frame)=}",
            )

        # RFC 8200 §4.3: total HBH length on the wire is (Hdr Ext Len + 1) * 8.
        hdr_ext_len = self._frame[1]
        total_hbh_len = (hdr_ext_len + 1) * 8

        if total_hbh_len > len(self._frame):
            raise Ip6HbhIntegrityError(
                "The condition '(hdr_ext_len + 1) * 8 <= len(self._frame)' must be met. "
                f"Got: {hdr_ext_len=}, {total_hbh_len=}, {len(self._frame)=}",
            )

        # Walk the TLV options block to confirm every option's length
        # field stays inside the declared HBH region.
        Ip6HbhOptions.validate_integrity(
            buffer=self._frame[IP6_HBH__HEADER__LEN:total_hbh_len],
        )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 HBH packet.
        """

        self._header = Ip6HbhHeader.from_buffer(self._frame)
        total_hbh_len = (self._header.hdr_ext_len + 1) * 8
        self._options = Ip6HbhOptions.from_buffer(
            self._frame[IP6_HBH__HEADER__LEN:total_hbh_len],
        )
        self._payload = self._frame[total_hbh_len:]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv6 HBH packet after parsing it.

        Applies RFC 8200 §4.2 action-on-unrecognized to every option
        in the parsed block. The chain-walker dispatch in Phase 8
        catches any 'Ip6HbhSanityError' raised here, consults its
        'pointer' / 'multicast_only' fields, and emits ICMPv6
        Parameter Problem code 2 (or silent discard) accordingly.

        Multicast-destination context is not available at the
        parser layer; the chain-walker may re-run sanity validation
        with 'ip6_dst_is_multicast=True' once it has the IPv6
        header in hand.
        """

        total_hbh_len = (self._header.hdr_ext_len + 1) * 8
        Ip6HbhOptions.validate_sanity(
            buffer=self._frame[IP6_HBH__HEADER__LEN:total_hbh_len],
        )

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv6 HBH packet header bytes (full header including
        the trailing options block).
        """

        return self._frame[: (self._header.hdr_ext_len + 1) * 8]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv6 HBH packet payload bytes.
        """

        return self._payload
