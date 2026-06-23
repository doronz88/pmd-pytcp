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
This module contains the IPv6 Destination Options protocol base class.

pmd_net_proto/protocols/ip6_dest_opts/ip6_dest_opts__base.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.proto import Proto
from pmd_net_proto.protocols.ip6_dest_opts.ip6_dest_opts__header import (
    Ip6DestOptsHeader,
    Ip6DestOptsHeaderProperties,
)
from pmd_net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import Ip6DestOptsOptions
from pmd_net_proto._compat import as_buffer


class Ip6DestOpts(Proto, Ip6DestOptsHeaderProperties):
    """
    The IPv6 Destination Options protocol base.
    """

    _header: Ip6DestOptsHeader
    _options: Ip6DestOptsOptions
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Dest Opts packet length (header + options + payload).
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Dest Opts packet log string.
        """

        return (
            f"IPv6_DESTOPTS next {self._header.next}, "
            f"hdr_ext_len {self._header.hdr_ext_len} "
            f"({(self._header.hdr_ext_len + 1) * 8} bytes), "
            f"options [{self._options}]"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 Dest Opts packet representation string.
        """

        return (
            f"{type(self).__name__}(header={self._header!r}, " f"options={self._options!r}, payload={self._payload!r})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Dest Opts packet as a memoryview.
        """

        buffer = bytearray(as_buffer(self._header))
        buffer += bytearray(as_buffer(self._options))
        buffer += as_buffer(self._payload)

        return memoryview(buffer)
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))


    @property
    def header(self) -> Ip6DestOptsHeader:
        """
        Get the IPv6 Dest Opts packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Ip6DestOptsOptions:
        """
        Get the IPv6 Dest Opts packet '_options' attribute.
        """

        return self._options

    @property
    def payload(self) -> Buffer:
        """
        Get the IPv6 Dest Opts packet '_payload' attribute.
        """

        return self._payload
