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
This module contains the IPv4 packet option classes.

net_proto/protocols/ip4/options/ip4__options.py

ver 3.0.4
"""

from abc import ABC
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType
from net_proto.protocols.ip4.options.ip4__option__eol import Ip4OptionEol
from net_proto.protocols.ip4.options.ip4__option__lsrr import Ip4OptionLsrr
from net_proto.protocols.ip4.options.ip4__option__nop import (
    IP4__OPTION__NOP__LEN,
    Ip4OptionNop,
)
from net_proto.protocols.ip4.options.ip4__option__router_alert import (
    Ip4OptionRouterAlert,
)
from net_proto.protocols.ip4.options.ip4__option__ssrr import Ip4OptionSsrr
from net_proto.protocols.ip4.options.ip4__option__unknown import (
    Ip4OptionUnknown,
)

IP4__OPTIONS__MAX_LEN = 40


class Ip4Options(ProtoOptions):
    """
    The IPv4 packet options.
    """

    @staticmethod
    def validate_integrity(
        *,
        frame: Buffer,
        hlen: int,
    ) -> None:
        """
        Run the IPv4 options integrity checks before parsing options.
        """

        offset = IP4__HEADER__LEN

        while offset < hlen:
            if frame[offset] == int(Ip4OptionType.EOL):
                break

            if frame[offset] == int(Ip4OptionType.NOP):
                offset += IP4__OPTION__NOP__LEN
                continue

            if (value := frame[offset + 1]) < 2:
                raise Ip4IntegrityError(
                    f"The IPv4 option length must be greater than 1. Got: {value!r}.",
                )

            offset += frame[offset + 1]
            if offset > hlen:
                raise Ip4IntegrityError(
                    f"The IPv4 option length must not extend past the header length. Got: {offset=}, {hlen=}",
                )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the IPv4 options from buffer.
        """

        offset = 0
        options: list[Ip4Option] = []

        while offset < len(buffer):
            match Ip4OptionType.from_bytes(buffer[offset : offset + 1]):
                case Ip4OptionType.EOL:
                    options.append(Ip4OptionEol.from_buffer(buffer[offset:]))
                    break
                case Ip4OptionType.NOP:
                    options.append(Ip4OptionNop.from_buffer(buffer[offset:]))
                case Ip4OptionType.LSRR:
                    options.append(Ip4OptionLsrr.from_buffer(buffer[offset:]))
                case Ip4OptionType.SSRR:
                    options.append(Ip4OptionSsrr.from_buffer(buffer[offset:]))
                case Ip4OptionType.ROUTER_ALERT:
                    options.append(Ip4OptionRouterAlert.from_buffer(buffer[offset:]))
                case _:
                    options.append(Ip4OptionUnknown.from_buffer(buffer[offset:]))

            offset += options[-1].len

        return cls(*options)


class Ip4OptionsProperties(ABC):
    """
    The IPv4 options properties mixin class.
    """

    _options: Ip4Options

    @property
    def lsrr(self) -> Ip4OptionLsrr | None:
        """
        Get the IPv4 'lsrr' option (RFC 791 Loose Source and Record Route),
        if present.
        """

        for option in self._options:
            if isinstance(option, Ip4OptionLsrr):
                return option
        return None

    @property
    def ssrr(self) -> Ip4OptionSsrr | None:
        """
        Get the IPv4 'ssrr' option (RFC 791 Strict Source and Record Route),
        if present.
        """

        for option in self._options:
            if isinstance(option, Ip4OptionSsrr):
                return option
        return None

    @property
    def router_alert(self) -> Ip4OptionRouterAlert | None:
        """
        Get the IPv4 'router_alert' option (RFC 2113), if present.
        """

        for option in self._options:
            if isinstance(option, Ip4OptionRouterAlert):
                return option
        return None
