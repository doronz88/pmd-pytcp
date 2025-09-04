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
This module contains the DHCPv4 packet options class.

net_proto/protocols/dhcp4/options/dhcp4_options.py

ver 3.0.4
"""


from abc import ABC
from typing import Self, override

from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__LEN
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    Dhcp4Option,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__end import Dhcp4OptionEnd
from net_proto.protocols.dhcp4.options.dhcp4_option__host_name import (
    Dhcp4OptionHostName,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__pad import (
    DHCP4__OPTION__PAD__LEN,
    Dhcp4OptionPad,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__router import (
    Dhcp4OptionRouter,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__srv_id import (
    Dhcp4OptionSrvId,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__subnet_mask import (
    Dhcp4OptionSubnetMask,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__unknown import (
    Dhcp4OptionUnknown,
)
from net_proto.protocols.ip4.ip4__defaults import IP4__MIN_MTU
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN
from net_proto.protocols.udp.udp__header import UDP__HEADER__LEN

DHCP4__OPTIONS__MAX_LEN = (
    IP4__MIN_MTU - IP4__HEADER__LEN - UDP__HEADER__LEN - DHCP4__HEADER__LEN
)


class Dhcp4Options(ProtoOptions):
    """
    The DHCPv4 packet options.
    """

    @property
    def host_name(self) -> str | None:
        """
        Get the value of the DHCP Host Name option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionHostName):
                return option.host_name

        return None

    @property
    def message_type(self) -> Dhcp4MessageType | None:
        """
        Get the value of the DHCP Message Type option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionMessageType):
                return option.message_type

        return None

    @property
    def param_req_list(self) -> list[Dhcp4OptionType] | None:
        """
        Get the value of the DHCP Parameter Request List option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionParamReqList):
                return option.param_req_list

        return None

    @property
    def req_ip_addr(self) -> Ip4Address | None:
        """
        Get the value of the DHCP Requested IP Address option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionReqIpAddr):
                return option.req_ip_addr

        return None

    @property
    def router(self) -> list[Ip4Address] | None:
        """
        Get the value of the DHCP Router option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionRouter):
                return option.routers

        return None

    @property
    def srv_id(self) -> Ip4Address | None:
        """
        Get the value of the DHCP Server Identifier option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionSrvId):
                return option.srv_id

        return None

    @property
    def subnet_mask(self) -> Ip4Mask | None:
        """
        Get the value of the DHCP Subnet Mask option if present.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionSubnetMask):
                return option.subnet_mask

        return None

    @staticmethod
    def validate_integrity(
        *,
        frame: bytes,
        hlen: int,
    ) -> None:
        """
        Run the DHCPv4 options integrity checks before parsing options.
        """

        offset = DHCP4__HEADER__LEN

        while offset < hlen:
            if frame[offset] == int(Dhcp4OptionType.END):
                break

            if frame[offset] == int(Dhcp4OptionType.PAD):
                offset += DHCP4__OPTION__PAD__LEN
                continue

            if (value := frame[offset + 1]) < 2:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option length must be greater than 1. "
                    f"Got: {value!r}.",
                )

            offset += frame[offset + 1]
            if offset > hlen:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option length must not extend past the header "
                    f"length. Got: {offset=}, {hlen=}",
                )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Read the DHCPv4 options from bytes.
        """

        offset = 0
        options: list[Dhcp4Option] = []

        while offset < len(_bytes):
            print(options)
            match Dhcp4OptionType.from_bytes(_bytes[offset:]):
                case Dhcp4OptionType.END:
                    options.append(Dhcp4OptionEnd.from_bytes(_bytes[offset:]))
                    break
                case Dhcp4OptionType.PAD:
                    options.append(Dhcp4OptionPad.from_bytes(_bytes[offset:]))
                case Dhcp4OptionType.HOST_NAME:
                    options.append(
                        Dhcp4OptionHostName.from_bytes(_bytes[offset:])
                    )
                case Dhcp4OptionType.MESSAGE_TYPE:
                    options.append(
                        Dhcp4OptionMessageType.from_bytes(_bytes[offset:])
                    )
                case Dhcp4OptionType.PARAM_REQ_LIST:
                    options.append(
                        Dhcp4OptionParamReqList.from_bytes(_bytes[offset:])
                    )
                case Dhcp4OptionType.REQ_IP_ADDR:
                    options.append(
                        Dhcp4OptionReqIpAddr.from_bytes(_bytes[offset:])
                    )
                case Dhcp4OptionType.ROUTER:
                    options.append(
                        Dhcp4OptionRouter.from_bytes(_bytes[offset:])
                    )
                case Dhcp4OptionType.SRV_ID:
                    options.append(Dhcp4OptionSrvId.from_bytes(_bytes[offset:]))
                case Dhcp4OptionType.SUBNET_MASK:
                    options.append(
                        Dhcp4OptionSubnetMask.from_bytes(_bytes[offset:])
                    )
                case _:
                    options.append(
                        Dhcp4OptionUnknown.from_bytes(_bytes[offset:])
                    )

            offset += options[-1].len

        return cls(*options)


class Dhcp4OptionsProperties(ABC):
    """
    The DHCPv4 options properties mixin class.
    """

    _options: Dhcp4Options

    @property
    def host_name(self) -> str | None:
        """
        Get the value of the DHCP Host Name option if present.
        """

        return self._options.host_name

    @property
    def message_type(self) -> Dhcp4MessageType | None:
        """
        Get the value of the DHCP Message Type option if present.
        """

        return self._options.message_type

    @property
    def param_req_list(self) -> list[Dhcp4OptionType] | None:
        """
        Get the value of the DHCP Parameter Request List option if present.
        """

        return self._options.param_req_list

    @property
    def req_ip_addr(self) -> Ip4Address | None:
        """
        Get the value of the DHCP Requested IP Address option if present.
        """

        return self._options.req_ip_addr

    @property
    def router(self) -> list[Ip4Address] | None:
        """
        Get the value of the DHCP Router option if present.
        """

        return self._options.router

    @property
    def srv_id(self) -> Ip4Address | None:
        """
        Get the value of the DHCP Server Identifier option if present.
        """

        return self._options.srv_id

    @property
    def subnet_mask(self) -> Ip4Mask | None:
        """
        Get the value of the DHCP Subnet Mask option if present.
        """

        return self._options.subnet_mask
