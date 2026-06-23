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

pmd_net_proto/protocols/dhcp4/options/dhcp4__options.py

ver 3.0.7
"""

from __future__ import annotations

from abc import ABC
from typing_extensions import Self, override

from pmd_net_addr import Ip4Address, Ip4Mask, Ip4Network
from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.proto_option import ProtoOptions
from pmd_net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from pmd_net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from pmd_net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__LEN
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__classless_static_route import (
    Dhcp4OptionClasslessStaticRoute,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__client_id import (
    Dhcp4OptionClientId,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__end import Dhcp4OptionEnd
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__host_name import (
    Dhcp4OptionHostName,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__lease_time import (
    Dhcp4OptionLeaseTime,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__max_msg_size import (
    Dhcp4OptionMaxMsgSize,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__overload import (
    Dhcp4OptionOverload,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__pad import (
    DHCP4__OPTION__PAD__LEN,
    Dhcp4OptionPad,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__rebinding_time import (
    Dhcp4OptionRebindingTime,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__renewal_time import (
    Dhcp4OptionRenewalTime,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__router import (
    Dhcp4OptionRouter,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__subnet_mask import (
    Dhcp4OptionSubnetMask,
)
from pmd_net_proto.protocols.dhcp4.options.dhcp4__option__unknown import (
    Dhcp4OptionUnknown,
)
from pmd_net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, IP4__MIN_MTU
from pmd_net_proto.protocols.udp.udp__header import UDP__HEADER__LEN
from pmd_net_proto._compat import as_buffer

DHCP4__OPTIONS__MAX_LEN = IP4__MIN_MTU - IP4__HEADER__LEN - UDP__HEADER__LEN - DHCP4__HEADER__LEN


class Dhcp4Options(ProtoOptions):
    """
    The DHCPv4 packet options.
    """

    @property
    def classless_static_route(self) -> list[tuple[Ip4Network, Ip4Address]] | None:
        """
        Get the DHCPv4 'classless_static_route' option value (RFC 3442).
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionClasslessStaticRoute):
                return option.routes

        return None

    @property
    def client_id(self) -> Buffer | None:
        """
        Get the DHCPv4 'client_id' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionClientId):
                return option.client_id

        return None

    @property
    def host_name(self) -> str | None:
        """
        Get the DHCPv4 'host_name' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionHostName):
                return option.host_name

        return None

    @property
    def lease_time(self) -> int | None:
        """
        Get the DHCPv4 'lease_time' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionLeaseTime):
                return option.lease_time

        return None

    @property
    def max_msg_size(self) -> int | None:
        """
        Get the DHCPv4 'max_msg_size' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionMaxMsgSize):
                return option.max_msg_size

        return None

    @property
    def option_overload(self) -> Dhcp4OptionOverload | None:
        """
        Get the DHCPv4 'option_overload' option (RFC 2132 §9.3).

        Returns the whole option object so the parser can consult
        its 'includes_file' / 'includes_sname' helpers when
        overlaying the BOOTP 'file' / 'sname' fields.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionOverload):
                return option

        return None

    @property
    def message_type(self) -> Dhcp4MessageType | None:
        """
        Get the DHCPv4 'message_type' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionMessageType):
                return option.message_type

        return None

    @property
    def param_req_list(self) -> list[Dhcp4OptionType] | None:
        """
        Get the DHCPv4 'param_req_list' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionParamReqList):
                return option.param_req_list

        return None

    @property
    def rebinding_time(self) -> int | None:
        """
        Get the DHCPv4 'rebinding_time' (T2) option value (RFC 2132 §9.8).

        When non-None this overrides the factor-based T2 default in
        the DHCPv4 client lifecycle.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionRebindingTime):
                return option.rebinding_time

        return None

    @property
    def renewal_time(self) -> int | None:
        """
        Get the DHCPv4 'renewal_time' (T1) option value (RFC 2132 §9.7).

        When non-None this overrides the factor-based T1 default in
        the DHCPv4 client lifecycle.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionRenewalTime):
                return option.renewal_time

        return None

    @property
    def req_ip_addr(self) -> Ip4Address | None:
        """
        Get the DHCPv4 'req_ip_addr' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionReqIpAddr):
                return option.req_ip_addr

        return None

    @property
    def router(self) -> list[Ip4Address] | None:
        """
        Get the DHCPv4 'router' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionRouter):
                return option.routers

        return None

    @property
    def server_id(self) -> Ip4Address | None:
        """
        Get the DHCPv4 'server_id' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionServerId):
                return option.server_id

        return None

    @property
    def subnet_mask(self) -> Ip4Mask | None:
        """
        Get the DHCPv4 'subnet_mask' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp4OptionSubnetMask):
                return option.subnet_mask

        return None

    @staticmethod
    def validate_integrity(
        *,
        frame: Buffer,
        hlen: int,
        offset: int = DHCP4__HEADER__LEN,
    ) -> None:
        """
        Run the DHCPv4 options integrity checks before parsing options.

        The default 'offset' (DHCP4__HEADER__LEN = 240) walks the
        main options block of a full DHCPv4 frame. RFC 2132 §9.3
        Option Overload reuses the BOOTP 'sname' / 'file' fields
        to carry additional options; the parser's overload pass
        calls this with 'offset=0' against the re-extracted
        sname/file slice so a hostile overloaded sub-block (e.g.
        an option claiming a length that extends past the slice
        end) is rejected with a typed Dhcp4IntegrityError before
        'Dhcp4Options.from_buffer' dispatches.
        """

        while offset < hlen:
            if frame[offset] == int(Dhcp4OptionType.END):
                break

            if frame[offset] == int(Dhcp4OptionType.PAD):
                offset += as_buffer(DHCP4__OPTION__PAD__LEN)
                continue

            # Unlike TCP, the DHCPv4 length byte encodes the data length
            # only (excluding the 2-byte type+length header), so the
            # minimum valid value is 0. Total option size on the wire is
            # DHCP4__OPTION__LEN + data_len.
            if offset + 1 >= hlen:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option is missing its length byte. Got: {offset=}, {hlen=}",
                )

            offset += DHCP4__OPTION__LEN + frame[offset + 1]
            if offset > hlen:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option length must not extend past the header length. Got: {offset=}, {hlen=}",
                )

    @staticmethod
    def _concatenated_classless_static_route_data(buffer: Buffer, /) -> bytes:
        """
        Join the data of every option-121 instance in 'buffer', in
        wire order.

        The Classless Static Route option is a concatenation-requiring
        option: a route set too large for a single 255-octet option is
        split across several option-121 instances whose data must be
        joined before decoding (RFC 3442 mandates RFC 3396 option
        concatenation). A split may fall on any byte boundary, so the
        instances cannot be decoded individually — only the joined
        data is a well-formed descriptor list. The caller must have
        run 'validate_integrity' first so each length byte is in
        bounds.
        """

        data = bytearray()
        offset = 0
        while offset < len(buffer):
            code = buffer[offset]
            if code == int(Dhcp4OptionType.END):
                break
            if code == int(Dhcp4OptionType.PAD):
                offset += as_buffer(DHCP4__OPTION__PAD__LEN)
                continue
            option_data_len = buffer[offset + 1]
            if code == int(Dhcp4OptionType.CLASSLESS_STATIC_ROUTE):
                data += bytes(buffer[offset + DHCP4__OPTION__LEN : offset + DHCP4__OPTION__LEN + option_data_len])
            offset += DHCP4__OPTION__LEN + option_data_len

        return bytes(data)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the DHCPv4 options from buffer.
        """

        # RFC 3396 / RFC 3442: gather the concatenation of every
        # option-121 instance up front so the (possibly split) route
        # list decodes as one option.
        classless_static_route_data = cls._concatenated_classless_static_route_data(buffer)

        offset = 0
        options: list[Dhcp4Option] = []
        classless_static_route_emitted = False

        while offset < len(buffer):
            _match_subject = Dhcp4OptionType.from_bytes(buffer[offset : offset + 1])
            if _match_subject == Dhcp4OptionType.END:
                options.append(Dhcp4OptionEnd.from_buffer(buffer[offset:]))
                break
            elif _match_subject == Dhcp4OptionType.PAD:
                options.append(Dhcp4OptionPad.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.CLASSLESS_STATIC_ROUTE:
                # Emit a single option built from the concatenated
                # data the first time a 121 instance is seen; later
                # instances only advance the cursor (their data is
                # already folded in). Individual instances are NOT
                # decoded — a split can fall mid-descriptor.
                if not classless_static_route_emitted:
                    routes = Dhcp4OptionClasslessStaticRoute.decode_routes(classless_static_route_data)
                    if not routes:
                        raise Dhcp4IntegrityError(
                            "The DHCPv4 Classless Static Route option must carry at least "
                            "one route (RFC 3442 minimum length 5 octets)."
                        )
                    options.append(Dhcp4OptionClasslessStaticRoute(routes))
                    classless_static_route_emitted = True
                offset += DHCP4__OPTION__LEN + buffer[offset + 1]
                continue
            elif _match_subject == Dhcp4OptionType.CLIENT_ID:
                options.append(Dhcp4OptionClientId.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.HOST_NAME:
                options.append(Dhcp4OptionHostName.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.LEASE_TIME:
                options.append(Dhcp4OptionLeaseTime.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.MAX_MSG_SIZE:
                options.append(Dhcp4OptionMaxMsgSize.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.MESSAGE_TYPE:
                options.append(Dhcp4OptionMessageType.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.OPTION_OVERLOAD:
                options.append(Dhcp4OptionOverload.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.PARAM_REQ_LIST:
                options.append(Dhcp4OptionParamReqList.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.REBINDING_TIME:
                options.append(Dhcp4OptionRebindingTime.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.RENEWAL_TIME:
                options.append(Dhcp4OptionRenewalTime.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.REQ_IP_ADDR:
                options.append(Dhcp4OptionReqIpAddr.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.ROUTER:
                options.append(Dhcp4OptionRouter.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.SERVER_ID:
                options.append(Dhcp4OptionServerId.from_buffer(buffer[offset:]))
            elif _match_subject == Dhcp4OptionType.SUBNET_MASK:
                options.append(Dhcp4OptionSubnetMask.from_buffer(buffer[offset:]))
            else:
                options.append(Dhcp4OptionUnknown.from_buffer(buffer[offset:]))

            offset += as_buffer(options[-1].len)

        return cls(*options)


class Dhcp4OptionsProperties(ABC):
    """
    The DHCPv4 options properties mixin class.
    """

    _options: Dhcp4Options

    @property
    def classless_static_route(self) -> list[tuple[Ip4Network, Ip4Address]] | None:
        """
        Get the DHCPv4 'classless_static_route' option value (RFC 3442).
        """

        return self._options.classless_static_route

    @property
    def client_id(self) -> Buffer | None:
        """
        Get the DHCPv4 'client_id' option value.
        """

        return self._options.client_id

    @property
    def host_name(self) -> str | None:
        """
        Get the DHCPv4 'host_name' option value.
        """

        return self._options.host_name

    @property
    def lease_time(self) -> int | None:
        """
        Get the DHCPv4 'lease_time' option value.
        """

        return self._options.lease_time

    @property
    def max_msg_size(self) -> int | None:
        """
        Get the DHCPv4 'max_msg_size' option value.
        """

        return self._options.max_msg_size

    @property
    def option_overload(self) -> Dhcp4OptionOverload | None:
        """
        Get the DHCPv4 'option_overload' option (RFC 2132 §9.3).
        """

        return self._options.option_overload

    @property
    def message_type(self) -> Dhcp4MessageType | None:
        """
        Get the DHCPv4 'message_type' option value.
        """

        return self._options.message_type

    @property
    def param_req_list(self) -> list[Dhcp4OptionType] | None:
        """
        Get the DHCPv4 'param_req_list' option value.
        """

        return self._options.param_req_list

    @property
    def rebinding_time(self) -> int | None:
        """
        Get the DHCPv4 'rebinding_time' option value (RFC 2132 §9.8).
        """

        return self._options.rebinding_time

    @property
    def renewal_time(self) -> int | None:
        """
        Get the DHCPv4 'renewal_time' option value (RFC 2132 §9.7).
        """

        return self._options.renewal_time

    @property
    def req_ip_addr(self) -> Ip4Address | None:
        """
        Get the DHCPv4 'req_ip_addr' option value.
        """

        return self._options.req_ip_addr

    @property
    def router(self) -> list[Ip4Address] | None:
        """
        Get the DHCPv4 'router' option value.
        """

        return self._options.router

    @property
    def server_id(self) -> Ip4Address | None:
        """
        Get the DHCPv4 'server_id' option value.
        """

        return self._options.server_id

    @property
    def subnet_mask(self) -> Ip4Mask | None:
        """
        Get the DHCPv4 'subnet_mask' option value.
        """

        return self._options.subnet_mask
