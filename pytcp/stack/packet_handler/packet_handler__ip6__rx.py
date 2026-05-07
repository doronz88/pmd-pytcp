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
This module contains packet handler for the inbound IPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__ip6__rx.py

ver 3.0.4
"""

import time as time_module
from abc import ABC
from typing import TYPE_CHECKING, cast

from net_proto import (
    Icmp6Message,
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
    Ip6Parser,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket


class PacketHandlerIp6Rx(ABC):
    """
    Class implements packet handler for the inbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Address
        from net_proto import Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx
        _ip6_multicast: list[Ip6Address]

        # pylint: disable=unused-argument

        def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_udp(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_tcp(self, packet_rx: PacketRx, /) -> None: ...

        def _phtx_icmp6(
            self,
            *,
            ip6__src: Ip6Address,
            ip6__dst: Ip6Address,
            ip6__hop: int = 64,
            icmp6__message: Icmp6Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def _ip6_unicast(self) -> list[Ip6Address]: ...

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv6 packets.
        """

        self._packet_stats_rx.ip6__pre_parse += 1

        try:
            Ip6Parser(packet_rx)

        except PacketValidationError as error:
            self._packet_stats_rx.ip6__failed_parse__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6}")

        # Check if received packet has been sent to us directly or by unicast
        # or multicast.
        if packet_rx.ip6.dst not in {*self._ip6_unicast, *self._ip6_multicast}:
            self._packet_stats_rx.ip6__dst_unknown__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - IP packet not destined for this stack, " "dropping",
            )
            return

        if packet_rx.ip6.dst in self._ip6_unicast:
            self._packet_stats_rx.ip6__dst_unicast += 1

        if packet_rx.ip6.dst in self._ip6_multicast:
            self._packet_stats_rx.ip6__dst_multicast += 1

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=packet_rx.ip6.next,
            raw__data=bytes(packet_rx.ip6.payload_bytes),  # memoryview: conversion for end-user interface.
            tracker=packet_rx.tracker,
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.raw__socket_match += 1
                __debug__ and log(
                    "ip6",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

        match packet_rx.ip6.next:
            case IpProto.IP6_FRAG:
                self._phrx_ip6_frag(packet_rx)
            case IpProto.ICMP6:
                self._phrx_icmp6(packet_rx)
            case IpProto.UDP:
                self._phrx_udp(packet_rx)
            case IpProto.TCP:
                self._phrx_tcp(packet_rx)
            case _:
                self._packet_stats_rx.ip6__no_proto_support__drop += 1
                __debug__ and log(
                    "ip6",
                    f"{packet_rx.tracker} - Unsupported protocol " f"{packet_rx.ip6.next}, dropping.",
                )
                self.__phrx_ip6__emit_unrecognized_next_header(packet_rx)

    def __phrx_ip6__emit_unrecognized_next_header(self, packet_rx: PacketRx) -> None:
        """
        Emit ICMPv6 Parameter Problem code 1 (Unrecognized Next Header)
        in response to an inbound IPv6 datagram whose Next Header field
        designates a transport protocol the host does not implement.

        Per RFC 8200 §4 the pointer field carries the byte offset of
        the offending Next Header. PyTCP does not currently process
        IPv6 extension headers, so the pointer is fixed at 6 (the
        offset of the Next Header field in the IPv6 main header).

        Subject to the host-requirements gates and rate limit.

        Reference: RFC 8200 §4 (IPv6 node MUST send Param Problem
        code 1 on unrecognized Next Header).
        Reference: RFC 4443 §3.4 (Parameter Problem code 1 wire format).
        Reference: RFC 4443 §2.4(e/f) (gate + rate-limit requirements).
        """

        # No configured unicast IPv6 address: cannot emit because the
        # source-IP reflection from packet_rx.ip6.dst would not be a
        # valid stack address.
        if not self._ip6_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp6_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._packet_stats_rx.ip6__no_proto_support__icmp6_param_problem_suppressed += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv6 Unrecognized Next Header "
                f"to {packet_rx.ip6.src}: {verdict}</>",
            )
            return

        self._packet_stats_rx.ip6__no_proto_support__respond_icmp6_param_problem += 1
        self._phtx_icmp6(
            ip6__src=packet_rx.ip6.dst,
            ip6__dst=packet_rx.ip6.src,
            icmp6__message=Icmp6MessageParameterProblem(
                code=Icmp6ParameterProblemCode.UNRECOGNIZED_NEXT_HEADER,
                pointer=6,
                data=packet_rx.ip.packet_bytes,
            ),
            echo_tracker=packet_rx.tracker,
        )
