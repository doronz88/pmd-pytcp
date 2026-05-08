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
This module contains packet handler for the inbound IPv4 packets.

pytcp/subsystems/packet_handler/packet_handler__ip4__rx.py

ver 3.0.4
"""

import struct
import time as time_module
from abc import ABC
from time import time
from typing import TYPE_CHECKING, cast

from net_proto import (
    IP4__HEADER__LEN,
    Icmp4DestinationUnreachableCode,
    Icmp4Message,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageParameterProblem,
    Icmp4ParameterProblemCode,
    Ip4Parser,
    Ip4SanityError,
    IpProto,
    PacketRx,
    PacketValidationError,
    inet_cksum,
)
from pytcp import stack
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket


class PacketHandlerIp4Rx(ABC):
    """
    Class implements packet handler for the inbound IPv4 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Address
        from net_proto import Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx
        _ip4_multicast: list[Ip4Address]
        _ip4_frag_flows: dict[IpFragFlowId, IpFragData]

        # pylint: disable=unused-argument

        def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_udp(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_tcp(self, packet_rx: PacketRx, /) -> None: ...

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def _ip4_unicast(self) -> list[Ip4Address]: ...

        @property
        def _ip4_broadcast(self) -> list[Ip4Address]: ...

    def _phrx_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv4 packets.
        """

        self._packet_stats_rx.ip4__pre_parse += 1

        try:
            Ip4Parser(packet_rx)

        except Ip4SanityError as error:
            self._packet_stats_rx.ip4__failed_parse__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            if error.pointer is not None:
                self.__phrx_ip4__emit_parameter_problem(packet_rx, error.pointer)
            return

        except PacketValidationError as error:
            self._packet_stats_rx.ip4__failed_parse__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ip4", f"{packet_rx.tracker} - {packet_rx.ip4}")

        # Source-route gate: drop inbound packets carrying LSRR or
        # SSRR options unless 'IP4__ACCEPT_SOURCE_ROUTE' is True.
        # Default False matches Linux's
        # 'net.ipv4.conf.*.accept_source_route' default and closes
        # an attack surface that the LSRR/SSRR echo support
        # otherwise widens — the Echo Reply path stays in place
        # for operators that explicitly opt in.
        if not stack.IP4__ACCEPT_SOURCE_ROUTE and (packet_rx.ip4.lsrr is not None or packet_rx.ip4.ssrr is not None):
            self._packet_stats_rx.ip4__source_route__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Dropping source-routed IPv4 packet "
                f"from {packet_rx.ip4.src} (IP4__ACCEPT_SOURCE_ROUTE=False)</>",
            )
            return

        # Check if received packet has been sent to us directly or by
        # unicast/broadcast, allow any destination if no unicast address
        # is configured (for DHCP client).
        if self._ip4_unicast and packet_rx.ip4.dst not in {
            *self._ip4_unicast,
            *self._ip4_multicast,
            *self._ip4_broadcast,
        }:
            self._packet_stats_rx.ip4__dst_unknown__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - IP packet not destined for this stack, " "dropping",
            )
            return

        if packet_rx.ip4.dst in self._ip4_unicast:
            self._packet_stats_rx.ip4__dst_unicast += 1

        if packet_rx.ip4.dst in self._ip4_multicast:
            self._packet_stats_rx.ip4__dst_multicast += 1

        if packet_rx.ip4.dst in self._ip4_broadcast:
            self._packet_stats_rx.ip4__dst_broadcast += 1

        # Check if packet is a fragment and if so process it accordingly.
        if packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf:
            self._packet_stats_rx.ip4__frag += 1
            if not (defragmented_packet_rx := self.__defragment_ip4_packet(packet_rx)):
                return
            packet_rx = defragmented_packet_rx
            self._packet_stats_rx.ip4__defrag += 1

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=packet_rx.ip4.proto,
            raw__data=bytes(packet_rx.ip4.payload_bytes),  # memoryview: conversion for end-user interface.
            tracker=packet_rx.tracker,
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.raw__socket_match += 1
                __debug__ and log(
                    "ip4",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

        match packet_rx.ip4.proto:
            case IpProto.ICMP4:
                self._phrx_icmp4(packet_rx)
            case IpProto.UDP:
                self._phrx_udp(packet_rx)
            case IpProto.TCP:
                self._phrx_tcp(packet_rx)
            case _:
                self._packet_stats_rx.ip4__no_proto_support__drop += 1
                __debug__ and log(
                    "ip4",
                    f"{packet_rx.tracker} - Unsupported protocol " f"{packet_rx.ip4.proto}, dropping.",
                )
                self.__phrx_ip4__emit_protocol_unreachable(packet_rx)

    def __phrx_ip4__emit_protocol_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Emit ICMPv4 Destination Unreachable code 2 (Protocol
        Unreachable) in response to an inbound IPv4 datagram whose
        'proto' field designates a transport protocol the host does
        not implement, subject to the host-requirements gates and
        rate limit.

        Reference: RFC 1122 §3.2.2.1 (host SHOULD generate Code 2).
        Reference: RFC 1122 §3.2.2 (gates: bcast/mcast destination,
        non-initial fragment, invalid source).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        # DHCP-client mode: no configured unicast IPv4 address. Cannot
        # emit ICMP errors because the source-IP reflection from
        # packet_rx.ip4.dst would not be a valid stack address.
        if not self._ip4_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp4_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._packet_stats_rx.ip4__no_proto_support__icmp4_unreachable_suppressed += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv4 Protocol Unreachable "
                f"to {packet_rx.ip4.src}: {verdict}</>",
            )
            return

        self._packet_stats_rx.ip4__no_proto_support__respond_icmp4_unreachable += 1
        self._phtx_icmp4(
            ip4__src=packet_rx.ip4.dst,
            ip4__dst=packet_rx.ip4.src,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.PROTOCOL,
                data=packet_rx.ip.packet_bytes,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __phrx_ip4__emit_parameter_problem(self, packet_rx: PacketRx, pointer: int) -> None:
        """
        Emit ICMPv4 Parameter Problem (Code 0) in response to an
        inbound IPv4 datagram whose header field at byte offset
        'pointer' fails sanity validation, subject to the host-
        requirements gates and rate limit.

        Reference: RFC 1122 §3.2.2.5 (host SHOULD generate Param Problem).
        Reference: RFC 792 (Parameter Problem pointer).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        # DHCP-client mode: no configured unicast IPv4 address. Cannot
        # emit ICMP errors because the source-IP reflection from
        # packet_rx.ip4.dst would not be a valid stack address.
        if not self._ip4_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp4_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._packet_stats_rx.ip4__sanity_error__icmp4_param_problem_suppressed += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv4 Parameter Problem "
                f"to {packet_rx.ip4.src}: {verdict}</>",
            )
            return

        self._packet_stats_rx.ip4__sanity_error__respond_icmp4_param_problem += 1
        self._phtx_icmp4(
            ip4__src=packet_rx.ip4.dst,
            ip4__dst=packet_rx.ip4.src,
            icmp4__message=Icmp4MessageParameterProblem(
                code=Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                pointer=pointer,
                data=packet_rx.ip.packet_bytes,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __defragment_ip4_packet(self, packet_rx: PacketRx) -> PacketRx | None:
        """
        Defragment IPv4 packet.
        """

        # Cleanup expired flows. A flow is kept while its age
        # (now - first-fragment timestamp) is below the timeout.
        now = time()
        self._ip4_frag_flows = {
            flow: self._ip4_frag_flows[flow]
            for flow in self._ip4_frag_flows
            if now - self._ip4_frag_flows[flow].timestamp < stack.IP4__FRAG_FLOW_TIMEOUT
        }

        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - IPv4 packet fragment, offset "
            f"{packet_rx.ip4.offset}, dlen {packet_rx.ip4.payload_len}"
            f"{'' if packet_rx.ip4.flag_mf else ', last'}",
        )

        flow_id = IpFragFlowId(
            src=packet_rx.ip4.src,
            dst=packet_rx.ip4.dst,
            id=packet_rx.ip4.id,
        )

        # Update flow db.
        if flow_id in self._ip4_frag_flows:
            self._ip4_frag_flows[flow_id].payload[packet_rx.ip4.offset] = packet_rx.ip4.payload_bytes
        else:
            self._ip4_frag_flows[flow_id] = IpFragData(
                header=packet_rx.ip4.header_bytes,
                payload={packet_rx.ip4.offset: packet_rx.ip4.payload_bytes},
            )
        if not packet_rx.ip4.flag_mf:
            self._ip4_frag_flows[flow_id].received_last_frag()

        # Test if we received all fragments.
        if not self._ip4_frag_flows[flow_id].last:
            return None
        payload_len = 0
        for offset in sorted(self._ip4_frag_flows[flow_id].payload):
            if offset > payload_len:
                return None
            payload_len = offset + len(self._ip4_frag_flows[flow_id].payload[offset])

        # Defragment packet.
        header = bytearray(self._ip4_frag_flows[flow_id].header)
        payload = bytearray(payload_len)
        for offset in sorted(self._ip4_frag_flows[flow_id].payload):
            struct.pack_into(
                f"{len(self._ip4_frag_flows[flow_id].payload[offset])}s",
                payload,
                offset,
                bytes(self._ip4_frag_flows[flow_id].payload[offset]),
            )
        del self._ip4_frag_flows[flow_id]
        header[0] = 0x45
        struct.pack_into("!H", header, 2, IP4__HEADER__LEN + len(payload))
        header[6] = header[7] = header[10] = header[11] = 0
        struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
        packet_rx = PacketRx(bytes(header) + payload)
        Ip4Parser(packet_rx)
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - Reasembled fragmented IPv4 packet, " f"dlen {len(payload)} bytes",
        )
        return packet_rx
