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
This module contains packet handler for the inbound UDP packets.

pytcp/subsystems/packet_handler/packet_handler__udp__rx.py

ver 3.0.3
"""

import time
from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, IpVersion
from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4Message,
    Icmp4MessageDestinationUnreachable,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    PacketRx,
    PacketValidationError,
    UdpParser,
)
from net_proto.protocols.udp.udp__errors import UdpZeroCksumIp6Error
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket


class PacketHandlerUdpRx(ABC):
    """
    Class implements packet handler for the inbound UDP packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Address, IpAddress
        from net_proto import Icmp6Message, Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx

        # pylint: disable=unused-argument

        def _phtx_udp(
            self,
            *,
            ip__src: Ip6Address | Ip4Address,
            ip__dst: Ip6Address | Ip4Address,
            udp__sport: int,
            udp__dport: int,
            udp__payload: bytes = bytes(),
            ip__ttl: int | None = None,
            ip__ecn: int = 0,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        def _phtx_icmp6(
            self,
            *,
            ip6__src: Ip6Address,
            ip6__dst: Ip6Address,
            ip6__hop: int | None = None,
            icmp6__message: Icmp6Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound UDP packets.
        """

        self._packet_stats_rx.udp__pre_parse += 1

        try:
            UdpParser(packet_rx)

        except UdpZeroCksumIp6Error as error:
            # RFC 8200 §8.1 / RFC 6935 §5: silent discard, no
            # ICMPv6 Parameter Problem. The dedicated counter
            # gives operators a greppable observability signal
            # distinct from generic UDP parse failures.
            self._packet_stats_rx.udp__ip6_zero_cksum__drop += 1
            __debug__ and log(
                "udp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        except PacketValidationError as error:
            self._packet_stats_rx.udp__failed_parse__drop += 1
            __debug__ and log(
                "udp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("udp", f"{packet_rx.tracker} - {packet_rx.udp}")

        # Ensure that UDP payload type is memoryview.
        assert isinstance(
            packet_rx.udp.payload, memoryview
        ), f"The payload must be a memoryview. Got {type(packet_rx.udp.payload)}"

        # Create UdpMetadata object and try to find matching UDP socket.
        packet_rx_md = UdpMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            udp__local_port=packet_rx.udp.dport,
            ip__remote_address=packet_rx.ip.src,
            udp__remote_port=packet_rx.udp.sport,
            udp__data=packet_rx.udp.payload,
            tracker=packet_rx.tracker,
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.udp__socket_match += 1
                __debug__ and log(
                    "udp",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
                )
                socket.process_udp_packet(packet_rx_md)
                return

        # Silently drop packet if it's source address is unspecified.
        if packet_rx.ip.src.is_unspecified:
            self._packet_stats_rx.udp__ip_source_unspecified += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - Received UDP packet from "
                f"{packet_rx.ip.src}, port {packet_rx.udp.sport} to "
                f"{packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping",
            )
            return

        # Handle the UDP Echo operation in case its enabled
        # (used for packet flow unit testing only).
        if stack.UDP__ECHO_NATIVE and packet_rx.udp.dport == 7:
            self._packet_stats_rx.udp__echo_native__respond_udp += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <INFO>Performing native " "UDP Echo operation</>",
            )

            self._phtx_udp(
                ip__src=packet_rx.ip.dst,
                ip__dst=packet_rx.ip.src,
                udp__sport=packet_rx.udp.dport,
                udp__dport=packet_rx.udp.sport,
                udp__payload=packet_rx.udp.payload,
            )
            return

        # Respond with ICMP Port Unreachable message if no matching
        # socket has been found, subject to the host-requirements
        # gates and the outbound rate limit.
        rate_limiter = (
            stack.icmp4_error_rate_limiter if packet_rx.ip.ver is IpVersion.IP4 else stack.icmp6_error_rate_limiter
        )
        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=rate_limiter,
            now=time.monotonic(),
        )
        if verdict is not None:
            if packet_rx.ip.ver is IpVersion.IP4:
                self._packet_stats_rx.udp__no_socket_match__icmp4_unreachable_suppressed += 1
            else:
                self._packet_stats_rx.udp__no_socket_match__icmp6_unreachable_suppressed += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <WARN>Suppressing ICMP Port-Unreachable "
                f"to {packet_rx.ip.src}: {verdict}</>",
            )
            return

        __debug__ and log(
            "udp",
            f"{packet_rx_md.tracker} - Received UDP packet from "
            f"{packet_rx.ip.src} to closed port "
            f"{packet_rx.udp.dport}, sending ICMPv4 Port Unreachable",
        )

        match packet_rx.ip.ver:
            case IpVersion.IP6:
                self._packet_stats_rx.udp__no_socket_match__respond_icmp6_unreachable += 1
                self._phtx_icmp6(
                    ip6__src=packet_rx.ip6.dst,
                    ip6__dst=packet_rx.ip6.src,
                    icmp6__message=Icmp6MessageDestinationUnreachable(
                        code=Icmp6DestinationUnreachableCode.PORT,
                        data=packet_rx.ip.packet_bytes,
                    ),
                    echo_tracker=packet_rx.tracker,
                )
            case IpVersion.IP4:
                self._packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable += 1
                self._phtx_icmp4(
                    ip4__src=packet_rx.ip4.dst,
                    ip4__dst=packet_rx.ip4.src,
                    icmp4__message=Icmp4MessageDestinationUnreachable(
                        code=Icmp4DestinationUnreachableCode.PORT,
                        data=packet_rx.ip.packet_bytes,
                    ),
                    echo_tracker=packet_rx.tracker,
                )
