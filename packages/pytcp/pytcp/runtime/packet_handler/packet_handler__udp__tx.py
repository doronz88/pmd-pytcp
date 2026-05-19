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
This module contains protocol support for the outbound UDP packets.

pytcp/subsystems/packet_handler/packet_handler__udp__tx.py

ver 3.0.6
"""

from abc import ABC
from typing import TYPE_CHECKING, Any, cast

from net_addr import Ip4Address, Ip6Address
from net_proto import Tracker, UdpAssembler
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ip4.options.ip4__options import Ip4Options
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerUdpTx(ABC):
    """
    Class implements packet handler for the outbound UDP packets.
    """

    if TYPE_CHECKING:
        from net_addr import IpAddress
        from net_proto import (
            IP6__DEFAULT_HOP_LIMIT,
            Icmp4Assembler,
            Icmp6Assembler,
            Ip4Payload,
            Ip6FragAssembler,
            Ip6Payload,
            RawAssembler,
        )
        from pytcp.lib.packet_stats import PacketStatsTx

        _packet_stats_tx: PacketStatsTx

        # pylint: disable=unused-argument

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int | None = None,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus: ...

        def _phtx_ip4(
            self,
            *,
            ip4__dst: Ip4Address,
            ip4__src: Ip4Address,
            ip4__ttl: int | None = None,
            ip4__flag_df: bool = False,
            ip4__options: Ip4Options = Ip4Options(),
            ip4__payload: Ip4Payload = RawAssembler(),
        ) -> TxStatus: ...

    def _phtx_udp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        udp__sport: int,
        udp__dport: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip4__options: Ip4Options | None = None,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound UDP packets. 'udp__no_cksum' threads
        through to 'UdpAssembler' to emit the RFC 6935 §5
        alternative-mode zero checksum (literal 0x0000) when
        the originating socket has 'UDP_NO_CHECK6_TX' set.
        """

        self._packet_stats_tx.udp__pre_assemble += 1

        udp_packet_tx = UdpAssembler(
            udp__sport=udp__sport,
            udp__dport=udp__dport,
            udp__payload=udp__payload,
            udp__no_cksum=udp__no_cksum,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

        match ip__src.is_ip6, ip__dst.is_ip6, ip__src.is_ip4, ip__dst.is_ip4:
            case True, True, False, False:
                self._packet_stats_tx.udp__send += 1
                ip6_kwargs: dict[str, Any] = {
                    "ip6__src": cast(Ip6Address, ip__src),
                    "ip6__dst": cast(Ip6Address, ip__dst),
                    "ip6__payload": udp_packet_tx,
                    "ip6__ecn": ip__ecn,
                }
                if ip__ttl is not None:
                    ip6_kwargs["ip6__hop"] = ip__ttl
                return self._phtx_ip6(**ip6_kwargs)
            case False, False, True, True:
                self._packet_stats_tx.udp__send += 1
                # RFC 791 §2.3 / RFC 1122 §3.3.3: an outbound UDP
                # datagram larger than the link MTU is fragmented,
                # not dropped, so DF=0 by default. This matches
                # Linux, whose default UDP socket (no IP_MTU_DISCOVER
                # set) fragments rather than path-MTU-discovers.
                # Phase 3: per-socket DF / PMTUD opt-in lands when
                # setsockopt(IP_MTU_DISCOVER) is wired through.
                ip4_kwargs: dict[str, Any] = {
                    "ip4__src": cast(Ip4Address, ip__src),
                    "ip4__dst": cast(Ip4Address, ip__dst),
                    "ip4__flag_df": False,
                    "ip4__payload": udp_packet_tx,
                    "ip4__ecn": ip__ecn,
                }
                if ip__ttl is not None:
                    ip4_kwargs["ip4__ttl"] = ip__ttl
                # Per-socket IPv4 options block (RFC 1122 §4.1.3.2)
                # threads through from setsockopt(IP_OPTIONS) on
                # the originating UDP socket.
                if ip4__options is not None and len(ip4__options) > 0:
                    ip4_kwargs["ip4__options"] = ip4__options
                return self._phtx_ip4(**ip4_kwargs)
            case _:
                raise ValueError(f"Invalid IP address version combination: {ip__src} -> {ip__dst}")

    def send_udp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip4__options: Ip4Options | None = None,
    ) -> TxStatus:
        """
        Interface method for UDP Socket -> Packet Assembler
        communication. 'udp__no_cksum' threads through the
        UdpSocket.send / sendto path to enable the RFC 6935 §5
        zero-checksum opt-in.
        """

        return self._phtx_udp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            udp__sport=udp__local_port,
            udp__dport=udp__remote_port,
            udp__payload=udp__payload,
            udp__no_cksum=udp__no_cksum,
            ip__ttl=ip__ttl,
            ip__ecn=ip__ecn,
            ip4__options=ip4__options,
        )
