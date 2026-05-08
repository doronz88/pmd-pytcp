############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains packet handler for the outbound ICMPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__icmp6__tx.py

ver 3.0.4
"""

import struct
from abc import ABC
from typing import TYPE_CHECKING

from net_addr import Ip6Address, Ip6Host, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6Message,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Type,
    IpProto,
    Tracker,
)
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__router_alert import (
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
    Ip6HbhOptionRouterAlert,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerIcmp6Tx(ABC):
    """
    Class defines methods for handling outbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from net_proto import IP6__DEFAULT_HOP_LIMIT, Ip6Payload, RawAssembler
        from pytcp.lib.packet_stats import PacketStatsTx

        _packet_stats_tx: PacketStatsTx
        _mac_unicast: MacAddress
        _ip6_multicast: list[Ip6Address]
        _ip6_host: list[Ip6Host]

        # pylint: disable=unused-argument

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = IP6__DEFAULT_HOP_LIMIT,
            ip6__ecn: int = 0,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

    def _phtx_icmp6(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__hop: int = 64,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv6 packets.
        """

        self._packet_stats_tx.icmp6__pre_assemble += 1

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=icmp6__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}")

        match icmp6__message.type, icmp6__message.code:
            case Icmp6Type.ECHO_REPLY, _:
                self._packet_stats_tx.icmp6__echo_reply__send += 1
            case Icmp6Type.ECHO_REQUEST, _:
                self._packet_stats_tx.icmp6__echo_request__send += 1
            case (
                Icmp6Type.DESTINATION_UNREACHABLE,
                Icmp6DestinationUnreachableCode.PORT,
            ):
                self._packet_stats_tx.icmp6__destination_unreachable__port__send += 1
            case Icmp6Type.PARAMETER_PROBLEM, _:
                self._packet_stats_tx.icmp6__parameter_problem__send += 1
            case Icmp6Type.ND__ROUTER_SOLICITATION, _:
                self._packet_stats_tx.icmp6__nd__router_solicitation__send += 1
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT, _:
                self._packet_stats_tx.icmp6__nd__router_advertisement__send += 1
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION, _:
                self._packet_stats_tx.icmp6__nd__neighbor_solicitation__send += 1
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT, _:
                self._packet_stats_tx.icmp6__nd__neighbor_advertisement__send += 1
            case Icmp6Type.MLD2__REPORT, _:
                self._packet_stats_tx.icmp6__mld2__report__send += 1
            case _:
                # Defensive drop: unsupported ICMPv6 type/code shouldn't
                # reach the TX path (the call sites enumerate their
                # message types), but if one does, count + drop is
                # robust where 'raise' would crash the calling thread.
                self._packet_stats_tx.icmp6__unknown__drop += 1
                __debug__ and log(
                    "icmp6",
                    f"{icmp6_packet_tx.tracker} - <CRIT>Dropping unsupported ICMPv6 "
                    f"type {icmp6__message.type}, code {icmp6__message.code}</>",
                )
                return TxStatus.DROPPED__ICMP6__UNKNOWN

        return self._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=icmp6_packet_tx,
        )

    def _send_icmp6_nd_dad_message(self, *, ip6_unicast_candidate: Ip6Address) -> None:
        """
        Send out ICMPv6 ND Duplicate Address Detection message.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=Ip6Address(),
            ip6__dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=ip6_unicast_candidate,
                options=Icmp6NdOptions(),  # ND DAD message has no options.
            ),
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 ND DAD message for " f"{ip6_unicast_candidate}, tx_status: {tx_status}",
            )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send out ICMPv6 Multicast Listener Report for given list of
        addresses, wrapped in a Hop-by-Hop Options header carrying
        the Router Alert option (value=MLD) so MLD-aware routers
        intercept the report per RFC 3810 §5 + RFC 2711.

        Hop Limit is fixed at 1 per RFC 3810 §5.2.13 (MLDv2 messages
        are link-local).
        """

        # Need to use set here to avoid reusing duplicate multicast entries
        # from stack_ip6_multicast list, also All Multicast Nodes address is
        # not being advertised as this is not necessary.
        icmp6_mlr2_multicast_address_record = {
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                multicast_address=multicast_address,
            )
            for multicast_address in self._ip6_multicast
            if multicast_address not in {Ip6Address("ff02::1")}
        }

        if not icmp6_mlr2_multicast_address_record:
            return

        ip6__src = self.ip6_unicast[0] if self.ip6_unicast else Ip6Address()
        ip6__dst = Ip6Address("ff02::16")

        # Build the ICMPv6 MLDv2 Report packet.
        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(records=list(icmp6_mlr2_multicast_address_record)),
        )

        # Pre-compute the ICMPv6 pseudo-header sum that will be used
        # to finalise the ICMPv6 checksum. RFC 4443 §2.3: the
        # pseudo-header carries 'src + dst + Upper-Layer Packet
        # Length + Next Header = 58' regardless of any extension
        # headers between IPv6 and ICMPv6, so the value can be
        # computed here without help from 'Ip6Assembler' (which
        # only auto-injects pshdr_sum on TCP/UDP/Icmp6/Raw payloads
        # — not when the immediate IPv6 payload is a Hop-by-Hop
        # extension header).
        pseudo_header = struct.pack(
            "! 16s 16s L BBBB",
            bytes(ip6__src),
            bytes(ip6__dst),
            len(icmp6_packet_tx),
            0,
            0,
            0,
            int(IpProto.ICMP6),
        )
        icmp6_packet_tx.pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))

        # Serialise the (now-checksummed) ICMPv6 packet to bytes for
        # carriage as the HBH payload.
        icmp6_buffers: list = []
        icmp6_packet_tx.assemble(icmp6_buffers)
        icmp6_bytes = b"".join(bytes(buf) for buf in icmp6_buffers)

        # Wrap in HBH carrying Router Alert (value=MLD per RFC 2711)
        # plus a PadN(0) to align the HBH header to 8 octets:
        #   2-byte HBH prefix + 4-byte RA + 2-byte PadN(0) = 8 bytes.
        hbh_packet_tx = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.ICMP6,
            ip6_hbh__options=Ip6HbhOptions(
                Ip6HbhOptionRouterAlert(
                    value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
                ),
                Ip6HbhOptionPadN(b""),
            ),
            ip6_hbh__payload=icmp6_bytes,
            echo_tracker=icmp6_packet_tx.tracker,
        )

        self._packet_stats_tx.icmp6__pre_assemble += 1
        self._packet_stats_tx.icmp6__mld2__report__send += 1

        tx_status = self._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=1,
            ip6__payload=hbh_packet_tx,
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                "Sent out ICMPv6 Multicast Listener Report (HBH+RA) for "
                f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 Multicast Listener Report (HBH+RA) for "
                f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}, "
                f"tx_status: {tx_status}",
            )

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send out ICMPv6 ND Router Solicitation.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=self.ip6_unicast[0],
            ip6__dst=Ip6Address("ff02::2"),
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageRouterSolicitation(
                options=Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=self._mac_unicast),
                ),
            ),
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Router Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Router Solicitation, {tx_status}",
            )

    def send_icmp6_neighbor_solicitation(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue ICMPv6 Neighbor Solicitation packet with TX ring.
        """

        # Pick appropriate source address
        ip6__src = Ip6Address()
        for ip6_host in self._ip6_host:
            if icmp6_ns_target_address in ip6_host.network:
                ip6__src = ip6_host.address

        # Send out ND Neighbor Solicitation message
        tx_status = self._phtx_icmp6(
            ip6__src=ip6__src,
            ip6__dst=icmp6_ns_target_address.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=icmp6_ns_target_address,
                options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self._mac_unicast)),
            ),
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Neighbor Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Neighbor Solicitation, {tx_status}",
            )

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int = 64,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv4 Socket -> FPA communication.
        """

        return self._phtx_icmp6(
            ip6__src=ip6__local_address,
            ip6__dst=ip6__remote_address,
            ip6__hop=ip6__hop,
            icmp6__message=icmp6__message,
        )
