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
This module contains the RFC 5227 IPv4 Address Conflict Detection
engine ('Ip4Acd') — the userspace ACD actor that runs probe and
announce over an AF_PACKET raw link socket, exactly as Linux's
'sd-ipv4acd' / 'n-acd' do. The Linux kernel performs no IPv4 ACD; the
client owns both the mechanism (sending ARP, reading ARP for
conflicts) and the policy (when to probe / announce / yield).

pytcp/protocols/ip4/acd/ip4_acd.py

ver 3.0.6
"""

import random
import time
from dataclasses import dataclass

from net_addr import Ip4Address, MacAddress
from net_proto import (
    ArpAssembler,
    ArpOperation,
    ArpParser,
    EthernetAssembler,
    EthernetParser,
    EtherType,
    PacketRx,
    PacketValidationError,
)
from net_proto.lib.buffer import Buffer
from pytcp.lib.logger import log
from pytcp.protocols.arp import arp__constants
from pytcp.socket import ETH_P_ARP, SOCK_RAW, AddressFamily, socket
from pytcp.socket.sockaddr_ll import SockAddrLl

# Inter-poll tick for the conflict watcher: how often the probe loop
# re-checks the ARP socket while waiting out a timing window. Small
# relative to the RFC 5227 sub-second timers, large enough not to spin.
_CONFLICT_POLL_TICK__SEC: float = 0.05

_BROADCAST_MAC = MacAddress(0xFFFFFFFFFFFF)


@dataclass(frozen=True, kw_only=True, slots=True)
class AcdResult:
    """
    Outcome of an 'Ip4Acd.probe' run. 'success=True' means the
    RFC 5227 §2.1.1 Probe sequence completed with no observed
    conflict; the address is safe to claim. 'success=False' means a
    conflicting ARP was seen during the probe window; 'conflict_mac'
    is the offending peer's hardware address.
    """

    success: bool
    address: Ip4Address
    conflict_mac: MacAddress | None = None


class Ip4Acd:
    """
    RFC 5227 IPv4 Address Conflict Detection engine over an AF_PACKET
    raw link socket — the PyTCP equivalent of 'sd-ipv4acd'.

    A consumer (the DHCPv4 client, the RFC 3927 link-local client)
    builds one bound to its interface's MAC + ifindex, then calls
    'probe()' before claiming an address and 'announce()' after. The
    engine opens an ethertype-ARP packet socket scoped to the ifindex,
    sends Probes / Announcements, and reads ARP off that socket to
    detect conflicts — the stack's own ARP RX path is uninvolved (the
    socket is a parallel tap, exactly as Linux's ACD library reads ARP
    independently of the kernel's ARP processing).

    The RFC 5227 timing constants are the live 'arp.*' sysctls, read
    through 'arp__constants' qualified access so an operator override
    takes effect on the next run.
    """

    def __init__(self, *, mac_address: MacAddress, ifindex: int) -> None:
        """
        Build an ACD engine bound to one interface's MAC and ifindex.
        """

        self._mac = mac_address
        self._ifindex = ifindex

    def probe(self, *, address: Ip4Address) -> AcdResult:
        """
        Run the RFC 5227 §2.1.1 ARP Probe sequence for 'address':
        an initial 0..PROBE_WAIT random delay, PROBE_NUM Probes spaced
        PROBE_MIN..PROBE_MAX apart, then an ANNOUNCE_WAIT quiet period —
        watching the ARP socket for a conflict throughout. Returns an
        'AcdResult'; blocks for the full window (~5-9 s with the default
        sysctls) unless a conflict is seen first.
        """

        sock = self._open_socket()
        try:
            return self._run_probe(sock, address)
        finally:
            sock.close()

    def announce(self, *, address: Ip4Address) -> None:
        """
        Emit the RFC 5227 §2.3 ANNOUNCE_NUM gratuitous-ARP burst for
        'address' (spaced ANNOUNCE_INTERVAL apart) so peers refresh any
        stale cache entry from a previous holder. Blocks for
        (ANNOUNCE_NUM - 1) * ANNOUNCE_INTERVAL seconds.
        """

        sock = self._open_socket()
        try:
            self._run_announce(sock, address)
        finally:
            sock.close()

    def _open_socket(self) -> socket:
        """
        Open a non-blocking AF_PACKET (SOCK_RAW) socket scoped to this
        interface's ifindex and filtered to the ARP ethertype.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW, protocol=ETH_P_ARP)
        sock.bind(SockAddrLl(ifindex=self._ifindex, ethertype=ETH_P_ARP))
        sock.setblocking(False)
        return sock

    def _run_probe(self, sock: socket, address: Ip4Address, /) -> AcdResult:
        """
        Probe loop over an already-open socket (the testable core of
        'probe'). Returns clean as soon as the full window elapses with
        no conflict, or conflict the moment one is observed.
        """

        # RFC 5227 §2.1.1 PROBE_WAIT — initial 0..PROBE_WAIT random delay
        # so a fleet powered on together does not probe in lockstep.
        if (
            mac := self._watch_for_conflict(sock, address, random.uniform(0, arp__constants.ARP__PROBE_WAIT))
        ) is not None:
            return AcdResult(success=False, address=address, conflict_mac=mac)

        # RFC 5227 §2.1.1 — PROBE_NUM Probes spaced PROBE_MIN..PROBE_MAX.
        for _ in range(arp__constants.ARP__PROBE_NUM):
            self._send(sock, oper=ArpOperation.REQUEST, spa=Ip4Address(), tpa=address)
            __debug__ and log("stack", f"<lg>ACD</>: sent ARP Probe for {address}")
            spacing = random.uniform(arp__constants.ARP__PROBE_MIN, arp__constants.ARP__PROBE_MAX)
            if (mac := self._watch_for_conflict(sock, address, spacing)) is not None:
                return AcdResult(success=False, address=address, conflict_mac=mac)

        # RFC 5227 §2.1.1 ANNOUNCE_WAIT — post-probe quiet period; a late
        # conflicting ARP can still flag the candidate here.
        if (mac := self._watch_for_conflict(sock, address, arp__constants.ARP__ANNOUNCE_WAIT)) is not None:
            return AcdResult(success=False, address=address, conflict_mac=mac)

        return AcdResult(success=True, address=address)

    def _run_announce(self, sock: socket, address: Ip4Address, /) -> None:
        """
        Announce burst over an already-open socket (the testable core of
        'announce').
        """

        for announce_idx in range(arp__constants.ARP__ANNOUNCE_NUM):
            if announce_idx > 0:
                time.sleep(arp__constants.ARP__ANNOUNCE_INTERVAL)
            self._send(sock, oper=ArpOperation.REQUEST, spa=address, tpa=address)
            __debug__ and log("stack", f"<lg>ACD</>: sent ARP Announcement for {address}")

    def _send(self, sock: socket, /, *, oper: ArpOperation, spa: Ip4Address, tpa: Ip4Address) -> None:
        """
        Build and transmit one broadcast ARP frame (Probe / Announcement
        / defensive) out the ACD socket. Probe: oper=REQUEST, spa=0.0.0.0.
        Announcement: oper=REQUEST, spa=tpa=address.
        """

        frame = bytes(
            EthernetAssembler(
                ethernet__src=self._mac,
                ethernet__dst=_BROADCAST_MAC,
                ethernet__payload=ArpAssembler(
                    arp__oper=oper,
                    arp__sha=self._mac,
                    arp__spa=spa,
                    arp__tha=MacAddress(),
                    arp__tpa=tpa,
                ),
            )
        )
        sock.sendto(frame, SockAddrLl(ifindex=self._ifindex, ethertype=ETH_P_ARP))

    def _watch_for_conflict(self, sock: socket, address: Ip4Address, duration: float, /) -> MacAddress | None:
        """
        Read ARP off the socket for up to 'duration' seconds, returning
        the offending peer MAC the moment a conflict for 'address' is
        observed, or 'None' if the window elapses cleanly. Drains any
        already-queued frames before honouring the deadline, so a
        conflict captured during a prior window is still caught when
        'duration' is short.
        """

        deadline = time.monotonic() + duration
        while True:
            try:
                frame, _ = sock.recvfrom()
            except BlockingIOError, TimeoutError:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(_CONFLICT_POLL_TICK__SEC)
                continue
            arp = self._parse_arp(frame)
            if arp is not None and self._is_conflict(arp, address):
                __debug__ and log("stack", f"<lg>ACD</>: conflict for {address} from {arp.sha}")
                return arp.sha

    def _parse_arp(self, frame: Buffer, /) -> ArpParser | None:
        """
        Parse a captured link-layer frame into its ARP header, or return
        'None' if it is not a well-formed Ethernet/ARP frame.
        """

        try:
            packet_rx = PacketRx(frame)
            EthernetParser(packet_rx)
            if packet_rx.ethernet.type is not EtherType.ARP:
                return None
            ArpParser(packet_rx)
        except PacketValidationError:
            return None
        return packet_rx.arp

    def _is_conflict(self, arp: ArpParser, address: Ip4Address, /) -> bool:
        """
        Decide whether an inbound ARP frame conflicts with our claim on
        'address' (RFC 5227 §2.1.1): a peer using the address (sender
        protocol address == ours) or a peer probing it simultaneously
        (sender == 0.0.0.0, target == ours). Frames from our own MAC are
        never conflicts.
        """

        if arp.sha == self._mac:
            return False
        if arp.spa == address:
            return True
        return bool(arp.spa.is_unspecified and arp.tpa == address)
