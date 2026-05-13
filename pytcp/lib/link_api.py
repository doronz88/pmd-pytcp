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
This module contains the Phase-1 link-control API ('LinkApi')
— the kernel/userspace boundary surface that consumer code
(the DHCPv4 client, the RFC 3927 link-local autoconfig client,
future operator-config tools) uses to read link-level state
(MAC, MTU, interface layer) without reaching into
'PacketHandler' internals. The Linux equivalents are
'ip link show' / RTNETLINK 'RTM_GETLINK' / 'RTM_NEWLINK'.

Phase 0 ships only the read-only minimum surface — MAC, MTU,
interface layer. Subsequent phases add interface name
(Phase 1), running state + flags (Phase 2), stats
introspection (Phase 3), and mutation via 'set_mtu' /
'set_mac_address' (Phase 4). See
'docs/refactor/link_api.md' for the full plan.

pytcp/lib/link_api.py

ver 3.0.4
"""

from dataclasses import dataclass, fields
from enum import Enum, auto
from typing import TYPE_CHECKING

from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

if TYPE_CHECKING:
    from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3


class LinkFlag(Enum):
    """
    Per-interface flag set mirroring Linux's IFF_* flag
    selection from 'linux/include/uapi/linux/if_link.h'.
    PyTCP exposes the four flags that have a meaningful
    semantic in the current stack:

    - BROADCAST   — interface carries broadcast traffic
                    (Ethernet on TAP).
    - MULTICAST   — interface carries multicast traffic
                    (Ethernet on TAP; IPv6 ND requires it).
    - LOOPBACK    — loopback interface (no consumer today;
                    listed for forward-compat with a future
                    loopback adapter).
    - POINTOPOINT — point-to-point link (TUN; no L2 broadcast
                    domain).

    Hardware-offload / multi-queue / qdisc flags from the
    Linux header are deliberately out of scope per the
    CLAUDE.md Project North Star non-goals.
    """

    BROADCAST = auto()
    MULTICAST = auto()
    LOOPBACK = auto()
    POINTOPOINT = auto()


_FLAGS_BY_LAYER: dict[InterfaceLayer, frozenset[LinkFlag]] = {
    InterfaceLayer.L2: frozenset({LinkFlag.BROADCAST, LinkFlag.MULTICAST}),
    InterfaceLayer.L3: frozenset({LinkFlag.POINTOPOINT}),
}


@dataclass(frozen=True, kw_only=True, slots=True)
class LinkStats:
    """
    Copy-by-value snapshot of cumulative link-level
    interface statistics — Linux's 'struct
    rtnl_link_stats64' first-eight-buckets equivalent
    surfaced by 'ip -s link show'.

    Bucket → PyTCP counter mapping (documented verbatim
    here so future drop counters know which bucket they
    join):

    - 'rx_packets' / 'tx_packets':
        L2 (TAP) → 'PacketStatsRx.ethernet__pre_parse' +
                   'ethernet_802_3__pre_parse' /
                   'PacketStatsTx.ethernet__pre_assemble' +
                   'ethernet_802_3__pre_assemble'.
        L3 (TUN) → 'ip4__pre_parse' + 'ip6__pre_parse' /
                   'ip4__pre_assemble' + 'ip6__pre_assemble'.

    - 'rx_bytes' / 'tx_bytes':
        Read directly from 'LinkStatsCounters' bumped by
        'RxRing' / 'TxRing' at frame receive / send time.
        Wire-level bytes regardless of which protocol
        consumed them.

    - 'rx_errors':
        Sum of every 'PacketStatsRx' field whose name ends
        in '__failed_parse__drop' — these are structural
        validation failures ("couldn't decode the wire
        format"), Linux's 'rx_errors' equivalent.

    - 'rx_dropped':
        Sum of every 'PacketStatsRx' field whose name ends
        in '__drop' EXCEPT '__failed_parse__drop' — these
        are policy / config drops the stack chose to
        discard for non-error reasons (no listener, MAC
        filter mismatch, rate-limit suppression, etc.).

    - 'tx_errors':
        Sum of every 'PacketStatsTx' field whose name
        starts with 'tx_ring__' AND ends in '__drop' —
        kernel-level transmit failures (queue full,
        OSError on writev).

    - 'tx_dropped':
        Sum of every 'PacketStatsTx' field whose name
        ends in '__drop' EXCEPT the 'tx_ring__*__drop'
        ones — policy / config TX drops (broadcast
        disallowed, src not owned, scope mismatch,
        link-local out-of-scope, etc.).

    Phase 3 does NOT include multicast counters
    ('rx_multicast' / 'tx_multicast' from Linux's
    rtnl_link_stats64); a future revision may add them
    when a consumer materialises.
    """

    rx_packets: int
    rx_bytes: int
    rx_errors: int
    rx_dropped: int
    tx_packets: int
    tx_bytes: int
    tx_errors: int
    tx_dropped: int


def _sum_drops(
    stats: PacketStatsRx | PacketStatsTx,
    *,
    prefix: str = "",
    suffix: str = "__drop",
    exclude_suffix: str | None = None,
    exclude_prefix: str | None = None,
) -> int:
    """
    Sum dataclass int fields matching the prefix / suffix
    filter — used to aggregate '*__drop' counters into
    LinkStats error/dropped buckets without hard-coding
    every field name.
    """

    total = 0
    for field in fields(stats):
        name = field.name
        if not name.endswith(suffix):
            continue
        if prefix and not name.startswith(prefix):
            continue
        if exclude_suffix is not None and name.endswith(exclude_suffix):
            continue
        if exclude_prefix is not None and name.startswith(exclude_prefix):
            continue
        total += getattr(stats, name)
    return total


class LinkApi:
    """
    Phase-1 link-control surface — mirrors Linux 'ip link
    show' / RTNETLINK 'RTM_GETLINK' semantics for the
    read-only subset.

    Phase-1 implementation: thin properties over
    'PacketHandler._mac_unicast' / '_interface_mtu' /
    '_interface_layer'. Consumer code — DHCPv4 client,
    RFC 3927 link-local autoconfig client, future
    operator-config CLI — uses ONLY this surface to read
    link-level facts. Never reaches into 'packet_handler.*'
    directly. This is the architectural seam the Phase-3
    north-star turns into a real IPC channel; the wrapper
    internals swap from direct attribute reads to
    RTNETLINK-equivalent message routing without any
    consumer change.

    Phase 0 covers MAC + MTU + interface layer. Phases 1-4
    add interface name, running state, flags, stats, and
    mutation. See 'docs/refactor/link_api.md' for the full
    roadmap.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3",
    ) -> None:
        """
        Bind the API to a packet handler instance. The packet
        handler owns the underlying link-level state; the API
        is the only sanctioned consumer of reads against that
        state.
        """

        self._packet_handler = packet_handler

    @property
    def mac_address(self) -> MacAddress | None:
        """
        Return the interface's unicast MAC address — Linux
        'ip link show eth0 | grep link/ether' equivalent.

        Returns None on L3 (TUN) interfaces, which have no
        Ethernet layer and therefore no MAC. The packet
        handler stores '_mac_unicast' only on the L2
        subclass; the 'getattr' fallback handles the L3
        case without an isinstance check.
        """

        return getattr(self._packet_handler, "_mac_unicast", None)

    @property
    def mtu(self) -> int:
        """
        Return the interface MTU in bytes — Linux
        'ip link show eth0 | grep mtu' equivalent.
        """

        return self._packet_handler._interface_mtu

    @property
    def name(self) -> str | None:
        """
        Return the interface name plumbed through by
        'stack.init()' (e.g. 'tap7', 'tun7') — Linux
        'ip link show' first-column equivalent.

        Returns None when the packet handler was
        constructed without an interface name — e.g. a
        unit-test fixture or 'mock__init' that skipped
        the name plumbing.
        """

        return self._packet_handler._interface_name

    @property
    def interface_layer(self) -> InterfaceLayer:
        """
        Return the interface layer (L2 = TAP, L3 = TUN) —
        Linux 'ip link show eth0 | grep link/' equivalent.
        """

        return self._packet_handler._interface_layer

    @property
    def is_running(self) -> bool:
        """
        Return True when the stack has been started via
        'stack.start()' and not yet stopped via
        'stack.stop()' — Linux's 'IFF_UP + IFF_RUNNING'
        equivalent. PyTCP collapses the two flags into one
        because per-subsystem-up granularity has no
        consumer today; a future split (e.g. admin-up vs
        link-up) would land as a Phase-2 multi-interface
        extension.

        Reads 'pytcp.stack.stack_running'; the module-level
        flag is maintained by 'start()' / 'stop()' and
        reset to False by 'mock__init()' for unit tests.
        """

        from pytcp import stack

        return stack.stack_running

    @property
    def stats(self) -> LinkStats:
        """
        Return a copy-by-value snapshot of cumulative
        link-level interface statistics — Linux 'ip -s
        link show eth0' RX/TX block equivalent.

        The returned 'LinkStats' is frozen + slotted; the
        caller cannot mutate stack-internal state through
        the snapshot per the Phase-3 north-star
        "introspection is read-only" constraint. See the
        'LinkStats' docstring for the bucket → counter
        mapping; aggregation walks 'PacketStatsRx' /
        'PacketStatsTx' fields by name pattern so adding
        a new '__drop' counter automatically lands in the
        right bucket (failed_parse vs other on RX; tx_ring
        vs other on TX).
        """

        rx = self._packet_handler._packet_stats_rx
        tx = self._packet_handler._packet_stats_tx
        link = self._packet_handler._link_stats
        layer = self._packet_handler._interface_layer

        if layer is InterfaceLayer.L2:
            rx_packets = rx.ethernet__pre_parse + rx.ethernet_802_3__pre_parse
            tx_packets = tx.ethernet__pre_assemble + tx.ethernet_802_3__pre_assemble
        else:
            rx_packets = rx.ip4__pre_parse + rx.ip6__pre_parse
            tx_packets = tx.ip4__pre_assemble + tx.ip6__pre_assemble

        rx_errors = _sum_drops(rx, suffix="__failed_parse__drop")
        rx_dropped = _sum_drops(rx, suffix="__drop", exclude_suffix="__failed_parse__drop")

        tx_errors = _sum_drops(tx, prefix="tx_ring__", suffix="__drop")
        tx_dropped = _sum_drops(tx, suffix="__drop", exclude_prefix="tx_ring__")

        return LinkStats(
            rx_packets=rx_packets,
            rx_bytes=link.rx_bytes,
            rx_errors=rx_errors,
            rx_dropped=rx_dropped,
            tx_packets=tx_packets,
            tx_bytes=link.tx_bytes,
            tx_errors=tx_errors,
            tx_dropped=tx_dropped,
        )

    @property
    def flags(self) -> frozenset[LinkFlag]:
        """
        Return the set of 'LinkFlag' values that apply to
        this interface — Linux 'ip link show eth0' '<...>'
        bracket equivalent.

        Phase-1 derives the set from 'interface_layer':
        L2 (TAP) carries BROADCAST + MULTICAST; L3 (TUN)
        carries POINTOPOINT. A future commit may add
        runtime-configurable flags (e.g. LOOPBACK when a
        loopback adapter lands, NOARP / DEBUG / PROMISC
        when consumers materialise).

        Returns a 'frozenset' (immutable, copy-by-value)
        so the caller cannot mutate stack-internal state
        through the returned reference.
        """

        return _FLAGS_BY_LAYER[self._packet_handler._interface_layer]
