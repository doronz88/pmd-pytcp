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
This module contains the IPv6 Neighbor Discovery state PyTCP
maintains across RA RX events: default-router list (§11) and
SLAAC per-prefix lifetime tracking (§12a). Mirrors the conceptual
data structures of RFC 4861 §6.3.4 ('Default Router List') and
RFC 4862 §5.5.3 ('Address Lifetime' state).

Future Tier-3 phases will grow this module with the per-address
state machine (§12b: PREFERRED → DEPRECATED → REMOVED), the
RA-header mirror state (§13: cur-hop-limit / reachable-time /
retrans-timer), and the Prf field on Icmp6DefaultRouter once §14
lands the RA-header parser extension.

pytcp/protocols/icmp6/nd/nd__router_state.py

ver 3.0.4
"""

from dataclasses import dataclass

from net_addr import Ip6Address, Ip6Network


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6DefaultRouter:
    """
    A single entry in the host's default-router list per
    RFC 4861 §6.3.4. 'expires_at' is a 'time.monotonic()'
    deadline; the accessor on the packet handler filters out
    entries whose deadline has passed (lazy ageing).
    """

    address: Ip6Address
    lifetime: int
    expires_at: float


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6SlaacPrefix:
    """
    A single SLAAC-eligible prefix learned from an RA's
    Prefix-Information option per RFC 4862 §5.5.3. Both
    deadlines are 'time.monotonic()' offsets of the advertised
    Valid / Preferred Lifetime values; the accessor on the
    packet handler filters out entries whose 'valid_until' has
    passed (lazy ageing).
    """

    prefix: Ip6Network
    preferred_until: float
    valid_until: float
