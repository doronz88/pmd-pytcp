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
This module contains the IPv6 runtime configuration constants
governing host-level outbound TX behaviour — the policy knobs
the stack TX path reads when emitting IPv6 datagrams.

pytcp/protocols/ip6/ip6__constants.py

ver 3.0.4
"""

# RFC 6437 §3 IPv6 Flow Label auto-generation toggle.
#
# When 1 (default), '_phtx_ip6' computes a 20-bit Flow Label
# per outbound datagram by hashing (src, dst) with the
# stack-wide 'IP6__FLOW_SECRET' — satisfying §3's
# "approximation to discrete uniform distribution" + "same
# value for packets of a given flow" requirements.
#
# When 0, '_phtx_ip6' emits flow=0 (the RFC 8200 §3 "no
# specific flow" form). The integration-test harness sets
# this to 0 so existing golden-byte fixtures continue to
# match; the dedicated RFC-6437-flow-label integration test
# flips it to 1 to exercise the auto-wire.
#
# Linux comparison: 'net.ipv6.flowlabel_state_ranges' /
# '/proc/sys/net/ipv6/flowlabel_consistency'. PyTCP's
# implementation is per-(src, dst), coarser than Linux's
# per-socket but sufficient for §3's per-flow stability
# clause (which explicitly allows coarser flow definitions).
IP6__FLOW_LABEL_GENERATION: int = 1


# Sysctl registration. The flow-label generation toggle is
# policy — Linux exposes equivalent knobs under
# '/proc/sys/net/ipv6/' — and operators may want to disable
# it on links where downstream forwarding plane treats
# flow=0 as a special-case (older middleboxes, RFC 6437
# §6.1 ECMP/LAG opting-out).
from pytcp.lib.sysctl import is_non_negative_int, register  # noqa: E402

register(
    key="ip6.flow_label_generation",
    module_name=__name__,
    attr="IP6__FLOW_LABEL_GENERATION",
    default=IP6__FLOW_LABEL_GENERATION,
    validator=is_non_negative_int("ip6.flow_label_generation"),
    description="RFC 6437 §3 IPv6 Flow Label auto-generation toggle (0 = emit flow=0; 1 = compute per (src,dst) hash).",
)
