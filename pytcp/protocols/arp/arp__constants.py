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
This module contains the ARP runtime configuration constants
governing cache aging, rate-limiting, conflict-defense, and
RFC 5227 probe / announce timing.

pytcp/protocols/arp/arp__constants.py

ver 3.0.4
"""

# RFC 5227 §1.1 / §2.4(c) defensive-ARP rate-limit. After
# emitting a defensive gratuitous ARP for an address, no
# further defense for that address is emitted until at least
# this many seconds have elapsed — prevents two hosts both
# defending the same IP from generating an "endless loop
# flooding the network with broadcast traffic" (the §2.4(c)
# MUST NOT failure mode).
ARP__DEFEND_INTERVAL = 10

# Cache-aging timeouts and the per-destination outbound-
# Request rate-limit moved to the generic NUD framework at
# 'pytcp/lib/neighbor__constants.py'. The ARP cache is now a
# thin adapter on 'NeighborCache[Ip4Address]' that reads:
#   - 'neighbor.reachable_time'    (was ARP__CACHE__ENTRY_MAX_AGE)
#   - 'neighbor.retrans_timer'     (was ARP__REQUEST_RATE_LIMIT)
#   - the rest of the 'neighbor.*' sysctl namespace.
# The legacy 'arp.cache.max_age' / 'arp.cache.refresh_time'
# sysctls are removed; operators tune cache aging via
# 'pytcp.stack.sysctl["neighbor.reachable_time"]' or the
# 'sysctls={"neighbor.X": ...}' bag kwarg on 'stack.init()'.

# RFC 5227 §1.1 / §2.3 ARP Announcement count and spacing.
# After successful DAD, the host MUST broadcast ANNOUNCE_NUM
# ARP Announcements spaced ANNOUNCE_INTERVAL seconds apart so
# peers refresh any stale ARP cache entries left over from the
# previous holder of the address. The host may begin using
# the IP immediately after the first Announcement; the second
# is insurance against peers that missed the first.
ARP__ANNOUNCE_NUM = 2
ARP__ANNOUNCE_INTERVAL = 2

# RFC 5227 §1.1 / §2.1.1 ARP Probe timing.
#   PROBE_WAIT — initial 0..PROBE_WAIT random delay before the
#                first Probe (so a fleet of hosts powered on
#                simultaneously do not all probe at the same
#                instant).
#   PROBE_NUM  — number of Probes broadcast per candidate.
#   PROBE_MIN / PROBE_MAX — uniform-random spacing between
#                successive Probes.
ARP__PROBE_WAIT = 1
ARP__PROBE_NUM = 3
ARP__PROBE_MIN = 1
ARP__PROBE_MAX = 2

# RFC 5227 §1.1 / §2.1.1 ANNOUNCE_WAIT post-probe quiet period.
# After the last ARP Probe is transmitted, the host waits this
# many seconds before emitting the first Announcement. Late
# conflicting ARPs arriving in this window must still be
# observable so the claim can be aborted; without the wait,
# the host would commit to the address the instant the probe
# loop ends.
ARP__ANNOUNCE_WAIT = 2

# Linux net.ipv4.conf.<iface>.arp_accept policy. Controls
# whether the cache is updated from ARP Requests / Replies
# whose sender IP is NOT on any of our local subnets.
#   0 = reject off-subnet senders (default, conservative).
#   1 = admit off-subnet senders (multi-VLAN / proxy-ARP setups).
ARP__ACCEPT = 0

# Linux net.ipv4.conf.<iface>.arp_ignore policy. Controls when
# we reply to inbound ARP Requests.
#   0 = reply for any local IP (PyTCP's single-subnet config
#       makes this functionally equivalent to mode 1).
#   1 = reply only when the target IP is one of ours
#       (default, current PyTCP baseline).
#   2 = also require the sender IP to be on one of our local
#       subnets (sender-subnet-match anti-spoof).
# Modes 3-8 (cluster / anycast variants) marked Phase 2 and
# rejected by the validator until a real consumer surfaces.
ARP__IGNORE = 1

# Sysctl registration. Every constant above is a policy knob
# (operator-tunable at boot via 'stack.init(sysctls={...})'
# or at runtime via 'pytcp.stack.sysctl["arp...."] = N'). The
# legacy cache-aging knobs ('arp.cache.max_age',
# 'arp.cache.refresh_time') are gone — the NUD migration
# (Phase 2) replaces them with the 'neighbor.*' namespace.
from pytcp.lib.sysctl import _finalize_validators, _is_positive_int, _register, get  # noqa: E402

_register(
    key="arp.defend_interval",
    module_name=__name__,
    attr="ARP__DEFEND_INTERVAL",
    default=ARP__DEFEND_INTERVAL,
    validator=_is_positive_int("arp.defend_interval"),
    description="RFC 5227 §2.4(c) DEFEND_INTERVAL — defensive-ARP rate-limit window, seconds.",
)
_register(
    key="arp.probe_wait",
    module_name=__name__,
    attr="ARP__PROBE_WAIT",
    default=ARP__PROBE_WAIT,
    validator=_is_positive_int("arp.probe_wait"),
    description="RFC 5227 §2.1.1 PROBE_WAIT — upper bound of initial random delay before first ARP Probe, seconds.",
)
_register(
    key="arp.probe_num",
    module_name=__name__,
    attr="ARP__PROBE_NUM",
    default=ARP__PROBE_NUM,
    validator=_is_positive_int("arp.probe_num"),
    description="RFC 5227 §2.1.1 PROBE_NUM — number of ARP Probes per candidate.",
)
_register(
    key="arp.probe_min",
    module_name=__name__,
    attr="ARP__PROBE_MIN",
    default=ARP__PROBE_MIN,
    validator=_is_positive_int("arp.probe_min"),
    description="RFC 5227 §2.1.1 PROBE_MIN — lower bound of inter-probe spacing, seconds; must be < arp.probe_max.",
)
_register(
    key="arp.probe_max",
    module_name=__name__,
    attr="ARP__PROBE_MAX",
    default=ARP__PROBE_MAX,
    validator=_is_positive_int("arp.probe_max"),
    description="RFC 5227 §2.1.1 PROBE_MAX — upper bound of inter-probe spacing, seconds.",
)
_register(
    key="arp.announce_num",
    module_name=__name__,
    attr="ARP__ANNOUNCE_NUM",
    default=ARP__ANNOUNCE_NUM,
    validator=_is_positive_int("arp.announce_num"),
    description="RFC 5227 §2.3 ANNOUNCE_NUM — number of ARP Announcements after successful DAD.",
)
_register(
    key="arp.announce_interval",
    module_name=__name__,
    attr="ARP__ANNOUNCE_INTERVAL",
    default=ARP__ANNOUNCE_INTERVAL,
    validator=_is_positive_int("arp.announce_interval"),
    description="RFC 5227 §2.3 ANNOUNCE_INTERVAL — spacing between back-to-back Announcements, seconds.",
)
_register(
    key="arp.announce_wait",
    module_name=__name__,
    attr="ARP__ANNOUNCE_WAIT",
    default=ARP__ANNOUNCE_WAIT,
    validator=_is_positive_int("arp.announce_wait"),
    description="RFC 5227 §2.1.1 ANNOUNCE_WAIT — post-probe quiet period before first Announcement, seconds.",
)


def _arp_accept_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected too —
    'isinstance(True, int)' is True in Python and we want
    the reject path to surface explicit type/value errors.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'arp.accept' must be 0 or 1; got {value!r}")


def _arp_ignore_validator(value: object) -> None:
    """
    Reject values outside the supported subset {0, 1, 2}.
    Modes 3-8 (Linux cluster / anycast variants) are
    deliberately rejected until a real PyTCP consumer surfaces.
    """

    if isinstance(value, bool) or value not in (0, 1, 2):
        raise ValueError(
            f"sysctl 'arp.ignore' must be 0, 1, or 2 (modes 3-8 deferred to "
            f"Phase 2 cluster / anycast support); got {value!r}"
        )


_register(
    key="arp.accept",
    module_name=__name__,
    attr="ARP__ACCEPT",
    default=ARP__ACCEPT,
    validator=_arp_accept_validator,
    description="Linux 'net.ipv4.conf.<iface>.arp_accept' (0=reject off-subnet, 1=admit).",
)
_register(
    key="arp.ignore",
    module_name=__name__,
    attr="ARP__IGNORE",
    default=ARP__IGNORE,
    validator=_arp_ignore_validator,
    description="Linux 'net.ipv4.conf.<iface>.arp_ignore' (0/1/2; modes 3-8 deferred).",
)


def _finalize__probe_min_lt_probe_max() -> None:
    """
    Cross-knob constraint — 'arp.probe_min' must be strictly
    less than 'arp.probe_max'. The probe-spacing draw uses
    'random.uniform(probe_min, probe_max)' which requires a
    non-degenerate range.
    """

    if get("arp.probe_min") >= get("arp.probe_max"):
        raise ValueError(
            f"sysctl 'arp.probe_min' ({get('arp.probe_min')}) must be strictly less than "
            f"'arp.probe_max' ({get('arp.probe_max')}); the inter-probe random.uniform "
            f"draw requires MIN < MAX."
        )


_finalize_validators.append(_finalize__probe_min_lt_probe_max)
