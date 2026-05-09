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

# ARP cache configuration.
ARP__CACHE__ENTRY_MAX_AGE = 3600
ARP__CACHE__ENTRY_REFRESH_TIME = 300

# RFC 5227 §1.1 / §2.4(c) defensive-ARP rate-limit. After
# emitting a defensive gratuitous ARP for an address, no
# further defense for that address is emitted until at least
# this many seconds have elapsed — prevents two hosts both
# defending the same IP from generating an "endless loop
# flooding the network with broadcast traffic" (the §2.4(c)
# MUST NOT failure mode).
ARP__DEFEND_INTERVAL = 10

# RFC 1122 §2.3.2.1 outbound-ARP-Request rate-limit. The host
# MUST NOT flood the link with repeated Requests for the same
# unresolved IP; the recommended maximum is 1 per second per
# destination. Used by 'ArpCache.find_entry' to gate Request
# emission via 'time.monotonic()' timestamps stored on the
# per-destination '_pending_resolution' table.
ARP__REQUEST_RATE_LIMIT = 1

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

# Sysctl registration. Every constant above except
# 'ARP__REQUEST_RATE_LIMIT' is a policy knob (operator-tunable
# at boot via 'stack.init()' or at runtime via
# 'pytcp.stack.sysctl["arp...."] = N'). The exception
# 'ARP__REQUEST_RATE_LIMIT' is RFC 1122 §2.3.2.1-pinned at 1 s
# "recommended" and PyTCP's rate-limit gate currently treats
# the recommendation as a hard floor — re-classify when there
# is a real consumer for a runtime override.
from pytcp.lib.sysctl import _finalize_validators, _is_positive_int, _register, get  # noqa: E402

_register(
    key="arp.cache.max_age",
    module_name=__name__,
    attr="ARP__CACHE__ENTRY_MAX_AGE",
    default=ARP__CACHE__ENTRY_MAX_AGE,
    validator=_is_positive_int("arp.cache.max_age"),
    description="ARP cache entry lifetime, seconds.",
)
_register(
    key="arp.cache.refresh_time",
    module_name=__name__,
    attr="ARP__CACHE__ENTRY_REFRESH_TIME",
    default=ARP__CACHE__ENTRY_REFRESH_TIME,
    validator=_is_positive_int("arp.cache.refresh_time"),
    description="ARP cache refresh-window window, seconds; must be < arp.cache.max_age.",
)
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


def _finalize__refresh_lt_max_age() -> None:
    """
    Cross-knob constraint — 'arp.cache.refresh_time' must be
    strictly less than 'arp.cache.max_age'. The refresh-window
    arithmetic in 'ArpCache._subsystem_loop' assumes
    REFRESH < MAX; equality skips the refresh path entirely
    and inversion produces a negative window.
    """

    if get("arp.cache.refresh_time") >= get("arp.cache.max_age"):
        raise ValueError(
            f"sysctl 'arp.cache.refresh_time' ({get('arp.cache.refresh_time')}) must be "
            f"strictly less than 'arp.cache.max_age' ({get('arp.cache.max_age')}); the "
            f"refresh-window arithmetic in the cache loop requires REFRESH < MAX."
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


_finalize_validators.append(_finalize__refresh_lt_max_age)
_finalize_validators.append(_finalize__probe_min_lt_probe_max)
