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
This module contains the IPv6 Neighbor Discovery runtime
configuration constants. The 'icmp6.*' sysctl namespace mirrors
Linux 'net.ipv6.conf.<iface>.*'.

Knobs land here as their consumers do; speculative API surface is
forbidden per CLAUDE.md ("don't design for hypothetical future
requirements"). The first knob to register is 'icmp6.accept_redirects'
(nd_linux_parity Phase 1B); subsequent phases will add timing knobs
(retrans_timer_ms, dad_transmits) and policy knobs (accept_ra_*) as
their consumers ship.

pytcp/protocols/icmp6/nd/nd__constants.py

ver 3.0.4
"""

from typing import Any

from pytcp.lib.sysctl import register

# Linux net.ipv6.conf.<iface>.accept_redirects policy. Controls
# whether inbound RFC 4861 §8 Redirect messages are processed
# (cache override) or silently dropped.
#   0 = drop every Redirect (kill switch — useful for security-
#       sensitive deployments where the off-link-spoofing risk
#       outweighs the route-optimisation benefit).
#   1 = process Redirects subject to RFC 4861 §8.1 acceptance
#       gates (host-side default; matches Linux's host default).
ICMP6__ACCEPT_REDIRECTS = 1

# Number of gratuitous Neighbor Advertisement messages emitted
# on host attachment (RFC 9131 §3 — the IPv6 analogue of
# RFC 5227 §2.3 ARP Announcement). Linux's default is 1; a
# value of 0 suppresses gratuitous-NA emission entirely (kill
# switch for stealth deployments).
ICMP6__GRATUITOUS_NA_COUNT = 1

# Number of DAD (Duplicate Address Detection) probes emitted
# per candidate address per RFC 4862 §5.1 ('DupAddrDetectTransmits',
# default 1). Linux exposes this as 'net.ipv6.conf.<iface>.
# dad_transmits'. A value of 0 disables DAD entirely.
ICMP6__DAD_TRANSMITS = 1

# Inter-probe wait between successive DAD probes, in
# milliseconds, per RFC 4861 §10 ('RetransTimer', default
# 1000ms). Linux exposes this as
# 'net.ipv6.conf.<iface>.retrans_time_ms'.
ICMP6__RETRANS_TIMER_MS = 1000

# Linux net.ipv6.conf.<iface>.accept_ra_defrtr policy. Controls
# whether inbound RA messages with a non-zero Router Lifetime
# install / refresh an entry in the host's default-router list
# (RFC 4861 §6.3.4).
#   0 = drop default-router learning entirely (host sees the RA's
#       prefix-info options but never gains a default route from
#       it — useful for static-routing or isolated deployments).
#   1 = process default-router updates per RFC 4861 §6.3.4 (Linux
#       host default).
ICMP6__ACCEPT_RA_DEFRTR = 1

# Linux net.ipv6.conf.<iface>.accept_ra_pinfo policy. Controls
# whether inbound RA Prefix-Information options install / refresh
# entries in the host's SLAAC prefix table (RFC 4862 §5.5.3).
#   0 = drop PI consumption entirely (no SLAAC state changes from
#       inbound RAs — useful for managed-config-only deployments
#       where addresses come from DHCPv6).
#   1 = process PI options per RFC 4862 §5.5.3 (Linux host
#       default).
ICMP6__ACCEPT_RA_PINFO = 1

# RFC 4862 §5.5.3 (e)(6) 2-hour rule constant. Defends an
# existing autoconfigured address from a router that advertises
# a short remaining lifetime: an unauthenticated router cannot
# shrink an address's valid lifetime below this floor unless
# the existing remaining is already at or below it. Per spec
# fixed at 2 hours = 7200 seconds; not user-tunable. Defined
# here as a protocol invariant rather than a sysctl because
# Linux exposes no knob for it (RFC compliance).
ICMP6__SLAAC__TWO_HOUR_RULE_S = 7200

# Linux net.ipv6.conf.<iface>.accept_ra_min_hop_limit policy.
# Floors the Cur-Hop-Limit values that PyTCP will accept from
# inbound RAs (RFC 4861 §6.3.4). Values strictly below this
# threshold are dropped — a defense against routers that
# advertise pathologically low Hop Limits which would cause
# legitimate destinations to become unreachable. Linux's
# default is 1.
ICMP6__ACCEPT_RA_MIN_HOP_LIMIT = 1

# RFC 4861 §6.3.7 RTR_SOLICITATION_INTERVAL — the initial
# retransmission timeout for the host's Router Solicitation
# loop, in milliseconds. RFC 7559 §2 amends this to be the
# IRT base for truncated binary exponential backoff. Default
# 4000 ms (4 s).
ICMP6__RTR_SOLICITATION_INTERVAL_MS = 4000

# RFC 7559 §2 maximum retransmission timeout (MRT cap) for
# the RS exponential-backoff loop, in milliseconds. Default
# 3 600 000 ms (1 hour). Combined with MAX_RTR_SOLICITATIONS
# this bounds how long a host pauses between unsuccessful RS
# retransmissions.
ICMP6__RTR_SOLICITATION_MAX_RT_MS = 3600000

# RFC 4861 §6.3.7 MAX_RTR_SOLICITATIONS — the maximum number
# of RS messages the host emits before giving up on RA-driven
# auto-configuration. Default 3 per RFC 4861. A value of 0
# disables RS entirely (kill switch for static-config-only
# deployments).
ICMP6__MAX_RTR_SOLICITATIONS = 3

# RFC 7527 Enhanced DAD — when enabled, every NS(DAD) probe
# carries a randomly-generated 6-byte Nonce option. The host
# tracks emitted nonces during the DAD session and silently
# drops inbound NS messages whose Nonce matches one of ours
# (loop-hairpin detection — distinguishes a switch echoing
# our probe back from a genuine peer DAD conflict). Default
# 1 per RFC 7527 / Linux 'enhanced_dad'. 0 disables the
# feature; DAD then uses RFC 4861 plain semantics where any
# NS targeting our tentative address aborts the claim.
ICMP6__ENHANCED_DAD = 1


def _accept_redirects_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_redirects' must be 0 or 1; got {value!r}")


def _gratuitous_na_count_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero is
    explicitly admitted (kill switch).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"sysctl 'icmp6.gratuitous_na_count' must be a non-negative int; got {value!r}")


def _dad_transmits_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero is
    explicitly admitted (DAD disabled).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"sysctl 'icmp6.dad_transmits' must be a non-negative int; got {value!r}")


def _retrans_timer_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive values
    — RetransTimer = 0 would tight-loop the probe sender.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"sysctl 'icmp6.retrans_timer_ms' must be a positive int; got {value!r}")


def _accept_ra_defrtr_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_ra_defrtr' must be 0 or 1; got {value!r}")


def _accept_ra_pinfo_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_ra_pinfo' must be 0 or 1; got {value!r}")


def _accept_ra_min_hop_limit_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and out-of-range
    values — Cur-Hop-Limit is an 8-bit unsigned field, so the
    floor must fit in [0, 255]. Zero accepts any advertised
    Hop Limit.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(
            f"sysctl 'icmp6.accept_ra_min_hop_limit' must be an int in [0, 255]; got {value!r}",
        )


def _rtr_solicitation_interval_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values — IRT = 0 would tight-loop the RS sender.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.rtr_solicitation_interval_ms' must be a positive int; got {value!r}",
        )


def _rtr_solicitation_max_rt_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values — MRT must be at least the IRT default to give
    backoff room. Tests use much smaller values via override.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.rtr_solicitation_max_rt_ms' must be a positive int; got {value!r}",
        )


def _max_rtr_solicitations_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    is admitted (kill switch).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.max_rtr_solicitations' must be a non-negative int; got {value!r}",
        )


def _enhanced_dad_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.enhanced_dad' must be 0 or 1; got {value!r}")


register(
    key="icmp6.accept_redirects",
    module_name=__name__,
    attr="ICMP6__ACCEPT_REDIRECTS",
    default=ICMP6__ACCEPT_REDIRECTS,
    validator=_accept_redirects_validator,
    description="Linux 'net.ipv6.conf.<iface>.accept_redirects' (0 = drop all RFC 4861 §8 Redirects; 1 = process).",
)
register(
    key="icmp6.gratuitous_na_count",
    module_name=__name__,
    attr="ICMP6__GRATUITOUS_NA_COUNT",
    default=ICMP6__GRATUITOUS_NA_COUNT,
    validator=_gratuitous_na_count_validator,
    description="Number of gratuitous NAs emitted on host attachment (RFC 9131 §3); 0 = kill switch.",
)
register(
    key="icmp6.dad_transmits",
    module_name=__name__,
    attr="ICMP6__DAD_TRANSMITS",
    default=ICMP6__DAD_TRANSMITS,
    validator=_dad_transmits_validator,
    description="Number of DAD probes per candidate address (RFC 4862 §5.1 DupAddrDetectTransmits); 0 disables DAD.",
)
register(
    key="icmp6.retrans_timer_ms",
    module_name=__name__,
    attr="ICMP6__RETRANS_TIMER_MS",
    default=ICMP6__RETRANS_TIMER_MS,
    validator=_retrans_timer_ms_validator,
    description="Inter-probe wait between DAD probes in milliseconds (RFC 4861 §10 RetransTimer; default 1000).",
)
register(
    key="icmp6.accept_ra_defrtr",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_DEFRTR",
    default=ICMP6__ACCEPT_RA_DEFRTR,
    validator=_accept_ra_defrtr_validator,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_defrtr' "
        "(0 = drop default-router learning; 1 = process RFC 4861 §6.3.4)."
    ),
)
register(
    key="icmp6.accept_ra_pinfo",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_PINFO",
    default=ICMP6__ACCEPT_RA_PINFO,
    validator=_accept_ra_pinfo_validator,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_pinfo' " "(0 = drop PI consumption; 1 = process RFC 4862 §5.5.3)."
    ),
)
register(
    key="icmp6.accept_ra_min_hop_limit",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_MIN_HOP_LIMIT",
    default=ICMP6__ACCEPT_RA_MIN_HOP_LIMIT,
    validator=_accept_ra_min_hop_limit_validator,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_min_hop_limit' "
        "(floor for accepting Cur-Hop-Limit; 0 accepts any value)."
    ),
)
register(
    key="icmp6.rtr_solicitation_interval_ms",
    module_name=__name__,
    attr="ICMP6__RTR_SOLICITATION_INTERVAL_MS",
    default=ICMP6__RTR_SOLICITATION_INTERVAL_MS,
    validator=_rtr_solicitation_interval_ms_validator,
    description=(
        "RFC 7559 §2 IRT (initial retransmission timeout) for " "the RS exponential-backoff loop; default 4000 ms."
    ),
)
register(
    key="icmp6.rtr_solicitation_max_rt_ms",
    module_name=__name__,
    attr="ICMP6__RTR_SOLICITATION_MAX_RT_MS",
    default=ICMP6__RTR_SOLICITATION_MAX_RT_MS,
    validator=_rtr_solicitation_max_rt_ms_validator,
    description=(
        "RFC 7559 §2 MRT (maximum retransmission timeout) cap "
        "for the RS exponential-backoff loop; default 3600000 ms."
    ),
)
register(
    key="icmp6.max_rtr_solicitations",
    module_name=__name__,
    attr="ICMP6__MAX_RTR_SOLICITATIONS",
    default=ICMP6__MAX_RTR_SOLICITATIONS,
    validator=_max_rtr_solicitations_validator,
    description=("RFC 4861 §6.3.7 MAX_RTR_SOLICITATIONS; default 3. " "0 disables RS entirely (kill switch)."),
)
register(
    key="icmp6.enhanced_dad",
    module_name=__name__,
    attr="ICMP6__ENHANCED_DAD",
    default=ICMP6__ENHANCED_DAD,
    validator=_enhanced_dad_validator,
    description=(
        "RFC 7527 Enhanced DAD with Nonce option (Linux 'enhanced_dad'); "
        "default 1. 0 falls back to RFC 4861 plain DAD semantics."
    ),
)
