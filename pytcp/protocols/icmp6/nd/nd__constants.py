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
