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
