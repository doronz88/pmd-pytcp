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
This module contains the IGMP runtime configuration constants — the
RFC 3376 §8 host timing / robustness defaults, exposed as policy
sysctls.

pytcp/protocols/igmp/igmp__constants.py

ver 3.0.6
"""

# RFC 3376 §8.1 Robustness Variable. The number of times a host
# transmits an unsolicited state-change Report (RV total, i.e. the
# initial Report plus RV-1 retransmits) so the membership change
# survives the loss of up to RV-1 packets. Linux exposes no per-host
# RV knob (it is fixed at 2); PyTCP makes it tunable.
IGMP__ROBUSTNESS_VARIABLE = 2

# RFC 3376 §8.11 Unsolicited Report Interval, in milliseconds (the RFC
# default is 1 second). Each state-change-Report retransmit is spaced
# by a value drawn uniformly at random from (0, this interval].
IGMP__UNSOLICITED_REPORT_INTERVAL__MS = 1000

# Linux 'net.ipv4.igmp_max_memberships' — the maximum number of
# multicast groups a host may join through the membership API
# (the all-systems group 224.0.0.1, joined implicitly at interface
# bring-up, does not count against this limit). Linux defaults to 20.
IGMP__MAX_MEMBERSHIPS = 20

# Sysctl registration. Every constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={...})' or at
# runtime via 'pytcp.stack.sysctl["igmp...."] = N'.
from pytcp.stack.sysctl import is_positive_int, register  # noqa: E402

register(
    key="igmp.robustness",
    module_name=__name__,
    attr="IGMP__ROBUSTNESS_VARIABLE",
    default=IGMP__ROBUSTNESS_VARIABLE,
    validator=is_positive_int("igmp.robustness"),
    description="RFC 3376 §8.1 Robustness Variable — unsolicited state-change Report transmission count.",
)
register(
    key="igmp.unsolicited_report_interval",
    module_name=__name__,
    attr="IGMP__UNSOLICITED_REPORT_INTERVAL__MS",
    default=IGMP__UNSOLICITED_REPORT_INTERVAL__MS,
    validator=is_positive_int("igmp.unsolicited_report_interval"),
    description="RFC 3376 §8.11 Unsolicited Report Interval — state-change Report retransmit spacing, ms.",
)
register(
    key="igmp.max_memberships",
    module_name=__name__,
    attr="IGMP__MAX_MEMBERSHIPS",
    default=IGMP__MAX_MEMBERSHIPS,
    validator=is_positive_int("igmp.max_memberships"),
    description="Linux 'net.ipv4.igmp_max_memberships' — max multicast groups joinable via the membership API.",
)
