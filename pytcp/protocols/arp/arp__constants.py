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
