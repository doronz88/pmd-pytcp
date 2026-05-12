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
This module contains the RFC 3927 IPv4 Link-Local autoconfig
runtime configuration constants — RFC 3927 §9 timing /
retry / rate-limit knobs registered as 'pytcp.lib.sysctl'
sysctls so the operator can tune them at boot or runtime.

Phase 1 lands the file with no sysctl registrations yet —
Phase 2 (retry loop) adds 'max_conflicts' and
'rate_limit_interval_s'; Phase 4 (DHCP coordination) adds
'dhcp_fallback_timeout_ms'.

pytcp/protocols/ip4_link_local/ip4_link_local__constants.py

ver 3.0.4
"""

# Phase 2 will add the sysctl registrations:
#   - ip4_link_local.max_conflicts (default 10, RFC §9)
#   - ip4_link_local.rate_limit_interval_s (default 60, RFC §9)
# Phase 4 will add:
#   - ip4_link_local.dhcp_fallback_timeout_ms (default 0, opt-in)
