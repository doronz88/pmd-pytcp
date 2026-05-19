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
This module contains the ICMP runtime support constants common to v4 and v6.

pytcp/protocols/icmp/icmp__constants.py

ver 3.0.6
"""

# Maximum sustained rate at which the stack will originate ICMP error
# messages, in packets per second [RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f)].
ICMP_ERROR__RATE_PPS = 100

# Maximum burst size for the ICMP error rate limiter, in tokens. A
# burst of this many error generations is permitted at a cold start
# or after an idle period; sustained rate is capped at RATE_PPS.
ICMP_ERROR__BURST = 50
