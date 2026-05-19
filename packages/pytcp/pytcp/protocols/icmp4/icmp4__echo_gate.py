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
This module contains the ICMPv4 Echo Reply emission gate. The gate
is the host-side Smurf-attack mitigation: an Echo Request whose
destination is a broadcast or multicast IPv4 address must not be
answered.

pytcp/protocols/icmp4/icmp4__echo_gate.py

ver 3.0.6
"""


def should_emit_echo_reply(
    *,
    dst_is_broadcast: bool,
    dst_is_multicast: bool,
) -> bool:
    """
    Return True if an ICMPv4 Echo Reply may be sent in response to an
    Echo Request whose IPv4 destination has the given properties.
    """

    return not (dst_is_broadcast or dst_is_multicast)
