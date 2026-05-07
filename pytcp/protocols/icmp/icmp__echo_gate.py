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
This module contains the ICMP Echo Reply emission gate. Lives next
to icmp__error_emitter.py because both files codify outbound-ICMP
policy, but the Echo gate is intentionally separate: Echo Reply is
not an ICMP error message, so the host-requirements error-generation
rules do not apply to it. The Echo-specific policy is the
RFC 1122 §3.2.2.6 Smurf-mitigation rule.

pytcp/protocols/icmp/icmp__echo_gate.py

ver 3.0.4
"""


def should_emit_echo_reply(
    *,
    dst_is_broadcast: bool,
    dst_is_multicast: bool,
) -> bool:
    """
    Return True if an ICMPv4 Echo Reply may be sent in response to an
    Echo Request whose IPv4 destination has the given properties.

    IPv6 deliberately does not call this — RFC 4443 §4.2 explicitly
    permits replying to Echo Requests received on a multicast
    destination, with appropriate src-address selection.
    """

    return not (dst_is_broadcast or dst_is_multicast)
