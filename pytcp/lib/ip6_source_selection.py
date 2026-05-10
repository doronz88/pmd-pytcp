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
This module contains pure helpers backing the RFC 6724 default
source-address selection algorithm.

The two helpers exposed here are scope-extraction
('ip6_address_scope') and common-prefix-length
('common_prefix_len'), the data PyTCP's selector consumes when
applying RFC 6724 §5 rules 2 and 8. The selector itself lives on
the IPv6 TX mixin because it needs the runtime address book
('_ip6_host', '_icmp6_slaac_addresses', '_icmp6_temp_addresses').

pytcp/lib/ip6_source_selection.py

ver 3.0.4
"""

from net_addr import Ip6Address

# Scope codepoints per RFC 4007 §5 / RFC 4291 §2.7. Numeric
# values are the multicast 'scop' field encoding so unicast and
# multicast scopes share a single integer space and rule-2
# comparison stays a plain integer comparison.
IP6__SCOPE__INTERFACE_LOCAL: int = 0x1
IP6__SCOPE__LINK_LOCAL: int = 0x2
IP6__SCOPE__GLOBAL: int = 0xE


def ip6_address_scope(address: Ip6Address, /) -> int:
    """
    Return the RFC 4007 §5 / RFC 4291 §2.7 scope value for the
    given IPv6 address. Multicast addresses report their 'scop'
    nibble verbatim; unicast addresses are categorised as
    interface-local (loopback ::1), link-local (fe80::/10), or
    global (everything else, including ULA and the unspecified
    address). The unspecified address is reported as global so
    the rule-2 comparison stays well-defined when it appears as
    a destination key.
    """

    if address.is_multicast:
        return (int(address) >> 112) & 0xF
    if address.is_loopback:
        return IP6__SCOPE__INTERFACE_LOCAL
    if address.is_link_local:
        return IP6__SCOPE__LINK_LOCAL
    return IP6__SCOPE__GLOBAL


def common_prefix_len(a: Ip6Address, b: Ip6Address, /) -> int:
    """
    Return the number of leading bits the two IPv6 addresses
    share. Identical addresses share 128 bits; addresses that
    disagree at bit position N share N bits. The function is
    symmetric in its arguments.
    """

    xor = int(a) ^ int(b)
    if xor == 0:
        return 128
    return 128 - xor.bit_length()
