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
This module contains the IPv4 runtime configuration constants
governing host-level outbound TX behaviour — the policy knobs
the stack TX path reads when emitting IPv4 datagrams.

pytcp/protocols/ip4/ip4__constants.py

ver 3.0.4
"""

# RFC 1122 §3.2.1.7 host-default TTL for outbound IPv4 unicast
# datagrams. The RFC requires the per-datagram TTL field to be
# settable by the transport layer (which PyTCP exposes via the
# 'ip4__ttl' kwarg on '_phtx_ip4') and "When a fixed TTL value
# is used, it MUST be configurable." The qualified-module read
# pattern in 'packet_handler__ip4__tx.py' resolves this
# attribute on every emission so the 'ip4.default_ttl' sysctl
# override is observable on the wire without a stack restart.
# Multicast destinations are independently pinned at TTL=1 per
# RFC 1112 §6.1 and do NOT consult this knob.
IP4__DEFAULT_TTL = 64


def _is_ip4_default_ttl(value: object) -> None:
    """
    Reject values outside the integer range 1..255. TTL=0 is
    explicitly forbidden by RFC 1122 §3.2.1.7 "A host MUST NOT
    send a datagram with a Time-to-Live (TTL) value of zero,"
    so the operator must not be able to set the default to a
    value that would violate the spec on every emitted packet.
    The 256 ceiling enforces the 8-bit wire field (RFC 791
    §3.1). Booleans are rejected too — 'isinstance(True, int)'
    is True in Python and would silently slip through.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 255:
        raise ValueError(
            f"sysctl 'ip4.default_ttl' must be an int in [1, 255]; got {value!r}",
        )


# Sysctl registration. 'IP4__DEFAULT_TTL' is a policy knob the
# operator may tune via 'stack.init(sysctls={"ip4.default_ttl":
# N})' at boot or 'pytcp.stack.sysctl["ip4.default_ttl"] = N'
# at runtime.
from pytcp.lib.sysctl import register  # noqa: E402

register(
    key="ip4.default_ttl",
    module_name=__name__,
    attr="IP4__DEFAULT_TTL",
    default=IP4__DEFAULT_TTL,
    validator=_is_ip4_default_ttl,
    description="RFC 1122 §3.2.1.7 — host-default TTL for outbound IPv4 unicast datagrams (1..255).",
)
