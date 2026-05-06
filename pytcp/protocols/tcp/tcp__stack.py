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
This module contains the TCP-specific stack-level state container,
aggregating the previously-scattered module-level mutable TFO state
('tcp__fastopen_cookies', 'tcp__fastopen_negative',
'tcp__fastopen_pending_count') into one object.

A single instance is held on 'pytcp.stack.tcp_stack'. Test
fixtures snapshot and replace the instance to isolate TFO state
between tests; before this class existed, every new module-level
field required a parallel snapshot+clear+restore in
'TcpSessionTestCase' (the canary for that footgun was commit
9d4d1c9b adding 'tcp__fastopen_negative' without updating the
test framework — three integration tests silently broke once any
earlier test in the suite drove a SYN-RTO; fixed by 943698f2).
With everything on 'TcpStack', adding a new mutable TCP-stack
field is an internal change to the dataclass and the existing
'stack.tcp_stack = TcpStack()' reset in 'TcpSessionTestCase'
covers it for free.

pytcp/protocols/tcp/tcp__stack.py

ver 3.0.4
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from net_addr import Ip4Address, Ip6Address


@dataclass(slots=True)
class TcpStack:
    """
    TCP-specific stack-level mutable state. Lives on
    'pytcp.stack.tcp_stack' as a process-wide singleton. Tests
    replace the instance per test case to isolate TFO state.
    """

    # RFC 7413 §3.1 / §4.1.3 Fast Open client-side cookie cache.
    # Maps peer IP address to the most-recently-seen cookie issued
    # by that peer in a SYN+ACK. A subsequent active-open SYN to
    # the same peer replays the cached cookie + (optionally) data
    # to skip the data RTT. Wire-format compatibility: the cookie
    # byte-strings are 4..16 bytes per RFC 7413 §2.
    fastopen_cookies: "dict[Ip4Address | Ip6Address, bytes]" = field(default_factory=dict)

    # RFC 7413 §4.1.3.1 negative-response cache: peers we have
    # seen TFO fail with (handshake completed via 3WHS rather
    # than the TFO fast path, indicating a middlebox or peer
    # that drops TFO-bearing SYNs). Subsequent active-open
    # attempts to a peer in this set bypass the TFO option
    # entirely so a known-bad path is not exercised on every
    # new connection.
    fastopen_negative: "set[Ip4Address | Ip6Address]" = field(default_factory=set)

    # RFC 7413 §4.2 PendingFastOpenRequests: count of TFO-
    # accepted active connections in SYN-RCVD state on the
    # server side. When the count meets or exceeds the
    # 'fastopen_qlen' limit configured on a listening socket,
    # the listen handler refuses TFO acceptance for the
    # incoming SYN (returns the empty-cookie cookie response
    # so the client falls back to 3WHS) until the in-flight
    # TFO connections drain to ESTABLISHED or CLOSED.
    fastopen_pending_count: int = 0
