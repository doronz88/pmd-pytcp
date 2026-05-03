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
This module contains the TCP session module-level constants.

Extracted to a dedicated module so per-state FSM handler modules
(tcp__fsm__<state>.py) can import these constants without
creating a circular import with tcp__session.py.

pytcp/protocols/tcp/tcp__constants.py

ver 3.0.4
"""

PACKET_RETRANSMIT_TIMEOUT = 1000  # Initial RTO in milliseconds (RFC 6298 §2.1).
# RFC 1122 §4.2.3.5 R2 (incorporated by RFC 9293 §3.8.3) mandates that the
# connection-abort timeout be at least 100 s. With the exponential-backoff
# cadence of 1, 2, 4, 8, 16, 32, 64 s per retransmit, six retries reach
# t = 2**7 - 1 = 127 s before abort, just past the R2 floor and matching the
# Linux 'tcp_syn_retries = 6' default. A lower count (e.g. 3 -> ~15 s) would
# violate the R2 floor and abort connections far sooner than the spec allows.
PACKET_RETRANSMIT_MAX_COUNT = 6
TIME_WAIT_DELAY = 30000  # 30s delay for the TIME_WAIT state, default is 30-120s
DELAYED_ACK_DELAY = 100  # Delay between consecutive delayed ACK outbound packets

# RFC 5961 §3 / §4 challenge-ACK rate limit. The receiver SHOULD NOT
# emit more than one challenge ACK per sliding 1-second window, so a
# burst of unacceptable segments cannot amplify into an outbound ACK
# flood. Linux's default value matches.
CHALLENGE_ACK_RATE_LIMIT_MS = 1000

# RFC 9293 §3.8.6.1 / RFC 1122 §4.2.2.17 zero-window persist timer.
# The first probe fires after the current RTO (initial = PACKET_RETRANSMIT_TIMEOUT),
# subsequent probes back off exponentially up to PERSIST_TIMEOUT_MAX (60 s);
# RFC 1122 §4.2.2.17 requires probes to continue indefinitely while the peer's
# window stays at zero, so the timer never gives up - only the connection's R2
# timeout (handled by '_retransmit_packet_timeout') tears the session down.
PERSIST_TIMEOUT_MAX = 60_000
