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
This module contains the DHCPv6 (RFC 8415) client constants. The
RFC-pinned wire values (UDP ports, the All_DHCP multicast group,
the §15 randomization factor) are protocol invariants; the
INFORMATION-REQUEST retransmission timers (§7.6) and the PyTCP
recv-budget bound are registered as 'pytcp.stack.sysctl' policy
knobs so operators can tune them via 'stack.init(sysctls={...})'
at boot or 'pytcp.stack.sysctl["dhcp6...."]' at runtime.

pytcp/protocols/dhcp6/dhcp6__constants.py

ver 3.0.6
"""

from net_addr import Ip6Address

# --- Protocol invariants (RFC-pinned; not operator-tunable) ---

# RFC 8415 §7.2 — DHCPv6 uses UDP. Clients listen on and send from
# port 546; servers (and relays) listen on port 547.
DHCP6__CLIENT_PORT = 546
DHCP6__SERVER_PORT = 547

# RFC 8415 §7.1 — All_DHCP_Relay_Agents_and_Servers, the link-scoped
# multicast group a client sends to when it has no configured server
# unicast address.
DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS = Ip6Address("ff02::1:2")

# RFC 8415 §15 — the retransmission randomization factor RAND is drawn
# uniformly from the range [-0.1, +0.1]; this is the magnitude of that
# symmetric window.
DHCP6__RAND_FACTOR = 0.1


# --- Policy knobs (sysctl-backed) ---

# RFC 8415 §7.6 — INF_TIMEOUT, the initial Information-request timeout
# (IRT) feeding the §15 retransmission algorithm.
DHCP6__INF_TIMEOUT_MS = 1000

# RFC 8415 §7.6 — INF_MAX_RT, the maximum Information-request timeout
# (MRT) the doubled-and-capped backoff converges to (1 hour).
DHCP6__INF_MAX_RT_MS = 3600000

# RFC 8415 §7.6 / §18.2.6 — INF_MAX_DELAY, the upper bound of the
# random delay before the very first INFORMATION-REQUEST so a fleet of
# hosts powered on simultaneously does not all transmit at once. Drawn
# uniformly from [0, INF_MAX_DELAY]; set 0 to transmit immediately
# (useful for tests and short-lived containerised hosts).
DHCP6__INF_MAX_DELAY_MS = 1000

# PyTCP recv-budget bound. RFC 8415 §7.6 sets the Information-request
# MRC (max retransmission count) and MRD (max retransmission duration)
# to 0 — "no maximum" — i.e. a conformant client retransmits forever.
# PyTCP bounds the stateless recv loop to this many attempts so a
# missing server does not pin the client thread indefinitely; on
# exhaustion the stateless fetch returns no configuration and the
# caller may retry later.
DHCP6__RETRANS_MAX_ATTEMPTS = 5


from pytcp.stack.sysctl import (  # noqa: E402
    get,
    is_non_negative_int,
    is_positive_int,
    register,
    register_finalize_validator,
)

register(
    key="dhcp6.inf_timeout_ms",
    module_name=__name__,
    attr="DHCP6__INF_TIMEOUT_MS",
    default=DHCP6__INF_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.inf_timeout_ms"),
    description="RFC 8415 §7.6 — INF_TIMEOUT, initial INFORMATION-REQUEST retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.inf_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__INF_MAX_RT_MS",
    default=DHCP6__INF_MAX_RT_MS,
    validator=is_positive_int("dhcp6.inf_max_rt_ms"),
    description="RFC 8415 §7.6 — INF_MAX_RT, maximum INFORMATION-REQUEST retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.inf_max_delay_ms",
    module_name=__name__,
    attr="DHCP6__INF_MAX_DELAY_MS",
    default=DHCP6__INF_MAX_DELAY_MS,
    validator=is_non_negative_int("dhcp6.inf_max_delay_ms"),
    description=(
        "RFC 8415 §18.2.6 — INF_MAX_DELAY, upper bound of the random delay before the first "
        "INFORMATION-REQUEST in milliseconds (set 0 to transmit immediately)."
    ),
)
register(
    key="dhcp6.retrans_max_attempts",
    module_name=__name__,
    attr="DHCP6__RETRANS_MAX_ATTEMPTS",
    default=DHCP6__RETRANS_MAX_ATTEMPTS,
    validator=is_positive_int("dhcp6.retrans_max_attempts"),
    description=(
        "PyTCP recv budget — total INFORMATION-REQUEST recv attempts before the stateless "
        "fetch gives up (RFC 8415 §7.6 sets INF MRC/MRD to 0 = retransmit forever)."
    ),
)


def _finalize__inf_timeout_le_max_rt() -> None:
    """
    Cross-knob constraint — 'dhcp6.inf_timeout_ms' must be no greater
    than 'dhcp6.inf_max_rt_ms'. The RFC 8415 §15 doubled-and-capped
    backoff with IRT > MRT would never actually double.
    """

    if get("dhcp6.inf_timeout_ms") > get("dhcp6.inf_max_rt_ms"):
        raise ValueError(
            f"sysctl 'dhcp6.inf_timeout_ms' ({get('dhcp6.inf_timeout_ms')}) must be "
            f"≤ 'dhcp6.inf_max_rt_ms' ({get('dhcp6.inf_max_rt_ms')}); the doubled-and-capped "
            f"backoff would otherwise never advance.",
        )


register_finalize_validator(_finalize__inf_timeout_le_max_rt)
