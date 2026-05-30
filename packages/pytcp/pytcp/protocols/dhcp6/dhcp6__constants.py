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

# RFC 8415 §7.6 — SOL_TIMEOUT / SOL_MAX_RT, the initial (IRT) and
# maximum (MRT) Solicit retransmit timeouts. A Solicit has no MRC/MRD
# bound either; PyTCP reuses 'dhcp6.retrans_max_attempts' as the
# SOLICIT recv budget.
DHCP6__SOL_TIMEOUT_MS = 1000
DHCP6__SOL_MAX_RT_MS = 3600000

# RFC 8415 §7.6 — REQ_TIMEOUT / REQ_MAX_RT / REQ_MAX_RC, the initial
# (IRT) and maximum (MRT) Request retransmit timeouts and the Request
# max retransmission count. Unlike Solicit, a Request is bounded by
# REQ_MAX_RC = 10; on exhaustion the client returns to Solicit.
DHCP6__REQ_TIMEOUT_MS = 1000
DHCP6__REQ_MAX_RT_MS = 30000
DHCP6__REQ_MAX_RC = 10


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
        "PyTCP recv budget — total INFORMATION-REQUEST / SOLICIT recv attempts before the "
        "fetch gives up (RFC 8415 §7.6 sets INF/SOL MRC/MRD to 0 = retransmit forever)."
    ),
)
register(
    key="dhcp6.sol_timeout_ms",
    module_name=__name__,
    attr="DHCP6__SOL_TIMEOUT_MS",
    default=DHCP6__SOL_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.sol_timeout_ms"),
    description="RFC 8415 §7.6 — SOL_TIMEOUT, initial SOLICIT retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.sol_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__SOL_MAX_RT_MS",
    default=DHCP6__SOL_MAX_RT_MS,
    validator=is_positive_int("dhcp6.sol_max_rt_ms"),
    description="RFC 8415 §7.6 — SOL_MAX_RT, maximum SOLICIT retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.req_timeout_ms",
    module_name=__name__,
    attr="DHCP6__REQ_TIMEOUT_MS",
    default=DHCP6__REQ_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.req_timeout_ms"),
    description="RFC 8415 §7.6 — REQ_TIMEOUT, initial REQUEST retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.req_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__REQ_MAX_RT_MS",
    default=DHCP6__REQ_MAX_RT_MS,
    validator=is_positive_int("dhcp6.req_max_rt_ms"),
    description="RFC 8415 §7.6 — REQ_MAX_RT, maximum REQUEST retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.req_max_rc",
    module_name=__name__,
    attr="DHCP6__REQ_MAX_RC",
    default=DHCP6__REQ_MAX_RC,
    validator=is_positive_int("dhcp6.req_max_rc"),
    description="RFC 8415 §7.6 — REQ_MAX_RC, REQUEST max retransmission count before returning to SOLICIT.",
)


def _finalize__irt_le_mrt(irt_key: str, mrt_key: str) -> None:
    """
    Cross-knob constraint — the IRT knob must be no greater than its
    paired MRT knob. The RFC 8415 §15 doubled-and-capped backoff with
    IRT > MRT would never actually double.
    """

    if get(irt_key) > get(mrt_key):
        raise ValueError(
            f"sysctl {irt_key!r} ({get(irt_key)}) must be ≤ {mrt_key!r} ({get(mrt_key)}); "
            f"the doubled-and-capped backoff would otherwise never advance.",
        )


register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.inf_timeout_ms", "dhcp6.inf_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.sol_timeout_ms", "dhcp6.sol_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.req_timeout_ms", "dhcp6.req_max_rt_ms"))
