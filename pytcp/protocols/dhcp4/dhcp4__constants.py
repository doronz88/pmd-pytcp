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
This module contains the DHCPv4 client runtime-tunable policy
constants governing RFC 2131 §4.1 retransmission backoff and the
RFC 2131 §3.1 step 4 bounded NAK-restart loop. Every constant
below is registered as a 'pytcp.lib.sysctl' knob so operators
can tune it via 'stack.init(sysctls={...})' at boot or
'pytcp.stack.sysctl["dhcp...."]' at runtime.

pytcp/protocols/dhcp4/dhcp4__constants.py

ver 3.0.4
"""

# RFC 2131 §4.1 — DHCPv4 retransmission backoff. The first
# retransmit fires 4 seconds after the initial DISCOVER /
# REQUEST; each successive retransmit doubles the delay up to
# 64 seconds. Each delay is randomised by ±1 second so a fleet
# of hosts powered on simultaneously does not all retransmit
# at the same instant.
DHCP4__RETRANS_INITIAL_MS = 4000
DHCP4__RETRANS_MAX_MS = 64000
DHCP4__RETRANS_JITTER_MS = 1000

# Total retransmit attempts (recv waits) per
# '_discover_request_once' round-trip. With the doubling
# sequence 4 / 8 / 16 / 32 / 64 seconds, 5 attempts yields
# the ~124-second budget the RFC's §3.1 step 5 worked example
# describes.
DHCP4__RETRANS_MAX_ATTEMPTS = 5

# RFC 2131 §3.1 step 4 — on DHCPNAK the client returns to
# INIT and restarts from DHCPDISCOVER. Bound the restart loop
# so a server that keeps NAK'ing cannot pin the client in an
# infinite cycle. Default 3 = up to 4 total
# DISCOVER/REQUEST attempts (initial + 3 restarts).
DHCP4__NAK_MAX_RESTARTS = 3

# RFC 2131 §4.4.1 startup desynchronisation delay — "the
# client SHOULD wait a random time between one and ten
# seconds to desynchronize the use of DHCP at startup". The
# delay is drawn uniformly from
# '[init_delay_min_ms, init_delay_max_ms]' (milliseconds);
# setting both to 0 disables the wait (useful for tests
# and for short-lived containerised hosts where startup
# desync is unnecessary).
DHCP4__INIT_DELAY_MIN_MS = 1000
DHCP4__INIT_DELAY_MAX_MS = 10000

# RFC 2131 §3.1 step 5 post-DHCPDECLINE wait — "The client
# SHOULD wait a minimum of ten seconds before restarting
# the configuration process to avoid excessive network
# traffic in case of looping." 10 000 ms matches the SHOULD
# floor; setting 0 disables the wait for deterministic
# tests.
DHCP4__DECLINE_BACKOFF_MS = 10000

from pytcp.lib.sysctl import (  # noqa: E402
    get,
    is_non_negative_int,
    is_positive_int,
    register,
    register_finalize_validator,
)

register(
    key="dhcp.retrans_initial_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_INITIAL_MS",
    default=DHCP4__RETRANS_INITIAL_MS,
    validator=is_positive_int("dhcp.retrans_initial_ms"),
    description="RFC 2131 §4.1 — initial retransmit delay in milliseconds (first retransmit at 4 s).",
)
register(
    key="dhcp.retrans_max_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_MAX_MS",
    default=DHCP4__RETRANS_MAX_MS,
    validator=is_positive_int("dhcp.retrans_max_ms"),
    description="RFC 2131 §4.1 — maximum retransmit delay in milliseconds (delays doubled up to 64 s).",
)
register(
    key="dhcp.retrans_max_attempts",
    module_name=__name__,
    attr="DHCP4__RETRANS_MAX_ATTEMPTS",
    default=DHCP4__RETRANS_MAX_ATTEMPTS,
    validator=is_positive_int("dhcp.retrans_max_attempts"),
    description="Phase 1 retransmit budget — total recv attempts before giving up (default 5 = ~124 s).",
)
register(
    key="dhcp.retrans_jitter_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_JITTER_MS",
    default=DHCP4__RETRANS_JITTER_MS,
    validator=is_non_negative_int("dhcp.retrans_jitter_ms"),
    description=(
        "RFC 2131 §4.1 — uniform ±jitter window around each " "retransmit delay (set 0 for deterministic backoff)."
    ),
)
register(
    key="dhcp.nak_max_restarts",
    module_name=__name__,
    attr="DHCP4__NAK_MAX_RESTARTS",
    default=DHCP4__NAK_MAX_RESTARTS,
    validator=is_non_negative_int("dhcp.nak_max_restarts"),
    description="RFC 2131 §3.1 step 4 — NAK-driven restart budget per fetch() (default 3 = up to 4 attempts).",
)
register(
    key="dhcp.init_delay_min_ms",
    module_name=__name__,
    attr="DHCP4__INIT_DELAY_MIN_MS",
    default=DHCP4__INIT_DELAY_MIN_MS,
    validator=is_non_negative_int("dhcp.init_delay_min_ms"),
    description=(
        "RFC 2131 §4.4.1 — lower bound of the startup "
        "desynchronisation delay in milliseconds (set 0 with "
        "max=0 to disable for tests)."
    ),
)
register(
    key="dhcp.init_delay_max_ms",
    module_name=__name__,
    attr="DHCP4__INIT_DELAY_MAX_MS",
    default=DHCP4__INIT_DELAY_MAX_MS,
    validator=is_non_negative_int("dhcp.init_delay_max_ms"),
    description=(
        "RFC 2131 §4.4.1 — upper bound of the startup "
        "desynchronisation delay in milliseconds (set 0 with "
        "min=0 to disable for tests)."
    ),
)
register(
    key="dhcp.decline_backoff_ms",
    module_name=__name__,
    attr="DHCP4__DECLINE_BACKOFF_MS",
    default=DHCP4__DECLINE_BACKOFF_MS,
    validator=is_non_negative_int("dhcp.decline_backoff_ms"),
    description=(
        "RFC 2131 §3.1 step 5 — post-DHCPDECLINE wait in "
        "milliseconds before restarting from DISCOVER "
        "(SHOULD ≥ 10 s; set 0 to disable for tests)."
    ),
)


def _finalize__retrans_initial_le_max() -> None:
    """
    Cross-knob constraint — 'dhcp.retrans_initial_ms' must be
    no greater than 'dhcp.retrans_max_ms'. A doubled-and-capped
    backoff with 'initial > max' would never actually double.
    """

    if get("dhcp.retrans_initial_ms") > get("dhcp.retrans_max_ms"):
        raise ValueError(
            f"sysctl 'dhcp.retrans_initial_ms' ({get('dhcp.retrans_initial_ms')}) must be "
            f"≤ 'dhcp.retrans_max_ms' ({get('dhcp.retrans_max_ms')}); the doubled-and-capped "
            f"backoff would otherwise never advance.",
        )


def _finalize__init_delay_min_le_max() -> None:
    """
    Cross-knob constraint — 'dhcp.init_delay_min_ms' must be
    no greater than 'dhcp.init_delay_max_ms'. The
    'random.uniform(min, max)' draw is undefined when
    'min > max'.
    """

    if get("dhcp.init_delay_min_ms") > get("dhcp.init_delay_max_ms"):
        raise ValueError(
            f"sysctl 'dhcp.init_delay_min_ms' ({get('dhcp.init_delay_min_ms')}) must be "
            f"≤ 'dhcp.init_delay_max_ms' ({get('dhcp.init_delay_max_ms')}); the "
            f"'random.uniform(min, max)' draw is undefined otherwise.",
        )


register_finalize_validator(_finalize__retrans_initial_le_max)
register_finalize_validator(_finalize__init_delay_min_le_max)
