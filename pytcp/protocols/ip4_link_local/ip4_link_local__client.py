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
This module contains the RFC 3927 IPv4 Link-Local autoconfig
client — a 'Subsystem' that picks a 169.254/16 candidate from
the MAC-seeded RNG, claims it via the sanctioned
'Ip4AddressApi.claim_with_acd' surface, defends it on
post-claim ARP conflicts, and coexists with the DHCPv4 client
per RFC 3927 §2.11 (read-only state-poll; never modifies DHCP
behaviour).

Phases 1-3 (shipped): subsystem skeleton + INIT-state
candidate selection + _do_claiming via the ACD API with the
retry / rate-limit loop pinned by RFC 3927 §9
(MAX_CONFLICTS = 10, RATE_LIMIT_INTERVAL = 60s) +
_on_bound_conflict (§2.5 defend / abandon decision tree)
wired via the address-API subscribe_conflicts callback.
Phase 4 (next): DHCPv4-fallback trigger.

pytcp/protocols/ip4_link_local/ip4_link_local__client.py

ver 3.0.4
"""

import time
from enum import Enum
from typing import override

from net_addr import Ip4Host, MacAddress
from pytcp.lib.address_api import ConflictEvent, Ip4AddressApi, SubscriptionHandle
from pytcp.lib.logger import log
from pytcp.lib.subsystem import Subsystem
from pytcp.protocols.arp import arp__constants
from pytcp.protocols.ip4_link_local import ip4_link_local__constants as ip4ll_const
from pytcp.protocols.ip4_link_local.ip4_link_local__rng import candidate_from_mac


class Ip4LinkLocalState(Enum):
    """
    RFC 3927 link-local autoconfig FSM state.

    INIT     — no candidate selected; the next subsystem-loop
               tick picks one.
    CLAIMING — 'claim_with_acd' in flight (probe + announce
               + install). Phase 2 wires this state.
    BOUND    — candidate installed via the address API; the
               subsystem subscribes for post-claim conflicts
               and defends per RFC 3927 §2.5. Phase 3 wires
               the defend / abandon decision.
    HALTED   — disabled (e.g. DHCPv4 succeeded; operator
               disabled). The subsystem-loop is a no-op
               until something else flips back to INIT.
    """

    INIT = "INIT"
    CLAIMING = "CLAIMING"
    BOUND = "BOUND"
    HALTED = "HALTED"


class Ip4LinkLocal(Subsystem):
    """
    RFC 3927 IPv4 Link-Local autoconfig client.
    """

    _subsystem_name = "IPv4 Link-Local Autoconfig"

    def __init__(self, *, mac_address: MacAddress, address_api: Ip4AddressApi) -> None:
        """
        Initialize the link-local autoconfig client. Binds to
        'mac_address' so the candidate-selection RNG seeds
        deterministically per host (RFC 3927 §2.1 SHOULD: same
        host picks the same address across reboots without
        persistent storage). 'address_api' is the sanctioned
        Phase-3-clean surface the subsystem uses to claim
        candidates ('claim_with_acd') and (in Phase 3) to
        subscribe for post-claim conflict events.
        """

        super().__init__(info=str(mac_address))
        self._mac_address: MacAddress = mac_address
        self._address_api: Ip4AddressApi = address_api
        self._state: Ip4LinkLocalState = Ip4LinkLocalState.INIT
        self._candidate: Ip4Host | None = None
        self._conflict_count: int = 0
        # RFC 3927 §2.5(b) DEFEND_INTERVAL bookkeeping. Holds the
        # monotonic timestamps of recent defensive ARPs; the §2.5
        # decision reads the most recent entry to decide
        # defend (first conflict in window) vs abandon (second).
        self._defend_history: list[float] = []
        # Subscription handle returned by 'subscribe_conflicts'
        # when the address is installed; passed back on abandon.
        self._subscription: SubscriptionHandle | None = None

    @override
    def _subsystem_loop(self) -> None:
        """
        One FSM tick. Dispatches on '_state'.
        """

        match self._state:
            case Ip4LinkLocalState.INIT:
                self._do_init()
            case Ip4LinkLocalState.CLAIMING:
                self._do_claiming()
            case Ip4LinkLocalState.BOUND:
                # Phase 3 idle-with-subscription state.
                pass
            case Ip4LinkLocalState.HALTED:
                pass

    def _do_init(self) -> None:
        """
        Pick a fresh link-local candidate via the MAC-seeded
        RNG (RFC 3927 §2.1). The 'conflict_count' selects the
        attempt index so a conflict-driven retry lands on a
        different candidate. Transitions to CLAIMING; the
        actual probe / announce / install happens in
        '_do_claiming' (Phase 2).
        """

        candidate_address = candidate_from_mac(
            mac=self._mac_address,
            attempt=self._conflict_count,
        )
        # The /16 mask is RFC-pinned: every 169.254 address is
        # on a single logical link.
        self._candidate = Ip4Host(f"{candidate_address}/16")
        __debug__ and log(
            "stack",
            f"<lg>Link-Local</>: candidate {self._candidate.address} " f"(attempt={self._conflict_count})",
        )
        self._state = Ip4LinkLocalState.CLAIMING

    def _do_claiming(self) -> None:
        """
        Delegate the RFC 3927 §2.2 probe + §2.4 announce to
        'Ip4AddressApi.claim_with_acd'. On clean probe the
        host is installed and the FSM transitions to BOUND.
        On conflict the FSM bumps the conflict counter and
        returns to INIT for a fresh candidate; after
        MAX_CONFLICTS consecutive conflicts the subsystem
        sleeps RATE_LIMIT_INTERVAL seconds before resetting
        the counter and trying again (RFC 3927 §9).
        """

        assert self._candidate is not None, "_do_claiming requires a candidate from _do_init"

        result = self._address_api.claim_with_acd(ip4_host=self._candidate)
        if result.success:
            self._conflict_count = 0
            self._defend_history = []
            self._subscription = self._address_api.subscribe_conflicts(
                address=self._candidate.address,
                on_conflict=self._on_bound_conflict,
            )
            self._state = Ip4LinkLocalState.BOUND
            __debug__ and log(
                "stack",
                f"<lg>Link-Local</>: claimed {self._candidate.address}",
            )
            return

        self._on_claim_conflict()

    def _on_claim_conflict(self) -> None:
        """
        Probe-conflict retry handler. Bumps the conflict
        counter, clears the candidate so the next INIT tick
        picks a fresh one, and (after MAX_CONFLICTS conflicts)
        sleeps RATE_LIMIT_INTERVAL seconds before resetting
        the counter for a fresh attempt round (RFC 3927 §9).
        """

        assert self._candidate is not None
        __debug__ and log(
            "stack",
            f"<lg>Link-Local</>: conflict on {self._candidate.address}; " f"retry (count={self._conflict_count + 1})",
        )
        self._candidate = None
        self._conflict_count += 1
        if self._conflict_count >= ip4ll_const.IP4_LINK_LOCAL__MAX_CONFLICTS:
            __debug__ and log(
                "stack",
                f"<lg>Link-Local</>: MAX_CONFLICTS reached; sleeping "
                f"{ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL}s",
            )
            time.sleep(ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL)
            self._conflict_count = 0
        self._state = Ip4LinkLocalState.INIT

    def _on_bound_conflict(self, event: ConflictEvent) -> None:
        """
        Subscription callback fired by 'Ip4AddressApi' on any
        post-claim ARP conflict matching our BOUND address.
        Implements the RFC 3927 §2.5 decision tree.

          - §2.5(b) — if no defensive ARP fired within the
            last 'ARP__DEFEND_INTERVAL' seconds, defend with
            a single gratuitous ARP and stay BOUND.

          - §2.5(a) — if a defensive ARP DID fire within the
            window, abandon the address: abort bound TCP
            sessions (§2.5 paragraph 7 SHOULD), remove the
            host via the API, unsubscribe, clear the
            candidate, bump the conflict counter, and
            transition to INIT for a fresh reconfigure.

        Runs on the ARP RX thread (the API's fan-out
        dispatcher); state mutations here race the main
        subsystem-loop thread, but the BOUND state's loop is
        a no-op so the race is benign.
        """

        assert self._candidate is not None, "_on_bound_conflict requires a bound candidate"
        now = time.monotonic()
        defend_window = arp__constants.ARP__DEFEND_INTERVAL
        recent = [t for t in self._defend_history if now - t < defend_window]

        if not recent:
            # §2.5(b): defend.
            self._defend_history.append(now)
            self._address_api.send_gratuitous_arp(address=event.address)
            __debug__ and log(
                "stack",
                f"<lg>Link-Local</>: defended {event.address} " f"against {event.sender_mac} (RFC 3927 §2.5(b))",
            )
            return

        # §2.5(a): abandon. The RFC SHOULDs are honoured:
        # active TCP sessions on the abandoned address get
        # ABORT; the address is removed via the public API.
        __debug__ and log(
            "stack",
            f"<lg>Link-Local</>: abandoning {event.address} "
            f"after second conflict in {defend_window}s (RFC 3927 §2.5(a))",
        )
        self._address_api.abort_bound_tcp_sessions(address=event.address)
        self._address_api.remove_host(ip4_address=event.address)
        if self._subscription is not None:
            self._address_api.unsubscribe_conflicts(handle=self._subscription)
            self._subscription = None
        self._candidate = None
        self._defend_history.clear()
        self._conflict_count += 1
        self._state = Ip4LinkLocalState.INIT
