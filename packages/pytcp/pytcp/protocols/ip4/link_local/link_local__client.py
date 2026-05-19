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

Phases 1-4 (shipped): subsystem skeleton + INIT-state
candidate selection + _do_claiming via the ACD API with the
retry / rate-limit loop pinned by RFC 3927 §9
(MAX_CONFLICTS = 10, RATE_LIMIT_INTERVAL = 60s) +
_on_bound_conflict (§2.5 defend / abandon decision tree)
wired via the address-API subscribe_conflicts callback +
_reconcile_with_dhcp (§1.9 / §2.11 fallback-on-DHCP-fail
and halt-on-DHCP-bind) driven by a polled is_dhcp_bound
predicate.

pytcp/protocols/ip4/link_local/link_local__client.py

ver 3.0.6
"""

import time
from enum import Enum
from typing import Callable, override

from net_addr import Ip4IfAddr, MacAddress
from pytcp.lib.logger import log
from pytcp.protocols.arp import arp__constants
from pytcp.protocols.ip4.link_local import link_local__constants as ip4ll_const
from pytcp.protocols.ip4.link_local.link_local__rng import candidate_from_mac
from pytcp.runtime.subsystem import Subsystem
from pytcp.stack.address import ConflictEvent, Ip4AddressApi, SubscriptionHandle


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

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        address_api: Ip4AddressApi,
        is_dhcp_bound: Callable[[], bool] | None = None,
    ) -> None:
        """
        Initialize the link-local autoconfig client. Binds to
        'mac_address' so the candidate-selection RNG seeds
        deterministically per host (RFC 3927 §2.1 SHOULD: same
        host picks the same address across reboots without
        persistent storage). 'address_api' is the sanctioned
        Phase-3-clean surface the subsystem uses to claim
        candidates ('claim_with_acd') and to subscribe for
        post-claim conflict events.

        'is_dhcp_bound' is an optional zero-argument predicate
        the subsystem polls on every tick to coordinate with
        the DHCPv4 client per RFC 3927 §1.9 / §2.11. Pass None
        when no DHCP client exists (link-local runs eager); pass
        a closure like 'lambda: stack.dhcp4_client.state is
        Dhcp4State.BOUND' to wire it up. The
        'ip4_link_local.dhcp_fallback_timeout_ms' sysctl gates
        whether the predicate is consulted at all: 0 disables
        the feature even when a getter is wired.
        """

        super().__init__(info=str(mac_address))
        self._mac_address: MacAddress = mac_address
        self._address_api: Ip4AddressApi = address_api
        self._is_dhcp_bound: Callable[[], bool] | None = is_dhcp_bound
        self._candidate: Ip4IfAddr | None = None
        self._conflict_count: int = 0
        # RFC 3927 §2.5(b) DEFEND_INTERVAL bookkeeping. Holds the
        # monotonic timestamps of recent defensive ARPs; the §2.5
        # decision reads the most recent entry to decide
        # defend (first conflict in window) vs abandon (second).
        self._defend_history: list[float] = []
        # Subscription handle returned by 'subscribe_conflicts'
        # when the address is installed; passed back on abandon.
        self._subscription: SubscriptionHandle | None = None
        # DHCP-fallback timer (RFC 3927 §1.9). 'None' = not
        # started; a float = the monotonic timestamp DHCP was
        # first observed unbound. The reconciler kicks off
        # claim when (now - this) >= dhcp_fallback_timeout_ms.
        self._dhcp_unbound_since: float | None = None
        # If the DHCP-fallback feature is active at construction
        # time (timeout > 0 AND a getter is wired), start
        # HALTED so the reconciler can drive the kick. Otherwise
        # start in INIT for eager claim. The sysctl is read once
        # at construction; runtime changes to the sysctl do not
        # restart the FSM (the reconciler still honours the live
        # value on each tick, just from whatever state we're in).
        if ip4ll_const.IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS > 0 and is_dhcp_bound is not None:
            self._state: Ip4LinkLocalState = Ip4LinkLocalState.HALTED
        else:
            self._state = Ip4LinkLocalState.INIT

    @override
    def _subsystem_loop(self) -> None:
        """
        One FSM tick. The DHCPv4 reconciler (RFC 3927 §1.9 /
        §2.11) runs first so a fresh DHCP-bind / DHCP-loss
        observation propagates before the per-state body runs.
        """

        self._reconcile_with_dhcp()
        match self._state:
            case Ip4LinkLocalState.INIT:
                self._do_init()
            case Ip4LinkLocalState.CLAIMING:
                self._do_claiming()
            case Ip4LinkLocalState.BOUND:
                # Idle; conflict handling is callback-driven via
                # the address API's subscribe_conflicts.
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
        self._candidate = Ip4IfAddr(f"{candidate_address}/16")
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

        result = self._address_api.claim_with_acd(ip4_ifaddr=self._candidate)
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
        self._address_api.remove_ifaddr(ip4_address=event.address)
        if self._subscription is not None:
            self._address_api.unsubscribe_conflicts(handle=self._subscription)
            self._subscription = None
        self._candidate = None
        self._defend_history.clear()
        self._conflict_count += 1
        self._state = Ip4LinkLocalState.INIT

    def _reconcile_with_dhcp(self) -> None:
        """
        RFC 3927 §1.9 / §2.11 DHCPv4 coordination. Reads the
        'is_dhcp_bound' predicate (if wired) on every tick and:

        - When DHCP is BOUND: release any held link-local
          address and transition to HALTED. The fallback
          timer resets.
        - When DHCP is NOT bound: start / continue the
          fallback timer. If the timer has accumulated
          'ip4_link_local.dhcp_fallback_timeout_ms' and the
          FSM is HALTED, transition to INIT to kick off
          autoconfig.

        The 'dhcp_fallback_timeout_ms' sysctl gates the whole
        feature: 0 means "no coordination — link-local runs
        independently of DHCP". A None 'is_dhcp_bound' also
        disables coordination (no DHCP client exists).

        Per RFC 3927 §2.11 the DHCP client itself is unchanged
        — coordination is one-way (link-local reads DHCP
        state; DHCP never reads link-local state).
        """

        fallback_ms = ip4ll_const.IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS
        if fallback_ms == 0 or self._is_dhcp_bound is None:
            return

        if self._is_dhcp_bound():
            # DHCP has a lease — release link-local if held
            # (RFC 3927 §1.9 / §2.11).
            if self._state is Ip4LinkLocalState.BOUND:
                self._release_bound_address()
            if self._state is not Ip4LinkLocalState.HALTED:
                self._state = Ip4LinkLocalState.HALTED
            self._dhcp_unbound_since = None
            return

        # DHCP not bound. Start / continue the fallback timer.
        now = time.monotonic()
        if self._dhcp_unbound_since is None:
            self._dhcp_unbound_since = now

        if self._state is Ip4LinkLocalState.HALTED:
            elapsed_ms = (now - self._dhcp_unbound_since) * 1000.0
            if elapsed_ms >= fallback_ms:
                __debug__ and log(
                    "stack",
                    f"<lg>Link-Local</>: DHCP unbound for " f"{elapsed_ms / 1000:.1f}s, kicking off autoconfig",
                )
                self._state = Ip4LinkLocalState.INIT
                self._dhcp_unbound_since = None

    def _release_bound_address(self) -> None:
        """
        Release the bound link-local address back to the
        address API — unsubscribe from conflict events,
        remove the host, clear candidate / counter / history.
        Used by the DHCP-bind reconcile path.
        """

        if self._subscription is not None:
            self._address_api.unsubscribe_conflicts(handle=self._subscription)
            self._subscription = None
        if self._candidate is not None:
            __debug__ and log(
                "stack",
                f"<lg>Link-Local</>: releasing {self._candidate.address} " f"(DHCP took over)",
            )
            self._address_api.remove_ifaddr(ip4_address=self._candidate.address)
        self._candidate = None
        self._defend_history.clear()
        self._conflict_count = 0
