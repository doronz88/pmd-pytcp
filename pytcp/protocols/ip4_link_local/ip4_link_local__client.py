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

Phase 1 (this commit): subsystem skeleton + INIT-state
candidate selection.
Phase 2 (next): _do_claiming via the ACD API + retry / rate-
limit loop.
Phase 3: _on_bound_conflict (§2.5 defend/abandon decision)
via the subscribe_conflicts callback.
Phase 4: DHCPv4-fallback trigger.

pytcp/protocols/ip4_link_local/ip4_link_local__client.py

ver 3.0.4
"""

from enum import Enum
from typing import override

from net_addr import Ip4Host, MacAddress
from pytcp.lib.logger import log
from pytcp.lib.subsystem import Subsystem
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

    def __init__(self, *, mac_address: MacAddress) -> None:
        """
        Initialize the link-local autoconfig client. Binds to
        'mac_address' so the candidate-selection RNG seeds
        deterministically per host (RFC 3927 §2.1 SHOULD: same
        host picks the same address across reboots without
        persistent storage).
        """

        super().__init__(info=str(mac_address))
        self._mac_address: MacAddress = mac_address
        self._state: Ip4LinkLocalState = Ip4LinkLocalState.INIT
        self._candidate: Ip4Host | None = None
        self._conflict_count: int = 0

    @override
    def _subsystem_loop(self) -> None:
        """
        One FSM tick. Dispatches on '_state'.
        """

        match self._state:
            case Ip4LinkLocalState.INIT:
                self._do_init()
            case Ip4LinkLocalState.CLAIMING:
                # Phase 2 wires this.
                pass
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
