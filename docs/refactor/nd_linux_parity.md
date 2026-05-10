# ND → Linux-host Parity Audit & Punch List

This document captures the IPv6 Neighbor Discovery work
needed to bring PyTCP's host-stack ND behaviour to default-
Linux parity. It records what shipped, what's still open,
and the implementation detail needed to resume each
remaining item without re-deriving it from scratch.

The classification follows the project's North Star
(`CLAUDE.md`): Phase 1 covers default-Linux **host**
behaviour; Phase 2 covers router-grade work. Items below
are marked Tier 1 (wire-format gaps), Tier 2 (RFC 4861 /
4862 core finish), Tier 3 (RA / SLAAC state tracking), Tier 4
(SLAAC privacy / modern IID), Tier 5 (DAD enhancements),
Tier 6 (RS hardening), or Tier 7 (Phase 2 / deferred).

ND is roughly 3× the surface of ARP — 14 governing RFCs vs 5
— so the punch list here is correspondingly larger. Items
are deliberately grain-sized so each is a one-session phase
analogous to the ARP-parity workflow.

Companion documents:
- `docs/refactor/arp_linux_parity.md` — IPv4 sibling, **closed**.
- `docs/refactor/nud_state_machine.md` — generic NUD FSM
  shared by ARP / ND, **closed** (Phases 1-6 shipped).

---

## §0 Status snapshot (2026-05-09)

### ✅ Shipped (already in tree)

| Area | Detail | RFC clause |
|---|---|---|
| ND wire format — NS / NA / RS / RA messages | parser + assembler under `net_proto/protocols/icmp6/message/nd/` | 4861 §4.1-§4.4 |
| ND options — SLLA / TLLA / PI | parser + assembler under `.../message/nd/option/` | 4861 §4.6.1-§4.6.2 |
| Generic NUD FSM (NeighborCache) | shared with IPv4 ARP; INCOMPLETE / REACHABLE / STALE / DELAY / PROBE / FAILED / PERMANENT | 4861 §7.3.2 |
| `NdCache` adapter — `pytcp/protocols/icmp6/nd/nd__cache.py` | kw-only public surface; protected-hook delegation; multicast-vs-unicast NS dispatch | (PyTCP) |
| **§1 wire format — Redirect message + Redirected Header option** | full parser/assembler under `net_proto/`, parser dispatch wired | RFC 4861 §4.5, §4.6.3 |
| **§1 RX handler — accept_redirects sysctl + §8.1/§8.3 host-side gates** | `__phrx_icmp6__nd_redirect` enforces accept_redirects sysctl, target acceptability, TLLA cache override; first-hop-router check deferred to §11 | RFC 4861 §8 |
| **§2 wire format — MTU option (RA-side)** | `Icmp6NdOptionMtu`, parser dispatch wired; runtime consumer absorbed into Tier 3 §13 | RFC 4861 §4.6.4 |
| **§4 wire format — Route Information option** | `Icmp6NdOptionRouteInfo` + `Icmp6NdRoutePreference` enum; variable 8/16/24-byte length per prefix; parser dispatch wired; runtime consumer absorbed into Tier 3 §11 | RFC 4191 §2.3 |
| **§7 ND Code-byte rejection across NS/NA/RS/RA/Redirect** | `Icmp6Parser._parse` wraps `from_buffer` ValueError as `Icmp6IntegrityError` so an out-of-range Code byte drops the frame instead of crashing the RX subsystem (Hop-Limit = 255 was already enforced per-message via `validate_sanity`) | RFC 4861 §6.1.1, §6.1.2, §7.1.1, §7.1.2, §8.1 |
| **§10 NS-during-DAD simultaneous-probe conflict** | `__phrx_icmp6__nd_neighbor_solicitation` checks the message's target_address against `_icmp6_nd_dad__ip6_unicast_candidate` BEFORE the `target not in ip6_unicast` early-return; on match, the host releases its DAD wait semaphore with `tlla = None` to abort the claim. New `icmp6__nd_neighbor_solicitation__dad_conflict` counter; new `_make_nd_ns_frame()` helper on NdTestCase | RFC 4862 §5.4.3 case (b) |
| **§5 NA emission helper refactor** | NA emission extracted from the NS RX inline path into a public `send_icmp6_neighbor_advertisement` TX helper (kw-only flags + include_tlla); enables the §6 gratuitous-NA path to share assembly | RFC 4861 §4.4 |
| **§6 Gratuitous NA on DAD success** | New `send_icmp6_neighbor_advertisement_gratuitous(ip6_unicast)` TX helper emits `icmp6.gratuitous_na_count` (default 1; 0 = kill switch) unsolicited NAs to ff02::1 with flag_o=True. Hooked from `_perform_ip6_nd_dad`'s no-duplicate branch — the IPv6 analogue of the IPv4 ARP Announcement we already ship | RFC 9131 §3 |
| **§8 Multi-probe DAD with RetransTimer** | `_perform_ip6_nd_dad` loops `icmp6.dad_transmits` times (default 1) spaced by `icmp6.retrans_timer_ms` (default 1000ms); a conflict event released mid-loop short-circuits further probing per RFC 4862 §5.4.5. Setting `icmp6.dad_transmits=0` disables DAD entirely | RFC 4862 §5.1, §5.4.5; RFC 4861 §10 RetransTimer |
| **§9 partial — `icmp6.dad_transmits` + `icmp6.retrans_timer_ms` sysctls** | First two timing knobs in the `icmp6.*` namespace beyond `accept_redirects` and `gratuitous_na_count`; further RFC 4861 §10 knobs (`reachable_time_ms`, `max_rtr_solicitations`, `accept_ra_*`) land with their consumers per "no API surface without consumer" rule | RFC 4861 §10 |
| **§11 default-router list with Router Lifetime** | `Icmp6DefaultRouter(address, lifetime, expires_at)` dataclass + per-RA `_update_icmp6_default_router` mutator + lazy-aged `get_icmp6_default_routers()` accessor; `icmp6.accept_ra_defrtr` sysctl gates the path; new RX counters `update_router` / `remove_router` / `defrtr__drop`. Prf field deferred to §14 | RFC 4861 §6.3.4 |
| **§12a SLAAC per-address lifetime tracking** | `Icmp6SlaacAddress(address, prefix, preferred_until, valid_until)` dataclass + per-PI `_update_icmp6_slaac_address` mutator + lazy-aged `get_icmp6_slaac_addresses()` accessor; EUI-64 address derivation; `icmp6.accept_ra_pinfo` sysctl gates the path; new RX counters `pi__update_address` / `pi__remove_address` / `pi__pinfo_disabled__drop` | RFC 4862 §5.5.3 |
| **§12b SLAAC per-address state machine + 2-hour rule** | `Icmp6SlaacAddressState` enum (`PREFERRED`/`DEPRECATED`) computed lazily from `time.monotonic()`; `get_icmp6_slaac_address_state(prefix=...)` accessor; (e)(6) 2-hour rule clamps refresh on existing entries (cases a/b/c); new RX counter `pi__2hour_rule_ignored__drop`. RFC 6724 source-address-selection consumer deferred to §12c | RFC 4862 §5.5.3 (e)(6), §5.5.4 |
| Basic single-probe DAD on address claim | `_send_icmp6_nd_dad_message` + 1-second blocking wait + NA-conflict detector | 4862 §5.1 (DupAddrDetectTransmits=1, partial) |
| EUI-64 SLAAC IID derivation | `Ip6Host.from_eui64` in net_addr | 4862 §5.5.3 (legacy IID) |
| Solicited-node multicast group join on address assignment | `_assign_ip6_multicast` / `_remove_ip6_multicast` | 4861 §7.2.1 |
| MLDv2 listener role + Router-Alert-wrapped Reports | `_send_icmp6_multicast_listener_report` | 3810 §5 |
| RA prefix harvesting for SLAAC | A-flag + link-local + lifetime checks; address derived via EUI-64 + DAD-claimed | 4862 §5.5.3 |
| TX-side unicast NS for cache refresh | `send_icmp6_neighbor_solicitation_unicast` (Phase 3 of NUD migration) | 4861 §7.3.3 (PROBE state) |
| ICMPv6 base — Echo / DU / TE / PP / PTB | full parser + assembler + RX dispatch | 4443 |

### 🔓 Remaining inventory

- **Tier 1** (wire-format completeness): §1–§4 below.
- **Tier 2** (RFC 4861 / 4862 core finish): §5–§10.
- **Tier 3** (RA / SLAAC state tracking): §11–§16.
- **Tier 4** (SLAAC privacy / modern IID): §17–§19.
- **Tier 5** (DAD enhancements): §20–§21.
- **Tier 6** (RS hardening + multi-router): §22–§25.
- **Tier 7** (Phase 2 / deferred): §26.

Total: 25 grain-sized items across 6 in-scope tiers; ~3-4
sessions per tier at the ARP-work cadence.

---

## §1 — Tier 1: Redirect message (RFC 4861 §4.5 / §8) ✗

**Type 137 is wholly missing from PyTCP.** No wire-format
module, no `Icmp6Type` enum entry, no RX handler.

### Why it matters (Phase 1)

Linux honours inbound ICMPv6 Redirects to update its
neighbour cache and route table — a router can tell a host
"for destination D, send to next-hop H" instead of via
itself. Default Linux processes Redirects subject to the
RFC 4861 §8.1 acceptance gates (hop-limit 255, ICMP code 0,
source must be the current first-hop, ICMP destination must
match the original packet's source, etc.). On a host-only
stack the route-table side is small (PyTCP's routing today
is "default route → RA gateway"), but the **neighbour-cache
override** (§8.3) is observable: a Redirect that names the
final destination as on-link must update the cache so
future TX skips the router.

### Phase 2 hook

Generating Redirects is a router-grade behaviour. Phase 2 /
deferred. The wire-format work below is shared with Phase 1
(host) consumption.

### Implementation sketch

1. Add `Icmp6Type.ND_REDIRECT = 137` to the enum.
2. New module
   `net_proto/protocols/icmp6/message/nd/icmp6__nd__message__redirect.py`
   following the existing NS/NA/RS/RA template — wire format
   per RFC 4861 §4.5 (Reserved field, Target Address, Destination
   Address, options).
3. Add the Redirected Header option (§4.6.3, type 4) — see §3.
4. Add the TLLA option in the Redirect's options block (already
   implemented; reuse).
5. RX handler `__phrx_icmp6__nd_redirect` in
   `packet_handler__icmp6__rx.py` performing the §8.1
   acceptance checks before applying §8.3 cache overrides.
6. Sysctl `icmp6.accept_redirects` (Linux:
   `net.ipv6.conf.<iface>.accept_redirects`, default 1 for
   hosts, 0 for routers). PyTCP defaults 1.

### Effort

Medium — ~150 lines wire-format + ~80 lines RX dispatch +
parser/assembler tests. Tests-first per
`feature_implementation.md` §2.

### RFC reference

RFC 4861 §4.5 wire format, §8 processing.

---

## §2 — Tier 1: MTU option (RFC 4861 §4.6.4) ✗

The Maximum Transmission Unit option (type 5) carried in RA
overrides the on-link MTU. PyTCP's RA parser silently
discards unknown options including MTU.

### Implementation sketch

1. New module
   `net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__mtu.py`
   following the SLLA/TLLA template.
2. Add `Icmp6NdOptionType.MTU = 5` and dispatch in
   `icmp6__nd__options.py`.
3. RA RX handler reads the MTU option and adjusts
   `interface_mtu` accordingly (gated by Linux's
   `net.ipv6.conf.<iface>.accept_ra_mtu` sysctl analogue).

### Effort

Small — ~40 lines + tests.

### RFC reference

RFC 4861 §4.6.4.

---

## §3 — Tier 1: Redirected Header option (RFC 4861 §4.6.3) ✗

Type 4. Carries the original packet's IP header + leading
payload back in a Redirect so the host can correlate. Required
by §8 processing.

Implementation: wire-format module + dispatch entry; consumed
by §1's Redirect RX handler.

### Effort

Small — ~30 lines wire format + tests. Pair this with §1.

### RFC reference

RFC 4861 §4.6.3.

---

## §4 — Tier 1: Route Information option (RFC 4191 §2.3) ✗

Type 24. Carried in RA. Lets a router tell hosts "for
prefix P, prefer me as the next-hop" — i.e. more-specific
routes beyond the default. Required for default-Linux
behaviour (`net.ipv6.conf.<iface>.accept_ra_rt_info_*`
sysctl knobs control acceptance per prefix length).

### Implementation sketch

1. New option module under `nd/option/`.
2. RA RX handler appends parsed Route Info to a
   `_icmp6_ra__route_info: list[(prefix, lifetime, gateway, prf)]`
   structure.
3. Outbound IPv6 routing consults this list before falling back
   to the default route (today: linear list in
   `_icmp6_ra__prefixes` plus a single `gateway`).

### Effort

Medium — ~80 lines option + ~50 lines route-table work.
Couples with §11 (default router list). Defer until §11
lands.

### RFC reference

RFC 4191 §2.3.

---

## §5 — Tier 2: NA emission helper (RFC 4861 §4.4) ⚠ partial

Today PyTCP has no `send_icmp6_neighbor_advertisement`
helper. NS RX implicitly produces an NA reply through the
RX handler at line 745+ of `packet_handler__icmp6__rx.py`,
but that path is not factored into a clean TX helper —
which means it can't be called from the gratuitous-NA path
(§6) or the NS-conflict-during-DAD path.

### Implementation sketch

Refactor the NA emission from `__phrx_icmp6__nd_neighbor_solicitation`
into a standalone `send_icmp6_neighbor_advertisement` helper on
the TX class. Same pattern as `_send_arp_reply`. Take target
address + caller-supplied flags (Solicited / Override / Router)
as kwargs.

### Effort

Small — refactor; no behaviour change. ~50 lines of moved code
+ tests.

### RFC reference

RFC 4861 §4.4 + §7.2.

---

## §6 — Tier 2: Gratuitous NA on DAD success (RFC 9131) ✗

The IPv6 analogue of ARP Announcement. After DAD passes,
emit one or more unsolicited NAs (target=self, Override
flag set, destination=all-nodes-multicast) so peers
preemptively populate their neighbour cache. Linux ships
this on modern kernels.

### Implementation sketch

1. New helper `send_icmp6_neighbor_advertisement_gratuitous`
   on the TX class (composes on §5).
2. Hook into the DAD-success path in
   `_create_stack_ip6_addressing` (after the DAD wait
   times out without conflict).
3. Sysctl `icmp6.gratuitous_na_count` (analogous to ARP's
   `arp.announce_num`); default 1 per RFC 9131.

### Effort

Small — ~60 lines + tests. Needs §5 first.

### RFC reference

RFC 9131 §3 (host emission of gratuitous NA).

---

## §7 — Tier 2: NS / NA / RS / RA hop-limit + code validation (RFC 4861 §6 / §7) ⚠

Per RFC 4861, every ND message MUST be received with IP Hop
Limit = 255 and ICMP Code = 0; otherwise silently discard.
This guards against off-link spoofing. PyTCP's RX handlers
do not perform these checks today.

### Implementation sketch

Single shared validation helper `_validate_nd_message_hop_limit_and_code(packet_rx)`
called at the top of every `__phrx_icmp6__nd_*` handler.
Drops the packet (with stat counter increment) on failure.

### Effort

Small — ~30 lines + matrix tests covering each handler.

### RFC reference

RFC 4861 §6.1.1, §6.1.2, §7.1.1, §7.1.2, §8.1.

---

## §8 — Tier 2: Multi-probe DAD with RetransTimer (RFC 4862 §5.1) ⚠

PyTCP currently sends ONE DAD probe and waits 1 second.
RFC 4862 default is `DupAddrDetectTransmits = 1` (so one
probe is RFC-compliant), but Linux defaults to 1 too with
`RetransTimer = 1000ms`. The gap is making the count and
timer **configurable** so deployments needing higher
confidence can tune them.

### Implementation sketch

1. Add sysctls `icmp6.dad_transmits` (default 1) and
   `icmp6.retrans_timer_ms` (default 1000) — register
   under the `icmp6.*` namespace through the sysctl
   framework.
2. Loop `_send_icmp6_nd_dad_message` `dad_transmits` times,
   spaced by `retrans_timer_ms`.
3. Conflict detection on any iteration aborts the loop.

### Effort

Small — ~40 lines + integration tests covering N=2 and
conflict-on-iteration-2.

### RFC reference

RFC 4862 §5.1, §5.4.

---

## §9 — Tier 2: ND constants module + sysctl namespace (RFC 4861 §10) ✗

ARP has `pytcp/protocols/arp/arp__constants.py` with all
ARP/RFC 5227 timers exposed as `arp.*` sysctls. ND has no
analogue today — every constant is hardcoded.

### Implementation sketch

New `pytcp/protocols/icmp6/nd/nd__constants.py` registering:
- `icmp6.dad_transmits` (RFC 4862 §5.1, default 1)
- `icmp6.retrans_timer_ms` (RFC 4861 §10, default 1000)
- `icmp6.reachable_time_ms` (RFC 4861 §10, default 30000)
  — note: the generic `neighbor.reachable_time` already
  exists; deduplicate (the ND name redirects to the
  generic).
- `icmp6.max_rtr_solicitations` (RFC 4861 §10, default 3)
- `icmp6.rtr_solicitation_interval_ms` (default 4000)
- `icmp6.accept_ra` (Linux parity, default 1)
- `icmp6.accept_redirects` (Linux parity, default 1 for
  hosts)
- `icmp6.accept_ra_mtu` (Linux parity, default 1)
- `icmp6.accept_ra_rt_info_min_plen` /
  `..._max_plen` (Linux parity)
- `icmp6.gratuitous_na_count` (RFC 9131; default 1)

### Effort

Medium — ~120 lines registry + per-knob validators +
tests pinning defaults. Most consumers (§4 / §6 / §8 / §10
/ §15) build on this.

### RFC reference

RFC 4861 §10 (default constants), Linux parity for the
`accept_*` family.

---

## §10 — Tier 2: NS-during-DAD conflict response (RFC 4862 §5.4.3) ⚠

Today PyTCP detects NA-during-DAD as a conflict but doesn't
look at incoming NS for our tentative address (RFC 4862
§5.4.3 case (b)). A peer probing the same address at the
same instant should also abort our DAD.

### Implementation sketch

In `__phrx_icmp6__nd_neighbor_solicitation`, after the
target-match gate, check if the target is in our tentative-
address list. If so, abort the DAD (analogous to the IPv4
simultaneous-probe path in ARP RX — see ARP-parity §1).

### Effort

Small — ~30 lines + integration test mirroring the ARP
simultaneous-probe test.

### RFC reference

RFC 4862 §5.4.3.

---

## §11 — Tier 3: Default router list with Router Lifetime (RFC 4861 §6.3.4) ✓

**Shipped.** `Icmp6DefaultRouter(address, lifetime, expires_at)` frozen
dataclass at `pytcp/protocols/icmp6/nd/nd__router_state.py`; the host's
list lives on `PacketHandler._icmp6_default_routers` (init in
`PacketHandlerL2.__init__`). RA RX (`__phrx_icmp6__nd_router_advertisement`)
calls `_update_icmp6_default_router(address=ip6.src, router_lifetime=msg.router_lifetime)`:
non-zero lifetime installs / refreshes the entry, zero lifetime removes
it. The public accessor `get_icmp6_default_routers()` lazy-ages: entries
past `expires_at` are filtered at access time, mirroring how Linux's
`rt6_check_expired` is invoked on demand.

Three new RX counters track the cardinality of state changes:
`icmp6__nd_router_advertisement__update_router`,
`icmp6__nd_router_advertisement__remove_router`,
`icmp6__nd_router_advertisement__defrtr__drop` (latter incremented when
the `icmp6.accept_ra_defrtr` sysctl is 0).

The Prf field on the entry is **deferred to §14** — the RA-header parser
does not yet extract bits 3-4 of the flags byte. The
`_icmp6_default_routers` list shape will gain a `prf` column when §14
ships; `Icmp6DefaultRouter` is currently 3-field. The `Icmp6NdRoutePreference`
enum from §4 will be reused when §14 lands.

### Sysctl

`icmp6.accept_ra_defrtr` registered with default 1 (Linux host default;
0 disables default-router learning entirely). Validator rejects booleans
and values outside {0, 1}.

### Tests

`pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__default_router_list.py`:
- `nonzero_lifetime_adds_default_router` — entry shape + monotonic deadline.
- `update_router_packet_stats` — RX counter pinned.
- `second_ra_updates_lifetime_in_place` — refresh idempotent on (address).
- `separate_routers_separate_entries` — distinct sources → distinct entries.
- `zero_lifetime_removes_default_router` — RFC 4861 §6.3.4 immediate timeout.
- `zero_lifetime_remove_packet_stats` — `remove_router` counter pinned.
- `expired_filtered` — lazy-ageing accessor honest.
- `accept_ra_defrtr_zero_drops_update` — sysctl kill-switch.
- `builder_emits_parseable_frame` — harness regression net for `_make_nd_ra_frame()`.

### RFC reference

RFC 4861 §6.3.4 (RA processing — default-router list maintenance).
Linux: `net/ipv6/ndisc.c::ndisc_router_discovery`,
`net.ipv6.conf.<iface>.accept_ra_defrtr`.

---

## §12 — Tier 3: PI lifetime tracking & address deprecation (RFC 4862 §5.5.3) ✓ (wire state) / ⚠ (RFC 6724)

### §12a (shipped) — Per-address lifetime tracking ✓

`Icmp6SlaacAddress(address, prefix, preferred_until, valid_until)`
frozen dataclass at `pytcp/protocols/icmp6/nd/nd__router_state.py`;
the host's table lives on `PacketHandler._icmp6_slaac_addresses`
(init in `PacketHandlerL2.__init__`). RA RX
(`__phrx_icmp6__nd_router_advertisement`) iterates the message's PI
options and, for each one that passes the `(e)(1)/(e)(2)/(e)(3)`
admit gates, calls
`_update_icmp6_slaac_address(prefix=..., valid_lifetime=..., preferred_lifetime=...)`.
Non-zero `valid_lifetime` installs / refreshes the entry (deduping
on `prefix`); zero `valid_lifetime` removes a matching entry — the
`(e)(6)(a)` "advertised lifetime overwrites address valid lifetime"
rule collapses to removal at value 0. Address derivation is EUI-64
(`Ip6Host.from_eui64(mac, prefix)`); RFC 7217 / 8981 alternates
land in Tier 4. Public lazy-aged accessor
`get_icmp6_slaac_addresses()` filters out entries whose `valid_until`
deadline has passed.

### §12b (shipped) — Per-address state machine + 2-hour rule ✓

`Icmp6SlaacAddressState` enum (`PREFERRED`, `DEPRECATED`) with
state computed lazily from `time.monotonic()` against the entry's
preferred / valid deadlines. `Icmp6SlaacAddress.state(now)` returns
`None` when `now >= valid_until` (the entry is REMOVED — accessors
filter it out). Public accessor
`get_icmp6_slaac_address_state(prefix=...)` returns the current
state or `None`.

The RFC 4862 §5.5.3 (e)(6) 2-hour rule clamps refresh on existing
entries: `_update_icmp6_slaac_address` checks remaining lifetime
on first match and:
- (a) accepts the advertised lifetime when it exceeds 2 hours OR
  the existing remaining;
- (b) ignores the PI entirely when remaining ≤ 2 hours (without
  SEND auth — PyTCP has no SEND, so the branch is unconditional);
- (c) clamps the new valid lifetime to 2 hours otherwise.

Counter `pi__2hour_rule_ignored__drop` tracks case (b).

### §12c (deferred) — RFC 6724 source-address-selection

The DEPRECATED state has no consumer until PyTCP integrates RFC 6724
source-address selection in the TX path. PyTCP today picks a source
address by a simple matching loop without preferring PREFERRED over
DEPRECATED. Tracked separately because RFC 6724 is its own large
phase (8 ordered rules, scope/label/prefer-temporary tables) that
deserves its own per-RFC adherence audit.

### §12d (deferred) — Operator clamps

Sysctls `icmp6.temp_pref_lifetime_ms` / `..._valid_lifetime_ms`
that clamp advertised lifetimes for safety. Composes with §17
(RFC 8981 temporary addresses) which adds parallel deprecation
timers; the sysctls are mostly meaningful in that context.

### Sysctl

`icmp6.accept_ra_pinfo` registered with default 1 (Linux host
default; 0 disables PI consumption entirely — for managed-config
deployments where addresses come from DHCPv6).

### Tests

`pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_address_tracking.py` (§12a):
- `nonzero_lifetimes_install_entry` — entry shape + monotonic deadlines.
- `update_address_packet_stats` — RX counter pinned.
- `second_pi_updates_lifetimes_in_place` — refresh idempotent on (prefix).
- `separate_prefixes_separate_entries` — multi-PI RA handling.
- `valid_lifetime_zero_removes_entry` — invalidation path.
- `valid_lifetime_zero_remove_packet_stats` — `remove_address` counter.
- `expired_filtered` — lazy-ageing accessor honest.
- `accept_ra_pinfo_zero_drops` — sysctl kill-switch.
- `processed_when_router_lifetime_zero` — confirms PI consumption is
  independent from §11 default-router learning.

`pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_address_state.py` (§12b):
- `state_preferred_within_preferred_lifetime` — PREFERRED branch.
- `state_deprecated_after_preferred_expires` — DEPRECATED branch.
- `state_none_after_valid_expires` — REMOVED (None) branch.
- `state_unknown_prefix_returns_none` — accessor totality.
- `2hour_rule_long_advertised_lifetime_accepts` — case (a) 2h ceiling.
- `2hour_rule_advertised_gt_remaining_accepts` — case (a) growth path.
- `2hour_rule_short_remaining_ignores_short` — case (b) anti-shrink.
- `2hour_rule_clamps_to_2_hours` — case (c) clamp.

### Effort

§12a — Small to medium — ~140 lines + integration tests.
§12b — Small — ~80 lines + integration tests.
§12c — Medium-large — ~200 lines + integration tests (RFC 6724).
§12d — Folded into §17 (RFC 8981 temporary addresses).

### RFC reference

RFC 4862 §5.5.3 (PI processing), §5.5.4 (address-deprecation lifecycle).
Linux: `net/ipv6/addrconf.c::addrconf_prefix_rcv`,
`net.ipv6.conf.<iface>.accept_ra_pinfo`.

---

## §13 — Tier 3: Cur-Hop-Limit / ReachableTime / RetransTimer from RA (RFC 4861 §6.3.4) ✗

These three fields in the RA header tell the host what
defaults to use. PyTCP ignores all three.

### Implementation sketch

1. `Cur-Hop-Limit` → write through to the IPv6 TX hop-limit
   default (gated by §9's `icmp6.accept_ra_hop_limit`
   sysctl).
2. `Reachable Time` → set `neighbor.reachable_time`
   sysctl (within sane bounds; clamp).
3. `Retrans Timer` → set `neighbor.retrans_timer` sysctl.

Trivial wire-format work; the gates are policy.

### Effort

Small — ~50 lines + tests.

### RFC reference

RFC 4861 §6.3.4.

---

## §14 — Tier 3: Router Preference (RFC 4191) ✗

The Prf field in the RA Reserved word indicates router
preference: 01=high, 00=medium (default), 11=low, 10=reserved.
Used by the default-router-list ordering (§11).

Implementation: parse the Prf field at RA RX; store in the
default-router-list entry; sort by preference. Couples with §11.

### Effort

Small — ~25 lines once §11 lands.

### RFC reference

RFC 4191 §2.1.

---

## §15 — Tier 3: RDNSS / DNSSL options (RFC 8106) ✗

Recursive DNS Server (type 25) and DNS Search List (type 31)
options in RA. Carry DNS configuration directly. Linux honours
both via `accept_ra_rdnss` / `accept_ra_dnssl` sysctls.

PyTCP today has no DNS resolver, so the consumer doesn't
exist yet. **This item is dormant — defer until PyTCP grows
a resolver consumer**, mirroring how RFC 5227 §2.1.1
MAX_CONFLICTS / RATE_LIMIT_INTERVAL is dormant in ARP-parity §3.

The two options' wire-format modules are still worth shipping
once §1's option-table machinery is in place; parsing them
into a discardable list is forward-compat (the sysctl
defaults to ignoring them anyway).

### Effort

Small — ~80 lines for both options + tests. Dormant runtime.

### RFC reference

RFC 8106 §5.1, §5.2.

---

## §16 — Tier 3: All `accept_ra_*` Linux-parity sysctls

The §9 constants module enumerates these. Each one is a
single conditional in the relevant RX handler:
`accept_ra_mtu`, `accept_ra_rt_info_*`, `accept_ra_pinfo`,
`accept_ra_defrtr`, `accept_ra_rdnss`, `accept_ra_dnssl`.
Linux defaults are mostly 1 except for the more-specific
flag families.

Ships incrementally with the corresponding consumers (§2,
§4, §11, §12, §15).

### Effort

Folded into the per-knob effort of §2-§15. No standalone
commit.

### RFC reference

Linux parity (`net/ipv6/ndisc.c`).

---

## §17 — Tier 4: RFC 7217 stable opaque IID

PyTCP today uses EUI-64 IIDs which embed the MAC address
and stay stable across networks. RFC 7217 generates
`F(prefix, network_id, dad_counter, secret_key)` cryptographic
hashes — stable per network but unlinkable across networks.

### Implementation sketch

1. New `Ip6Host.from_rfc7217(prefix, mac, secret_key, dad_counter)`
   classmethod — same shape as `from_eui64` but cryptographically
   derived.
2. Sysctl `icmp6.use_rfc7217` (Linux:
   `addr_gen_mode = 2`, default on modern Linux). When set,
   SLAAC uses RFC 7217 in place of EUI-64.

### Effort

Medium — ~100 lines + tests pinning the hash recipe.
Couples with the RFC 7217 stub adherence record at
`docs/rfc/icmp6/rfc7217__stable_iid/`.

### RFC reference

RFC 7217 §5.

---

## §18 — Tier 4: RFC 8981 temporary addresses (privacy)

Generates an additional **random IID** per prefix (parallel
to the stable address) for outbound flows. Linux's
`use_tempaddr = 2` enables this by default.

Builds on §12 (address deprecation), §11 (per-address state),
§17 (the recipe-style IID generator). Source-address
selection (RFC 6724 rule 7) prefers temporary for
outbound.

### Implementation sketch

1. Random IID generator avoiding RFC 5453 reserved IIDs.
2. Per-prefix temporary-address table parallel to the
   stable address.
3. Regeneration cycle (RFC 8981 §3.4): preferred-lifetime
   ~24h, valid-lifetime ~7d, regenerate at preferred-1h.
4. Source-address selection updates.

### Effort

Large — ~250 lines + integration tests covering address
regeneration and DAD-conflict handling on regenerated IIDs.
Couples with the RFC 8981 stub adherence record.

### RFC reference

RFC 8981 §3.

---

## §19 — Tier 4: RFC 4941 (legacy privacy extensions)

Predecessor of §18. Mark the existing
`docs/rfc/icmp6/rfc4941__privacy_extensions/` adherence
record as **superseded by §18 / RFC 8981**. No
implementation work — RFC 4941 is obsolete.

### Effort

Doc-only edit.

---

## §20 — Tier 5: Optimistic DAD (RFC 4429) ✗

Lets the host begin **using** the tentative address
immediately (subject to restrictions) rather than waiting
for DAD to complete. Linux supports it via
`optimistic_dad = 1`.

### Implementation sketch

1. New address state OPTIMISTIC alongside TENTATIVE / VALID.
2. Outbound path admits OPTIMISTIC addresses for sending
   (with the Override flag clear in any NA emission, per
   RFC 4429 §3.3).
3. DAD result transitions OPTIMISTIC → VALID on success or
   tears down on conflict.

### Effort

Medium — ~120 lines + integration tests. Couples with §11
and §12.

### RFC reference

RFC 4429.

---

## §21 — Tier 5: Enhanced DAD with Nonce option (RFC 7527) ✗

Mitigates loop-hairpin false-positive DAD failures (where
our own probe loops back through a switch and we mistake
it for a peer's NS). The Nonce option (type 14) lets us
match outbound probe to inbound echo and drop the echo
without aborting DAD.

### Implementation sketch

1. New Nonce option module under `nd/option/`.
2. DAD probe TX includes a Nonce.
3. NS RX during DAD: if the inbound NS carries a Nonce we
   sent, drop it (we're hearing our own echo).

### Effort

Small — ~60 lines + integration test simulating the loop-
hairpin.

### RFC reference

RFC 7527 §4.

---

## §22 — Tier 6: RS exponential backoff (RFC 7559) ✗

Today PyTCP sends a fixed number of RSs at fixed spacing.
RFC 7559 prescribes randomised exponential backoff to avoid
synchronised RS storms when many hosts boot together.

### Implementation sketch

Replace the fixed-interval RS loop with the RFC 7559
algorithm: start at `RTR_SOLICITATION_INTERVAL` (4 s),
multiply by 2 each iteration, cap at 3600 s, randomise ±10%.

### Effort

Small — ~30 lines + tests.

### RFC reference

RFC 7559 §2.

---

## §23 — Tier 6: First-hop router selection in multi-prefix networks (RFC 8028) ✗

When the host has addresses from multiple prefixes (e.g.
two ISPs), pick the default router whose advertised prefix
covers the source address being used. Couples with §11
(default router list) and §12 (per-address state) plus
RFC 6724 source-address selection.

### Implementation sketch

In the outbound TX path, when more than one default router
exists, prefer the one whose RA prefix matches the source
address. Fall back to the highest-preference router if no
match.

### Effort

Small — ~40 lines once §11 lands.

### RFC reference

RFC 8028 §3.

---

## §24 — Tier 6: Host-to-router load sharing (RFC 4311) ✗

When multiple equal-preference default routers exist, RFC
4311 §3 SHOULD distribute traffic across them in proportion
to a host-side load-sharing policy. Linux implements
weighted round-robin.

Couples with §11 + §23. Lower priority (informational
nice-to-have on a single-WAN host).

### Effort

Small — ~30 lines once §11 + §23 land.

### RFC reference

RFC 4311 §3.

---

## §25 — Tier 6: RA Flags option (RFC 5175) ✗

Type 26. Extends the RA Reserved word with additional
reachability-and-managed-flag bits. Currently no consumer
on the host side beyond what the RA header already carries.

Mark as low-priority. Wire-format module + parser; no
runtime branch needed unless a real consumer surfaces.

### Effort

Tiny — ~30 lines wire format, no runtime.

### RFC reference

RFC 5175.

---

## §26 — Tier 7: Phase 2 / deferred (per North Star)

Out of scope until PyTCP grows router-grade behaviour or
mobility support. **Do not implement.**

- **Redirect generation** (RFC 4861 §4.5) — router-side TX
  of the message §1 covers on RX. Phase 2.
- **MIPv6 Mobile IPv6** (RFC 6275) — mobility extensions
  excluded by North Star.
- **NEMO** / **MIPv6 RH2 processing** — mobility, excluded.
- **SEND** (RFC 3971 Secure Neighbor Discovery) — crypto
  extensions excluded by North Star.
- **RFC 6775 ND for LoWPAN** — niche IoT, defer
  indefinitely.
- **RFC 8505 Registration extensions** — same niche, defer.
- **MLDv2 Querier role** (RFC 3810 §6) — router-grade.
  Phase 2.
- **Proxy ND** (RFC 4389) — router/bridge function.
  Phase 2.

---

## §27 — Key file inventory

```
net_proto/protocols/icmp6/
├── icmp6__assembler.py / parser.py / base.py / errors.py
├── message/
│   ├── icmp6__message.py                     # base + Icmp6Type enum (Redirect MISSING)
│   ├── icmp6__message__{echo_request, echo_reply}.py
│   ├── icmp6__message__{destination_unreachable, packet_too_big}.py
│   ├── icmp6__message__{parameter_problem, time_exceeded}.py
│   ├── icmp6__message__unknown.py
│   ├── nd/
│   │   ├── icmp6__nd__message.py              # base
│   │   ├── icmp6__nd__message__neighbor_{solicitation, advertisement}.py
│   │   ├── icmp6__nd__message__router_{solicitation, advertisement}.py
│   │   ├── (icmp6__nd__message__redirect.py)  # MISSING — §1
│   │   └── option/
│   │       ├── icmp6__nd__option.py            # base
│   │       ├── icmp6__nd__options.py           # container
│   │       ├── icmp6__nd__option__{slla, tlla, pi}.py
│   │       ├── icmp6__nd__option__unknown.py
│   │       └── (mtu / redirected_header / route_info /
│   │            rdnss / dnssl / nonce / ra_flags) # MISSING — §2-§4, §15, §21, §25
│   └── mld2/
│       ├── icmp6__mld2__message__report.py
│       └── icmp6__mld2__multicast_address_record.py

pytcp/protocols/icmp6/
├── icmp6__echo_gate.py
└── nd/
    └── nd__cache.py                            # NeighborCache adapter (shipped)
    └── (nd__constants.py)                      # MISSING — Tier 2 §9
    └── (nd__redirect_handler.py)               # MISSING — Phase 1B (Tier 1 §1)
    └── (nd__dad.py)                            # MISSING — Tier 2 §8 / §10
    └── (nd__router_state.py)                   # MISSING — Tier 3 §11–§14
    └── (nd__slaac.py)                          # MISSING — Tier 3 §12 / Tier 4 §17–§18

pytcp/stack/packet_handler/
├── packet_handler__icmp6__rx.py                # RX dispatch
└── packet_handler__icmp6__tx.py                # TX helpers

pytcp/stack/packet_handler/__init__.py
└── _create_stack_ip6_addressing                # DAD + SLAAC entry point
```

---

## §28 — RFC adherence record inventory

Every adherence record under `docs/rfc/icmp6/`:

| RFC | Topic | Status today | Tackled in this plan |
|---|---|---|---|
| 3810 | MLDv2 | stub (host-listener role shipped; querier Phase 2) | §26 |
| 4191 | Default Router Preferences | stub | §14 (parse Prf), §11 (router list) |
| 4311 | Host-to-router load sharing | stub | §24 |
| 4429 | Optimistic DAD | stub | §20 |
| 4443 | ICMPv6 base | stub | (already shipped; refresh after Tier 2) |
| 4861 | IPv6 ND | stub | §1, §5, §7, §10, §11, §13 |
| 4862 | SLAAC | stub | §8, §10, §12, §17, §18 |
| 4941 | Privacy extensions (legacy) | stub (obsoleted by 8981) | §19 (mark superseded) |
| 5175 | RA flags option | stub | §25 |
| 6980 | ND no-fragmentation | audited | (already met) |
| 7217 | Stable opaque IID | audited | §17 |
| 7527 | Enhanced DAD | stub | §21 |
| 7559 | RS backoff | stub | §22 |
| 8028 | First-hop router selection | stub | §23 |
| 8106 | RA DNS options | stub | §15 (parse-only; consumer dormant) |
| 8981 | Temporary addresses | stub (added by this commit) | §18 |
| 9131 | Gratuitous NA | stub (added by this commit) | §6 |

Refreshing each adherence record into a full per-RFC audit
(via the `rfc_adherence_audit` skill) is a separate task,
naturally pinned to the matching tier-item commit.

---

## §29 — Resume prompt

When picking this work back up, the entry sequence is:

1. **Pick a tier.** Tier 1 (wire-format completeness) is
   the most natural start: §1 Redirect message + §3
   Redirected Header option pair, then §2 MTU, then
   §4 Route Info. Each is a one-session commit.
2. **For each item, follow `feature_implementation.md` §2
   tests-first.** The test pinning the spec requirement
   opens the commit; the implementation flips it green.
3. **Update the matching `docs/rfc/icmp6/<rfcXXXX>/
   adherence.md`** record in the same commit (the
   `feedback_audit_in_lockstep_with_code` rule).
4. **Mark this doc's §0 status snapshot** in the same
   commit so the punch list stays current.

Tier 2 (§5–§10) is the most impact-per-line: adds the
core Linux-parity behaviours every modern host expects.
Tier 3 (§11–§16) is the bulk of the RA / SLAAC machinery
work; expect the longest tier. Tier 4–6 are smaller and
mostly couple to Tier 3 infrastructure.

The ARP-parity work that closed in commit `47a98ba0` is
the canonical reference for the workflow rhythm: 30
commits / ~6 tier-items / 5 phases / one focused session
per phase. ND should pace similarly.
