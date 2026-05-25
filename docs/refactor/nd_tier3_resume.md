# ND Tier 3 — Resume Guide

> **SUPERSEDED point-in-time snapshot (note added 2026-05-25).** ND
> Tier 3 (§11–§16) has shipped, along with Tiers 1–6; this guide is
> kept as archaeology. Authoritative status: `nd_linux_parity.md` §0
> and `v3_0_6_remaining_work.md`.

Session-specific resume guidance for Tier 3 of
`docs/refactor/nd_linux_parity.md`. Use this alongside the
parity doc; this file is the "where we are / what to do
next" pointer.

## State at the time of writing (last commit `6eceb56b`)

**Closed:** Tier 1 wire-format completeness (§1, §2, §3, §4)
+ Tier 2 RFC 4861/4862 core finish (§5, §6, §7, §8, §9
partial, §10).

**Recent commits worth reading before resuming** (in
chronological order):

| Hash | Item | Why it matters for Tier 3 |
|---|---|---|
| `77151ea5` | Parity audit doc + 8981/9131 stubs | Source of truth for what's left |
| `5094e63b` | §1A Redirect message wire format | Pattern for wire-format adds |
| `923de2d3` | §1B Redirect RX handler + sysctl | Pattern for RX handler + `accept_*` sysctl |
| `87c7f0ed` | §2 MTU option wire format | RA-side option pattern |
| `e6ad1030` | §4 Route Information option wire format + Prf enum | Variable-length option pattern; Prf enum already shipped |
| `923de2d3`, `3deaef93`, `6eceb56b` | `nd__constants.py` evolution | Sysctl registration pattern |
| `68a66e88` | §10 simultaneous-probe DAD | Pattern for `_make_nd_*_frame` harness extension |
| `3deaef93` | §5 + §6 NA helper + gratuitous NA | Pattern for "extract helper, add behaviour" pairing |
| `6eceb56b` | §8 + §9-partial multi-probe DAD | Pattern for sysctl-tunable timing loops |

## Tier 3 items (§11-§16)

All sketches live in `docs/refactor/nd_linux_parity.md` —
read each section before tackling it.

| # | Item | Couples-to | Effort |
|---|---|---|---|
| §11 | Default-router list with Router Lifetime | foundation; unblocks §13/§14/§23 | Medium |
| §12 | PI lifetime tracking & address deprecation | needs §11 | Medium-large |
| §13 | Cur-Hop-Limit / ReachableTime / RetransTimer from RA | needs §11; needs `accept_ra_*` sysctls | Small |
| §14 | Router Preference (Prf field consumption) | needs §11; **Prf enum already shipped in §4** | Small |
| §15 | RDNSS / DNSSL options (RFC 8106) | parse-only; runtime consumer is dormant | Small (~80 lines) |
| §16 | All `accept_ra_*` Linux-parity sysctls | folded into §13/§15 | Folded |

## Recommended phase order

1. **§11 first.** Foundation for everything else. Adds
   `_icmp6_default_routers: list[(addr, lifetime, expires_at, prf)]`
   to the packet handler, RA RX handler appends/updates entries,
   background subsystem ages out expired routers. The Prf field
   is already parsed by the RA option dispatcher (we shipped the
   enum in §4 commit `e6ad1030`); it just isn't stored anywhere
   yet — §11 + §14 land it together for free.
2. **§12 next.** Per-prefix preferred / valid lifetime
   tracking; address deprecation. Couples with §11 because
   addresses are derived from PI options and the deprecation
   cycle ages independently of router lifetime. Largest item
   in the tier.
3. **§13 after §11.** Three RA fields → three sysctl writes.
   Trivial wire-format work; the gates are policy. Each gated
   by an `icmp6.accept_ra_*` sysctl from §16.
4. **§14 paired with §11.** Prf field already parsed; just
   store on the default-router-list entry and sort by
   preference.
5. **§15 last.** RDNSS/DNSSL wire-format only; no runtime
   consumer until PyTCP grows a resolver. Mark dormant.

## Key files Tier 3 will touch

- `packages/pytcp/pytcp/protocols/icmp6/nd/` — new files for
  `nd__router_state.py` (§11/§12 state machine), grow
  `nd__constants.py` for `accept_ra_*` knobs.
- `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py` —
  `__phrx_icmp6__nd_router_advertisement` becomes the RA
  consumer hub. Currently appends to `_icmp6_ra__prefixes`;
  rewrite to use the new router-state machine.
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` —
  `_icmp6_default_routers` attribute, init in setUp,
  background ageing in a Subsystem loop (consider a new
  `Icmp6NdRouterStateSubsystem` analogous to NeighborCache).
- `packages/net_proto/net_proto/protocols/icmp6/message/nd/option/` — new option
  modules for §15 (RDNSS, DNSSL).
- `packages/pytcp/pytcp/lib/packet_stats.py` — new counters per item:
  `icmp6__nd_router_advertisement__update_router`,
  `icmp6__nd_router_advertisement__expired_router`,
  `icmp6__nd_router_advertisement__rdnss_dnssl__drop` (gated
  by accept_ra_* = 0), etc.

## Test harness extensions needed

The `NdTestCase` in `packages/pytcp/pytcp/tests/lib/nd_testcase.py` currently
has `_make_nd_redirect_frame()` and `_make_nd_ns_frame()`.
Tier 3 tests will need:

- `_make_nd_ra_frame(*, src, dst, prefixes=, route_lifetime=, prf=, options=)`
  — builds an Ethernet/IPv6/ICMPv6 RA frame for RX injection.
  Used by every §11-§14 test. Add this with the first §11 test.
- Possibly `_inject_ra_with_pi(...)` / `_inject_ra_with_route_info(...)`
  convenience layers — only add when the test asks for them.

The integration-test runtime should mock `time.monotonic` so
ageing-out tests don't actually wait. Use the existing
`FakeTimer` plumbing in `IcmpTestCase` if it covers monotonic
time (check before ad-libbing).

## RFC clauses to cite per §

Use the trailing `Reference:` line per
`unit_testing.md` §7. Canonical pickers:

| § | RFC clause |
|---|---|
| §11 | RFC 4861 §6.3.4 (RA processing) + RFC 4861 §5.3 (Conceptual Sending Algorithm; default-router selection) |
| §11 (lifetime expiry) | RFC 4861 §6.3.5 (timing out router state) |
| §12 | RFC 4862 §5.5.3 (PI processing) + §5.5.4 (address-deprecation lifecycle) |
| §13 | RFC 4861 §6.3.4 (Cur-Hop-Limit / ReachableTime / RetransTimer from RA) |
| §14 | RFC 4191 §2.1 (Prf encoding) + RFC 4191 §2.2 (route-table preference rule) |
| §15 | RFC 8106 §5.1 (RDNSS option) + §5.2 (DNSSL option) |
| §16 | Linux `net.ipv6.conf.<iface>.accept_ra_*` (no RFC clause; cite "Linux parity" per §10's wording) |

## Tests-first, sysctl-first, no speculative API

Three rules to keep in mind every commit:

1. **Tests-first.** Each phase opens with failing tests
   (per `feature_implementation.md` §2). Verify the failure
   mode is right (ImportError → AttributeError → assertion)
   before flipping green.
2. **Sysctl-first.** Knobs land in `nd__constants.py` only
   when their consumer ships in the same commit. The Tier 2
   §9 work is "partial" precisely because we DON'T register
   the full RFC 4861 §10 set up front.
3. **No API surface without consumer.** §15 RDNSS/DNSSL
   wire formats can ship even though there's no consumer —
   they're parse-only and forward-compat. But don't add a
   "default DNS resolver list" attribute on the packet
   handler that nothing reads.

## Pre-resume checklist

Before starting:

- [ ] Read `docs/refactor/nd_linux_parity.md` §0 (status
      snapshot) and §11-§16 sections in full.
- [ ] Read commit `6eceb56b` (the §8+§9 commit that closed
      Tier 2) to confirm the sysctl pattern.
- [ ] Read commit `923de2d3` (§1B Redirect RX handler) for
      the canonical "RX handler + sysctl gate" pattern §13
      will mimic.
- [ ] `git pull` if working from a fresh checkout.
- [ ] `make lint && make test` to confirm the baseline is
      green before adding new code.
