# ND Parity — Session Resume Guide

State at the time of writing: branch `PyTCP_3_0__pre_release`,
HEAD `aa9f4858`, all session commits pushed to origin.

## What shipped this session (16 commits)

In order:

| Commit | § | Title |
|---|---|---|
| `a9387896` | §11 | Default-router list with Router Lifetime |
| `02308945` | §12a | SLAAC per-prefix lifetime tracking |
| `e7988d97` | §12b | Per-address state machine + 2-hour rule |
| `2e0a21f0` | §13a | RA host-parameter mirror state |
| `d2c81d4d` | §13b | Wire RA mirror to TX / NUD / DAD consumers |
| `0336de71` | §14 | Router Preference (Prf field) |
| `63c8cdd6` | §15 | RDNSS / DNSSL option wire format |
| `1d8a4269` | (doc) | §15 framing cleanup — drop "deferred consumer" |
| `68110b6f` | §19 | RFC 4941 marked superseded by RFC 8981 |
| `6324bd93` | §22 | RS exponential backoff (RFC 7559 §2) |
| `04e6f453` | §25 | RA Flags option wire format (RFC 5175) |
| `afcc1955` | §25-fix | RA Flags parser accepts length ≥ 1 |
| `69eb69ce` | §21 | Enhanced DAD with Nonce option (RFC 7527) |
| `f65f332f` | §17 | RFC 7217 stable opaque IIDs |
| `aa25c6b3` | §18a | RFC 8981 random IID generator |
| `1f084762` | §23 | RFC 8028 first-hop router selection |
| `aa9f4858` | §24 | RFC 4311 host-to-router load sharing |

## Tier status

| Tier | Status | Notes |
|---|---|---|
| **Tier 1** (wire-format completeness §1-§4) | ✓ closed | shipped before this session |
| **Tier 2** (RFC 4861 / 4862 core §5-§10) | ✓ closed | shipped before this session |
| **Tier 3** (RA / SLAAC state §11-§16) | ✓ closed | this session |
| **Tier 4** (SLAAC privacy / modern IID §17-§19) | ⚠ partial | §17 ✓, §18a ✓, §18b/c/d deferred, §19 ✓ |
| **Tier 5** (DAD enhancements §20-§21) | ⚠ partial | §20 NOT shipped, §21 ✓ |
| **Tier 6** (RS hardening + multi-router §22-§25) | ✓ closed | this session |
| **Tier 7** (Phase 2 / mobility §26) | out of scope per CLAUDE.md North Star |

## What's left

### §20 — RFC 4429 Optimistic DAD

Lets the host use the tentative address immediately rather
than waiting for DAD to complete. Scoped at ~120-200 lines:
async DAD rewrite, tristate address model
(TENTATIVE / OPTIMISTIC / VALID), NA Override flag clear
during OPTIMISTIC per §3.3, DAD-success / DAD-failure
transitions.

Currently DAD is synchronous (`_perform_ip6_nd_dad` blocks);
boot flow is sequential per-address. §20 needs that to
become async — fairly invasive.

Files involved:
- `pytcp/stack/packet_handler/__init__.py` (`_perform_ip6_nd_dad`,
  `_create_stack_ip6_addressing`)
- `pytcp/stack/packet_handler/packet_handler__icmp6__tx.py`
  (`send_icmp6_neighbor_advertisement` — Override flag handling)
- `net_addr/ip6_host.py` or sidecar (state field)
- `pytcp/protocols/icmp6/nd/nd__router_state.py` or
  `nd__constants.py` (sysctl `icmp6.optimistic_dad`)

### §12c / §18d — RFC 6724 source-address selection

The DEPRECATED state from §12b and the temporary IID
generator from §18a both have no observable consumer until
RFC 6724 is wired into the TX source-address picker. RFC
6724 is its own large phase (8 ordered rules) and also
affects IPv4 source selection. Estimated ~200-300 lines plus
its own per-RFC adherence audit. Tracked at
`docs/rfc/ip6/rfc6724__default_address_selection/` (likely
needs to be created).

### §18b — RFC 8981 SLAAC integration

Per-prefix temp-address table parallel to
`_icmp6_slaac_addresses`. When a PI is admitted AND
`icmp6.use_tempaddr` is non-zero, generate a temp address
via `Ip6Host.from_rfc8981_temp(...)`, claim it via DAD,
insert into `_ip6_host`. RFC 8981 §3.4 lifetime clamps
(TEMP_PREFERRED_LIFETIME default 1 day, TEMP_VALID_LIFETIME
default 7 days). ~150 lines.

### §18c — RFC 8981 regeneration subsystem

Background thread rotates the temp address before its
preferred lifetime expires per RFC 8981 §3.4. DESYNC_FACTOR
random offset. Couples with §18b. ~100 lines.

### §13b TX hop-limit / §22 / etc consumer-wiring follow-ups

Mostly already done; the §13a→§13b wiring shipped; the
§17→`_derive_ip6_host` consumer wired; the §22 boot-flow
RS retransmit wired. No outstanding follow-ups.

## Suggested order for resuming

1. **§20 Optimistic DAD** — the only Tier 5 gap. Async DAD
   refactor is genuinely invasive but bounded.
2. **§18b SLAAC integration** — gives the §18a temp IID
   generator an actual consumer.
3. **§12c / §18d RFC 6724 source-address selection** — its
   own large phase. Set up the per-RFC adherence record at
   `docs/rfc/ip6/rfc6724__default_address_selection/` and
   work in passes (rules 1-3 first, then 4-6, then 7-8).
4. **§18c regeneration subsystem** — depends on §18b being
   in place.

## Pre-resume checklist

- [ ] `git pull` if working from a fresh checkout.
- [ ] `make lint && make test` — should report 9954 tests
      passing, 4 skipped, lint clean.
- [ ] Read `docs/refactor/nd_linux_parity.md` §0 status
      snapshot for the canonical inventory.
- [ ] Pick §20, §18b, or §12c per the order above.
