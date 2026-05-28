# PyTCP sysctl migration — current state + remaining work

**Status:** audit performed 2026-05-28. Companion to
`docs/refactor/sysctl_framework.md` (the framework design and
the Phase-1/Phase-2 retrospective). This document is the
"what's left" ledger.

## 0. TL;DR

10 of 11 `*__constants.py` modules are fully migrated. The
ICMPv6/ND module is functionally complete (22/23 — the one
remaining constant is an RFC-pinned invariant that
correctly stays static). Three migration targets remain,
all deferred-by-design per the framework's "migrate-when-
touched" rule, not by oversight:

1. **`protocols/tcp/tcp__constants.py`** — ~10 policy knobs,
   biggest gap. Naming-convention fix bundled in (bare
   `PACKET_RETRANSMIT_TIMEOUT` → `TCP__<SUBJECT>__<FIELD>`).
2. **`protocols/icmp/icmp__constants.py`** — 2 knobs (the
   shared ICMP error rate-limiter).
3. **`stack/__init__.py`** — 4 policy constants (accept-
   source-route + fragment-flow-timeout v4/v6 + ephemeral
   port range).

No feature work blocks on any of these; they sit on the
"next time the package is touched" cadence the framework
prescribes (`sysctl_framework.md` §Phase 3+). This document
exists so a focused sysctl-cleanup pass can land them in one
sweep when an operator wants to.

## 1. Current state — per-package

| Package | Constants | Registered | Status |
|---|---:|---:|---|
| `lib/neighbor__constants.py` | 10 | 10 | ✅ full |
| `protocols/arp/arp__constants.py` | 12 | 12 | ✅ full (Phase 1 of the framework) |
| `protocols/dhcp4/dhcp4__constants.py` | 20 | 20 | ✅ full |
| `protocols/icmp4/icmp4__constants.py` | 1 | 1 | ✅ full |
| `protocols/icmp6/nd/nd__constants.py` | 23 | 22 | ✅ effectively complete — see §2.1 below |
| `protocols/igmp/igmp__constants.py` | 5 | 5 | ✅ full |
| `protocols/ip4/ip4__constants.py` | 2 | 2 | ✅ full |
| `protocols/ip4/link_local/link_local__constants.py` | 3 | 3 | ✅ full |
| `protocols/ip6/ip6__constants.py` | 4 | 4 | ✅ full |
| **`protocols/icmp/icmp__constants.py`** | **2** | **0** | ❌ §3 |
| **`protocols/tcp/tcp__constants.py`** | **~10** | **0** | ❌ §4 |
| **`stack/__init__.py`** | **~4 policy + others static-by-design** | **0** | ❌ §5 |

## 2. Effectively-complete cases (no action needed)

### 2.1 `nd__constants.py` — 22 / 23

The unregistered constant is `ICMP6__SLAAC__TWO_HOUR_RULE_S`
(value `7200`). RFC 4862 §5.5.3 pins this at exactly two
hours; Linux has no sysctl for it. Per the framework's §1
heuristic ("if Linux uses `#define`, it's invariant"), it
correctly stays as a plain module-level constant. No
action.

## 3. ICMP error rate-limiter — `protocols/icmp/icmp__constants.py`

Two knobs, both registered with the shared rate-limiter
that powers ICMPv4 + ICMPv6 error origination.

| Current constant | Value | Proposed sysctl key | Validator | Linux equivalent | RFC citation |
|---|---|---|---|---|---|
| `ICMP_ERROR__RATE_PPS` | 100 | `icmp.error.rate_pps` | positive int | `net.ipv4.icmp_ratelimit` (1000 ms / N tokens); IPv6 `net.ipv6.icmp.ratelimit` is the same shape | RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) |
| `ICMP_ERROR__BURST` | 50 | `icmp.error.burst` | positive int | `net.ipv4.icmp_msgs_burst` (5.x kernels) | n/a (RFC permits implementation choice) |

Sysctl-naming note: Linux uses `icmp_ratelimit` (period in
ms — tokens per second is `1000 / period`). PyTCP's
`ICMP_ERROR__RATE_PPS` is more direct (packets per
second). Keep PyTCP's `rate_pps` semantics; document the
Linux mapping in the `description=` field.

No explicit `stack.init()` kwarg needed — niche knob;
operators reach it via `sysctls={"icmp.error.rate_pps": ...}`
or `pytcp.stack.sysctl["icmp.error.rate_pps"] = N`.

Single-commit migration. Test pin already exists at
`tests/unit/protocols/icmp/test__icmp__error_emitter__rate_limiter.py`
(the §I1 no-GIL lock-discipline test); confirm it keeps
passing through qualified-module-access reads from the rate
limiter.

## 4. TCP — `protocols/tcp/tcp__constants.py` (biggest gap)

Ten policy knobs, none registered. **Two work items bundle
here**: register all ten + normalise the bare-name pattern
(`PACKET_RETRANSMIT_TIMEOUT`) to the
`TCP__<SUBJECT>__<FIELD>` double-underscore hierarchy
mandated by `source_files.md` §7. Both changes land in one
commit per the framework's per-package-atomic rule.

### 4.1 Knob inventory

| Current constant | Value | Proposed sysctl key + new attr name | Validator | Linux equivalent | RFC citation |
|---|---|---|---|---|---|
| `PACKET_RETRANSMIT_TIMEOUT` | `1000` ms | `tcp.rto.initial_ms` / `TCP__RTO__INITIAL_MS` | positive int | `net.ipv4.tcp_rto_min` (loosely; Linux has min + initial = `TCP_TIMEOUT_INIT`) | RFC 6298 §2.1 |
| `PACKET_RETRANSMIT_MAX_COUNT` | `6` | `tcp.retransmit.max_count` / `TCP__RETRANSMIT__MAX_COUNT` | positive int | `net.ipv4.tcp_retries2` | RFC 1122 §4.2.3.5 R2 (incorporated by RFC 9293 §3.8.3) |
| `TIME_WAIT_DELAY` | `30000` ms | `tcp.time_wait.delay_ms` / `TCP__TIME_WAIT__DELAY_MS` | positive int | `net.ipv4.tcp_fin_timeout` | RFC 9293 §3.10.1 (2*MSL) |
| `DELAYED_ACK_DELAY` | `100` ms | `tcp.delayed_ack.delay_ms` / `TCP__DELAYED_ACK__DELAY_MS` | positive int; ≤ 500 | `net.ipv4.tcp_delack_min` (loosely) | RFC 1122 §4.2.3.2 / RFC 9293 §3.8.6.3 |
| `CHALLENGE_ACK_RATE_LIMIT_MS` | `1000` ms | `tcp.challenge_ack.rate_limit_ms` / `TCP__CHALLENGE_ACK__RATE_LIMIT_MS` | positive int | `net.ipv4.tcp_challenge_ack_limit` (Linux counts segments/sec; PyTCP uses ms window — document the mapping) | RFC 5961 §3 / §4 |
| `PERSIST_TIMEOUT_MAX` | `60_000` ms | `tcp.persist.timeout_max_ms` / `TCP__PERSIST__TIMEOUT_MAX_MS` | positive int | no exact equivalent (Linux uses `TCP_RTO_MAX` floor) | RFC 9293 §3.8.6.1 / RFC 1122 §4.2.2.17 |
| `KEEPALIVE_IDLE_TIME` | `7_200_000` ms | `tcp.keepalive.idle_time_ms` / `TCP__KEEPALIVE__IDLE_TIME_MS` | positive int; ≥ 2 hours (RFC 1122 floor) | `net.ipv4.tcp_keepalive_time` (in seconds — convert) | RFC 1122 §4.2.3.6 |
| `KEEPALIVE_PROBE_INTERVAL` | `75_000` ms | `tcp.keepalive.probe_interval_ms` / `TCP__KEEPALIVE__PROBE_INTERVAL_MS` | positive int | `net.ipv4.tcp_keepalive_intvl` (seconds) | RFC 1122 §4.2.3.6 |
| `KEEPALIVE_PROBE_MAX_COUNT` | `9` | `tcp.keepalive.probe_max_count` / `TCP__KEEPALIVE__PROBE_MAX_COUNT` | positive int | `net.ipv4.tcp_keepalive_probes` | RFC 1122 §4.2.3.6 |
| `TS_RECENT_OUTDATED_THRESHOLD_MS` | `24 * 86_400 * 1_000` (24 days) | `tcp.ts_recent.outdated_threshold_ms` / `TCP__TS_RECENT__OUTDATED_THRESHOLD_MS` | positive int | no Linux equivalent (RFC § floor) | RFC 7323 §5.5 |

### 4.2 Naming-convention normalization

All ten constants currently violate `source_files.md` §7
(bare `PACKET_RETRANSMIT_TIMEOUT` rather than the canonical
`TCP__<SUBJECT>__<FIELD>` hierarchy used by every other
protocol's `*__constants.py`). The migration renames every
attribute simultaneously. Call-site impact: every
`tcp__constants.<NAME>` reference in `session/`, `fsm/`,
`socket/` flips to the new name in the same commit.

Use `git grep -l "tcp__constants\."` to find the call
sites — expect ~10–15 files.

### 4.3 Cross-knob validators

Two cross-knob invariants warrant `_finalize_validators()`
hooks:

- `tcp.persist.timeout_max_ms` ≥ `tcp.rto.initial_ms`
  (persist can't time out faster than the initial RTO).
- `tcp.keepalive.idle_time_ms` ≥ 7_200_000 ms = 2 hours
  (RFC 1122 §4.2.3.6 hard floor; per-knob validator alone
  is enough, no cross-knob check needed).

### 4.4 Explicit `stack.init()` kwargs

Promote the operator-facing ones (anything Linux exposes
under `/proc/sys/net/ipv4/tcp_*`) to explicit kwargs:

- `tcp_rto_initial_ms`
- `tcp_retransmit_max_count`
- `tcp_time_wait_delay_ms`
- `tcp_keepalive_idle_time_ms`
- `tcp_keepalive_probe_interval_ms`
- `tcp_keepalive_probe_max_count`

Leave the others on the `sysctls={...}` bag (niche;
delayed-ACK, challenge-ACK, persist-max, ts-recent
threshold).

### 4.5 Test plan

- Per-knob: write a failing test before the migration that
  patches the sysctl key and asserts the runtime observes
  the new value. Reference: `tests/unit/lib/test__lib__sysctl.py`
  for the registry contract; per-knob behavioural tests
  live alongside the existing TCP integration suite.
- Cross-knob validator: a unit test in
  `tests/unit/lib/test__lib__sysctl.py` asserting the
  finalize hook rejects the violating combination with both
  knob names in the message.
- The full TCP integration suite (550 tests today) is the
  behaviour regression net — every test that depends on
  `PACKET_RETRANSMIT_TIMEOUT` etc. continues passing
  because the registry writes through to the renamed
  module attribute.

### 4.6 Open question: ISS / TFO / port secrets

`tcp/tcp__constants.py` is silent on the four secrets that
live on `stack/__init__.py`
(`TCP__ISS_SECRET`, `TCP__FASTOPEN_SECRET`, `TCP__PORT_SECRET`).
These are deliberate one-shot-per-boot `secrets.token_bytes(16)`
calls — NOT policy, do not migrate. Document this in the
TCP migration commit's body so the choice is greppable.

## 5. Stack-wide — `pytcp/stack/__init__.py`

Many module-level constants here are static-by-design
(secrets, boot-time addresses, version strings). The
genuinely-policy candidates are:

| Current constant | Value | Proposed sysctl key | Validator | Linux equivalent | RFC citation |
|---|---|---|---|---|---|
| `IP4__ACCEPT_SOURCE_ROUTE` | `False` | `ip4.accept_source_route` | bool | `net.ipv4.conf.<if>.accept_source_route` | RFC 791 §3.1 (LSRR / SSRR) |
| `IP4__FRAG_FLOW_TIMEOUT` | `5` sec | `ip4.frag.flow_timeout_s` | positive int | `net.ipv4.ipfrag_time` | RFC 815 (reassembly TTL) |
| `IP6__FRAG_FLOW_TIMEOUT` | `5` sec | `ip6.frag.flow_timeout_s` | positive int | `net.ipv6.ip6frag_time` | RFC 8200 §4.5 (60 s recommended; PyTCP defaults to Linux's 5 s) |
| `EPHEMERAL_PORT_RANGE` | `range(32768, 61000)` | `net.ephemeral_port_range_low` + `_high` (two keys) OR a single typed key | `_is_valid_port_range` (low < high, both ∈ [1024, 65535]) | `net.ipv4.ip_local_port_range` | RFC 6056 §3.2 |

### 5.1 Constants explicitly kept static (rationale documented)

| Constant | Why static |
|---|---|
| `TCP__ISS_SECRET`, `IP6__FLOW_SECRET`, `TCP__FASTOPEN_SECRET`, `TCP__PORT_SECRET` | Cryptographic boot secrets; mutating at runtime would defeat their purpose. |
| `MAC_ADDRESS`, `IP4_ADDRESS`, `IP4_GATEWAY`, `IP6_ADDRESS`, `IP6_GATEWAY` | Boot-time defaults; per-interface address/route state lives in the Address / Route APIs. |
| `IP4__SUPPORT`, `IP6__SUPPORT` | Hard on/off; per-interface enable is the Phase-2 Link-API job. |
| `INTERFACE__TAP__MTU`, `INTERFACE__TUN__MTU` | Per-link, owned by the Link API today; init-time defaults are not the right surface for these. |
| `TCP__FASTOPEN_CACHE_MAX_SIZE` | Borderline — currently a TFO cache cap. Could move into the TCP migration (§4) as a TFO-cache knob if the operator-tuning case ever surfaces. |
| `UDP__ECHO_NATIVE` | Test-only debug flag; the comment says "should always be disabled." Stays static. |
| `STACK__DEFAULT_IFINDEX`, `INTERFACE__MAX_COUNT`, `PYTCP_VERSION`, `GITHUB_REPO`, `EPHEMERAL_PORT_RANGE_STEP` (if added), `LOG__CHANNEL` / `LOG__DEBUG` / `LOG__OUTPUT` | Invariants or logging-system config, not network policy. |

### 5.2 Where the knobs land in code

`stack/__init__.py` is restricted under the Phase-3
directory restructure (per the `pytcp_directory_restructure`
memory) — it now holds only Phase-3 public APIs +
boot-time configuration. The four migration targets above
need a home. Recommendation: place the `_register(...)`
calls in a new `pytcp/stack/sysctl_seeds.py` module
imported by `stack/lifecycle.py::init()`, so
`stack/__init__.py` keeps the module-level constants (the
canonical storage) but the registration metadata lives
beside the lifecycle. Alternative: register in
`stack/sysctl.py` itself in a `_seed_stack_constants()` hook
called from `init()`.

Decide the home in the migration commit; document the
choice in the commit body.

## 6. Migration order

1. **TCP** (§4) — biggest, naming-convention fix bundled.
   One commit. Expect ~20 files touched.
2. **ICMP rate-limiter** (§3) — small (2 knobs); pairs
   well as a follow-up because the I1 no-GIL test already
   covers it.
3. **Stack-wide** (§5) — smallest, 4 knobs; needs the
   `sysctl_seeds.py` (or equivalent) decision.

Each is one atomic commit per the framework's "no
half-migrated package state" rule. Push only when the user
asks.

## 7. Per-knob workflow

Invoke the
[`sysctl_knob`](../../.claude/skills/sysctl_knob/SKILL.md) skill
for each knob. The skill encodes: classify, register,
optional explicit `stack.init()` kwarg, validator, tests-
first, audit-doc Reference, §7.2 docstring audit, commit.

## 8. Pre-commit checklist (per package)

1. `make lint` clean (codespell + isort + black + flake8
   + mypy strict).
2. `make test` clean (~11757 + new sysctl-behavioural
   tests).
3. `unit_testing.md` §7.2 docstring audit clean on every
   test file you wrote or modified.
4. RFC adherence docs that cite the old constant names get
   their citations updated in the same commit.
5. No half-migrated package state — every policy constant
   in the file is either registered or has an inline
   comment explaining why it's invariant.

## 9. Cross-references

- [`docs/refactor/sysctl_framework.md`](sysctl_framework.md)
  — design + Phase-1/Phase-2 retrospective. This document
  is the §Phase 3+ "remaining packages" follow-up.
- [`.claude/rules/pytcp.md`](../../.claude/rules/pytcp.md)
  §2 — policy vs invariant classification heuristic; the
  qualified-module-access pattern at §2.1.
- [`.claude/rules/source_files.md`](../../.claude/rules/source_files.md)
  §7 — the `<PROTO>__<SUBJECT>__<FIELD>` naming convention
  the TCP migration normalises to.
- [`.claude/skills/sysctl_knob/SKILL.md`](../../.claude/skills/sysctl_knob/SKILL.md)
  — per-knob workflow.

## 10. Definition of done

The sysctl-migration track is closed when:

1. `protocols/tcp/tcp__constants.py` has every policy
   constant registered + renamed to the
   `TCP__<SUBJECT>__<FIELD>` convention.
2. `protocols/icmp/icmp__constants.py` has both knobs
   registered.
3. `stack/__init__.py`'s four policy candidates are
   registered (via whichever seeds module the migration
   commit chooses).
4. `make test` + `make lint` green.
5. This document is amended to reflect "DONE" status, OR
   marked DELETED with the closure recorded in a memory
   entry.
6. `MEMORY.md` index entry for sysctl status updated.
