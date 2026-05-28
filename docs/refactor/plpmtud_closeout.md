# PLPMTUD — close-out plan (the "remaining 20%")

**Authored:** 2026-05-28 on `PyTCP_3_0_6`. Successor to
`docs/refactor/plpmtud_unified_engine.md` (the 2026-05-14
implementation plan; Phases 0–5 SHIPPED).

This doc covers the **actually open** PLPMTUD work — the
piece the v3.0.6 ledger §2.1 lists as "remaining 20%" but
without naming the specific code surface. After auditing
the shipped state (Phase 0 below), the gap is precisely:

> **ICMP-independent active probing** — the canonical RFC
> 4821 §3 "Probing without ICMP" scenario. Today the
> probe-emit hook ships (`session/tcp__session__tx.py:434-440`)
> behind a per-session boolean (`_plpmtud_probing_enabled`,
> default `False`), but the hook only fires when
> `candidate_mtu > snd_mss`, which in steady-state never
> happens because `snd_mss` saturates at the interface
> MTU. The whole point of PLPMTUD — discovering the path
> MTU when ICMP PTBs are blackholed — therefore never
> triggers on the TCP transport.

The fix is small, Linux-mirrored, and bounded: a tristate
`tcp.mtu_probing` sysctl (0 = off, 1 = on RTO-suspected
black-hole, 2 = always-on aggressive) that the adapter
consults to decide whether to seed `snd_mss` BELOW
`interface_mtu` on session init so the engine has
upward-probing headroom.

---

## 1. What is actually shipped (Phase 0 audit, 2026-05-28)

Verified against `PyTCP_3_0_6` at HEAD `914dfe89` after
the per-interface sysctl track closed.

### 1.1 Engine + framework (SHIPPED 2026-05-14)

- `packages/pytcp/pytcp/lib/plpmtud.py::PmtuSearch[A]` —
  RFC 8899 §5 state machine, binary-search ladder, ICMP
  coexistence, black-hole detection. 21 unit tests.
- `stack.pmtu_state` registry + `current_pmtu(dst)`
  helper. 6 unit tests.
- `TcpPlpmtudAdapter` + per-session lifecycle wiring +
  `snd_una`-advance probe-ack hook + RTO probe-loss hook.
  12 adapter unit tests + 5 wiring integration tests.
- `UdpPlpmtudAdapter` + per-socket `probe_pmtu` /
  `ack_probe` / `timeout_probe` manual API. 13 adapter
  unit tests + 6 integration tests.

### 1.2 Linux-aligned semantics (SHIPPED 2026-05-14)

- `PmtuSearch.on_classical_pmtu` shrinks `current_mtu`
  only — `search_high` stays at `interface_mtu` so the
  engine retains upward-probing headroom after an ICMP
  PTB. Matches Linux's `tcp_mtu_probing` behaviour.
- `snd_mss` grow-on-probe-ack hook in
  `TcpAckProcessor.on_snd_una_advance` — when the engine's
  `current_mtu` rises, the session's `snd_mss` follows.
- 4 Linux-aligned integration tests.

### 1.3 TCP probe-segment emit (SHIPPED 2026-05-14, default-off)

- `session/tcp__session__tx.py::_transmit_data` calls
  `adapter.candidate_mtu`; when
  `_plpmtud_probing_enabled and candidate is not None and
  probe_payload > snd_mss and enough data is buffered`,
  the next segment is sized to `probe_payload` instead of
  `snd_mss`. `adapter.record_emitted_probe(seq, size)`
  tracks the in-flight probe for ack/loss correlation.
- 4 probe-emit integration tests.

### 1.4 The gap (NOT shipped)

| Gap | Impact |
|---|---|
| **No sysctl-level enable** — `_plpmtud_probing_enabled` is a per-session boolean with no operator surface. Sessions are constructed with `False`; nothing flips it. | Probe-emit is dead code in default deployments. |
| **No "cold-start" probe seed** — even with the flag flipped, `snd_mss` initialises to `interface_mtu - overhead`, which equals the engine's `_max_mtu`. The probe-emit gate `probe_payload > snd_mss` therefore never fires until an ICMP PTB has shrunken `snd_mss` first. | PLPMTUD's defining use case (surviving ICMP blackholes — RFC 4821 §3, the whole reason this RFC exists) is unreachable from the TCP transport. |
| **Phase 3 header in `plpmtud_unified_engine.md` still says "PARTIAL"** despite all sub-sections (3a / 3b / 3c-min / 3d Linux-aligned) marked SHIPPED. | Reviewer confusion about state. |
| **v3.0.6 ledger §2.1** lists this as the only open optional with vague "remaining 20%" wording. | Same. |

---

## 2. Goal

Make active PLPMTUD probing reachable from the TCP
transport in a Linux-mirroring way:

1. A `tcp.mtu_probing` per-interface sysctl (Linux
   `net.ipv4.tcp_mtu_probing`) that the operator flips to
   enable probing.
2. A "cold-start" path that seeds `snd_mss` from
   `TCP_BASE_MSS` (Linux's `net.ipv4.tcp_base_mss`,
   default 1024) on session establishment when probing
   is enabled, so the engine has immediate upward-probing
   headroom toward `interface_mtu`.
3. RFC 4821 §3 "Probing without ICMP" path becomes
   reachable on the TCP transport (it already works on
   UDP via the manual probe API).

**Out of scope for this close-out (deferred-with-rationale):**

- Linux `tcp_mtu_probing=1` semantics ("enable after RTO
  loss suspected to be black-hole"). Mode 1 detects a
  black-hole by observing repeated RTOs without any
  successful ack and only then enables probing. Mode 2
  is the simpler "always-on" alternative — sufficient for
  the RFC 4821 §3 conformance and the much more common
  PyTCP deployment pattern (small operator-controlled
  hosts where mode 1's heuristics are unnecessary).
  Document mode 1 as a deferred enhancement.
- Strict RFC 4821 §7.4 cwnd-exempt + §7.5 probe-only RTO
  compliance. Linux deliberately deviates from these for
  ~15 years; both adherence records already document this
  as a "Linux-pragmatic deviation". Leave as-is.

---

## 3. Architecture

### 3.1 Sysctl

`tcp.mtu_probing` — tristate int, per-interface
(`interface_scope=True` per the just-shipped per-iface
namespace migration):

| Value | Linux name | Behaviour |
|---|---|---|
| 0 | TCP_MTU_PROBE_DISABLED | Probing OFF. `snd_mss` seeded as today (`interface_mtu - overhead`). Default. |
| 2 | TCP_MTU_PROBE_ALWAYS | Probing ON. `snd_mss` seeded from `tcp.base_mss` on session init. Engine immediately has candidate > `snd_mss` and probes upward. |

(Linux's mode `1` = "after RTO black-hole suspected" —
deferred. Validator rejects `1` until that mode lands so
the operator sees a clear error.)

Registration in `packages/pytcp/pytcp/protocols/tcp/tcp__constants.py`
alongside the other TCP knobs. Default 0. Per-iface
storage.

`tcp.base_mss` — companion knob, per-interface, int.

| Value | Linux name | Behaviour |
|---|---|---|
| 1024 (default) | `net.ipv4.tcp_base_mss` | Initial `snd_mss` seed when mtu_probing > 0. |

PyTCP-side default matches Linux. Validator: ≥ 88 (RFC
1122 §4.2.2.6 MIN_MSS floor).

### 3.2 Session init wiring

`TcpSession.__init__`:

```python
egress_mtu = self._egress_interface_mtu()
ifname = ...  # the egress interface's name

self._plpmtud_adapter = TcpPlpmtudAdapter(
    remote_ip_address=remote_ip_address,
    interface_mtu=egress_mtu,
)

mode = sysctl_iface.get_for_iface("tcp.mtu_probing", ifname)
self._plpmtud_probing_enabled = mode != 0
if self._plpmtud_probing_enabled:
    # Linux-mirroring cold-start: seed snd_mss from
    # tcp.base_mss so the engine has upward-probing
    # headroom toward interface_mtu. Without this seed
    # snd_mss saturates at engine._max_mtu and the
    # probe-emit gate never fires (RFC 4821 §3).
    base_mss = sysctl_iface.get_for_iface("tcp.base_mss", ifname)
    initial_snd_mss = min(base_mss - self._ip_tcp_overhead, egress_mtu - self._ip_tcp_overhead)
    self._win.snd_mss = initial_snd_mss
```

The handshake MSS-option-negotiation MUST cap the
cold-start seed: if the peer advertises a smaller MSS,
the negotiated value wins (existing behaviour;
`_apply_received_mss` already does the lower-bound
take).

### 3.3 No new code in the probe-emit hot path

The probe-emit hook in `session/tcp__session__tx.py:434-440`
is unchanged — it already checks
`_plpmtud_probing_enabled` + `candidate_mtu > snd_mss` +
buffered data. Phase 3c-min shipped the hook; the only
thing this close-out adds is **a real path that makes the
gate condition reachable**.

### 3.4 `TCP_MAXSEG` socket-option interaction

`TCP_MAXSEG` (Linux per-socket override of `snd_mss`) is
NOT migrated; it stays as a separate explicit per-socket
knob. Operator opt-in via `tcp.mtu_probing=2` is the
sysctl path; `setsockopt(TCP_MAXSEG, …)` is the
per-socket path. They coexist: the socket-option write
wins (it's the higher-precedence explicit caller). See
`socket_linux_parity_audit.md` for the existing
`TCP_MAXSEG` row (currently `met`).

---

## 4. Phased delivery

Three phases. All tests-first. ~half-day total.

### Phase 1 — `tcp.base_mss` sysctl

**Goal:** the prerequisite knob lands first so Phase 2's
cold-start seed has something to read.

**Touches:**

- `packages/pytcp/pytcp/protocols/tcp/tcp__constants.py` — add
  `TCP__BASE_MSS: dict[str, int] = {"default": 1024}` per
  the per-iface namespace shape. Validator: int ≥ 88
  (RFC 1122 §4.2.2.6 MIN_MSS). `interface_scope=True`.
- `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__sysctls.py`
  — add default-registration + per-iface override +
  validator-rejection tests for `tcp.base_mss`.

**Test:**

- `test__tcp__sysctl__base_mss_default_is_1024` —
  registered with default 1024 (Linux parity).
- `test__tcp__sysctl__base_mss_per_iface_override` —
  per-iface key path works.
- `test__tcp__sysctl__base_mss_rejects_below_min_mss` —
  validator rejects 87 (below RFC 1122 MIN_MSS floor).

**Effort:** 30 min.

**Use the [`sysctl_knob`](../../.claude/skills/sysctl_knob/SKILL.md)
skill** for the registration mechanics + the §7.2
docstring audit + the audit-doc Reference.

### Phase 2 — `tcp.mtu_probing` sysctl + cold-start seed

**Goal:** the operator-facing enable + the cold-start
`snd_mss` seed wiring. Probe-emit becomes reachable.

**Touches:**

- `packages/pytcp/pytcp/protocols/tcp/tcp__constants.py` — add
  `TCP__MTU_PROBING: dict[str, int] = {"default": 0}`.
  Validator: int ∈ {0, 2} (1 deferred; emits explicit
  rejection message naming the deferred mode).
  `interface_scope=True`.
- `packages/pytcp/pytcp/protocols/tcp/session/tcp__session.py::__init__`
  — read both sysctls via `sysctl_iface.get_for_iface`;
  when mode != 0, seed `_win.snd_mss` from base_mss
  (capped at `interface_mtu - overhead`); flip
  `_plpmtud_probing_enabled`. The egress interface name
  comes from the same plumbing the existing
  `_egress_interface_mtu()` consumer uses.
- (Verify and update the few `TcpSession` test fixtures
  that mock `_plpmtud_adapter` — they should keep working
  but a quick grep against `_plpmtud_probing_enabled` for
  any test that relied on it being False with no override
  catches regressions.)

**Tests (integration, all new):**

- `test__tcp__plpmtud__mtu_probing_default_off_no_seed` —
  with `tcp.mtu_probing=0` (default), session opens with
  `snd_mss == egress_mtu - overhead` (current
  behaviour). Pin against regression.
- `test__tcp__plpmtud__mtu_probing_2_seeds_snd_mss_from_base_mss`
  — with `tcp.mtu_probing=2`, session opens with
  `snd_mss == base_mss - overhead`.
- `test__tcp__plpmtud__mtu_probing_2_enables_probe_emit_flag`
  — `_plpmtud_probing_enabled` flipped True.
- `test__tcp__plpmtud__mtu_probing_per_iface_scope` —
  setting `tcp.tap_a.mtu_probing=2` does NOT affect
  sessions on tap_b.
- `test__tcp__plpmtud__mtu_probing_rejects_mode_1` —
  validator-rejects the unsupported mode-1 value with a
  message naming the deferred-mode rationale.
- `test__tcp__plpmtud__cold_start_seed_capped_at_interface_mtu`
  — when `tcp.base_mss > interface_mtu - overhead` (a
  pathological operator config), the seed clamps to the
  interface ceiling (sanity-cap).
- `test__tcp__plpmtud__cold_start_probe_emits_upward` —
  end-to-end: with `mtu_probing=2`, the first
  `_transmit_data` call after enough data is buffered
  emits a probe sized > `snd_mss`, the probe is acked,
  `snd_mss` grows. Drive against a `FakeTimer` if needed.

**Effort:** ~3 hours including the test matrix.

**Adherence-record refresh:** the `RFC 4821 §3 "Probing
without ICMP"` row in
`docs/rfc/tcp/rfc4821__plpmtud/adherence.md` already
reads "met" but the rationale text references the
default-off limitation. Refresh the prose to reflect that
the gate is now reachable via the new sysctl. Same for
the RFC 8899 §3 row.

### Phase 3 — Doc reconciliation

**Goal:** reflect the close-out in every pointer doc so a
future reader doesn't re-discover the gap.

**Touches:**

- `docs/refactor/plpmtud_unified_engine.md` — Phase 3
  header flipped from `PARTIAL` to `SHIPPED`. Add a
  one-paragraph note pointing at this close-out doc as
  the follow-up that closed the operator-surface gap.
- `docs/refactor/v3_0_6_remaining_work.md` — §2.1 flipped
  from "open optional" to "CLOSED 2026-05-28" with the
  commits referenced.
- `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` and
  `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` — refresh
  the top-line wording: "The remaining gap is the TCP
  probe-segment emit path (Phase 3c, deferred)" → "Active
  probing reachable via `tcp.mtu_probing=2`; the
  Linux-pragmatic §7.4/§7.5 deviation is still in
  effect."
- `docs/refactor/socket_linux_parity_audit.md` — verify
  the row for "active PLPMTUD" status, refresh if needed.

**No code, no tests. Doc-only commit.**

**Effort:** ~30 min.

---

## 5. Definition of done

- All three phases shipped on `PyTCP_3_0_6`.
- `make lint` clean (mypy strict / black / isort / flake8
  / pylint / codespell).
- `make test` clean — current 11848 + 9 new tests.
- §7.2 docstring audit clean on every new/modified test
  file.
- `v3_0_6_remaining_work.md` §2.1 marked CLOSED.
- `plpmtud_unified_engine.md` Phase 3 header flipped to
  SHIPPED with a pointer to this close-out doc.
- RFC 4821 + RFC 8899 adherence records refreshed.
- A `project_plpmtud_closed` memory entry recorded with
  the commit hashes.

## 6. Cross-references

- `docs/refactor/plpmtud_unified_engine.md` — the
  authoritative implementation plan; this doc is the
  follow-up that closes its actual operator-surface gap.
- `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` — RFC 4821
  audit (refresh in Phase 3).
- `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` — RFC
  8899 audit (refresh in Phase 3).
- `docs/refactor/sysctl_per_interface.md` — the
  just-closed per-iface namespace migration; Phase 1 + 2
  knobs land as interface-scope right out of the gate.
- `.claude/skills/sysctl_knob/SKILL.md` — used for each
  Phase 1 / Phase 2 sysctl add.
- `.claude/rules/feature_implementation.md` — tests-first
  workflow.

---

## 7. Resume prompt (paste verbatim in a fresh session)

```
Read docs/refactor/plpmtud_closeout.md end to end — it is the
authoritative close-out plan for the PLPMTUD active probe-emit gap
(v3.0.6 ledger §2.1) on PyTCP_3_0_6 at HEAD 914dfe89. Then read
CLAUDE.md (Project North Star) and the relevant rule files in
.claude/rules/ (feature_implementation.md, pytcp.md, sysctl_knob skill).

Context: PLPMTUD engine + adapters + probe-emit code are SHIPPED
(plan_doc.md Phases 0-5, 2026-05-14). The probe-emit hook lives in
session/tcp__session__tx.py:434-440 behind a per-session boolean
'_plpmtud_probing_enabled' (default False) AND a 'candidate_mtu >
snd_mss' gate that today never trips because snd_mss saturates at
interface_mtu. The result: the RFC 4821 §3 "Probing without ICMP"
use case — the whole reason this RFC exists — is unreachable.

The close-out is exactly: add a 'tcp.mtu_probing' tristate sysctl
(0=off default, 2=always-on; mode 1 deferred) + a 'tcp.base_mss'
companion knob, then have TcpSession.__init__ read both via the
just-shipped per-iface namespace ('sysctl_iface.get_for_iface') and
seed snd_mss from base_mss when probing is enabled. Both knobs are
interface_scope=True per the 2026-05-28 per-iface migration. Linux-
mirroring throughout.

Three phases, all tests-first, ~half-day total:
  Phase 1 — 'tcp.base_mss' sysctl (3 tests, 30 min). Use the
            sysctl_knob skill for the mechanics.
  Phase 2 — 'tcp.mtu_probing' sysctl + cold-start snd_mss seed in
            TcpSession.__init__ (7 integration tests, ~3 h). The
            probe-emit hot path is unchanged; only the gate
            condition becomes reachable.
  Phase 3 — Doc reconciliation: flip plpmtud_unified_engine.md
            Phase 3 header to SHIPPED, mark v3.0.6 ledger §2.1
            CLOSED, refresh both RFC adherence records. Doc-only.

Out of scope (deferred-with-rationale): Linux mode 1 ("on RTO
black-hole suspected") needs heuristics PyTCP doesn't have today;
strict RFC §7.4 cwnd-exempt + §7.5 probe-only RTO already
documented as Linux-pragmatic deviation.

Follow the standing discipline: tests-first (a failing test that
pins the requirement before any fix), one logical unit per commit,
make lint + full make test + the §7.2 docstring audit clean before
each commit, modernise legacy typing/Python forms on touch, commit
trailer "Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>", push only when I explicitly say so.
Refresh the relevant adherence record in the same commit as the
code when an RFC-governed behaviour changes.

Before writing code, run the Phase 0 audit at §1 of the close-out
doc to confirm the assertions about shipped state still hold —
this plan is a snapshot and may have drifted.

I want to start Phase 1 (tcp.base_mss).
```
