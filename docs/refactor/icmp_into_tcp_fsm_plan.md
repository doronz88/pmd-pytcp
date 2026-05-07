# ICMP feed → TcpSession FSM dispatch (4th source) — refactor plan

**Status:** PLANNED — not started.
**Last commit before this plan:** `6f44091e` (ip4/ip6 Protocol Unreachable, SHOULD #1).
**Suite state at planning time:** 8825 passing / 4 skipped, lint clean.

---

## Goal

Convert ICMP feed into `TcpSession` from direct method calls
(`on_unreachable`, `on_time_exceeded`, `on_parameter_problem`,
`on_pmtu`) into a 4th FSM dispatch source — peer with the
existing **segment**, **syscall**, and **timer** sources. After
the refactor, ICMP events route through `tcp_fsm(icmp=event)` and
are handled by per-state `handle_icmp(session, event)` functions
in each `tcp__fsm__<state>.py` module.

This refactor also closes SHOULD #3 (RFC 5927 §6 hard-vs-soft
error semantics) naturally — each per-state handler decides what
"hard" means in its state.

## Why now (before more SHOULDs)

1. Each new `on_*`-style call site we add (Param Problem
   generation #2, future MSG_ERRQUEUE delivery, etc.) becomes
   another spot to refactor later. Pay the cost once now while
   the surface is small (4 methods × 6-8 call sites).
2. SHOULD #3 is *literally what this refactor naturally produces*
   — doing them together is cheaper than separately.
3. Architectural consistency: TCP has 3 dispatch sources today;
   ICMP is a peer input class. Promoting it aligns the model.

## Current state (pre-refactor)

ICMP feeds in via direct methods on `TcpSession`:

| Method | File | Triggered from | Behavior |
|---|---|---|---|
| `on_unreachable(icmp_type, icmp_code)` | `pytcp/protocols/tcp/tcp__session.py:799` | `packet_handler__icmp[46]__rx.py` Dest-Unreachable demux | Sets `_connection_error`, releases blocked syscalls; SYN_SENT + Code 3 (Port) aborts to CLOSED |
| `on_time_exceeded(icmp_type, icmp_code)` | `tcp__session.py:746` | β.2 / β.4 Time Exceeded demux | Logs only (RFC 5927 §6 soft) |
| `on_parameter_problem(icmp_type, icmp_code)` | `tcp__session.py:776` | β.3 / β.5 Param Problem demux | Logs only (RFC 5927 §6 soft) |
| `on_pmtu(next_hop_mtu, ip_version)` | `tcp__session.py:768` | Frag-Needed (v4) / PTB (v6) | Updates `_win.snd_mss`, writes `stack.pmtu_cache` |

Per-state logic is currently **inlined** in these methods:
`on_unreachable` does `if self._state is FsmState.SYN_SENT`. This
works but doesn't factor through the per-state FSM modules.

Helper that stays put: `is_seq_in_window(seq)` — used by RX
handlers BEFORE dispatching, not part of FSM.

## Target state (post-refactor)

Naming follows the existing `UdpMetadata` / `RawMetadata`
convention (`pytcp/socket/udp__metadata.py`,
`pytcp/socket/raw__metadata.py`) — the dataclass that flows from
the packet handler to the upper-layer consumer is suffixed
`Metadata`. ICMP-into-TCP-FSM follows the same shape: the
metadata describes a normalized inbound ICMP event, and the FSM
is its consumer. The file lives next to the FSM that consumes
it, under `pytcp/protocols/tcp/`.

```python
# pytcp/protocols/tcp/tcp__icmp_metadata.py (new)
class IcmpCategory(IntEnum):
    DEST_UNREACHABLE = 1
    TIME_EXCEEDED    = 2
    PARAM_PROBLEM    = 3
    PMTU             = 4

@dataclass(frozen=True, kw_only=True, slots=True)
class IcmpMetadata:
    category:      IcmpCategory
    icmp_type:     int
    icmp_code:     int
    pointer:       int | None  = None  # PARAM_PROBLEM v6 only (32-bit)
    next_hop_mtu:  int | None  = None  # PMTU only
    ip_version:    int                 # 4 or 6 (relevant for PMTU floor)
```

```python
# Dispatch:
session.tcp_fsm(icmp=IcmpMetadata(category=IcmpCategory.DEST_UNREACHABLE,
                               icmp_type=3, icmp_code=3, ip_version=4))

# Per-state handler (one per state file):
# pytcp/protocols/tcp/fsm/tcp__fsm__syn_sent.py
def handle_icmp(session: "TcpSession", metadata: IcmpMetadata) -> None:
    """SYN_SENT: hard-error (Port Unreachable) aborts; soft-errors diagnostic."""
    if event.category is IcmpCategory.DEST_UNREACHABLE and event.icmp_code == 3:
        session._connection_error = ConnError.REFUSED
        session._event__rx_buffer.set()
        session._event__connect.release()
        session._change_state(FsmState.CLOSED)
        return
    if event.category is IcmpCategory.DEST_UNREACHABLE and event.icmp_code == 1:
        session._connection_error = ConnError.HOST_UNREACHABLE
        session._event__rx_buffer.set()
        session._event__connect.release()
        return
    # ... etc
    # All other categories are soft per RFC 5927 §6 — log only.
```

## Phasing

### Phase 1 — additive shim (no behavioral change)

**Commit subject:** `tcp: add IcmpMetadata + tcp_fsm(icmp=...) additive dispatch`

**New files:**
- `pytcp/protocols/tcp/tcp__icmp_metadata.py` — `IcmpMetadata` dataclass + `IcmpCategory` enum
- `pytcp/tests/unit/protocols/tcp/test__tcp__icmp_metadata.py` — dataclass invariants

**Modified files:**
- `pytcp/protocols/tcp/fsm/tcp__fsm.py` — `tcp_fsm()` signature: add `icmp: IcmpMetadata | None = None  # follows UdpMetadata / RawMetadata convention`
- `pytcp/protocols/tcp/fsm/tcp__fsm.py` — top of dispatch: if `icmp is not None`, call `_dispatch_icmp(icmp)`
- `_dispatch_icmp` (new internal): for now, translates back to existing `on_*` calls. This keeps the additive contract — both old API and new API work.

**Exit criteria:**
- `tcp_fsm(icmp=...)` accepts events and produces same behavior as direct `on_*` calls
- All existing tests still pass (no migration yet)
- ~150-250 LOC

### Phase 2 — per-state `handle_icmp` modules + hard/soft refactor

**Commit subject:** `tcp/fsm: factor ICMP handling into per-state modules (closes RFC 5927 §6)`

**Modified files:**
- `pytcp/protocols/tcp/fsm/tcp__fsm__listen.py` — add `handle_icmp` (essentially no-op; nothing to abort)
- `pytcp/protocols/tcp/fsm/tcp__fsm__syn_sent.py` — hard error → ConnError + CLOSED
- `pytcp/protocols/tcp/fsm/tcp__fsm__syn_rcvd.py` — RFC 9293: ICMP errors are advisory
- `pytcp/protocols/tcp/fsm/tcp__fsm__established.py` — soft errors only; PMTU = update MSS
- `pytcp/protocols/tcp/fsm/tcp__fsm__fin_wait_1.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm__fin_wait_2.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm__close_wait.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm__closing.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm__last_ack.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm__time_wait.py` — soft only
- `pytcp/protocols/tcp/fsm/tcp__fsm.py` — `_dispatch_icmp` routes to per-state `handle_icmp` instead of legacy `on_*`

**RFC 5927 §6 hard-vs-soft taxonomy applied:**
- **Hard** (per RFC 5927 §6): Dest-Unreachable codes 0 (Net), 1 (Host), 3 (Port — but only in SYN_SENT), Time-Exceeded code 0 in SYN_SENT (RFC 5927 §6.1.5).
- **Soft** (everything else): Dest-Unreachable codes 2/4/5/etc., Time-Exceeded in synchronized states, Parameter Problem.
- **Hard error in SYN_SENT** → abort. **Hard error in synchronized state** → discard (RFC 5927 §3, RFC 1122 §4.2.3.9).
- **PMTU** is special: not "hard" or "soft" — it's an MSS-update event, applicable in any synchronized state.

**New unit tests** (one file per FSM state for `handle_icmp`):
- `pytcp/tests/unit/protocols/tcp/fsm/test__tcp__fsm__syn_sent__handle_icmp.py`
- ... etc per state, covering hard/soft/PMTU paths

**Exit criteria:**
- All existing integration tests for `on_unreachable` / `on_time_exceeded` etc. still pass (Phase 1 shim still in place)
- New per-state unit tests pin the hard-vs-soft semantics
- rfc1122 §3.2.2.1 "Code 0/1/5 hint-not-proof" audit entry: **partial** → **met**
- rfc1122 §3.2.2.4 §3.2.2.5 audits gain test references for per-state behavior
- ~600-800 LOC

### Phase 3 — migrate packet handlers + tests to `tcp_fsm(icmp=...)`

**Commit subject:** `icmp: route ICMP errors through tcp_fsm(icmp=...) dispatch`

**Modified files:**
- `pytcp/stack/packet_handler/packet_handler__icmp4__rx.py` — replace `socket._tcp_session.on_unreachable(...)` with `socket._tcp_session.tcp_fsm(icmp=IcmpMetadata(...))` (5 call sites: dest-unreachable, time-exceeded, param-problem, pmtu — × the dispatch_tcp helpers)
- `pytcp/stack/packet_handler/packet_handler__icmp6__rx.py` — same (5 call sites)
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_unreachable.py` — rename to `test__tcp__session__icmp__dest_unreachable.py`, drive via `tcp_fsm(icmp=...)`
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_time_exceeded.py` — rename to `..__icmp__time_exceeded.py`, drive via FSM
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_time_exceeded__ip6.py` — same
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_parameter_problem.py` — same
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_parameter_problem__ip6.py` — same

**Exit criteria:**
- All ICMP→TCP integration tests routing through FSM dispatch
- No remaining caller of `on_unreachable` / `on_time_exceeded` / `on_parameter_problem` / `on_pmtu` outside the Phase 1 shim
- ~400-600 LOC churn

### Phase 4 — delete the `on_*` legacy methods

**Commit subject:** `tcp/session: drop legacy on_* ICMP methods (now go through FSM)`

**Modified files:**
- `pytcp/protocols/tcp/tcp__session.py` — delete `on_unreachable`, `on_time_exceeded`, `on_parameter_problem`, `on_pmtu`
- `pytcp/protocols/tcp/fsm/tcp__fsm.py` — `_dispatch_icmp` no longer needs the legacy fallback; pure per-state dispatch
- `pytcp/tests/unit/protocols/tcp/test__tcp__session__lifecycle.py` (or similar) — drop any tests that referenced the legacy methods directly

**Exit criteria:**
- `grep -r 'on_unreachable\|on_time_exceeded\|on_parameter_problem\|on_pmtu' pytcp net_proto` returns empty
- ~50-150 LOC deletion
- Audit refresh: rfc1122 §3.2.2.4/.5 audit calls explicitly cite the per-state handler files

## File-level migration map

| Old API call | New API call |
|---|---|
| `session.on_unreachable(icmp_type=3, icmp_code=3)` | `session.tcp_fsm(icmp=IcmpMetadata(category=IcmpCategory.DEST_UNREACHABLE, icmp_type=3, icmp_code=3, ip_version=4))` |
| `session.on_time_exceeded(icmp_type=11, icmp_code=0)` | `session.tcp_fsm(icmp=IcmpMetadata(category=IcmpCategory.TIME_EXCEEDED, icmp_type=11, icmp_code=0, ip_version=4))` |
| `session.on_parameter_problem(icmp_type=12, icmp_code=0)` | `session.tcp_fsm(icmp=IcmpMetadata(category=IcmpCategory.PARAM_PROBLEM, icmp_type=12, icmp_code=0, pointer=20, ip_version=4))` |
| `session.on_pmtu(next_hop_mtu=1280, ip_version=4)` | `session.tcp_fsm(icmp=IcmpMetadata(category=IcmpCategory.PMTU, icmp_type=3, icmp_code=4, next_hop_mtu=1280, ip_version=4))` |

## Test surface implications

After Phase 4:
- ~22 tests across the 4 ICMP integration files migrate to FSM dispatch
- ~10-15 new per-state unit tests (one per state × hard/soft cases)
- The `is_seq_in_window` helper stays public on `TcpSession` (used by RX BEFORE dispatch)
- `_connection_error`, `_change_state` access pattern unchanged

## Audit refresh points

- `docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`
  - §3.2.2.1 "Code 0/1/5 hint-not-proof": partial → met (Phase 2)
  - §3.2.2.4 / §3.2.2.5 audit's per-state handler refs (Phase 4)
- `docs/rfc/tcp/rfc5927__icmp_tcp_attacks/adherence.md` (cross-link from icmp4/)
  - §6 hard-vs-soft: explicitly walked per-state (Phase 2)
- `docs/rfc/tcp/rfc1122__host_requirements/adherence.md`
  - §4.2.3.9 (TCP MUST react to ICMP) updated with FSM dispatch references (Phase 4)
- `pytcp/protocols/tcp/tcp__session.py` docstring update (Phase 4)

## Risk register

| Risk | Mitigation |
|---|---|
| Phase 1's "shim" temporarily duplicates the dispatch logic | Phase 4 deletes the legacy path; suite-green throughout |
| Per-state handlers proliferate boilerplate | Many states share "all soft, just log" — extract a default helper |
| Test fixture migration breaks 8825-test baseline | One commit per phase; full `make test && make lint` between |
| `pmtu_cache` writes need to stay outside FSM (process-wide) | `handle_icmp` for PMTU writes the global cache, then mutates `_win.snd_mss` |
| `_event__rx_buffer.set()` / `_event__connect.release()` are per-session | Passed via `session` argument to `handle_icmp`, no change in semantics |

## Estimated scope

- 4 commits
- ~1500-2200 LOC total (source + tests)
- Phase 1: 1-2 hours
- Phase 2: 3-4 hours (most work — per-state handlers + tests)
- Phase 3: 2 hours
- Phase 4: 30 min (deletion + audit polish)

## Cross-references

- Current ICMP audit: `docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`
- RFC 5927 audit (TCP-side): `docs/rfc/tcp/rfc5927__icmp_tcp_attacks/`
- TCP improvement plan: `docs/refactor/tcp_codebase_improvement_plan.md`
- Prior refactor (ICMP demux + PMTUD): `docs/refactor/icmp_demux_pmtud_plan.md`
- Auto-memory commitment: `feedback_audit_in_lockstep_with_code` — every audit refresh in same commit as code

## Resume prompt (after compaction)

> Continue the ICMP→TCP-FSM-dispatch refactor per
> `docs/refactor/icmp_into_tcp_fsm_plan.md`. We're starting with
> Phase 1 (additive `tcp_fsm(icmp=...)` shim that translates back
> to the existing `on_*` methods). Tests-first: build
> `IcmpMetadata` + dataclass tests, then extend the `tcp_fsm`
> signature, run lint+suite, commit. Then proceed phase by phase.
> Last commit before this work: `6f44091e`. Current suite: 8825
> passing / 4 skipped.
