# PyTCP — Integration Test Authoring Rule

This rule codifies how integration tests are written in PyTCP.
The companion rule [`unit_testing.md`](unit_testing.md) covers
test-file conventions that apply to **every** test (file
skeleton, docstring shape, mocking discipline §6a, isolation
§10a, modern Python features §10b, the §7.2 docstring audit).
This rule covers what is **specific to integration tests** —
the test-harness hierarchy on top of `unittest.TestCase`, how
to drive RX frames into the stack, how to capture and decode
TX frames the stack emits, and how to assert on the resulting
wire-level + stat-counter observable state.

Unit-test rules continue to apply unless overridden here. When
the two rules disagree, this rule wins for files under
`packages/pytcp/pytcp/tests/integration/...`.

---

## 1. Scope — integration vs. unit

| Layer | Path | What it covers |
|---|---|---|
| **Unit** | `<pkg>/tests/unit/...` | Pure-function helpers, dataclass invariants, parser/assembler wire format, header asserts. Imports the SUT in isolation; mocks every dependency. |
| **Integration** | `packages/pytcp/pytcp/tests/integration/...` | FSM transitions, multi-segment wire-level interactions, timer-driven behaviour, packet-handler RX/TX paths, socket-API plumbing. Constructs the real `PacketHandler`; mocks only the OS-facing edges (`TxRing` for outbound bytes, `ArpCache` / `NdCache` for resolution). |

Integration tests verify **observable behaviour across module
boundaries** — what the stack actually emits when given an
inbound frame, what counters it updates, what state it
transitions through. They are the canonical pin for
RFC-conformance work on transport / network protocols (TCP
FSM, ICMP demux, ND lifecycle, ARP resolution, fragment
reassembly).

When in doubt: if the test would still be meaningful without
the `PacketHandler` instance, write a unit test. If you need
to assert "what frames went out the wire after I fed in this
RX frame," write an integration test.

## 2. Framework and toolchain

Integration tests use the same toolchain as unit tests
(unit_testing.md §1):

- Native `unittest.TestCase` (no `pytest`, no `testslide`).
- `parameterized_class` for parametric matrices.
- Python 3.14+ floor — same modern-Python feature rules
  apply ([`python_features.md`](python_features.md)).
- mypy strict on every test file.
- `make lint` is the gate; `make test` is the run.
- Mocks are strict — `create_autospec(Cls, spec_set=True)`
  for owned mocks, `patch(..., autospec=True, spec_set=True)`
  for context-managed patches. See `unit_testing.md §6a` —
  the rule is identical, integration tests don't get a pass.

## 3. File structure and placement

**Canonical pattern (memorise this).** Integration tests
live under `packages/pytcp/pytcp/tests/integration/`. Per-handler smoke
tests sit at the integration root; mechanism-focused tests
sit under `protocols/<proto>/` mirroring the source tree:

```
SOURCE                                                     TEST
─────────────────────────────────────────────────          ──────────────────────────────────────────────────────────────────────────
packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py   →  packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip6__tx.py
packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py   →  packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py
packages/pytcp/pytcp/protocols/icmp6/nd/nd__cache.py                   →  packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__<mechanism>.py
packages/pytcp/pytcp/protocols/tcp/tcp__session.py                     →  packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__<scenario>.py
packages/pytcp/pytcp/socket/tcp__socket.py                             →  (driven via TcpSessionTestCase under protocols/tcp/...)
RFC 6724 IPv6 source-address selection                  →  packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py
```

Every test directory is a regular package: an empty
`__init__.py` lives at every level. Matches the rest of
the codebase (see [`source_files.md`](source_files.md) §2.4).

### 3.1 Where files live

| Source area | Test path |
|---|---|
| `packages/pytcp/pytcp/runtime/packet_handler/<file>.py` (per-protocol RX/TX handler) | `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<proto>__<rx\|tx>.py` |
| `packages/pytcp/pytcp/protocols/<proto>/<file>.py` (protocol runtime — FSM, caches) | `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<proto>__<scenario>.py` |
| Cross-cutting RFC mechanism that spans handler + protocol | `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<proto>__<rfc-mechanism>.py` |
| Socket-API behaviour | integration cases via `TcpSessionTestCase` under `packages/pytcp/pytcp/tests/integration/protocols/tcp/...` |

The `packages/pytcp/pytcp/tests/integration/` tree mirrors the source tree
where the line is clean. The per-handler tests
(`test__packet_handler__<proto>__<rx|tx>.py`) sit at the
integration root because they're the smoke-test surface for
the whole packet-handler graph, not a single protocol.

### 3.2 File-level skeleton

Integration test files are library modules — no shebang, no
executable bit. The skeleton:

1. 80-char `#`-bordered copyright/license block on line 1.
2. Module docstring (description + repo-relative path + `ver 3.0.x`).
3. Imports — stdlib → `parameterized` → local packages
   (`net_addr`, `net_proto`, `pytcp`). Multi-import from one
   module uses parentheses, never backslash continuation.
4. Module-level constants (frame fixtures, builder helpers).
5. `TestCase` classes (subclassing the appropriate harness
   per §4).

No `__all__`. No `if __name__ == "__main__":`. No
`from __future__ import annotations` and no `TYPE_CHECKING`
guard unless the file has a genuine circular import.

### 3.3 File naming

| Source artefact | Test filename pattern |
|---|---|
| `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__<proto>__rx.py` | `test__packet_handler__<proto>__rx.py` |
| `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__<proto>__tx.py` | `test__packet_handler__<proto>__tx.py` |
| RFC-mechanism focus on a protocol | `test__<proto>__<rfc-mechanism>.py` (e.g. `test__icmp6__nd__optimistic_dad.py`) |
| TCP session scenarios | `test__tcp__session__<scenario>.py` (e.g. `test__tcp__session__handshake__passive.py`) |
| ICMP demux behaviour | `test__icmp<4\|6>__<scenario>.py` |
| ARP wire-level RX/TX | `test__packet_handler__arp__<rx\|tx>.py` for the per-handler smoke; per-mechanism files under `packages/pytcp/pytcp/tests/integration/protocols/arp/` |

Class names: `TestPacketHandler<Proto><RxTx>__<Scenario>`
(e.g. `TestPacketHandlerEthernetTxIp6Lookup`) or
`Test<Proto>__<Mechanism>` for the protocol-focus files
(e.g. `TestIcmp6Nd__OptimisticDad__StateLifecycle`).

Method names: `test__<proto>__<scenario>__<aspect>` (e.g.
`test__ip6__rfc6724_rule2__global_dst_picks_global_source`)
— the leading `test__<proto>` is mandatory so the audit
script can identify which protocol family the method tests.

## 4. Harness hierarchy

```
unittest.TestCase
└── NetworkTestCase             (packages/pytcp/pytcp/tests/lib/network_testcase.py)
    │   ├── mock TxRing / ArpCache / NdCache (create_autospec, spec_set=True)
    │   ├── pre-populated routing table (STACK / HOST_A / HOST_B / HOST_C / ROUTER)
    │   ├── stack.__dict__ snapshot+restore for LOG__CHANNEL, *_SUPPORT, MTU sysctls
    │   ├── deterministic IPv6 frag-id counter
    │   └── self._packet_handler = PacketHandlerL2(...)
    │
    ├── IcmpTestCase            (packages/pytcp/pytcp/tests/lib/icmp_testcase.py)
    │   │   Adds: FakeTimer over stack.timer + snapshot of
    │   │   stack.sockets / stack.tcp_stack / stack.pmtu_cache /
    │   │   icmp4_error_rate_limiter / icmp6_error_rate_limiter
    │   │   ICMP probe parsers, fluent _assert_icmp4/6_message,
    │   │   _drive_rx, _advance, _start_patch, _assert_no_tx,
    │   │   _assert_packet_stats_rx / _tx
    │   │
    │   └── NdTestCase          (packages/pytcp/pytcp/tests/lib/nd_testcase.py)
    │           Adds: ND-specific frame builders, NA-driven
    │           cache-entry installers, RA / NS / NA helpers.
    │
    ├── ArpTestCase             (packages/pytcp/pytcp/tests/lib/arp_testcase.py)
    │       Adds: time.monotonic patching for ARP-FSM timer
    │       tests, ARP frame builders, ARP-Request /
    │       Gratuitous-ARP / DAD drivers.
    │
    └── TcpSessionTestCase      (packages/pytcp/pytcp/tests/lib/tcp_session_testcase.py)
            Adds: TCP-specific _drive_rx / _advance / _assert_segment,
            TCP segment factory, FSM-aware state assertions.
```

**Pick the harness whose surface matches the SUT's protocol
family.** If you find yourself adding helpers to a more-
general harness (e.g. adding ICMP-specific assertions to
`NetworkTestCase`), promote them to the specific harness
instead.

When a new RFC-mechanism needs a harness that doesn't exist
(e.g. a new transport protocol), build a fresh subclass of
the closest existing one — never inline the
mock-construction + snapshot/restore boilerplate in the test
file itself.

## 5. The harness contract

Every integration test starts from a harness `setUp` that
guarantees the following invariants. **Do not bypass them.**

### 5.1 What `NetworkTestCase.setUp` gives you

- `self._packet_handler: PacketHandlerL2` — a real packet
  handler whose `_ip4_ifaddr` / `_ip6_ifaddr` / `_mac_unicast` /
  `_ip4_multicast` / `_ip6_multicast` are pre-populated to
  the canonical fixture topology (see the ASCII diagrams at
  the top of `network_testcase.py`):
    - `STACK` = 10.0.1.7 / 2001:db8:0:1::7 with MAC
      02:00:00:00:00:07
    - `HOST_A` = on-link, ARP/ND cache hit
    - `HOST_B` = on-link, ARP/ND cache miss
    - `HOST_C` = off-link via router, gateway cache hit
    - `ROUTER_B` = ND cache miss (negative-test target)
- `self._frames_tx: list[bytes]` — every frame the stack
  emits via the mocked `TxRing.enqueue` gets recorded here.
  Tests assert on the contents.
- `stack.tx_ring` / `stack.arp_cache` / `stack.nd_cache` —
  replaced with `create_autospec(..., spec_set=True)` mocks
  configured to return pre-table values on lookup. Unknown
  keys **raise** (`AssertionError`), so a test that triggers
  an unexpected resolution sees the failure loudly rather
  than silently returning `None`.

### 5.2 What `NetworkTestCase.tearDown` cleans up

- Restores `stack.__dict__` for the patched globals
  (`LOG__CHANNEL`, `IP6__SUPPORT`, `IP4__SUPPORT`, etc.).
- Stops the deterministic frag-id patch.
- The mocks are auto-cleaned by the test process exiting —
  but the module-level state on `stack` MUST be restored for
  the next test to see clean state.

### 5.3 What `IcmpTestCase.setUp` additionally gives you

- `self._timer: FakeTimer` — deterministic clock substitute
  for `stack.timer`. Use `self._advance(ms=N)` to step it.
- `stack.sockets` cleared (snapshot restored on tearDown).
- `stack.tcp_stack` replaced with a fresh `TcpStack` instance.
- `stack.pmtu_cache` cleared.
- Both ICMP error rate limiters replaced with fresh instances
  so each test starts with a full burst quota.
- `self._patches: list` — slot for `_start_patch(target, new)`
  to register per-test patches; all auto-stopped in `tearDown`.

### 5.4 Adding module-level state to `packages/pytcp/pytcp/stack/__init__.py`

**MANDATORY** — any commit that adds a new module-level
attribute to `packages/pytcp/pytcp/stack/__init__.py` MUST update the
relevant testcase's `setUp` / `tearDown` to snapshot and
restore the attribute. The "passes-alone, fails-in-suite"
bug class this rule prevents:

```python
# Bad pattern that this rule catches:
# 1. Test A calls stack.init() which mutates stack.foo
# 2. Test B runs after A and sees the leaked value
# 3. Test B passes in isolation (no init() happened) but
#    fails in suite (A's mutation leaked).
```

Without snapshot/restore in the harness, the leak is silent.
For new attributes on `stack`, extend the relevant harness'
`_*_prior` slot pattern (see `IcmpTestCase.setUp` for the
canonical example with `sockets_prior`, `tcp_stack_prior`,
`pmtu_cache_prior`, error-rate-limiter priors).

The same rule applies to `pytcp.stack.sysctl` keys — but the
registry exposes `sysctl_module.reset_to_defaults()` as the
canonical restore, which the harness `tearDown` should call
for any test that overrode a sysctl.

## 6. Driving RX (inbound frames)

The canonical RX entry point is `self._drive_rx(frame=...)`
on `IcmpTestCase` / `TcpSessionTestCase`. It feeds the frame
into `PacketHandler._phrx_ethernet` and returns a list of TX
frames the stack produced **as a direct result of that
single RX**:

```python
# Good
tx_frames = self._drive_rx(frame=self._build_ns_frame(
    target_address=STACK__IP6_HOST.address,
    source_address=HOST_A__IP6_ADDRESS,
    source_mac=HOST_A__MAC_ADDRESS,
))

self.assertEqual(
    len(tx_frames),
    1,
    msg="NS for our owned address must elicit one NA reply.",
)
```

### 6.1 Frame construction

Frames go in as raw `bytes`. The harness or the test file
provides builders:

- **Per-protocol builders on the harness.** `ArpTestCase`
  exposes `_build_arp_frame(...)`. `NdTestCase` exposes ND
  message builders. Use them when they exist.
- **Assembler chaining.** When no harness builder fits,
  construct via the production assemblers and serialise:
  ```python
  ip6_packet = Ip6Assembler(
      ip6__src=HOST_A__IP6_ADDRESS,
      ip6__dst=STACK__IP6_HOST.address,
      ip6__payload=tcp_segment,
  )
  eth_frame = EthernetAssembler(
      ethernet__src=HOST_A__MAC_ADDRESS,
      ethernet__dst=STACK__MAC_ADDRESS,
      ethernet__payload=ip6_packet,
  )
  buffers: list[Buffer] = []
  eth_frame.assemble(buffers)
  frame_bytes = b"".join(buffers)
  ```
- **Hand-built byte fixtures.** Acceptable when the test
  needs to exercise wire-format edge cases (malformed
  options, intentional integrity violations) that the
  assembler refuses to produce. Hand-built frames MUST carry
  the field-by-field annotation comment per
  `unit_testing.md §5`.

Per-test frame builders that don't belong on a harness go
into module-level helpers near the top of the test file:

```python
def _ethernet_ip6(*, ip6_payload: object, ip6_next: IpProto = IpProto.RAW) -> bytes:
    """Wrap any IPv6 assembler-style payload in Ethernet/IPv6 framing."""
    ...
```

### 6.2 Advancing the virtual clock

Timer-driven behaviour (retransmits, RTOs, DAD probes, NUD
state transitions) is exercised via `self._advance(ms=N)`.
The harness installs a `FakeTimer` over `stack.timer` in
`setUp`, so `time.monotonic()` reads inside the SUT return
a controlled value:

```python
# Drive the initial probe
self._drive_rx(frame=ra_with_pi)
tx = self._advance(ms=100)
self.assertEqual(len(tx), 1, msg="Initial DAD probe must fire.")

# Drive the retransmit
tx = self._advance(ms=nd_const.ICMP6__RETRANS_TIMER)
self.assertEqual(len(tx), 1, msg="Second DAD probe must fire after RetransTimer.")
```

**MUST NOT** use real `time.sleep()` or wall-clock
`time.monotonic()` in integration tests
(`unit_testing.md §10a.1`).

## 7. Capturing TX (outbound frames)

The harness records every outbound frame the stack emits via
the mocked `TxRing.enqueue`. Three observation surfaces:

### 7.1 `self._frames_tx` — the global slot

`NetworkTestCase` appends every emitted frame here. Useful
for "did the stack ever emit X" assertions and for the
`_assert_no_tx()` invariant check:

```python
self._assert_no_tx()  # nothing emitted since last drain
```

### 7.2 `_drive_rx` / `_advance` return value — the delta

Both `_drive_rx` and `_advance` snapshot `len(self._frames_tx)`
on entry and return only the frames emitted between then and
their return. **Prefer the return value** for per-action
assertions; reach into `self._frames_tx` only when you need
to inspect frames across multiple actions:

```python
# Good
tx = self._drive_rx(frame=...)
self.assertEqual(len(tx), 2, msg="Expected NA reply + gratuitous NA.")

# Avoid
self._drive_rx(frame=...)
self.assertEqual(len(self._frames_tx), 2, ...)  # depends on prior state
```

### 7.3 Parsing TX back into a probe

Hand-comparing raw bytes against a golden buffer is
**forbidden** for new integration tests. The canonical
pattern is:

1. Drive RX → get TX frames back.
2. Parse each TX frame back into a typed probe dataclass via
   `self._parse_tx_<proto>(frame)`.
3. Assert on probe fields via fluent `_assert_<proto>_message(probe, **expected)`.

```python
# Good — probe + fluent assert
tx = self._drive_rx(frame=ns_frame)
probe = self._parse_tx_icmp6(tx[0])
self._assert_icmp6_message(
    probe,
    type=Icmp6Type.ND_NEIGHBOR_ADVERTISEMENT,
    target=STACK__IP6_HOST.address,
    ip_src=STACK__IP6_HOST.address,
    ip_dst=HOST_A__IP6_ADDRESS,
    ip_hop=255,
    eth_src=STACK__MAC_ADDRESS,
    eth_dst=HOST_A__MAC_ADDRESS,
)
```

Failure modes the probe pattern catches that byte-comparison
hides:

- The test passes for the wrong reason (e.g. a flag bit
  changed but the test only checked the message type).
- The error message points at the failing field
  (`Unexpected ICMPv6 ND target on outbound message`) rather
  than at "bytes don't match" with a 200-byte hex diff.
- The test survives wire-format additions (a new option in
  the message doesn't break unrelated assertions).

`_assert_*_message` uses a `_UNSET` sentinel for every
field — fields the test doesn't care about are simply not
passed. Pass `None` explicitly to assert that an optional
field IS absent.

### 7.4 When a hand-built golden byte buffer is appropriate

- The test is specifically asserting the **wire format**
  (e.g. "options must serialise in this exact order").
- The test exercises a corner case the assembler can't
  produce (intentional integrity violation).
- The test is in the per-handler smoke files
  (`test__packet_handler__<proto>__<rx|tx>.py`) where the
  established convention is parametrized golden frames with
  field-by-field annotations.

Even in those cases, the golden byte buffer MUST carry the
field-by-field annotation comment per `unit_testing.md §5`.

## 8. Stat-counter assertions

Every packet handler maintains per-protocol counters on
`packet_handler.packet_stats_rx` / `.packet_stats_tx`
(dataclasses with one `int` field per counter). Integration
tests assert on these as the secondary observable — every
RX path that takes a particular branch bumps a specific
counter, and every TX-side decision likewise.

The canonical helper is `_assert_packet_stats_rx(...)` /
`_assert_packet_stats_tx(...)` on `IcmpTestCase` /
`TcpSessionTestCase`:

```python
# Good — exact (every unspecified counter MUST be zero)
self._assert_packet_stats_rx(
    icmp6__pre_parse=1,
    icmp6__nd__neighbor_solicitation=1,
    icmp6__nd__neighbor_solicitation__reply=1,
)
```

The `exact=True` default (omit the kwarg) pins the *absence*
of side-effect counters — any counter not in the kwargs
must be zero. This is mandatory for new tests because the
strict default mirrors the byte-equality regression net of
the legacy parametrized tests; loose checks let a regression
that bumps an unrelated counter slip through.

`exact=False` is only acceptable when the test is genuinely
running multiple operations and only cares about the named
counters. Document the choice in the docstring.

## 9. Test method docstrings

**Canonical shape (memorise this).** Every test method has
a docstring with exactly three parts in this order:

```python
def test__icmp6__nd__optimistic__na_clears_override_flag(self) -> None:
    """
    Ensure a Neighbor Advertisement emitted while the
    source address is in the OPTIMISTIC state has the
    Override (O) flag cleared so peers do not overwrite an
    existing cache entry on the basis of an unverified
    address.

    Reference: RFC 4429 §3.3 (Override flag clearing while OPTIMISTIC).
    """
```

The three parts:

1. **Description**, opening word `Ensure`, stating the
   behavioural guarantee from the caller's perspective.
2. **Blank line.**
3. **One `Reference:` line per cited RFC clause** in the form
   `Reference: RFC <number> §<section> (<short description>).`

Rules (each MUST / MUST NOT, not SHOULD):

- The description describes *what* is guaranteed, never
  *how* the test exercises it.
- **MUST NOT** put RFC citations inline in the description
  (`"Per RFC X §Y ..."`, `"RFC X §Y figure N"`, etc.). The
  trailing `Reference:` line is the canonical citation;
  duplicating it inline is the exact failure mode this
  rule prevents.
- **MUST** include a `Reference:` line. Pure plumbing tests
  with no RFC clause use one of the two acceptable fallback
  citations:
    - `Reference: PyTCP test infrastructure (no RFC clause).`
    - `Reference: RFC 9293 §3.9 (User/TCP interface).`
      (for socket-API plumbing).
- A test that pins behaviour from multiple RFCs uses one
  `Reference:` line per clause, in citation-precedence
  order (RFC 9293 over 793, etc.):
    ```python
    Reference: RFC 9293 §3.10.7.4 (R2 abort emits RST).
    Reference: RFC 1122 §4.2.3.5 (R2 ≥ 100 s retransmit abort).
    ```
    **MUST NOT** bundle multiple citations into a single
    `Reference:` line — each clause gets its own line so
    the citation stays greppable.
- **MUST NOT** leave `[FLAGS BUG]` markers in committed
  docstrings.

Class docstrings are a single noun phrase (e.g.
`"The IPv6 ND optimistic-DAD optimistic-path tests."`).
Class-level docstrings MAY contain RFC references; this
rule applies only to test-method docstrings.

### 9.1 Pre-commit self-audit (MANDATORY)

Run this audit against every integration-test file you write
or modify, before staging the commit. Any non-empty output
is a blocker:

```bash
python3 << 'EOF'
import re, sys
from pathlib import Path

FILES = [
    "packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<...>.py",
    # ... list every integration-test file you wrote or modified.
]

violations = []
for path in FILES:
    text = Path(path).read_text()
    for m in re.finditer(
        r'def (test__\w+)\(self\) -> None:\s*\n\s*"""(.*?)"""',
        text, re.DOTALL,
    ):
        name, body = m.group(1), m.group(2)
        if "Reference:" not in body:
            violations.append(f"{path}::{name} — missing 'Reference:' line")
        if not re.search(r'^\s+Ensure ', body):
            violations.append(f"{path}::{name} — must start with 'Ensure '")
        if "[FLAGS BUG]" in body:
            violations.append(f"{path}::{name} — contains '[FLAGS BUG]' marker")
        desc = re.sub(r'\n\s*Reference:.*', '', body, flags=re.DOTALL)
        for pat in (r'[Pp]er RFC \d', r'RFC \d+\s*§', r'RFC \d+\s+figure'):
            if re.search(pat, desc):
                violations.append(
                    f"{path}::{name} — inline RFC citation in description; "
                    f"pattern={pat!r}"
                )

for v in violations:
    print(v)
sys.exit(1 if violations else 0)
EOF
```

The four invariants the audit pins:

1. Every test method has a `Reference:` line.
2. Every description starts with `Ensure `.
3. No `[FLAGS BUG]` markers remain in committed test files.
4. No inline `Per RFC X §Y`, `RFC X §Y`, or `RFC X figure N`
   citation in the description text (the trailing
   `Reference:` line is the canonical home for the
   citation).

## 10. Mocking discipline in integration tests

`unit_testing.md §6a` applies in full. Specific reminders
for integration tests:

### 10.1 The harness owns the canonical mocks

`TxRing` / `ArpCache` / `NdCache` / `Timer` / `TcpStack` /
ICMP rate limiters are mocked **by the harness** with
`create_autospec(..., spec_set=True)`. Do not re-mock them
in your test file — the harness sets them up so every
integration test sees consistent fixtures.

If your test needs to override a single attribute on a
harness-owned mock (e.g. force a specific MAC for a
particular destination), mutate it directly:

```python
def test__custom_routing(self) -> None:
    """..."""

    # Override the canonical fixture for this one test.
    stack.nd_cache.find_entry.side_effect = lambda *, ip6_address: \
        SPECIAL_MAC if ip6_address == TARGET else None

    ...
```

Note: this leaks if not cleaned up. For multi-step tests
that need a custom side_effect, register a snapshot/restore
in `setUp` / `tearDown` of a subclass test class — don't
mutate harness state across test methods.

### 10.2 Forbidden patterns

- **Bare `MagicMock()`** in integration tests (same as unit
  tests).
- **Re-patching `stack.tx_ring`** in a test that uses
  `NetworkTestCase` — the harness already patched it.
  Mutate the existing mock instead.
- **Per-test `stack.init()` calls.** The harness installs
  the stack singletons via `stack.mock__init(...)` — calling
  `stack.init()` from a test body bypasses the
  snapshot/restore and breaks isolation.
- **Real `threading.Thread` / `time.sleep` in test bodies.**
  Use the `FakeTimer` virtual clock + `_advance(ms=)`. If a
  SUT spawns a daemon thread (e.g.
  `_claim_ip6_address_async`), patch the thread spawn or
  join it inline with a short timeout.

## 11. Parametric matrices

`@parameterized_class` works the same way as in unit tests
(`unit_testing.md §4`). The case-dict keys for integration
tests typically include:

```python
@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Request to stack IPv6 address.",
            "_rx_frame": <bytes>,            # the inbound frame
            "_expected__tx_frames": [...],   # OR _expected__probes
            "_expected__packet_stats_rx": PacketStatsRx(...),
            "_expected__packet_stats_tx": PacketStatsTx(...),
        },
        ...
    ]
)
class TestPacketHandlerIcmp6Rx(NetworkTestCase):
    _description: str
    _rx_frame: bytes
    _expected__tx_frames: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    def test__icmp6__rx__sends_expected_frames(self) -> None:
        """
        Ensure ...

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        self._packet_handler._phrx_ethernet(PacketRx(self._rx_frame))

        self.assertEqual(
            self._frames_tx,
            self._expected__tx_frames,
            msg=f"Unexpected TX frames for case: {self._description}",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected packet_stats_rx for case: {self._description}",
        )
```

Use parametric matrices for the per-handler smoke files
(test every entry-point branch once). Use the fluent probe +
`_assert_<proto>_message` pattern for new mechanism-focused
files (one test method per behaviour, no golden byte
buffers).

## 12. Forbidden patterns roundup

A single index of the integration-test-specific
anti-patterns this rule forbids. Unit-test anti-patterns
(`unit_testing.md §11`) apply identically.

| Anti-pattern | Replace with | Section |
|---|---|---|
| Hand-comparing TX bytes against a hex literal in a new mechanism-focused test | `_parse_tx_<proto>(tx[0])` + `_assert_<proto>_message(probe, ...)` | §7.3 |
| Re-mocking `stack.tx_ring` / `arp_cache` / `nd_cache` in a `NetworkTestCase` subclass | mutate the harness-owned mock | §10.1 |
| Calling `stack.init()` from a test body | rely on `stack.mock__init(...)` from harness | §10.2 |
| `time.sleep()` in a test body | `self._advance(ms=N)` against the FakeTimer | §6.2 |
| Real `threading.Thread` outliving the test | `self.addCleanup(thread.stop)` or patch the spawn | `unit_testing.md §10a.3` |
| Adding stack module state without snapshot/restore in the harness | extend the harness `setUp` / `tearDown` in the same commit | §5.4 |
| `exact=False` on `_assert_packet_stats_*` without justification | use the strict default; document if loose is necessary | §8 |
| Inheriting from `unittest.TestCase` directly for a packet-handler test | inherit from the protocol-appropriate harness | §4 |
| Frame builders inlined as multi-line byte literals inside test methods | hoist to module-level helpers near the top of the file | §6.1 |
| Inline RFC citations in test docstrings | trailing `Reference: RFC <n> §<s> (<desc>).` line | §9 |
| Per-test `stack.LOG__CHANNEL` enable for debugging — left in committed code | harness silences logs; revert before commit | `unit_testing.md §10a.4` |

## 13. Workflow

Same as `unit_testing.md §10`:

1. Read the source under test. Confirm which branches /
   handlers / counters exist.
2. Decide which harness fits (§4). If none fits, build a
   subclass — don't inline the boilerplate.
3. Draft the test file following this rule.
4. Run:
   ```bash
   python -m unittest <path/to/test_file>
   coverage run --source=<source> -m unittest <path/to/test_file>
   coverage report -m
   make lint
   ```
5. Run the §7.2 docstring audit on the new file
   (`unit_testing.md §7.2`).
6. Iterate until coverage is 100% on the target component
   and lint is clean.
7. Commit with a focused message; include the RFC clause(s)
   pinned in the body.
8. Push / sync before moving to the next file.

## 14. Reference implementations

When in doubt, mirror the structure of:

- **Per-handler smoke (parametric, golden frames):**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip6__tx.py`
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
- **Mechanism-focused (probe + fluent assert):**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__optimistic_dad.py`
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc8981_temp.py`
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py`
- **TCP FSM scenario:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__passive.py`
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py`
- **Harness sources** (read these when extending or
  subclassing):
  `packages/pytcp/pytcp/tests/lib/network_testcase.py` (base — TxRing /
  ArpCache / NdCache mocks, stack snapshot/restore, fixture
  topology)
  `packages/pytcp/pytcp/tests/lib/icmp_testcase.py` (FakeTimer + ICMP
  probes + fluent message assert)
  `packages/pytcp/pytcp/tests/lib/nd_testcase.py` (ND-specific builders)
  `packages/pytcp/pytcp/tests/lib/arp_testcase.py` (monotonic-clock
  patching, ARP frame builders, DAD drivers)
  `packages/pytcp/pytcp/tests/lib/tcp_session_testcase.py` (TCP segment
  factory, FSM-aware assertions)
  `packages/pytcp/pytcp/tests/lib/fake_timer.py` (the virtual clock itself)

These files are the canonical examples. Any deviation from
this rule should be justified by something that appears in
one of them — not by novel patterns introduced in a new
file.

## 15. Cross-references

- [`unit_testing.md`](unit_testing.md) — file-level test
  authoring rule. Applies to integration tests except where
  this rule overrides.
- [`unit_testing.md`](unit_testing.md) §7 — test-method
  docstring shape (`Ensure ...` + `Reference: ...`),
  applies identically.
- [`unit_testing.md`](unit_testing.md) §7.2 — the
  pre-commit self-audit script. Run it on every integration-
  test file you write or modify.
- [`unit_testing.md`](unit_testing.md) §6a — mocking
  discipline (`create_autospec(..., spec_set=True)`,
  `patch(..., autospec=True)`, no bare `MagicMock()`).
- [`unit_testing.md`](unit_testing.md) §10a — test isolation
  and determinism (no real time / network / threads
  leaking, module-state snapshot/restore).
- [`unit_testing.md`](unit_testing.md) §10b — modern Python
  features in tests (`@override` on setUp/tearDown,
  `enterContext`, walrus, etc.).
- [`python_features.md`](python_features.md) — Python
  language-feature rule. Test files are Python source and
  the rule applies.
- [`feature_implementation.md`](feature_implementation.md)
  — tests-first workflow. Integration tests are the
  canonical "spec-conformance pin" surface for RFC work.
- [`typing.md`](typing.md) — annotation discipline,
  generics, `Self`, `@override`. Test files are Python
  source; the typing rule applies.
- [`source_files.md`](source_files.md) — general PyTCP
  source-file conventions. Test files share the
  file-skeleton, copyright-block, and module-docstring
  conventions.
- [`net_addr.md`](net_addr.md),
  [`net_proto.md`](net_proto.md), and
  [`pytcp.md`](pytcp.md) — what the SUT looks like for each
  subpackage; read the relevant one when designing
  integration tests that exercise that subpackage's
  surface.
