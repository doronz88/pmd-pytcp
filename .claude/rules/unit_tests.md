# PyTCP — Unit Test Authoring Rule

This rule codifies how unit tests are written in PyTCP. It is distilled
from the tests under `net_addr/tests/unit/` and
`net_proto/tests/unit/protocols/` after they were rewritten to native
`unittest`. Every new test file in this project MUST follow it.

The rule covers: framework, file layout, naming, parameterization
pattern, byte-frame comments, assertion style, and the matrix of test
files required for each protocol.

---

## 1. Framework

- Use **native `unittest`** from the standard library. Do **not** use
  `testslide`.
- Import: `from unittest import TestCase`.
- Parameterization uses `parameterized` (already a dev dependency) via
  `@parameterized_class`:
  ```python
  from parameterized import parameterized_class  # type: ignore
  ```
- Zero runtime dependencies outside stdlib still holds for the stack
  itself; `parameterized` is test-only and acceptable.

## 2. File structure

Every test file follows the exact same file-level skeleton as the rest
of the codebase (see `CLAUDE.md §Coding Style Rules / File Structure`):

1. `#!/usr/bin/env python3` shebang
2. The 80-char `#`-bordered copyright/license block (verbatim, no edits)
3. Module docstring:
   ```python
   """
   <one-sentence description>.

   <relative path from repo root to this file>

   ver 3.0.x
   """
   ```
4. Imports — stdlib first, then `parameterized`, then local packages
   (`net_addr`, `net_proto`, `pytcp`). Multi-import from one module uses
   parentheses, never backslash continuation.
5. Module-level constants (baseline frames, shared fixtures).
6. `TestCase` classes.

No `__all__`. No module-level code between the constants and the first
class.

## 3. File naming and placement

- Files go under `<package>/tests/unit/…` mirroring the source layout.
  For a protocol at `net_proto/protocols/<proto>/`, tests live at
  `net_proto/tests/unit/protocols/<proto>/`.
- Double-underscore separators, same as source files. Per-aspect
  splitting is mandatory:

  | Source artifact          | Test file                                                            |
  | ------------------------ | -------------------------------------------------------------------- |
  | Header dataclass         | `test__<proto>__header__asserts.py`                                  |
  | Assembler construction   | `test__<proto>__assembler__asserts.py` *(if any kwargs asserts)*     |
  | Assembler operation      | `test__<proto>__assembler__operation.py`                             |
  | Parser integrity checks  | `test__<proto>__parser__integrity_checks.py`                         |
  | Parser sanity checks     | `test__<proto>__parser__sanity_checks.py`                            |
  | Parser operation         | `test__<proto>__parser__operation.py`                                |
  | Each option (if any)     | `test__<proto>__option__<name>.py`                                   |
  | Options container        | `test__<proto>__options.py`                                          |

  Examples: `test__udp__header__asserts.py`,
  `test__tcp__parser__integrity_checks.py`,
  `test__tcp__option__mss.py`.

- Class naming: `Test<Component>[__<Variant>]`. Method naming:
  `test__<proto>__<component>[__<aspect>]`. No trailing underscores.
  No dunder test names.

## 4. Parameterization pattern (canonical)

Use `@parameterized_class` with a list of dicts — one dict per case.
Every dict uses the **same key set** across a test class:

```python
@parameterized_class(
    [
        {
            "_description": "Human-readable summary of this case.",
            "_args": [...],            # optional positional args for setUp
            "_kwargs": {...},          # optional kwargs for setUp
            "_mocked_values": {...},   # optional (external state stubs)
            "_results": {...},         # expected outputs keyed by aspect
        },
        ...
    ]
)
class TestFooBar(TestCase):
    """
    <one-line purpose>.
    """

    # Declare every parametrized attribute as a class annotation so
    # mypy strict mode accepts field access in the test methods.
    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the SUT from '_args' / '_kwargs'.
        """
        ...

    def test__proto__aspect(self) -> None:
        """
        Ensure <behavioral guarantee>.
        """
        ...
```

Guidelines:

- The class-level type annotations for `_description`, `_args`,
  `_kwargs`, `_results`, `_mocked_values` are **required** — without
  them mypy strict will fail on `self._args`.
- One behavioral guarantee per test method. Do not pack unrelated
  asserts into one test. Split by aspect (`__len__`, `__str__`,
  `__repr__`, `__bytes__`, each property, each flag path).
- `_results` is always a `dict[str, Any]` keyed by the aspect name.
  The key name is usually the dunder or property under test
  (`"__bytes__"`, `"__repr__"`, `"sport"`, `"header"`, `"payload"`).
- Prefer one parametrized `TestCase` for the happy path and
  separate unparametrized `TestCase`s for corner cases (defaults,
  boundary-accepted values, misc functions like `Tracker`).

## 5. Byte-frame annotation rule (MANDATORY)

Every raw-byte frame in a test fixture carries a structured comment
explaining each field. The comment lives **immediately above the bytes
literal** and is written in the same style across the repo:

```python
# UDP wire frame (8 bytes, header-only):
#   Bytes 0-1 : 0x3039 -> sport=12345
#   Bytes 2-3 : 0xd431 -> dport=54321
#   Bytes 4-5 : 0x0008 -> plen=8 (header-only)
#   Bytes 6-7 : 0xfb8c -> cksum (valid for init=0)
_BASELINE_FRAME = b"\x30\x39\xd4\x31\x00\x08\xfb\x8c"
```

Or, for protocol-level summaries (ARP, Ethernet):

```python
# ARP (Ethernet/IPv4)
#   Hardware type : 0x0001 (Ethernet)
#   Protocol type : 0x0800 (IPv4)
#   HLEN / PLEN   : 6 / 4
#   Operation     : 1 (Request)
#   Sender MAC    : 02:00:00:00:00:91
#   Sender IP     : 10.0.1.91
#   Target MAC    : 00:00:00:00:00:07
#   Target IP     : 10.0.1.7
#
#   Summary       : Unicast ARP request — "Who has 10.0.1.7? Tell 10.0.1.91."
```

Rules:

- Byte ranges use `Bytes A-B` (or `Byte A` for single bytes).
- Hex constants in the comment match the actual bytes exactly. Pad to
  full field width (`0x0008`, not `0x8`).
- If a test deliberately breaks a field to trigger an integrity/sanity
  branch, the comment calls that out in parentheses (e.g.
  `plen=7 (integrity violation: < 8)`, `cksum (intentionally wrong)`).
- For payload fixtures that repeat (`b"X" * 65527`), the comment
  describes the pattern in words (`65527 bytes of 'X'`).
- When you **review** or **move** an existing frame, re-verify the
  comment still matches byte-for-byte. Stale comments are worse than
  no comments.

## 6. Assertion style

All assertions include a descriptive `msg=` argument — no bare
`assertEqual(a, b)`. The message explains the guarantee, not the
mechanics, and interpolates the parametrized `_description` when
inside a `@parameterized_class` test so failures pinpoint the case:

```python
self.assertEqual(
    udp_parser.header,
    self._results["header"],
    msg=f"Unexpected parsed header for case: {self._description}",
)
```

For single-case tests, the message still describes the invariant:

```python
self.assertEqual(
    len(buffers[0]),
    UDP__HEADER__LEN,
    msg="UdpAssembler.assemble must append the 8-byte fixed header first.",
)
```

For `assertRaises`, capture the exception and assert on the full
error message text:

```python
with self.assertRaises(UdpIntegrityError) as error:
    UdpParser(self._packet_rx)

self.assertEqual(
    str(error.exception),
    f"[INTEGRITY ERROR][UDP] {self._error_message}",
    msg=f"Unexpected integrity-error message for case: {self._description}",
)
```

The error-message prefix is always the canonical `[CATEGORY][PROTO] `
form the protocol's `*Error` class produces (e.g.
`[SANITY ERROR][UDP] `, `[INTEGRITY ERROR][TCP] `). Do **not** hand-roll
the prefix in test fixtures.

Prohibited:

- `assertTrue(a == b)` — use `assertEqual(a, b, msg=...)`.
- `assertEqual(a, b)` without `msg=` in new code.
- Parentheses around a single string literal in a dict value:
  ```python
  # Bad
  "__repr__": ("UdpHeader(sport=0, dport=0, plen=0, cksum=0)"),
  # Good
  "__repr__": "UdpHeader(sport=0, dport=0, plen=0, cksum=0)",
  ```
  The parenthesized form is a leftover from multi-line string
  concatenation — drop them when the value fits on one line.

Prefer `!r` inside f-string assertion messages for values (`Got: {value!r}`).

## 7. Test-method docstrings

Every test method has a docstring. First word is always **"Ensure"**,
describing the behavioral guarantee from the caller's perspective:

```python
def test__udp__parser__payload(self) -> None:
    """
    Ensure the UDP packet parser extracts the payload starting at
    'UDP__HEADER__LEN' and ending at 'header.plen'.
    """
```

Do not describe *how* the code is tested — describe *what* is
guaranteed. Method bodies that exercise edge cases often call out the
RFC or a past-regression in a second sentence:

```python
def test__udp__parser__integrity__zero_cksum_skips_validation(self) -> None:
    """
    Ensure a frame with cksum=0 bypasses checksum validation even
    when the bytes would otherwise not sum to zero. RFC 768 allows a
    transmitter to set the UDP checksum to zero, in which case the
    receiver must not validate it.
    """
```

Class docstrings are one noun phrase
(`"The UDP packet parser sanity checks tests."`).

## 8. Required test matrix per protocol

For every protocol `<proto>` under `net_proto/protocols/`, the
following files must exist and cover the following aspects. Miss none
of these; coverage targets 100% line/branch for the component under
test.

### 8.1 `test__<proto>__header__asserts.py`

Tests the frozen dataclass `__post_init__` assertions.

- `setUp` builds a valid default `self._kwargs` dict that would
  construct a minimal valid header.
- First test: `test__<proto>__header__default_accepted` — constructs
  once and asserts `len(header) == <PROTO>__HEADER__LEN` so a
  regression that makes the baseline invalid is caught immediately.
- One test per field per assert branch. For integer fields this is
  always `__under_min` and `__over_max`, using
  `UINT_8__MIN - 1`, `UINT_8__MAX + 1`, etc. from `net_proto`.
- For enum fields: `__not_<TypeName>` — passes a string or other wrong
  type, asserts message contains `Got: {type(value)!r}`.
- Assertion message template:
  ```
  The '<field>' field must be a <N>-bit unsigned integer. Got: {value!r}
  The '<field>' field must be a <EnumName>. Got: {type(value)!r}
  ```
  Match the source's assert message text verbatim.

### 8.2 `test__<proto>__assembler__asserts.py`

Only needed when the assembler performs its own constructor asserts
beyond what the header validates (e.g. TCP options length).

- `defaults_accepted` test first.
- One test per assert branch — under/over/misaligned/invalid-shape.
- Also cover boundary-accepted values (e.g. `options_len exactly
  TCP__OPTIONS__MAX_LEN`) so a tightening regression is caught.

### 8.3 `test__<proto>__assembler__operation.py`

Parametrized happy-path matrix covering at minimum:

- Minimum (zero/empty payload) and maximum (UINT16 ceiling) field
  values.
- A typical realistic packet.
- Protocol-specific edge cases (e.g. cksum=0 for UDP, every TCP flag
  combination that matters).

Per case, `_results` must include **every** observable aspect:

```python
"_results": {
    "__len__": <int>,
    "__str__": <str>,
    "__repr__": <str>,
    "__bytes__": <bytes>,          # annotated with a wire-frame comment
    # Every property the assembler exposes:
    "sport": 12345,
    "dport": 54321,
    "plen": 24,
    "cksum": 0,
    "header": UdpHeader(...),
    "payload": b"...",
}
```

One `test__<proto>__assembler__<aspect>` method per key. Additionally:

- `test__<proto>__assembler__assemble` — appends to a `list[Buffer]`
  and verifies concatenation equals `__bytes__`.
- `test__<proto>__assembler__assemble__buffer_layout` — checks the
  exact number of buffers appended and the length of each, so
  downstream code relying on positional indexing is safe.

A separate unparametrized `TestFooAssemblerMisc` covers:

- `echo_tracker` plumbing (assembler stores the provided Tracker).
- `defaults` — constructing with no kwargs yields a minimal valid
  object.

### 8.4 `test__<proto>__parser__integrity_checks.py`

Two test classes:

1. **Parametrized rejection matrix** — one case per integrity branch in
   the parser's `_validate_integrity()`. Use one shared baseline
   frame constant at module level; each case either:
   - reuses the baseline and perturbs `_ip__payload_len` /
     `_ip__pshdr_sum`, or
   - supplies a bespoke frame with one field deliberately broken
     (always annotated in the comment: `plen=7 (integrity violation)`).

   The test body asserts `assertRaises(<Proto>IntegrityError)` and
   matches the full formatted error message, including the canonical
   `[INTEGRITY ERROR][<PROTO>] ` prefix.

2. **Boundary-accepted class** — `Test<Proto>ParserIntegrityBoundary`
   — constructs the shortest frame that passes every integrity check
   and asserts it parses. Guards against future tightening that would
   silently reject the minimum-valid packet.

Stub the IP layer with `SimpleNamespace`:

```python
from types import SimpleNamespace

self._packet_rx = PacketRx(self._frame_rx)
self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
    payload_len=self._ip__payload_len,
    pshdr_sum=self._ip__pshdr_sum,
)
```

The UDP/TCP parsers only read `ip.payload_len` and `ip.pshdr_sum`, so
the stub is sufficient and the tests are IPv4/IPv6 agnostic. State
this in the class docstring.

### 8.5 `test__<proto>__parser__sanity_checks.py`

Same shape as integrity checks, but every case is a structurally valid
frame that violates a logical invariant (`sport == 0`,
`dport == 0`, etc.). Asserts on `<Proto>SanityError` with the
`[SANITY ERROR][<PROTO>] ` prefix.

### 8.6 `test__<proto>__parser__operation.py`

Parametrized happy-path matrix, similar shape to the assembler
operation matrix. Per case, `_results` must include:

```python
"_results": {
    "header": <ProtoHeader>(...),
    "payload": b"...",
    # plus each parser property the protocol exposes
}
```

Methods on the class cover:

- `test__<proto>__parser__header` — decoded header equals expected.
- `test__<proto>__parser__payload` — extracted payload equals expected.
- `test__<proto>__parser__packet_rx_<proto>` — parser installs itself
  on `packet_rx.<proto>`.
- `test__<proto>__parser__packet_rx_frame_advanced_past_header` —
  verifies `packet_rx.frame` has been advanced to the payload.
- Any additional fields exposed by the parser's `*HeaderProperties`
  mixin.

### 8.7 Options tests (protocols with TLV options, e.g. TCP)

One file per option type (`test__<proto>__option__<name>.py`). Each
file has typically two `TestCase` classes:

1. `Test<Proto>Option<Name>Asserts` — constructor boundary asserts
   (under_min, over_max for every integer field).
2. `Test<Proto>Option<Name>Assembler` — parametrized matrix of
   `__len__` / `__str__` / `__repr__` / `__bytes__` / property values.
3. Optionally a parser/integrity class per option.

Plus `test__<proto>__options.py` for the options container itself —
covering composition, ordering, length computation, lookup properties
(e.g. `options.mss`), and the integrity rules enforced on the whole
set.

## 9. Production-code fixes

Writing thorough tests routinely surfaces bugs in the protocol
sources. When this happens:

- Keep the fix minimal and targeted.
- Bundle it with the test commit that exercises it.
- In the commit body, list each issue and the fix applied. Example:

  ```
  Add udp parser integrity-check tests

  Bundles a production-code fix for udp__parser.py: the plen
  upper-bound check used `<` where the RFC requires `<=`, which
  rejected maximum-size datagrams. Caught by the new UINT16-ceiling
  parametrized case.
  ```

Typical issues surfaced by this process: incorrect validation bounds,
missing sanity checks, off-by-one parsing, misleading docstrings,
missing `@override`, properties that don't match the field they
claim to expose, style violations against `CLAUDE.md`.

## 10. Workflow

Work one test file at a time. For each file:

1. Read the source under test. Confirm which branches/fields/dunders
   exist.
2. Draft the test file following this rule.
3. Run:
   ```bash
   python -m unittest <path/to/test_file>
   coverage run --source=<source> -m unittest <path/to/test_file>
   coverage report -m
   make lint
   ```
4. Iterate until coverage is 100% for the target component and lint
   is clean.
5. Commit with a focused message; include any production-code fix
   notes in the body.
6. Push/sync before moving to the next file.

## 11. Anti-patterns to avoid

- Mixing multiple unrelated assertions in one `test__*` method.
- Omitting `msg=` on assertions.
- Parenthesizing single-line string values in dicts.
- Writing byte literals without a matching annotation comment — or
  letting the comment drift out of sync with the bytes.
- Hand-constructing error-message prefixes like `"[UDP] "` instead of
  relying on the `*Error` class's canonical prefix.
- Using `testslide.TestCase` in new code.
- Asserting on private parser internals (`parser._frame`) rather than
  the public contract (`parser.header`, `parser.payload`, properties).
- Coupling a parser test to a specific IP version when the parser only
  reads stub-able IP attributes.
- Losing coverage on the "shortest valid packet" / "minimum accepted"
  boundary by only testing rejection.

## 12. Reference implementations

When in doubt, mirror the structure of:

- `net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py`
  (header asserts)
- `net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py`
  (integrity matrix + boundary class, `SimpleNamespace` IP stub)
- `net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py`
  (sanity matrix)
- `net_proto/tests/unit/protocols/udp/test__udp__parser__operation.py`
  (parser operation matrix)
- `net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py`
  (assembler operation matrix + Misc class)
- `net_proto/tests/unit/protocols/tcp/test__tcp__assembler__asserts.py`
  (assembler constructor asserts with boundary-accepted cases)
- `net_proto/tests/unit/protocols/tcp/test__tcp__option__mss.py`
  (single option: asserts + assembler matrix)
- `net_proto/tests/unit/protocols/tcp/test__tcp__options.py`
  (options container composition)
- `net_proto/tests/unit/protocols/arp/test__arp__parser__operation.py`
  (multi-line protocol-summary frame annotation style)
- `net_addr/tests/unit/test__ip4_address.py`
  (value-class parameterized matrix: per-property assertions,
  equality/hash/roundtrip blocks split into dedicated TestCases)

These files are the canonical examples. Any deviation from this rule
should be justified by something that appears in one of them — not by
novel patterns introduced in a new file.
