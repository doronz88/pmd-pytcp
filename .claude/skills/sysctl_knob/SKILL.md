---
name: sysctl_knob
description: Add a new runtime-tunable sysctl knob to PyTCP — the registered policy-tunable equivalent of a Linux net.* sysctl. Invoke when adding a new knob, migrating an existing module-level constant from static to runtime-tunable, or doing a per-package migration sweep of `*__constants.py` policy values. Do NOT invoke for protocol-invariant constants (RFC-pinned wire values, header sizes, IANA codepoints) — those stay as plain module constants.
---

# PyTCP sysctl knob skill

This skill captures the workflow for adding a single
runtime-tunable knob (a "sysctl") to PyTCP. The framework
itself — registry shape, naming convention, classification
rule, migration phases — lives at
`docs/refactor/sysctl_framework.md`. This skill is the
turn-the-crank checklist for a single knob: classify,
register, accessor surface, init() kwarg (where appropriate),
validator, tests-first, audit-doc Reference, §7.2 docstring
audit, commit.

## When to invoke

- A user asks to "make X configurable" / "add a stack-init
  parameter for Y" / "expose Z as a sysctl."
- A feature commit needs a runtime-tunable value that doesn't
  exist as a knob yet.
- A per-package migration sweep is in progress and the next
  constant needs classification + registration (per
  `sysctl_framework.md` §8 Phase 1+).
- An existing static constant is being promoted to a knob
  because a real consumer (operator request, RFC SHOULD,
  Linux parity) has emerged.

## When NOT to invoke

- For protocol-invariant constants — header struct sizes,
  RFC-pinned wire values, IANA codepoints, enum values.
  These stay as plain module-level constants. See
  `sysctl_framework.md` §1 for the classification rule.
- For test-only scaffolding — if the only consumer would be
  a test, the test can patch the module attribute directly
  without registering a public knob.
- Before the registry exists — Phase 0 of the framework
  (`packages/pytcp/pytcp/stack/sysctl.py`) must be in place. If `_register`
  is not importable, the framework hasn't been built yet;
  start there instead.

## Pre-flight

Before touching code:

1. **Confirm the knob is policy, not invariant.** Apply the
   `sysctl_framework.md` §1 heuristic: if Linux has the
   equivalent under `/proc/sys/net/`, it's policy. If Linux
   uses `#define` or an inline `const`, it's invariant. When
   ambiguous, default to invariant (mutability is forever
   load-bearing once exposed).
2. **Decide the dotted-name canonical key.** Mirror Linux
   hierarchy where applicable; otherwise
   `<package>.<subject>.<field>` snake_case. Examples in
   `sysctl_framework.md` §3.
3. **Decide whether the knob gets an explicit `stack.init()`
   kwarg or rides the `sysctls={...}` bag.** Explicit if
   most users will tune it; bag if niche. The decision is
   reversible — promoting a niche knob to explicit later is
   a one-line addition. The bag is keyed by the canonical
   dotted name (no underscore→dot auto-conversion).

## Output diff (canonical shape)

A new knob lands as a single tests-first commit touching:

```
packages/pytcp/pytcp/protocols/<package>/<proto>__constants.py     # registration call
packages/pytcp/pytcp/stack/sysctl.py                                  # (if a new validator helper)
packages/pytcp/pytcp/stack/__init__.py                              # (if explicit kwarg)
packages/pytcp/pytcp/tests/unit/<package>/test__<...>.py            # behavior pin
docs/rfc/<group>/<rfcXXXX__name>/adherence.md        # Reference + status flip if RFC-driven
docs/refactor/sysctl_framework.md                    # add to §1 example table
```

Per-package migrations land all of a package's policy
constants in one commit, not piecemeal — a half-migrated
package is the failure mode this framework is trying to
avoid (see `sysctl_framework.md` §8).

## Step-by-step

### 1. Classify (pre-flight)

Confirm policy vs invariant per `sysctl_framework.md` §1.
Stop if invariant.

### 2. Register at the constants module

Append to the relevant `*__constants.py`:

```python
from pytcp.stack.sysctl import _register, _is_positive_int

ARP__CACHE__ENTRY_MAX_AGE = 3600  # existing constant stays as the default

_register(
    key="arp.cache.max_age",
    module=__import__(__name__),     # this module
    attr="ARP__CACHE__ENTRY_MAX_AGE", # the ALL_CAPS attribute
    default=ARP__CACHE__ENTRY_MAX_AGE,
    validator=_is_positive_int("arp.cache.max_age"),
    description="ARP cache entry lifetime in seconds.",
)
```

Order of `_register` calls matters when a validator depends
on another knob's value (e.g.
`arp.cache.refresh_time < arp.cache.max_age`). Register the
dependency first.

### 3. Add the validator (if novel)

If the validator function doesn't already exist in
`packages/pytcp/pytcp/stack/sysctl.py`, add it next to the existing helpers:

```python
def _is_positive_int(name: str) -> Callable[[Any], None]:
    def validator(value: Any) -> None:
        if not isinstance(value, int) or value <= 0:
            raise ValueError(
                f"sysctl '{name}' must be a positive int; got {value!r}"
            )
    return validator
```

Cross-knob constraints (e.g. `refresh < max`) go into the
`_finalize_validators()` list as a separate function that
runs after every kwarg is applied — see
`sysctl_framework.md` §5.

### 4. (Optional) Promote to explicit `stack.init()` kwarg

If the knob is one most users will tune, add it to
`packages/pytcp/pytcp/stack/__init__.py::init()`:

```python
def init(
    *,
    fd: int,
    layer: InterfaceLayer,
    # ...
    arp_cache_max_age: int | None = None,    # new explicit kwarg
    sysctls: dict[str, Any] | None = None,    # bag stays (dotted-name keys)
) -> None:
    if arp_cache_max_age is not None:
        sysctl.set("arp.cache.max_age", arp_cache_max_age)
    if sysctls is not None:
        for key, value in sysctls.items():
            sysctl.set(key, value)
    sysctl.finalize_validators()
    # ... rest of init
```

### 5. Tests-first

Write the failing test BEFORE the code that flips it green
(per `.claude/rules/feature_implementation.md` §2). For a
single-knob addition, the failing test typically pins:

- `sysctl.set(key, value)` updates the module attribute.
- The validator rejects the documented invalid case with
  `ValueError`.
- A behavior path that reads the knob honours the override
  (e.g. `_subsystem_loop` aging arithmetic against the new
  value).
- (If kwarg) `stack.init(arp_cache_max_age=N)` propagates
  through to the registered value.

Test file location follows
`.claude/rules/unit_testing.md` §3 — typically
`packages/pytcp/pytcp/tests/unit/<package>/test__<...>.py` or a new
`packages/pytcp/pytcp/tests/unit/lib/test__lib__sysctl.py` for registry-level
behavior.

Run before adding the implementation. Verify failures are for
the predicted reason (per `feature_implementation.md` §2 step
2). If the test passes pre-fix, the gap was already closed —
double-check before claiming done.

### 6. Implement

Apply the `_register(...)` call + (optional) explicit
kwarg + (optional) novel validator. Re-run tests. Confirm
flip green.

### 7. Audit-doc Reference

If the knob exists because of an RFC clause or a Linux
sysctl, update the relevant adherence record under
`docs/rfc/<group>/<rfcXXXX__name>/adherence.md`. Walk the
existing flow:

- Find the section that covers the SHOULD/MUST the knob
  satisfies.
- Flip its status from "not implemented" / "partial" to
  "met" with a one-sentence rationale.
- Update the test-coverage matrix and the overall-assessment
  table.

If the knob has no RFC justification, add a one-line entry
to `docs/refactor/sysctl_framework.md` §1 example table so
the index stays current.

### 8. Run §7.2 docstring audit

`.claude/rules/unit_testing.md` §7.2 audit on every test file
touched. Any output is a blocker.

```bash
python3 << 'EOF'
import re, sys
from pathlib import Path

FILES = ["packages/pytcp/pytcp/tests/unit/<...>.py"]  # list every modified test file
violations = []
for path in FILES:
    text = Path(path).read_text()
    for m in re.finditer(
        # Tolerant signature pattern — matches single-line and
        # multi-line `def test__x(...) -> None:` forms (a naive
        # `\(self\)` silently skips multi-line signatures).
        r'def (test__\w+)\([^)]*\)\s*->\s*None:\s*\n\s*"""(.*?)"""',
        text, re.DOTALL,
    ):
        name, body = m.group(1), m.group(2)
        if "Reference:" not in body:
            violations.append(f"{path}::{name} — missing 'Reference:' line")
        if not re.search(r'^\s+Ensure ', body):
            violations.append(f"{path}::{name} — must start with 'Ensure '")
        desc = re.sub(r'\n\s*Reference:.*', '', body, flags=re.DOTALL)
        for pat in (r'[Pp]er RFC \d', r'RFC \d+\s*§', r'RFC \d+\s+figure'):
            if re.search(pat, desc):
                violations.append(f"{path}::{name} — inline RFC citation; pattern={pat!r}")
for v in violations:
    print(v)
sys.exit(1 if violations else 0)
EOF
```

If a touched test file has pre-existing violations, the
clean-up obligation is the whole file (per
`unit_testing.md` §7.2). Either bundle the cleanup with this
commit or land a prep commit first.

### 9. Lint + test

`make lint && make test`. Both must be clean before commit.

### 10. Commit

One commit per knob (or one commit per package for a
migration sweep). Commit message body:

```
<package>: register <key> as runtime-tunable sysctl

<one-paragraph why — Linux parity, RFC SHOULD, operator ask>.

Add 'pytcp.stack.sysctl' registration for '<key>' with
default <X> and a positive-int validator. <If kwarg:>
Promote to explicit 'stack.init(<kwarg_name>=...)' kwarg
since this is one of the more frequently-tuned knobs.

Tests-first <pin> at '<test path>::<test name>'. Pre-fix
<failure mode>; post-fix passes.

<Reference: RFC X §Y / Linux net.ipv4.foo_bar>.

Lint clean. <N> passing, <M> skipped.

Co-Authored-By: ...
```

## Anti-patterns

- **Bypassing `set()` to write the module attribute
  directly.** Even when "we know it's safe," the validator
  is the contract — bypassing it now creates the same bug
  later when a less-careful caller does the same.
- **Forgetting the audit-doc update.** A knob added without
  a Reference (RFC clause or Linux sysctl) accumulates as
  unjustified API surface — no one knows whether it's
  supposed to be there.
- **Validators that don't include the offending key in the
  error message.** Without the key, a `ValueError` from a
  `sysctls={...}` bag tells the user nothing.
- **Half-migrating a package.** If a sweep migrates 5 of 10
  policy constants in a `*__constants.py` and stops, the
  remaining 5 sit as second-class citizens — operators will
  be confused which knob is mutable. Always finish the
  package.
- **Promoting a knob to explicit kwarg "just in case."**
  The `sysctls={...}` bag is the default surface; explicit
  kwargs are for knobs that genuinely warrant the type-safety
  + IDE autocomplete tax. Reversible later.
- **Adding a sysctl whose only consumer is a test.** That's
  a test-scaffolding need, not a public-API need; patch the
  module attribute directly. The framework is for surfaces
  the operator can reasonably expect to tune, not for test
  conveniences.
