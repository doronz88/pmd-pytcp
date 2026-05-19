# Umbrella `PyTCP` wheel packaging — tracked defect

Status: **open / tracked** (decoupled from the `PyTCP-net_addr`
split, which is complete and correct on its own).

## Symptom

`pip install PyTCP` into a clean environment, then `import pytcp`
→ `ModuleNotFoundError`. The built umbrella wheel is non-functional.

## Evidence

The `pytcp-3.0.5-py3-none-any.whl` payload, in full (every `.py`
outside `*.dist-info/`):

```
net_proto/__init__.py
pytcp/__init__.py
pytcp/template.py
```

3 of 323 source files. All of `pytcp/socket/`, `pytcp/runtime/`,
`pytcp/protocols/`, `pytcp/stack/`, `net_proto/lib/`,
`net_proto/protocols/`, … are absent from the distribution.

This is **pre-existing and already public**: `PyTCP 3.0.4` on PyPI
uses the same `[tool.setuptools.packages.find] include = ["pytcp",
"net_addr", "net_proto"]` and ships the same broken wheel (it also
has `requires_dist: None`). The `net_addr` split neither caused nor
worsened it; the split's own dist (`PyTCP-net_addr`) is verified
correct via a clean-venv install.

## Root causes (three, independent)

1. **Exact, non-glob `include` patterns.** setuptools matches
   `"pytcp"` against the dotted package name `pytcp` only — never
   `pytcp.socket` etc. Subpackages are filtered out by pattern.
   Needs `["pytcp*", "net_proto*"]`.
2. **PEP 420 namespace subpackages.** `pytcp`: 4 regular / 17
   namespace; `net_proto`: 2 regular / 28 namespace
   (`pytcp/lib`, `pytcp/runtime`, `pytcp/protocols`,
   `net_proto/protocols`, … have no `__init__.py`). setuptools'
   default `find` is regular-only; even after fixing (1) these 45
   subpackages stay invisible. Needs namespace discovery
   (`[tool.setuptools.packages.find] namespaces = true`, verified
   against an actual build).
3. **Undeclared runtime dependency.** The bundled `net_proto`
   does `from aenum import …` at import time, but the umbrella
   declares `dependencies = []`. A correct umbrella needs
   `aenum` (and must decide whether to also depend on
   `PyTCP-net_addr`, since `net_addr` is no longer bundled).

## Constraints on fixing / testing

- **`setuptools` and `wheel` are not in the dev venv** (modern
  venv; only present transiently inside a networked isolated
  `python -m build`). So an offline, deterministic packaging unit
  test (per `unit_testing.md` §10a) is not currently possible
  without a dev-env change; an isolated build needs network.
  CI's `publish.yml` only works because GitHub runners have
  network.
- There is no packaging-test harness in the repo.

## Remediation plan (its own phase, not the net_addr split)

1. Add `setuptools` + `wheel` to `requirements_dev.txt` so the
   wheel can be built offline (`--no-isolation`) and asserted.
2. `[tool.setuptools.packages.find]`: `namespaces = true` +
   `include = ["pytcp*", "net_proto*"]`; decide
   `exclude = ["*.tests*"]` (the net_addr dist excludes its
   tests; the umbrella historically shipped none of anything).
3. Declare runtime deps: at least `aenum`; decide whether the
   umbrella should `dependencies += ["PyTCP-net_addr==<ver>"]`
   (and stop being a superset) or remain independent.
4. Tests-first: a build-based packaging test (now offline-capable
   per step 1) asserting the wheel contains representative
   subpackages from every namespace tree and that `import pytcp`
   succeeds from a clean install; assert `net_addr` is NOT in the
   umbrella payload.
5. `make validate` + clean-venv `pip install PyTCP` smoke.

## Release decoupling (in effect now)

`publish.yml` is gated by release-tag prefix:

- `net_addr-vX.Y.Z` → publishes **only** `PyTCP-net_addr`.
- `vX.Y.Z` → publishes **only** the umbrella `PyTCP`.

So `PyTCP-net_addr` can ship on its own tag without the
known-broken umbrella riding along. The umbrella publish path is
intentionally untouched (no regression vs. the already-public
3.0.4) until this remediation lands.
