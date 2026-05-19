# Umbrella `PyTCP` wheel packaging — tracked defect

Status: **RESOLVED** (2026-05-19) — **by dissolution, not repair**.
`pytcp` was extracted into its own PEP 517 project
`packages/pytcp/` (`include = ["pytcp*"]`, namespace discovery,
tests excluded, `py.typed`); the `PyTCP` dist is now the `pytcp`
package depending on `PyTCP-net_proto==3.0.5` +
`PyTCP-net_addr==3.0.5`, and the repo-root `pyproject.toml` is
tooling-only. The first correct `PyTCP` wheel ships **130 `.py`**
incl. all `pytcp.runtime.*` / `pytcp.protocols.*` namespace
subpackages (vs. the historical 3-file wheel), twine-clean,
pinned by `test__packaging__dist_wheels.py::TestPackagingPytcpWheel`.
The monolithic umbrella build that exhibited this defect no longer
exists. Remaining text below is kept as the historical record.

---

Original status: open / tracked (decoupled from the
`PyTCP-net_addr` split, which is complete and correct on its
own).

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

## Root causes (two, independent)

1. **Exact, non-glob `include` patterns** — the dominant cause.
   setuptools matches `"pytcp"` against the dotted package name
   `pytcp` only — never `pytcp.socket` etc. Subpackages are
   filtered out by pattern. Fix: `["pytcp*", "net_proto*"]`.

   **Empirically isolated** during the net_proto split
   (`packages/net_proto`, 2 regular / 28 PEP 420 namespace
   subpackages): with the per-package pyproject,
   `include = ["net_proto*"]` → wheel ships **193** `.py`
   (all namespace subpackages included);
   `include = ["net_proto"]` → wheel ships **1** `.py`. So the
   glob alone is sufficient and the prior "needs
   `namespaces = true`" hypothesis is **disproven**:
   `[tool.setuptools.packages.find]` in `pyproject.toml` already
   performs namespace discovery (`find_namespace`) by default —
   `find_namespace_packages('.', include=['pytcp*'])` returns 58
   packages vs. 1 for `include=['pytcp']`. No `namespaces = true`
   key is required; only the trailing `*`. Pinned for net_proto
   by `packages/net_proto/net_proto/tests/unit/
   test__packaging__dist_wheels.py` (umbrella-style exact pattern
   → 6 failing assertions).
2. **Undeclared runtime dependency.** The bundled `net_proto`
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

1. `setuptools` + `wheel` are now in `requirements_dev.txt` (done
   during the net_proto split) so the wheel builds offline
   (`--no-isolation`) and can be asserted.
2. `[tool.setuptools.packages.find]`: `include = ["pytcp*",
   "net_proto*"]` (the trailing `*` is the whole fix — see Root
   cause 1; **no `namespaces = true` needed**, pyproject `find`
   already does namespace discovery); decide
   `exclude = ["*.tests*"]` (the net_addr / net_proto dists
   exclude their tests; the umbrella historically shipped almost
   nothing).
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
