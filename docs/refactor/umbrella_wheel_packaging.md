# Umbrella `PyTCP` wheel packaging — CLOSED

**Status:** RESOLVED 2026-05-19 by **dissolution**, not repair.
Kept as the historical record of a long-standing defect on
PyPI ≤ `PyTCP 3.0.4`.

## What it was

The built `PyTCP` umbrella wheel shipped 3 of 323 source files
(`net_proto/__init__.py`, `pytcp/__init__.py`,
`pytcp/template.py`) — `pip install PyTCP` then `import pytcp`
raised `ModuleNotFoundError`. Pre-existing and already public on
PyPI ≤ 3.0.4; not caused by the monorepo split.

## Root cause (a single one, in the end)

`[tool.setuptools.packages.find] include = ["pytcp"]` used an
**exact, non-glob** pattern: setuptools matched only the
top-level `pytcp` package, never `pytcp.socket`, `pytcp.lib`,
… Empirically isolated during the net_proto split: with the
per-package pyproject, `include = ["net_proto*"]` ships 193
`.py` (all 28 PEP 420 namespace subpackages); `["net_proto"]`
ships 1 `.py`. A previously-suspected second cause —
"needs `namespaces = true`" — was disproven: pyproject `find`
already enables namespace discovery, so the trailing `*` is
the entire fix. (The umbrella also failed to declare its
`aenum` runtime dep — folded into the dissolution; aenum was
later removed entirely.)

## How it was fixed

The monolithic umbrella build was **dissolved** by completing
the monorepo split: `pytcp` was extracted into
`packages/pytcp/` with its own PEP 517 project
(`include = ["pytcp*"]`, namespace discovery, tests excluded,
`py.typed`); the `PyTCP` dist is now the `pytcp` package
depending on `PyTCP-net_proto` + `PyTCP-net_addr`. The
repo-root `pyproject.toml` is tooling-only. The first
correctly-packaged `PyTCP` ships 130 `.py` incl. all
`pytcp.runtime.*` / `pytcp.protocols.*` namespace subpackages.

## Where the regression is pinned

`packages/pytcp/pytcp/tests/unit/test__packaging__dist_wheels.py`
builds each dist offline (`python -m build --no-isolation`) and
asserts the wheel ships its namespace subpackages, excludes
tests, and carries `py.typed` — for `PyTCP-net_addr`,
`PyTCP-net_proto`, **and `PyTCP`**. A revert to the non-glob
pattern would re-introduce the umbrella bug and fail this test.

No further action.
