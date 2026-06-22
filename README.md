# pmd-pytcp

A minimal fork of [PyTCP](https://github.com/ccie18643/PyTCP) (Sebastian Majewski's
pure-Python TCP/IP stack), maintained **solely as a dependency of
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3)** for its no-root, in-process
iOS 17+ userspace tunnel. It is not a general-purpose release and is not affiliated with or
endorsed by upstream PyTCP.

This is a true git fork: it sits on top of upstream PyTCP's history (forked at commit
`85b2aec5`), so the changes below are isolated commits that can be cherry-picked back upstream.
Licensed under the **GNU GPL v3** (see `LICENSE`), same as upstream — all original copyright and
authorship are retained.

## What's changed vs upstream

1. **`io_backend` (cherry-pickable upstream).** Upstream calls `os.eventfd` / `os.read` /
   `os.writev` directly (Linux-only), so an embedding host had to monkeypatch the `os` module
   process-globally to run on macOS/Windows. The first fork commit adds `pytcp/lib/io_backend.py`
   — a cross-platform `eventfd` wakeup + interface `read`/`writev` — and routes the runtime rings
   and socket layer through it. On Linux with a real fd it delegates straight to `os.*`. This
   commit uses upstream's package names and is intended to be useful upstream as-is.

2. **Package rename (fork-only).** The second fork commit renames `pytcp` → `pmd_pytcp`,
   `net_addr` → `pmd_net_addr`, `net_proto` → `pmd_net_proto` (and applies fork metadata), so a
   user who also has the real PyTCP installed gets neither shadowed. This is intentionally
   fork-specific and not meant for upstream.

The protocol stack itself is unmodified; please send protocol/stack improvements to upstream
PyTCP, not here.

## Scope

- Requires Python >= 3.14 (matches pymobiledevice3's userspace-tunnel gate).
- Tracks upstream's test status; this fork does not aim to fix pre-existing upstream test
  failures, only to carry the two changes above.
