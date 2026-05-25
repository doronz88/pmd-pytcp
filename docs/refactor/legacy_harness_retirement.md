# Legacy Packet-Handler Test-Harness Retirement — Scoping

The paired follow-on to the mixin → composition collapse
(`packet_handler_composition.md`, §8). The collapse track is **complete
and pushed** (steps 1–12, `6a7f13d8 … 10c5b749` on `PyTCP_3_0_6`); every
packet-handler mixin is now a composed sub-handler over a typed
`PacketHandler` back-reference, and both `PacketHandlerL2` /
`PacketHandlerL3` inherit zero mixins.

**Status: COMPLETE 2026-05-24.** All 13 legacy per-handler smoke files
retired across 6 per-protocol commits + 1 harness-consistency commit
(`be259380` sign-off … `0a94137e`). The
`tests/integration/packet_handler/` tree now holds only the three
out-of-scope `test__packet_socket__*` files.

Decisions (locked): 1→(b) fold into `protocols/<proto>/` + delete smoke
file; 2→keep direct construction (drop the link/address-API aspiration);
3→hard no-coverage-loss diff bar; 4→leave the 3 `test__packet_socket__*`
files; 5→per-protocol commit pairs.

Outcomes per protocol:

| Protocol | Disposition | Harness | Suite |
|----------|-------------|---------|-------|
| arp | both files deleted (proven subset of `protocols/arp/`) | — | 11323→11296 (−27 dup) |
| ip6_frag | migrated → `test__ip6__reassembly.py` / `test__ip6__fragmentation.py` | `Ip6TestCase` | 11296 (relocate) |
| udp | migrated → `test__udp__{rx,tx}.py`; dropped 1 proven dup (ip6 zero-cksum, covered by `no_check6`) | `UdpTestCase` | 11296→11295 (−1 dup) |
| tcp | migrated → `test__tcp__{rx,tx}.py` | `TcpSessionTestCase` | 11295 (relocate) |
| ip4 | migrated → `test__ip4__{rx,tx}.py` + `test__ip4__source_route.py` | `Ip4TestCase` | 11295 (relocate) |
| ip6 | migrated → `test__ip6__{rx,tx}.py` | `Ip6TestCase` | 11295 (relocate) |

The two deletions (arp, udp-zero-cksum) are proven-duplicate removals per
the §4.3 diff bar; everything else is faithful relocation with the golden
frames preserved byte-for-byte. Final state: every migrated file uses its
protocol-specific harness; final suite 11295, all green, `make lint` clean.
This document deliberately *corrects* the §8 sketch in
`packet_handler_composition.md`, which was written before the current
test layout was verified and is wrong on its central premise (see §1).

---

## 1. What §8 got wrong (verified 2026-05-24)

`packet_handler_composition.md` §8 said:

> Introduce `PacketHandlerTestCase` … Migrate the ~10
> `tests/integration/packet_handler/test__packet_handler__*` files … onto
> it; **delete the `NetworkTestCase` compat alias.**

The "delete the NetworkTestCase compat alias" framing is **incorrect for
the current codebase**:

- `NetworkTestCase` (`tests/lib/network_testcase.py:191`,
  `class NetworkTestCase(TestCase)`) is **not** an alias. It is the
  **foundational base harness** that *every* protocol harness extends:

  ```
  TestCase
  └── NetworkTestCase                         (base: mock TxRing/ArpCache/NdCache,
      │                                         fixture topology, stack.mock__init,
      │                                         _add_interface, frag-id determinism)
      ├── EthernetTestCase
      ├── Ethernet8023TestCase
      ├── ArpTestCase
      ├── Ip4TestCase
      ├── Ip6TestCase
      ├── UdpTestCase
      ├── IcmpTestCase ── NdTestCase
      └── TcpSessionTestCase
  ```

  It is referenced across ~40 test files (directly or via a subclass).
  It is **already modernised** to the post-singleton world: it builds a
  real `PacketHandlerL2(...)` and wires the mocked per-interface rings /
  caches through `stack.mock__init(...)` (the singletons the old plan
  assumed are long gone, `e5dc77f5`). There is nothing legacy about it
  and nothing to delete.

- So the retirement target is **not** `NetworkTestCase`. It is the **13
  `tests/integration/packet_handler/test__packet_handler__<proto>__<rx|tx>.py`
  per-handler smoke files**, which are the actual legacy artifact.

## 2. The actual legacy artifact

The 13 files (all subclass the **raw** `NetworkTestCase` directly, *not*
a protocol-specific harness):

```
test__packet_handler__arp__rx.py        test__packet_handler__arp__tx.py
test__packet_handler__ip4__rx.py        test__packet_handler__ip4__tx.py
test__packet_handler__ip4__rx__source_route.py
test__packet_handler__ip6__rx.py        test__packet_handler__ip6__tx.py
test__packet_handler__ip6_frag__rx.py   test__packet_handler__ip6_frag__tx.py
test__packet_handler__tcp__rx.py        test__packet_handler__tcp__tx.py
test__packet_handler__udp__rx.py        test__packet_handler__udp__tx.py
```

They predate the per-protocol harnesses and the
`tests/integration/protocols/<proto>/` tree (which exists for arp, dhcp4,
ethernet, ethernet_802_3, icmp4, icmp6, ip4, ip6, tcp, udp and uses the
richer harnesses + the `drive_rx` / probe / `_assert_<proto>_message`
fluent pattern documented in `integration_testing.md`). The legacy files
tend to use raw `NetworkTestCase` + hand-built golden-byte frames +
`packet_stats` snapshots — the older idiom.

**Not in scope of "per-handler smoke":** the 3
`tests/integration/packet_handler/test__packet_socket__*.py` files
(AF_PACKET SOCK_RAW bind / rx-tap / tx) are a *different* surface
(packet sockets, not the per-protocol RX/TX smoke). They legitimately
live here and should stay (or move to a `protocols/packet_socket/` dir as
a separate, optional tidy — decide in §4).

## 3. Why this is a real (if small) track

After the collapse, the per-handler RX/TX behaviour is already covered at
two layers:

1. **Unit** — `tests/unit/runtime/packet_handler/test__runtime__packet_handler__<proto>__<rx|tx>.py`
   (the `_StubInterface` + sub-handler tests, migrated in steps 1–12).
2. **Integration, protocol-focused** — `tests/integration/protocols/<proto>/`
   (the modern harness + fluent-probe pattern).

The 13 legacy files are a **third, overlapping** layer in the older idiom.
The retirement question is: do they still pin anything the other two
layers don't, and if not, fold/migrate/delete them so there is one
obvious integration home per protocol.

## 4. Decisions needed before any code (sign-off required)

| # | Question | Options | Lean |
|---|---|---|---|
| 1 | What replaces the 13 files? | **(a)** New `PacketHandlerTestCase(NetworkTestCase)` base + migrate all 13 onto it (mirrors `TcpSessionTestCase`); **(b)** Fold each file's cases into the matching `protocols/<proto>/` dir under that protocol's existing harness, delete the `packet_handler/` smoke file; **(c)** Audit-and-prune: keep files that pin unique behaviour, delete pure duplicates, leave the rest on `NetworkTestCase`. | **(b)** — one integration home per protocol, no new harness layer, kills the third overlapping idiom. (a) adds a harness for files that arguably should not exist as a separate set. |
| 2 | "Construct via link/address APIs" (the §8 aspiration)? | Build interfaces through `stack.link` / `stack.address` public APIs vs. keep `NetworkTestCase`'s direct `PacketHandlerL2(...)` + `mock__init`. | **Keep direct construction.** White-box RX-drive tests must inject mocked rings/caches; routing that through the public APIs buys little and the harness already encapsulates it. Drop this aspiration unless a concrete consumer wants it. |
| 3 | Coverage-preservation bar | Each legacy file's unique assertions must be proven to survive (counter snapshots, golden frames, source-route drop, frag reassembly, RFC-specific paths) before deletion — diff each against the protocol-dir + unit coverage. | Mandatory: no net coverage loss. A legacy case with no equivalent elsewhere migrates verbatim (modernised to the harness idiom); a true duplicate is deleted with a one-line note in the commit. |
| 4 | `test__packet_socket__*` (3 files) | Leave in `packet_handler/`; or move to `protocols/packet_socket/`. | Out of scope for this track — leave them. Optional tidy later. |
| 5 | Revert granularity | One commit per protocol (arp, ip4, ip6, ip6_frag, tcp, udp) like the collapse. | Yes — per-protocol commit pairs, full `make test` + §7.2 audit each. |

## 5. Proposed shape once §4 is decided (assuming 1→(b))

Per protocol `<proto>` with a legacy smoke file:

1. **Read** `tests/integration/packet_handler/test__packet_handler__<proto>__<dir>.py`
   and the existing `tests/integration/protocols/<proto>/` tests.
2. **Diff coverage.** For each legacy test method, find its equivalent in
   the protocol dir (or the `_StubInterface` unit test). Tabulate
   unique-vs-duplicate.
3. **Migrate the uniques** into a `tests/integration/protocols/<proto>/`
   file under that protocol's harness, modernised to the
   `drive_rx`/probe/fluent-assert idiom where it fits (golden-byte frames
   are still allowed per `integration_testing.md` §7.4 for wire-format
   assertions).
4. **Delete** the legacy `packet_handler/<proto>` file.
5. **Gate:** `make lint`, full `make test` (must stay 11323), §7.2
   docstring audit on touched files.
6. **Commit** per protocol; push only when asked.

Ordering by independence (smallest blast radius first): arp, ip6_frag,
udp, tcp, ip4 (incl. the source-route file), ip6.

## 6. Risks / watch-items

- **Coverage regression** is the only real risk — mitigated by the §4.3
  diff bar. The legacy files carry some RFC-specific paths (IPv4
  source-route drop, IPv6 EH-chain, frag reassembly ECN aggregation)
  that must land somewhere.
- **`NetworkTestCase` stays.** Do not touch it beyond what a migration
  needs; it underpins the whole integration suite.
- **No behaviour change** — this is a test-only consolidation. Source is
  untouched.
- The `protocols/<proto>/` dirs already have many files; adding the
  migrated cases there should follow the existing file-naming
  (`test__<proto>__<proto>__<rx|tx>.py` per `integration_testing.md` §3.3
  for per-handler smoke, or `test__<proto>__<mechanism>.py` for
  mechanism-focused).

## 7. References

- `docs/refactor/packet_handler_composition.md` — the completed collapse
  track; §8 is the (here-corrected) sketch this supersedes.
- `.claude/rules/integration_testing.md` — harness hierarchy (§4), the
  drive_rx/probe/fluent-assert pattern (§6–§7), golden-frame policy
  (§7.4), file naming (§3.3).
- `tests/lib/network_testcase.py` — the base harness (not a target).
- `tests/lib/tcp_session_testcase.py` — the model the §8 sketch pointed
  at for a protocol-focused harness.
