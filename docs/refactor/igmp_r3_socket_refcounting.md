# IGMP R3 — Per-socket Membership Refcounting (Sub-plan)

| Field   | Value                                                                 |
|---------|-----------------------------------------------------------------------|
| Status  | Plan — tests-first, no code yet                                       |
| Author  | IGMP design review (2026-05-26)                                       |
| Parent  | `docs/refactor/igmp_refinements.md` §B R3                             |
| Couples | R7 (graceful leave on shutdown — shares the leave path)              |
| Scope   | Make IPv4 multicast membership reference-counted so a group survives until the last holder leaves, and release a socket's memberships on `close()`. NOT new IGMP wire behaviour — the state-change Reports (R1) are unchanged; only *when* the join/leave edges fire changes. |

---

## 1. Problem — today's behaviour

Membership is **presence-based per interface** with no record of *who*
joined:

- `MembershipApi.join` (`stack/membership.py`) is idempotent on
  presence — `if group in handler._ip4_multicast: return`. The first
  joiner adds the group (+ `CHANGE_TO_EXCLUDE_MODE` Report); a second
  joiner is a **silent no-op**.
- `MembershipApi.leave` is presence-based — the first leave calls
  `_remove_ip4_multicast` (drops the MAC filter + sends a
  `CHANGE_TO_INCLUDE_MODE` Leave) and the group is **gone**, even if
  another holder still wants it.
- The socket option handler `_ipproto_ip_membership`
  (`socket/__init__.py`) is a `@staticmethod` — no `self`, so a join /
  leave is **not associated with the issuing socket** and dispatches
  straight to the interface-level API.

Two coupled defects fall out:

1. **First leave wins.** Two sockets joining `239.1.1.1`; when one
   leaves (or closes), the group is dropped and a Leave is sent to the
   router, silently cutting off the other socket.
2. **Close leaks the membership.** A socket that joined and then
   `close()`s without an explicit `IP_DROP_MEMBERSHIP` leaves the group
   joined forever — there is no socket→membership ownership to unwind.

## 2. Linux reference

`net/ipv4/igmp.c` + `net/ipv4/ip_sockglue.c`:

- `struct ip_mc_socklist` — per-socket list of `(ifindex, group)` the
  socket joined.
- Per-interface `struct ip_mc_list` carries a user/refcount.
- `setsockopt(IP_ADD_MEMBERSHIP)` → `ip_mc_join_group`: appends to the
  socket's list and bumps the interface refcount; the IGMP join fires
  only on the `0→1` edge. A socket re-joining a group it already holds
  gets **`EADDRINUSE`**.
- `setsockopt(IP_DROP_MEMBERSHIP)` → `ip_mc_leave_group`: removes from
  the socket's list and decrements; the IGMP Leave fires only on the
  `1→0` edge. Dropping a group the socket is not a member of gets
  **`EADDRNOTAVAIL`**.
- `close()` → `ip_mc_drop_socket`: walks the socket's list and drops
  each membership.
- `net.ipv4.igmp_max_memberships` is a **per-socket** cap on the number
  of groups one socket may join.

## 3. Chosen model

One reference mechanism on the interface, so socket joins and operator
(`ip maddr`-style) joins cannot fight (no split-brain). Per group, the
interface tracks:

| Field            | Meaning                                                        |
|------------------|----------------------------------------------------------------|
| `permanent`      | `True` for 224.0.0.1 (and any future kernel-internal join); never decremented, cannot be left. |
| `operator`       | `True` while the operator API holds the group (set-once, so `MembershipApi.join` stays idempotent). |
| `socket_refcount`| count of distinct sockets currently holding the group.         |

**Joined predicate** = `permanent or operator or socket_refcount > 0`.
The existing `_ip4_multicast` list keeps its meaning — the set of
currently-joined groups (MAC filter installed + IGMP-reported). The
refcount layer decides the **edges**:

- A reference is acquired and the predicate flips `False→True` →
  `_assign_ip4_multicast(group)` (the existing edge primitive: filter +
  `CHANGE_TO_EXCLUDE_MODE` Report).
- A reference is released and the predicate flips `True→False` →
  `_remove_ip4_multicast(group)` (filter drop + `CHANGE_TO_INCLUDE_MODE`
  Leave).

`_assign_ip4_multicast` / `_remove_ip4_multicast` are unchanged — they
stay the edge primitives (so the R1 retransmit path is untouched); only
their *callers* become edge-gated.

Illustrative interface helpers (pseudocode — not final):

```python
def _mc_ref_acquire(self, group, *, kind):   # kind: SOCKET | OPERATOR
    was_joined = self._mc_is_joined(group)
    ... bump operator flag or socket_refcount ...
    if not was_joined and self._mc_is_joined(group):
        self._assign_ip4_multicast(group)     # 0->1 edge

def _mc_ref_release(self, group, *, kind):
    ... clear operator flag or decrement socket_refcount ...
    if was_joined and not self._mc_is_joined(group):
        self._remove_ip4_multicast(group)     # 1->0 edge
```

The socket gains a join-set `self._ip4_memberships: set[tuple[int,
Ip4Address]]`; `_ipproto_ip_membership` becomes an **instance** method
that records into it and `close()` releases each entry.

## 4. Decisions (and rationale)

1. **Unified interface refcount (not socket-layer-only).** Both socket
   and operator joins feed one predicate so an operator leave cannot
   clobber a socket holder and vice-versa. The alternative (refcount
   only at the socket layer, operator API stays fully presence-based)
   leaves the operator/socket split-brain — rejected.
2. **`MembershipApi.join/leave` keep their idempotent operator
   contract.** They manipulate the single `operator` flag, so existing
   `MembershipApi` tests (two joins = one state; leave drops when no
   other holder) still hold. Only the *cross-actor* case changes:
   operator-leave no longer drops a group a socket still holds.
3. **Socket double-join → `EADDRINUSE`; socket drop of a non-member →
   `EADDRNOTAVAIL`** (Linux parity). Behaviour change vs today's
   lenient no-op; flagged in the tests.
4. **`close()` releases the socket's memberships** (Linux
   `ip_mc_drop_socket`). This is the leak fix and the natural overlap
   point with R7.
5. **224.0.0.1 stays `permanent`** — never refcounted, never left
   (existing guard preserved).

## 5. Out of scope / deferred

- **Per-socket `igmp_max_memberships`.** Linux scopes the cap per
  socket; the join-set introduced here is the correct future home, but
  R3 keeps the existing **per-interface** cap to avoid widening the
  blast radius. Tracked as a follow-on near R4 (which fixes the cap's
  errno: `EINVAL`→`ENOBUFS`).
- **Source-specific membership** (`IP_ADD_SOURCE_MEMBERSHIP`, RFC 3376
  §9) — separate feature track.
- **MLDv2 parity.** The IPv6 side has the same presence-based shape;
  mirror this model there as a sibling task once R3 lands for IPv4.

## 6. Touch list

- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` — per-group
  ref state + `_mc_ref_acquire` / `_mc_ref_release` / `_mc_is_joined`
  helpers (L2 + L3); initialise state at construction; mark 224.0.0.1
  permanent at boot-join.
- `packages/pytcp/pytcp/stack/membership.py` — `join` / `leave` route
  through the operator reference; `list_memberships` unchanged.
- `packages/pytcp/pytcp/socket/__init__.py` — `_ipproto_ip_membership`
  becomes an instance method recording into `self._ip4_memberships`;
  `EADDRINUSE` / `EADDRNOTAVAIL` mapping; `close()` releases the set.
- Tests under
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/`.
- `docs/rfc/ip4/rfc3376__igmp_v3/adherence.md` — refresh the §6 /
  membership-lifecycle entry (refcounted edges).
- `docs/refactor/igmp_refinements.md` — mark R3 shipped on landing.

## 7. Tests-first plan (phased)

Each phase opens with the failing tests, then the implementation flips
them green. Immediate-Report assertions can use `NetworkTestCase` (the
Leave is an immediate Report — no timer advance needed); retransmit-
train assertions use `IcmpTestCase`.

### Phase A — interface refcount via two sockets — SHIPPED

**Shipped.** `MembershipRefKind` (OPERATOR / SOCKET) added to the
membership API; `MembershipApi.join` / `leave` take a `kind` and route
through new edge-gated interface helpers `_mc_is_joined` /
`_mc_ref_acquire` / `_mc_ref_release` (per-group `_Ip4MulticastRefs` =
`operator` flag + `socket_count`), so `_assign` / `_remove_ip4_multicast`
(and their Reports) fire only on the not-joined↔joined edge. The socket
facade's `_ipproto_ip_membership` is now an instance method recording
each `(ifindex, group)` in `self._ip4_memberships` and acquiring /
releasing a SOCKET reference. All four
`test__igmp__socket_membership_refcount.py` tests pass.

**Failing tests first** (new
`test__igmp__socket_membership_refcount.py`):

- `test__igmp__refcount__second_joiner_emits_no_report` — two sockets
  join G; assert exactly **one** `CHANGE_TO_EXCLUDE_MODE` Report fired
  (the `0→1` edge), the second join is silent, and `list_memberships`
  shows G once.
- `test__igmp__refcount__first_leaver_retains_group` — two sockets join
  G, one leaves; assert G is **still joined** and **no** Leave Report
  fired.
- `test__igmp__refcount__last_leaver_drops_group` — the second leaves;
  assert G dropped + exactly one `CHANGE_TO_INCLUDE_MODE` Leave.
- `test__igmp__refcount__operator_leave_respects_socket_holder` — a
  socket holds G, operator `leave` is called; assert G retained, no
  Leave (decision 1/2).

**Then implement** the interface ref state + edge gating and the
instance-method socket handler.

### Phase B — close releases memberships

**Failing tests first:**

- `test__igmp__refcount__close_releases_membership` — a socket joins G
  then `close()`s; assert G released + one Leave (it was the only
  holder).
- `test__igmp__refcount__close_one_of_two_retains_group` — two sockets
  join G, one `close()`s; assert G retained, no Leave; the other
  `close()`s → G dropped + Leave.

**Then implement** `close()` cleanup walking `self._ip4_memberships`.

### Phase C — Linux errno parity

**Failing tests first:**

- `test__igmp__refcount__double_join_raises_eaddrinuse` — same socket
  joins G twice; second `setsockopt(IP_ADD_MEMBERSHIP)` raises
  `OSError(EADDRINUSE)`; the interface refcount stays 1.
- `test__igmp__refcount__drop_non_member_raises_eaddrnotavail` —
  `IP_DROP_MEMBERSHIP` for a group this socket never joined raises
  `OSError(EADDRNOTAVAIL)`.

**Then implement** the per-socket join-set membership checks + errno
mapping.

## 8. Existing tests to revisit

- `test__igmp__socket_membership_opts.py` — was written against the
  presence-based static handler; re-verify each case under the
  refcount model (single-socket join/leave behaviour is unchanged, so
  most should pass as-is; the double-join / drop-non-member cases move
  to Phase C semantics).
- `test__igmp__membership_api.py` — operator idempotency + leave-drops
  cases must stay green (decision 2); add the cross-actor case in
  Phase A.

## 9. Sequencing

Phase A → B → C, each a tests-first commit (A and B may combine if the
close hook is small). R3 and **R7** (graceful leave on shutdown) share
the leave path — land R3 first so R7's shutdown sweep simply releases
every holder through the same edge-gated primitive. The full
`make test` runs after each phase (the socket facade + shared
interface state are broad-blast surfaces).

## 10. Cross-references

- `docs/refactor/igmp_refinements.md` — the parent ledger (R3, R7).
- `docs/refactor/igmp_host_membership.md` — the shipped Phases 0-6.
- `docs/rfc/ip4/rfc3376__igmp_v3/adherence.md` — §6 membership
  lifecycle.
- Linux `net/ipv4/igmp.c`, `net/ipv4/ip_sockglue.c`
  (`ip_mc_join_group`, `ip_mc_leave_group`, `ip_mc_drop_socket`).
