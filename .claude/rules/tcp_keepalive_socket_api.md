# PyTCP — TCP Keep-Alive Socket-API Record

**Status: SHIPPED** (all 5 phases delivered). This document
was originally a phased plan; it has been rewritten as a
completion record. Future sessions wanting to extend the
BSD socket-API surface (e.g. add `TCP_NODELAY`,
`SO_RCVBUF`) can use this record as the canonical pattern
to mirror.

Phase-by-phase commit map:

| Phase | Description                                          | Commit       |
|-------|------------------------------------------------------|--------------|
| 0     | `SocketOption` enum + `SOL_SOCKET` constant          | `f356ad9c`   |
| 1     | `TcpSocket.setsockopt` / `getsockopt` for SO_KEEPALIVE | `1cf10cdd` |
| 2     | Propagate SO_KEEPALIVE through TcpSocket → TcpSession | `21047340`  |
| 3     | Update keep-alive flag comment to socket-API path    | `3f2d6660`   |
| 4     | Per-connection overrides via TCP_KEEPIDLE/INTVL/CNT  | `0647485a`   |

Tests delivered: 15 setsockopt/getsockopt unit tests in
`pytcp/tests/unit/socket/test__socket__tcp__socket.py` + 9
keep-alive integration tests in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive.py`.

The original plan body is preserved below as a historical
reference.

---

## 1. Mission (delivered)

The keep-alive mechanism (`tcp__session.py`,
`tcp__fsm__established.py`, six-scenario integration test in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive.py`)
is internally complete: idle-timer arming, probe emission with
`seq=SND.NXT-1`, probe-ack reset, tear-down on
`KEEPALIVE_PROBE_MAX_COUNT` unanswered probes. The
application-facing API is now wired — RFC 1122 §4.2.3.6
mandate fulfilled.

The work in this plan delivers four BSD socket options:

| Option              | Level         | Type | Default | Purpose                                          |
|---------------------|---------------|------|---------|--------------------------------------------------|
| `SO_KEEPALIVE`      | `SOL_SOCKET`  | int  | 0       | Enable / disable keep-alive on this connection   |
| `TCP_KEEPIDLE`      | `IPPROTO_TCP` | int  | None    | Per-conn override for `KEEPALIVE_IDLE_TIME`      |
| `TCP_KEEPINTVL`     | `IPPROTO_TCP` | int  | None    | Per-conn override for `KEEPALIVE_PROBE_INTERVAL` |
| `TCP_KEEPCNT`       | `IPPROTO_TCP` | int  | None    | Per-conn override for `KEEPALIVE_PROBE_MAX_COUNT`|

After this work, the canonical Linux-style invocation works:

```python
sock = socket(family=AddressFamily.INET4, type_=SocketType.SOCK_STREAM)
sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
sock.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 60)     # optional
sock.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 10)    # optional
sock.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 5)       # optional
sock.connect(("10.0.1.7", 80))
# Connection has keep-alive enabled with 60 s idle / 10 s probe / 5 probes.
```

`SO_KEEPALIVE` is the MUST per RFC 1122; the three TCP-level
overrides are convenience that matches Linux behaviour but are
not RFC-mandated. Phases 0-3 deliver `SO_KEEPALIVE` plus
`getsockopt` round-trip; phase 4 adds the per-connection
overrides.

---

## 2. Standing principles (preserved)

1. **Tests-first per phase.** Each phase opens with a tests-first
   commit asserting the new behaviour, with `[FLAGS BUG]`
   failures for unimplemented surface. The fix commit follows.
   Mirrors the workflow in `tcp_session_integration_tests.md`
   §7 and the keepalive feature commits `16ea847` / `bb34a81`.
2. **Test invariant.** Suite count and pass count never drop
   across a green commit boundary. The keepalive baseline at
   the start of this plan is `7833 passing, 17 skipped, 0
   failures`.
3. **No pre-fix bug fixes.** If something stale is surfaced
   while wiring this up (e.g. the inaccurate "Flip True before
   CONNECT / LISTEN" comment in `tcp__session.py`'s
   `_keepalive_enabled` declaration), capture it but defer the
   correction to a separate small commit so the option-API
   commits stay focused.
4. **POSIX shape, integer-int values.** `setsockopt` takes an
   `int` value; for boolean options (`SO_KEEPALIVE`) any
   non-zero is True. `getsockopt` returns the stored `int`.
   This matches the stdlib `socket` module and the Linux
   man page.
5. **Validation at the boundary, not later.** `setsockopt`
   raises on unknown level / optname / out-of-range value
   immediately, not silently storing garbage that a later
   `getsockopt` would surface.

---

## 3. Target architecture (final state)

```
pytcp/
    socket/
        __init__.py                  Add SocketOptionLevel + SocketOption enums
        tcp__socket.py               TcpSocket grows setsockopt / getsockopt + per-option storage;
                                     connect() / listen() propagate to TcpSession
    protocols/
        tcp/
            tcp__session.py          TcpSession grows _keepalive_idle_override / _keepalive_interval_override /
                                     _keepalive_max_count_override (Optional[int]); _keepalive_arm_idle
                                     and _keepalive_tick read 'override or tcp__constants.X'.
                                     Listener-fork in tcp__fsm__listen.py copies these onto the
                                     freshly-constructed listening session so the next-connection
                                     child inherits.
    tests/
        unit/
            socket/
                test__socket__tcp__socket.py            Grows SocketOption tests
        integration/
            protocols/
                tcp/
                    test__tcp__session__keepalive_socket_api.py  NEW — end-to-end via setsockopt
```

The per-session override fields default to `None`; the keep-
alive helpers read `self._keepalive_idle_override or
tcp__constants.KEEPALIVE_IDLE_TIME` etc. so phase 4 is a pure
add — no existing test needs to change.

---

## 4. Phase-by-phase plan

### Phase 0 — Add socket option enums (preflight)

Single commit, no behaviour change.

1. In `pytcp/socket/__init__.py` add two `IntEnum` (NOT
   `NameEnum`) classes — option levels and option names use
   integer values everywhere in the BSD API; matching Linux
   numbers keeps interop expectations honest:
   ```python
   class SocketOptionLevel(IntEnum):
       """
       BSD setsockopt 'level' parameter.
       """

       SOL_SOCKET = 1
       IPPROTO_TCP = 6

   class SocketOption(IntEnum):
       """
       BSD setsockopt 'optname' parameter.
       """

       SO_KEEPALIVE = 9       # SOL_SOCKET
       TCP_KEEPIDLE = 4       # IPPROTO_TCP, in seconds
       TCP_KEEPINTVL = 5      # IPPROTO_TCP, in seconds
       TCP_KEEPCNT = 6        # IPPROTO_TCP, count
   ```
2. Re-export the enums and the bare `SOL_SOCKET` /
   `IPPROTO_TCP` / `SO_KEEPALIVE` / `TCP_KEEP*` integer aliases
   so call sites can use either form (the stdlib `socket` module
   exposes both, applications expect both).
3. `make lint` / `make test` clean — no functional change.

### Phase 1 — `setsockopt` / `getsockopt` skeleton

Tests-first commit + fix commit.

**Tests** (`pytcp/tests/unit/socket/test__socket__tcp__socket.py`,
new `TestTcpSocketOptions` class):

  - `test__tcp_socket__setsockopt__so_keepalive_stores_flag`
    [FLAGS BUG] — calls
    `sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)`, asserts a
    later `sock.getsockopt(SOL_SOCKET, SO_KEEPALIVE) == 1`.
    Fails today because the methods don't exist.
  - `test__tcp_socket__setsockopt__so_keepalive_zero_disables`
    [FLAGS BUG] — same shape, value 0, asserts round-trip.
  - `test__tcp_socket__setsockopt__non_zero_value_normalises_to_one`
    regression guard — boolean options collapse non-zero to 1
    (matches Linux). `setsockopt(..., 42)`,
    `getsockopt(...) == 1`.
  - `test__tcp_socket__setsockopt__unknown_level_raises`
    [FLAGS BUG] — invalid level raises `OSError(ENOPROTOOPT)`
    or a clear typed error. (Matches POSIX semantics.)
  - `test__tcp_socket__setsockopt__unknown_optname_raises`
    [FLAGS BUG] — invalid optname raises.
  - `test__tcp_socket__getsockopt__default_so_keepalive_is_zero`
    regression — fresh socket, `getsockopt(SO_KEEPALIVE) == 0`.

**Fix** (`pytcp/socket/tcp__socket.py`):

  - Add `_so_keepalive: bool = False` attribute initialized in
    `__init__`.
  - Add `setsockopt(level, optname, value, /)` that dispatches
    on `(level, optname)` and stores into the appropriate
    attribute.
  - Add `getsockopt(level, optname, /)` that reads back the
    stored value as `int`.
  - Validation: `(SOL_SOCKET, SO_KEEPALIVE)` is the only legal
    pair in this phase; other combinations raise.

After phase 1, the API exists but does nothing. The session
still has to propagate the flag.

### Phase 2 — Propagate `SO_KEEPALIVE` into `TcpSession`

Tests-first commit + fix commit.

**Tests** (new
`pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive_socket_api.py`):

  - `test__keepalive_api__setsockopt_then_connect_arms_keepalive`
    [FLAGS BUG] — drive an active-open with
    `setsockopt(SO_KEEPALIVE, 1)` before `connect`, advance past
    KEEPALIVE_IDLE_TIME, assert one probe fires. Today the flag
    is set on the socket but never reaches the session, so no
    probe.
  - `test__keepalive_api__no_setsockopt_no_probe`
    regression — equivalent of the existing
    `disabled_by_default_no_probe_ever_fires` but driven via
    the socket API. Should pass with no implementation change
    (default-off invariant).
  - `test__keepalive_api__setsockopt_then_listen_propagates_to_child`
    [FLAGS BUG] — listening socket with
    `setsockopt(SO_KEEPALIVE, 1)`, drive a peer SYN, assert the
    accept()'d child socket has `_so_keepalive == 1` AND its
    underlying session's `_keepalive_enabled == True`. Tests
    listener-fork inheritance.

**Fix** (`pytcp/socket/tcp__socket.py`):

  - In `connect()`, after `self._tcp_session = TcpSession(...)`
    and before `self._tcp_session.connect()`:
    ```python
    self._tcp_session._keepalive_enabled = self._so_keepalive
    ```
  - Same in `listen()` after the listening session is
    constructed.

**Fix** (`pytcp/protocols/tcp/tcp__fsm__listen.py`):

  - In the listener-fork pivot (the in-place re-binding of the
    LISTEN-state session to the child + fresh listening
    session), the FRESH listening session inherits the keep-
    alive setting from the listening socket so subsequent
    children also get it. Concretely: after
    `tcp_session = TcpSession(...)` and
    `session._socket._tcp_session = tcp_session`, propagate via
    ```python
    tcp_session._keepalive_enabled = session._socket._so_keepalive
    ```

### Phase 3 — Documentation + comment fixes

Single small commit.

  - Update the `_keepalive_enabled` declaration comment in
    `tcp__session.py` (lines 173-181) — currently says "Flip
    True before CONNECT / LISTEN to enable", which is
    impossible from outside the session. The new comment
    should say: "Set via TcpSocket.setsockopt(SOL_SOCKET,
    SO_KEEPALIVE, 1); the socket propagates the flag into this
    field at TcpSession construction time."
  - Add a docstring example to `TcpSocket.setsockopt` showing
    the `SO_KEEPALIVE` enable form.
  - Update `CLAUDE.md` if the BSD-socket facade description
    needs adjusting (probably not, the existing text is
    generic).

### Phase 4 — Per-connection overrides (optional / Linux parity)

Tests-first commit + fix commit. This is gravy on top of
phases 0-3; phases 0-3 alone deliver the RFC 1122 MUST.

**Tests:**

  - `test__keepalive_api__tcp_keepidle_override_uses_per_conn_value`
    [FLAGS BUG] — `setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 200)`
    before connect, advance to verify probe fires at 200 ms
    boundary instead of the patched-default 100 ms. (Patch the
    constant default to a different value to confirm the
    override is read, not the constant.)
  - Same shape for `TCP_KEEPINTVL` and `TCP_KEEPCNT`.
  - `test__keepalive_api__overrides_set_after_connect_take_effect`
    [FLAGS BUG] — Linux `setsockopt(TCP_KEEPIDLE, ...)` works
    even mid-connection. Verify mutating
    `_keepalive_idle_override` post-handshake is honoured by
    the next idle-timer arm.
  - `test__keepalive_api__getsockopt_overrides_round_trip`
    regression / [FLAGS BUG] — set / read each TCP-level
    override.

**Fix** (`pytcp/protocols/tcp/tcp__session.py`):

  - Add three `Optional[int]` instance fields:
    ```python
    self._keepalive_idle_override: int | None = None
    self._keepalive_interval_override: int | None = None
    self._keepalive_max_count_override: int | None = None
    ```
  - Modify `_keepalive_arm_idle` to use
    ```python
    timeout=self._keepalive_idle_override or tcp__constants.KEEPALIVE_IDLE_TIME
    ```
  - Same `or`-fallback in `_keepalive_tick` for
    `KEEPALIVE_PROBE_INTERVAL` and `KEEPALIVE_PROBE_MAX_COUNT`.

**Fix** (`pytcp/socket/tcp__socket.py`):

  - Add three matching socket-side fields (same `Optional[int]`
    shape).
  - Extend `setsockopt` / `getsockopt` to handle the three new
    `(IPPROTO_TCP, TCP_KEEP*)` pairs.
  - Propagate in `connect()` / `listen()` alongside the
    `_so_keepalive` flag.
  - Listener-fork propagation in `tcp__fsm__listen.py` extends
    to copy all three.

---

## 5. Importer / call-site map

Adjusted by this work:

| File                                            | Phase | Change                                                    |
|-------------------------------------------------|-------|-----------------------------------------------------------|
| `pytcp/socket/__init__.py`                      | 0     | New `SocketOptionLevel` / `SocketOption` enums             |
| `pytcp/socket/tcp__socket.py`                   | 1, 2, 4 | `setsockopt` / `getsockopt`; per-option fields; propagation in `connect()` / `listen()` |
| `pytcp/protocols/tcp/tcp__session.py`           | 3, 4 | Comment fix; per-connection override fields and helper-read changes |
| `pytcp/protocols/tcp/tcp__fsm__listen.py`       | 2, 4 | Listener-fork copies keepalive options to fresh listening session |
| `CLAUDE.md`                                     | 3   | (Likely no change needed)                                  |

New test files:

| File                                                                                            | Phase  |
|-------------------------------------------------------------------------------------------------|--------|
| `pytcp/tests/unit/socket/test__socket__tcp__socket.py` (existing, grow `TestTcpSocketOptions`)  | 1, 4 |
| `pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive_socket_api.py` (new)       | 2, 4 |

---

## 6. Estimated effort

| Phase | Description                          | Commits | Risk    |
|-------|--------------------------------------|---------|---------|
| 0     | Add SocketOption enums (preflight)   | 1       | trivial |
| 1     | setsockopt / getsockopt skeleton     | 2 (test + fix) | low |
| 2     | SO_KEEPALIVE propagation             | 2       | low |
| 3     | Docstring / comment cleanup          | 1       | trivial |
| 4     | Per-connection overrides (optional)  | 2-3     | medium |

Total: **8-9 commits**, ~3-4 hours of focused work in a fresh
context. Phase 4 is the only one that requires new test
patching of constants and careful timing accounting (mirror
the existing keepalive scenarios' timing approach).

---

## 7. Anti-patterns to avoid

- **Don't introduce a separate "TcpSocketOptions" class.** Per-
  option fields live directly on `TcpSocket`. Future options
  (TCP_NODELAY, SO_RCVBUF, etc.) follow the same pattern and
  the option-name / option-field mapping stays explicit.

- **Don't validate option values inside `TcpSession`.**
  Validation happens at the BSD-API boundary in
  `TcpSocket.setsockopt` so the session always sees clean
  pre-validated config. The session field types are the
  load-bearing contract between the layers.

- **Don't expose `setsockopt` on `RawSocket` / `UdpSocket`
  unless tests are written for them.** Keep the surface tight.
  TCP-level options are TCP-only by definition; SOL_SOCKET-
  level options like SO_KEEPALIVE are TCP-meaningful here but
  could in principle apply to raw / udp later — defer until
  there's a real consumer.

- **Don't use `NameEnum` for `SocketOptionLevel` /
  `SocketOption`.** These need integer values that match the
  Linux numbers (the BSD API is integer-typed); use `IntEnum`
  from `enum`.

- **Don't add `setsockopt` calls inside the keepalive helpers
  (`_keepalive_arm_idle` / `_keepalive_tick`).** Those are
  protocol-runtime functions; they read the override fields
  directly. The socket layer is the only consumer of
  `setsockopt`.

- **Don't break the bilateral-flag-set semantics.** In
  TcpSession, `_keepalive_enabled` is a bool. The socket
  layer's `_so_keepalive` is also a bool (or 0/1 int). At the
  propagation hook in `connect()` / `listen()`, the
  `bool(self._so_keepalive)` cast is the canonical bridge.

- **Don't conflate "option set" with "option enabled".**
  `setsockopt(SO_KEEPALIVE, 0)` is a valid call that disables
  a previously-enabled keep-alive. `setsockopt(TCP_KEEPIDLE,
  0)` should NOT mean "disable", it should mean "use 0 ms"
  (which is degenerate but the API doesn't gate it). For
  TCP_KEEP* overrides, the special "no override" value is
  `None` (set by *not* calling setsockopt at all), not 0.

---

## 8. Re-orient command for new sessions

```bash
git log --oneline -10
ls pytcp/socket/tcp__socket.py
grep -n "setsockopt\|SO_KEEPALIVE" pytcp/socket/__init__.py pytcp/socket/tcp__socket.py 2>/dev/null
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive_socket_api.py 2>/dev/null
make test 2>&1 | tail -5
```

What it tells you:
- No `setsockopt` in either file → phase 0/1 not started.
- `setsockopt` present but no `keepalive_socket_api` test file
  → phase 2 not started.
- All present → phase 3/4 status check via the test file's
  scenario list.

Match against §4 to pick up where the prior session left off.

---

## 9. Cross-references

- Keep-alive feature shipped: commits `6d54e14` (preflight
  constants) → `16ea847` (tests) → `b0c7791` (test #6
  strengthening) → `bb34a81` (impl).
- Keep-alive integration tests:
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive.py`
  (covers protocol-level behaviour; this plan covers the
  socket-layer wiring above it).
- TcpSocket facade: `pytcp/socket/tcp__socket.py` —
  `connect()` at line 266, `listen()` at line 322 are the
  propagation hook points.
- Listener-fork pattern:
  `pytcp/protocols/tcp/tcp__fsm__listen.py` — the in-place
  pivot at lines ~120-145 is where child-session inheritance
  needs the keepalive fields copied.
- Coding style for socket options: `.claude/rules/coding_style.md`
  §15 (enums), §6 (module-level constants), §17 (docstring
  format).
- Unit test authoring: `.claude/rules/unit_tests.md` §3 (test
  filename mapping for `pytcp/socket/*.py` sources).
