# Socket parity — `sendmsg` + `SO_LINGER` plan (Track B, corrected scope)

**Authored:** 2026-05-29 on `PyTCP_3_0_6` (HEAD `7766508b`, after the
H2 SO_REUSEPORT track shipped). This is the detailed plan for what the
`socket_parity_followup.md` §2.2 called the "H8 + M2 + M8 cmsg bundle".

## 0. Reality check — most of the bundle is already shipped

The follow-up plan was written before the IP_RECVERR / cmsg work
landed and is **stale**. A code survey of `PyTCP_3_0_6` shows:

- **M8 (`MSG_ERRQUEUE`) is DONE.** `MsgFlag.MSG_ERRQUEUE` exists;
  `UdpSocket.recvmsg` / `TcpSocket.recvmsg` pop the per-socket
  `_error_queue` and emit an `IP_RECVERR` / `IPV6_RECVERR` cmsg via
  `pack_sock_extended_err` (`pytcp/socket/error_queue.py`). Integration
  tests exist: `test__tcp__session__ip_recverr.py`,
  `test__udp__socket_api.py`, `test__udp__ip_options.py`.
- **M2 recv-side (`recvmsg`) is DONE.** Both `UdpSocket.recvmsg`
  (`udp__socket.py:665`) and `TcpSocket.recvmsg` (`tcp__socket.py:1136`)
  return the stdlib `(data, ancdata, msg_flags, address)` shape, with
  `ancdata` already the stdlib `list[(level, type, bytes)]` form. They
  also emit IP_OPTIONS / IP_TOS / IPV6_TCLASS cmsgs when the matching
  `IP_RECV*` option is set.
- **No byte-level CMSG codec is needed.** stdlib `recvmsg`/`sendmsg`
  exchange ancillary data as parsed `(level, type, data)` tuples, not a
  `CMSG_FIRSTHDR`-aligned buffer. PyTCP already uses the tuple form, so
  the follow-up doc's "cmsg encoder/decoder layer" is moot.

**What genuinely remains:**

1. **M2 send-side — `sendmsg` is absent everywhere** (`grep -rn "def
   sendmsg"` → nothing). This is the missing half of the msg API.
2. **Msg-surface completion on the base + Raw flavours.** The abstract
   `socket` base (`socket/__init__.py`) declares neither `recvmsg` nor
   `sendmsg` (both `recvmsg`s live only on the Udp/Tcp subclasses).
   `RawSocket` has no `recvmsg`. For drop-in parity the base should
   declare both (NotImplementedError stubs) and Raw should implement
   them.
3. **H8 `SO_LINGER` — absent from scratch** (`grep -rn "LINGER"` →
   nothing). Option storage + close-path drain behaviour.

Scope is therefore ~1–2 days, not the 3–4 the follow-up estimated.

---

## 1. Phase A — `sendmsg` (M2 send-side) + base/Raw msg surface

**Goal.** Expose stdlib
`sendmsg(buffers, ancdata=[], flags=0, address=None)` and complete the
abstract msg surface so `socket` (the base) and `RawSocket` carry both
`recvmsg` and `sendmsg`.

### A.1 Base abstract stubs (`socket/__init__.py`)
- Add `recvmsg(self, bufsize=None, ancbufsize=0, flags=0, timeout=None)
  -> tuple[bytes, list[tuple[int, int, bytes]], int, <addr>]` and
  `sendmsg(self, buffers, ancdata=(), flags=0, address=None) -> int`
  as `raise NotImplementedError` stubs alongside the existing
  `recv`/`recvfrom`/`sendto` stubs (lines ~1568–1688). Mirrors the
  stdlib signatures. Fixes the "`socket` has no attribute recvmsg"
  type-view (pyright) and gives consumers the parity surface.

### A.2 `UdpSocket.sendmsg` (`udp__socket.py`)
- `buffers`: an iterable of bytes-likes; concatenate to one datagram
  payload (stdlib scatter-gather semantics).
- `address`: when given, behave like `sendto` (unconnected send); when
  `None`, require a connected socket (behave like `send`). Reuse the
  existing `sendto` / `send` body — do not duplicate the bind /
  broadcast-gate / route logic.
- `ancdata`: **Phase-1 = accept-and-ignore unsupported cmsg types.**
  Linux silently ignores cmsg types the protocol doesn't honour; PyTCP
  honours none on send initially (per-send IP_TOS / IP_TTL / IP_PKTINFO
  override is a documented follow-up — mark `# Phase 2: honour
  per-send IP_TOS/IP_TTL cmsg`). Validate that each ancdata entry is a
  3-tuple; otherwise raise the stdlib-shaped error.
- Return the number of payload bytes sent.

### A.3 `TcpSocket.sendmsg` (`tcp__socket.py`)
- `buffers` concatenated → existing `send` path. `address` MUST be
  `None` (connected); raise if supplied (stream socket). `ancdata`
  accepted/ignored as in A.2.

### A.4 `RawSocket.recvmsg` + `RawSocket.sendmsg` (`raw__socket.py`)
- `sendmsg`: concatenate buffers → existing `sendto`/`send`.
- `recvmsg`: wrap the existing `recvfrom` body, return
  `(data, [], 0, address)` — raw sockets carry no cmsgs in PyTCP today
  (the error queue is wired for UDP/TCP). Keep `ancdata` empty;
  document.
- (PacketSocket: out of scope — AF_PACKET has its own `SockAddrLl`
  surface and no cmsg consumer.)

### A.5 Tests-first
- Unit (`test__socket__udp__socket.py`, `__tcp__socket.py`,
  `__raw__socket.py`):
  - `sendmsg([b"AB", b"CD"])` on a connected socket sends `b"ABCD"`
    (scatter-gather concatenation) — assert via the captured TX frame /
    `enqueue` mock payload.
  - `sendmsg([...], address=(ip, port))` on an unconnected UDP socket
    sends to that address.
  - `sendmsg(..., ancdata=[(IPPROTO_IP, IP_TOS, b"\\x10")])` is accepted
    and does not raise (ignored Phase-1).
  - `sendmsg([...], address=...)` on a connected TCP socket raises.
  - `RawSocket.recvmsg` returns the `(data, [], 0, addr)` shape.
- Integration: a `sendmsg` round-trip on UDP through the real TX path
  (extend `test__udp__socket_api.py`) — bytes land on the wire.

---

## 2. Phase B — `SO_LINGER` (H8)

**Goal.** Linux `setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii",
l_onoff, l_linger))` + the close-path behaviour it selects.

### B.1 Option plumbing (`socket/__init__.py`)
- `SolSocketOption.SO_LINGER = 13` (free in the enum; `SO_LINGER=13` at
  SOL_SOCKET — verified against stdlib) + bare alias `SO_LINGER`.
- Field `_so_linger: tuple[int, int] | None` (the `(l_onoff, l_linger)`
  pair, `None` = unset), init `None`.
- setsockopt: the `value` arg already accepts `bytes` (since the H4
  IGMP work). Add a case decoding `struct.unpack("@ii", value)` →
  store `(onoff, linger)`; reject a wrong-length buffer.
- getsockopt: pack `struct.pack("@ii", *(self._so_linger or (0, 0)))`
  back to `bytes` (stdlib returns the linger struct bytes for
  SO_LINGER).

### B.2 Close-path behaviour (`tcp__socket.py` `close()` + `TcpSession`)
TCP-only (linger is meaningless for connectionless UDP/RAW — store it,
no-op on close, matching Linux). Three cases keyed on `_so_linger`:
- **unset, or `l_onoff == 0`** (default): current behaviour — `close()`
  returns immediately; FIN is sent and the FSM drains in the
  background.
- **`l_onoff == 1, l_linger > 0`** (lingering close): `close()` blocks
  until the session reaches a fully-closed state (FIN ACK'd, all queued
  TX drained) OR `l_linger` seconds elapse, then force-finishes. Wait on
  an existing session event / poll the FSM state with a deadline; do
  NOT busy-spin (respect the test-determinism rule — the integration
  test drives the virtual clock).
- **`l_onoff == 1, l_linger == 0`** (abortive close): emit RST
  immediately and discard queued data — i.e. drive `SysCall.ABORT`
  rather than the graceful FIN path (RFC 9293 §3.10.7.4 abort
  semantics). This is the well-known "SO_LINGER zero → RST" idiom.

Reuse the existing close / ABORT machinery; the new code is the
3-way branch on `_so_linger`, not a new teardown path.

### B.3 Tests-first
- Unit: `setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii", 1, 30))`
  → `getsockopt(SOL_SOCKET, SO_LINGER)` round-trips the same bytes;
  default reads as `(0, 0)` packed; wrong-length buffer raises.
- Integration (`TcpTestCase`):
  - `l_onoff=1, l_linger=0` close on an ESTABLISHED session emits a RST
    (assert the TX segment carries RST), not a FIN.
  - graceful (`l_onoff=0`) close still emits FIN (regression guard).
  - lingering (`l_onoff=1, l_linger>0`) close returns after the FIN is
    ACK'd within the timeout (drive the peer ACK via the harness);
    and returns at the deadline when the peer never ACKs (advance the
    virtual clock past `l_linger`).

---

## 3. Phase C — bookkeeping
- Refresh `socket_linux_parity_audit.md` §100: flip **H8 SO_LINGER**,
  **M2 sendmsg/recvmsg**, **M8 MSG_ERRQUEUE** rows to shipped (M2 recv
  / M8 were already shipped — correct the ledger to say so), in the
  same commit as the code that completes each.
- Update `socket_parity_followup.md` §2.2 — mark the bundle done.

---

## 4. Discipline (unchanged from the H2 track)
- Tests-first: a failing test pinning the requirement before each fix.
- One logical unit per commit; `make lint` + full `make test` + the
  §7.2 docstring audit clean before each commit.
- Modernise legacy typing / Python forms on touch.
- RFC / Linux-ground every behavioural claim (cite `socket(7)`,
  `tcp(7)` SO_LINGER, RFC 9293 §3.10.7.4 for the RST-on-abort path).
- Refresh the audit doc in the same commit as a row's status change.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context)
  <noreply@anthropic.com>`. Push only when explicitly asked.

## 5. Out of scope (documented, not implemented)
- Per-send cmsg honouring (IP_TOS / IP_TTL / IP_PKTINFO on `sendmsg`) —
  accept-and-ignore in Phase A; marked `# Phase 2:`.
- Byte-level `CMSG_*` codec — not needed (tuple form is stdlib parity).
- `MSG_OOB` send/recv semantics — PyTCP universally inlines urgent data
  (RFC 6093 §6); unchanged.
- PacketSocket (AF_PACKET) msg surface — no cmsg consumer.

---

## 6. Resume prompt (paste verbatim in a fresh session after compacting)

```
Read docs/refactor/socket_sendmsg_so_linger.md end to end — it's the
detailed plan for the remaining socket-layer "msg API + SO_LINGER" work
on PyTCP_3_0_6 (Track B). Then read CLAUDE.md (Project North Star) and
the rule files in .claude/rules/ (feature_implementation.md, pytcp.md,
typing.md).

Context: the H2 SO_REUSEPORT track shipped + pushed (commits
af536889..7766508b). A code survey then found Track B is mostly already
done: recvmsg (M2 recv-side) and MSG_ERRQUEUE -> IP_RECVERR cmsg (M8)
are SHIPPED on UdpSocket/TcpSocket with tests, and error_queue.py
exists. The cmsg representation is already the stdlib
list[(level,type,data)] tuple form (no byte-level CMSG codec needed).

What genuinely remains (see the plan doc §0):
  Phase A — sendmsg (the missing send-side of M2) on base/Udp/Tcp/Raw
            + complete the abstract recvmsg/sendmsg surface on the base
            class and RawSocket. ancdata accept-and-ignore Phase-1.
  Phase B — SO_LINGER (H8) from scratch: SolSocketOption.SO_LINGER=13 +
            bytes-encoded setsockopt/getsockopt (struct linger) + the
            3-way close-path branch (graceful FIN / lingering wait /
            zero-linger RST-abort). TCP-only behaviour; no-op storage
            on UDP/RAW.
  Phase C — refresh socket_linux_parity_audit.md §100 (H8 + M2 + M8
            rows) and socket_parity_followup.md §2.2.

Follow the standing discipline: tests-first (failing test before each
fix), one logical unit per commit, make lint + full make test + §7.2
docstring audit clean before each commit, modernise legacy forms on
touch, RFC/Linux-ground behavioural claims, commit trailer
"Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
push only when I explicitly say so. Refresh the audit doc in the same
commit as the code when a row's status changes.

Start with Phase A.
```
