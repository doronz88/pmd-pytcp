# IPv6 Extension Headers — Deployment Plan

**Status:** **SHIPPED** on `PyTCP_3_0_6`. All phases landed: the
`Ip6_HBH` / `IP6_ROUTING` / `IP6_DEST_OPTS` / `IP6_NO_NEXT_HEADER`
`IpProto` members, the typed HBH / Destination-Options / Routing-Header
parsers + options (`packages/net_proto/net_proto/protocols/ip6_hbh/`,
`ip6_dest_opts/`, `ip6_routing/`), the IPv6 RX chain-walker dispatch,
and the RFC 8200 / RFC 5095 adherence records. The sections below are
retained as the implementation guide / archaeology.
**Branch:** delivered on `PyTCP_3_0_6` (this plan was authored on the
earlier `PyTCP_3_0__pre_release` line).

---

## 0. Reading order before any code

A fresh agent picking this up MUST read, in order:

1. **This document** end to end.
2. `CLAUDE.md` — Project North Star (Linux parity in two phases),
   Tests First MUST, file-naming + linting conventions.
3. `.claude/rules/feature_implementation.md` — commit discipline,
   tests-first procedure, "Linux as tiebreaker" rule.
4. `.claude/rules/unit_testing.md` — full test-authoring rule
   including the §7.2 self-audit script (BLOCKER — non-negotiable
   before every commit).
5. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` — source authoring rule
   (file skeleton, license block, dataclass conventions, six-file
   per-protocol layout).
6. `docs/refactor/icmp_demux_pmtud_plan.md` — the precedent plan
   from a previous multi-phase project. Same project shape;
   reference for tone and detail level.
7. `docs/rfc/icmp6/rfc4443__icmp6/rfc4443.txt`,
   `docs/rfc/icmp6/rfc4861__ipv6_nd/rfc4861.txt`,
   `docs/rfc/ip6/rfc8200__ipv6/rfc8200.txt`,
   `docs/rfc/ip6/rfc5095__deprecate_rh0/rfc5095.txt`,
   `docs/rfc/ip6/rfc8504__ipv6_node_reqs/rfc8504.txt`,
   `docs/rfc/icmp6/rfc3810__mld2/rfc3810.txt` — RFC text
   (already downloaded and in-tree).

---

## 1. Goal

Build first-class typed parsing/assembling for the three IPv6
extension headers PyTCP currently does not handle — Hop-by-Hop
Options (`IpProto.IP6_HBH = 0`), Routing Header
(`IpProto.IP6_ROUTING = 43`), and Destination Options
(`IpProto.IP6_DEST_OPTS = 60`) — and wire them into the IPv6 RX
path with a chain-walking dispatch in RFC 8200 §4.1 order.
Outcome: PyTCP closes RFC 8200 §4 (extension-header processing),
RFC 5095 §3 (RH0 hard-drop), and unblocks RFC-compliant MLDv2
emission per RFC 3810 §5.

This is the IPv6-layer feature-parity push that the
ICMPv6-specific work (RA prefix lifetime, NS DAD validation,
MLDv2 RX cleanup — tasks 283 / 284 / 285) depends on for
correctness on real networks.

### 1.1 Why this matters concretely

- **Multicast doesn't currently work in real networks.** MLDv2
  reports MUST carry HBH Router Alert (RFC 3810 §5 + RFC 2711);
  MLD-aware switches/routers silently ignore reports without it,
  so peer multicast traffic never reaches the host. PyTCP today
  cannot emit HBH on outbound packets, so MLDv2 group joining
  is broken.
- **Inbound IPv6 packets carrying any non-Frag extension header
  are dropped with Parameter Problem code 1.** The catch-all
  unrecognized-next-header path in
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py:151-167`
  rejects HBH (next=0), Routing (43), DestOpts (60). Linux
  freely uses these; PyTCP silently breaks interop with hosts
  that send them.
- **RH0 amplification attack vector is open.** RFC 5095 §3
  hard-drops RH0 with Parameter Problem code 0, pointer at the
  routing-type byte. PyTCP currently emits Parameter Problem
  code 1 with pointer 6 — wrong code, wrong pointer, but the
  packet is dropped, so the security MUST is met *in spirit*
  but not *in letter*.
- **Phase-2 router work is foreclosed without typed extensions.**
  A future router must forward extension headers faithfully;
  blob-and-drop semantics today force a rewrite later.
  The Project North Star (`CLAUDE.md`) mandates parsing as
  typed objects to keep the Phase-2 upgrade path open.

---

## 2. Scope

### 2.1 In scope (Phase 1 — host stack parity)

| Component | RFC | Files added | Notes |
|---|---|---|---|
| Hop-by-Hop Options package | 8200 §4.3 | `packages/net_proto/net_proto/protocols/ip6_hbh/` (6 files + `options/` subdir) | Mirrors `packages/net_proto/net_proto/protocols/ip6_frag/` shape |
| Pad1, PadN options | 8200 §4.2 | `ip6_hbh/options/ip6_hbh__option__{pad1,padn}.py` | TLV padding |
| Router Alert option | 2711 | `ip6_hbh/options/ip6_hbh__option__router_alert.py` | Type 0x05, length 2 |
| Jumbo Payload option | 2675 | `ip6_hbh/options/ip6_hbh__option__jumbo_payload.py` | Type 0xC2, length 4; with payload-length=0 semantics |
| CALIPSO option | 5570 | `ip6_hbh/options/ip6_hbh__option__calipso.py` | Type 0x07; shallow (DOI + opaque tags), Linux NetLabel parity |
| Destination Options package | 8200 §4.6 | `packages/net_proto/net_proto/protocols/ip6_dest_opts/` | Same shape as `ip6_hbh/` |
| Destination Options Pad1, PadN | 8200 §4.2 | `ip6_dest_opts/options/...` | Re-use Pad1/PadN — see decision §3.4 |
| Tunnel Encapsulation Limit | 2473 §4 | `ip6_dest_opts/options/ip6_dest_opts__option__tunnel_encapsulation_limit.py` | Linux parity |
| Routing Header package | 8200 §4.4 + RFC 5095 | `packages/net_proto/net_proto/protocols/ip6_routing/` | RH0 hard-drop, others parsed-as-opaque |
| Chain-walker dispatch | 8200 §4.1 + §4.2 | edits in `packet_handler__ip6__rx.py` | Forward chain walk; Frag re-entry preserved |
| MLDv2 HBH Router Alert | 3810 §5 + 2711 | edits in `packet_handler__icmp6__tx.py` (or wherever MLDv2 reports are emitted) | Outbound MLDv2 reports MUST carry HBH RA |
| Adherence records | 8200, 5095 | `docs/rfc/ip6/rfc8200__ipv6/adherence.md`, `docs/rfc/ip6/rfc5095__deprecate_rh0/adherence.md` | Phase-by-phase clause-pinning audit |

### 2.2 Out of scope (deliberate non-goals)

| Item | Why excluded | Where recorded |
|---|---|---|
| AH (Authentication Header, next=51) | Crypto extension; explicit non-goal in `CLAUDE.md` Project North Star | This plan §2.2 |
| ESP (Encapsulating Security Payload, next=50) | Same | Same |
| RH2 mobility processing (Type 2) | Mobility extensions explicit non-goal | Parsed as opaque only; no semantic action |
| RH3 RPL semantics (Type 3) | IoT-specific, not Linux-host scope | Parsed as opaque only |
| RH4 Segment Routing semantics (Type 4) | Datacenter feature, Linux-host scope | Parsed as opaque only |
| Home Address option (Type 0xC9) in DestOpts | RFC 6275 mobility | Skip |
| IOAM option | RFC 9197 — not Linux-default | Skip |
| Quick-Start option (RFC 4782) | Experimental | Skip |

### 2.3 Out of scope (deferrable to follow-up Phase-1 commits)

| Item | Why deferred | Phase |
|---|---|---|
| Fragment-overlap detection (RFC 5722) | Independent of extension-header chain | Task 281 — can run in parallel |
| Atomic-fragment fast-path (RFC 8200 §4.5) | Independent | Task 282 — parallel |
| Other ICMPv6 punch-list items (NS DAD §284, RA prefix lifetime §283, MLDv2 stub cleanup §285) | Independent of extension headers | Run in parallel after Phase 0 |

### 2.4 Phase 2 (router-grade) hooks

Per the Project North Star "Phase 2 awareness" rule, every
parser must preserve fields a forwarder would need to re-emit
the same packet. Concretely:

- HBH options: the option's `Type` byte (including the top-2-bit
  action-on-unrecognized) and `Data` payload preserved in the
  `Ip6HbhOption*` dataclass so a future forwarder re-emits
  byte-for-byte.
- Routing Header: the routing-type byte preserved as `RoutingType`
  enum (incl. unknown values via the dynamic-extension hook in
  `ProtoEnumByte`); segments-left and addresses preserved as
  list. Forwarder needs all of these to decrement `segments_left`
  and pop the next address.
- Destination Options: same as HBH.
- Mark `# Phase 2:` comments on any host-side simplifications
  (e.g. dropping unknown-option-action-codes 01/10/11 vs.
  forwarder behavior — see §3.7).

---

## 3. Architecture decisions

### 3.1 Per-extension package layout

Each extension header gets its own package under
`packages/net_proto/net_proto/protocols/`, peer of `ip6_frag/`:

```
packages/net_proto/net_proto/protocols/ip6_hbh/
  ip6_hbh__header.py       # frozen dataclass + RFC 8200 §4.3 wire format
  ip6_hbh__base.py         # dunders + property accessors
  ip6_hbh__parser.py       # 3-phase pipeline + chain advance
  ip6_hbh__assembler.py    # kw-only ctor + assemble()
  ip6_hbh__errors.py       # Ip6HbhIntegrityError, Ip6HbhSanityError
  options/
    ip6_hbh__option.py        # base + Ip6HbhOptionType enum
    ip6_hbh__option__pad1.py  # 1-byte Pad1
    ip6_hbh__option__padn.py  # variable-length PadN
    ip6_hbh__option__unknown.py  # generic catch-all (per Phase-2 awareness)
    ip6_hbh__options.py       # container + walker + RFC 8200 §4.2 action handling
```

`ip6_dest_opts/` mirrors this layout. `ip6_routing/` has no
TLV-options subdir (RH is fixed-format per type, not TLV).

### 3.2 Chain-walker dispatch

Today's `_phrx_ip6` does a flat 4-arm match. After Phase 8 it
becomes:

```python
def _phrx_ip6(self, packet_rx):
    # Existing setup (parse, raw-socket dispatch, etc.) UNCHANGED.
    ...
    self._phrx_ip6__walk_chain(packet_rx, current_next=packet_rx.ip6.next)

def _phrx_ip6__walk_chain(self, packet_rx, *, current_next: IpProto):
    """
    Walk the IPv6 extension-header chain in RFC 8200 §4.1 order
    and hand off to the transport layer when the chain is exhausted.

    HBH (if present) MUST be the first extension header — see
    §3.5 below for the enforcement rule.
    """
    while current_next in EXTENSION_HEADER_PROTOS:
        match current_next:
            case IpProto.IP6_HBH:
                self._phrx_ip6_hbh(packet_rx)        # advances frame, sets packet_rx.ip6_hbh
                current_next = packet_rx.ip6_hbh.next
            case IpProto.IP6_ROUTING:
                self._phrx_ip6_routing(packet_rx)    # may hard-drop on RH0
                if packet_rx.dropped: return
                current_next = packet_rx.ip6_routing.next
            case IpProto.IP6_FRAG:
                self._phrx_ip6_frag(packet_rx)       # may reassemble + re-enter via _phrx_ip6
                return                                # reassembly path handles continuation
            case IpProto.IP6_DEST_OPTS:
                self._phrx_ip6_dest_opts(packet_rx)
                current_next = packet_rx.ip6_dest_opts.next
    # Transport dispatch
    match current_next:
        case IpProto.ICMP6:  self._phrx_icmp6(packet_rx)
        case IpProto.UDP:    self._phrx_udp(packet_rx)
        case IpProto.TCP:    self._phrx_tcp(packet_rx)
        case IpProto.IP6_NO_NEXT_HEADER:  self._packet_stats_rx.ip6__no_next_header += 1  # RFC 8200 §4.7
        case _:              self.__phrx_ip6__emit_unrecognized_next_header(packet_rx)
```

Where `EXTENSION_HEADER_PROTOS = {IP6_HBH, IP6_ROUTING, IP6_FRAG, IP6_DEST_OPTS}`.

### 3.3 Frag re-entry preserved verbatim

`_phrx_ip6_frag` keeps its existing implementation:
- Parses the Frag header
- Stores the fragment in `_ip6_frag_flows`
- On final fragment: rebuilds a synthetic `PacketRx` (line
  143-145 in current `packet_handler__ip6_frag__rx.py`), splices
  the inner next-header into IPv6 header byte 6, calls
  `self._phrx_ip6(defragmented_packet_rx)` — re-enters the
  walker from the top.

Why preserved: a defragmented packet legitimately needs to be
re-parsed because (a) its length changed, (b) the inner
extension-header chain (HBH/Routing/DestOpts before Frag in
the original chain) has been preserved on the synthetic header
and needs walking again now that reassembly is complete.

### 3.4 Pad1/PadN options shared between HBH and DestOpts

RFC 8200 §4.2 defines Pad1 (Type 0x00) and PadN (Type 0x01)
identically for both HBH and DestOpts. PyTCP's design choice:

> Each extension package declares its own typed Pad1/PadN
> dataclasses (in `ip6_hbh/options/...` and
> `ip6_dest_opts/options/...`). The wire format is identical;
> the type discrimination is by enclosing extension package.
> No shared base for the option dataclass — keeps each package
> self-contained, mirrors the IPv4 options pattern (no shared
> base across protocols).

Phase-2-awareness note: this duplicates ~30 LOC across the two
packages. Acceptable per the IPv4 options precedent (each
protocol's options are independent).

### 3.5 RFC 8200 §4.3 — HBH MUST be first

> "If the IPv6 header includes a Hop-by-Hop Options header, this
> header MUST be processed before any other header processing
> starts (i.e., the Hop-by-Hop Options header MUST be the
> first extension header following the IPv6 header)."

Enforcement: the chain walker rejects an HBH that appears after
any other extension header. Concretely: in
`_phrx_ip6__walk_chain`, if `current_next == IP6_HBH` and we've
already processed at least one extension header, drop the
packet with Parameter Problem code 1, pointer 40 (offset of the
out-of-order HBH).

Counter: `ip6__hbh__not_first__drop`.

### 3.6 RFC 8200 §4.2 — Action-on-unrecognized for HBH/DestOpts options

The TLV option Type byte's top 2 bits encode what to do when
the option is unrecognized:

| Top 2 bits | Action |
|---|---|
| 00 | Skip the option, continue processing |
| 01 | Discard the packet, no ICMP |
| 10 | Discard the packet, send ICMP Parameter Problem code 2 (unrecognized option) |
| 11 | Discard the packet, send ICMP Parameter Problem code 2 if dst is unicast (skip if multicast) |

The options-walker in `Ip6HbhOptions` (and `Ip6DestOptsOptions`)
applies this rule. Parser raises:
- `Ip6HbhSanityError` with `pointer` field set when actions
  10/11 apply (caller emits Param Problem code 2)
- `Ip6HbhIntegrityError` for malformed option lengths

Counters:
- `ip6_hbh__option__skipped` (action 00)
- `ip6_hbh__option__discarded` (action 01)
- `ip6_hbh__option__param_problem` (action 10/11)

### 3.7 RH0 hard-drop (RFC 5095 §3)

The Routing Header parser inspects the routing-type byte
(offset 2 in the RH header) BEFORE building the dataclass.
If `routing_type == 0`, raise `Ip6RoutingIntegrityError` with
`pointer = 42` (offset of the routing-type byte: 40-byte IPv6
header + offset 2 inside RH).

The RX handler catches this, increments
`ip6_routing__rh0__drop`, and emits Parameter Problem code 0
(erroneous header field encountered) with the offending
pointer per the standard error path (not code 1!).

Other RH types (2/3/4) parse as opaque `Ip6RoutingUnknown`
preserving:
- `routing_type: int` (or `RoutingType` enum if known)
- `segments_left: int`
- `data: bytes` (everything after the fixed 4-byte header)

The host does not act on these — passes through to the
transport. Phase-2 forwarders will re-emit the same bytes.

### 3.8 IpProto enum extensions

`packages/net_proto/net_proto/lib/enums.py` adds four new members (Phase 0 commit):

```python
class IpProto(ProtoEnumByte):
    IP6_HBH = 0           # NEW — RFC 8200 §4.3 Hop-by-Hop Options
    ICMP4 = 1
    IP4 = 4               # CHANGED from 0 — RFC 2003 IPv4-in-IPv4 (Phase -1)
    TCP = 6
    UDP = 17
    IP6 = 41
    IP6_ROUTING = 43      # NEW — RFC 8200 §4.4
    IP6_FRAG = 44
    ICMP6 = 58
    IP6_NO_NEXT_HEADER = 59  # NEW — RFC 8200 §4.7
    IP6_DEST_OPTS = 60    # NEW — RFC 8200 §4.6
    RAW = 255
```

**Pre-resolved collision:** the original plan put `IP4 = 0`
and tried to add `IP6_HBH = 0` alongside, but Python's enum
semantics make duplicate-value declarations into aliases
(not distinct members), so that was unworkable. Phase -1
(below) lands first to set `IpProto.IP4 = 4` to its IANA-
correct value (RFC 2003 IPv4-in-IPv4 next-header) and
decouple the BSD socket constant `IPPROTO_IP` (which BSD
defines as `0`, the "default protocol" sentinel — not an
IANA next-header value). With `IP4 = 4`, `IP6_HBH = 0` slots
in cleanly with no alias collision.

`from_int` already handles unknown values via `aenum`; no
changes needed there.

### 3.9 TX-side surface for HBH

For Phase 9 (MLDv2 HBH RA wiring) we need to emit HBH on
outbound packets. The IP6 TX assembler signature gains an
optional kwarg:

```python
def _phtx_ip6(
    self,
    *,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
    ip6__hop: int = STACK__IP6_DEFAULT_HOP,
    ip6__hbh: Ip6HbhAssembler | None = None,   # NEW
    ip6__payload: ProtoAssembler,
    ip6__next: IpProto | None = None,           # NEW (overrides payload-derived next)
    echo_tracker: Tracker | None = None,
) -> TxStatus:
    ...
```

When `ip6__hbh is not None`, the IPv6 header's `next` is set
to `IP6_HBH` and the HBH bytes are inserted before the payload.
The assembler chains the HBH's `next` to the payload's
`IpProto.from_proto(payload)`.

Routing / DestOpts TX assemblers exist but no internal caller
uses them in Phase 1 (forwarder doesn't exist yet). They're
built for symmetry and to enable Phase 2 cleanly.

---

## 4. Phase-by-phase commit plan

Each phase is one commit. Phase -1 lands first; phases within
the same level (e.g. 1a/1b/1c) can run in parallel by
different agents but each commit is atomic.

### Phase -1 — Fix `IpProto.IP4` IANA value + decouple BSD `IPPROTO_IP` (1 commit)

**Subject:** `packages/net_proto/net_proto/enums + packages/pytcp/pytcp/socket: align IpProto.IP4 with IANA, decouple BSD IPPROTO_IP`

**Why first:** the existing `IpProto.IP4 = 0` (introduced in
commit `f344cfc04` 2024-09-14 as a rename of the legacy
`IpProto.IPPROTO_IP = 0` member) conflates two unrelated
namespaces:

- **BSD socket API:** `IPPROTO_IP = 0` — the "default protocol"
  sentinel for `socket()` calls; never serialized to a wire
  byte (Linux: `<netinet/in.h>`).
- **IANA next-header:** value `0` is HOPOPT (Hop-by-Hop);
  IPv4-in-IPv4 encapsulation is value `4` (RFC 2003).

The conflation blocks adding `IP6_HBH = 0` cleanly (Python's
enum semantics turn duplicate values into aliases — not
distinct members). It also has a latent bug: today's socket
factory rejects `socket(AF_INET, SOCK_STREAM, IPPROTO_IP)`
because the BSD-spec sentinel `0` doesn't match any of the
factory's `IpProto.TCP | None` cases.

**Scope:**
- `packages/net_proto/net_proto/lib/enums.py`: change `IpProto.IP4 = 0 → IP4 = 4`
  (IANA RFC 2003).
- `packages/pytcp/pytcp/socket/__init__.py`:
  - `IPPROTO_IP: int = 0` (plain int, decoupled from `IpProto`).
    Inline comment cites BSD `<netinet/in.h>`.
  - Rename `IPPROTO_IP4 → IPPROTO_IPIP` (matches Linux's
    stdlib `socket.IPPROTO_IPIP = 4`); points at
    `IpProto.IP4` (which is now `4`, IANA-correct).
  - Update `socket.__new__` factory `match` to coerce the
    BSD `IPPROTO_IP` sentinel (plain int `0`) to `None`
    before dispatch, so `socket(AF_INET, SOCK_STREAM, 0)`
    correctly returns `TcpSocket`.
- `packages/pytcp/pytcp/socket/raw__socket.py`:
  - Remove the `protocol or IpProto.IP4` / `protocol or IpProto.IP6`
    fallbacks. Raise `OSError(errno.EPROTONOSUPPORT, ...)`
    when no protocol is specified (Linux parity:
    `socket(AF_INET, SOCK_RAW, 0)` returns `EPROTONOSUPPORT`).
  - Tighten the `protocol` parameter type to `IpProto` (no
    more `None`).

**Tests-first (MANDATORY per CLAUDE.md):**
- `packages/net_proto/net_proto/tests/unit/lib/test__lib__enums.py`:
  - `IpProto.IP4` value is `4`, bytes is `b'\x04'`,
    `from_int(4) is IpProto.IP4`, `from_int(0) is not IpProto.IP4`
- `packages/pytcp/pytcp/tests/unit/socket/test__socket__base.py`:
  - `IPPROTO_IP == 0` (plain int) and `not isinstance(IPPROTO_IP, IpProto)`
  - `IPPROTO_IPIP is IpProto.IP4`
  - `socket(AF_INET, SOCK_STREAM, IPPROTO_IP)` returns `TcpSocket`
    (the BSD default-protocol sentinel pathway)
  - `socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)` returns `UdpSocket`
  - The old `test__socket__ipproto_aliases` rewritten to reflect
    the new contract (some entries become `is`, others become
    `==` against `int`)
- `packages/pytcp/pytcp/tests/unit/socket/test__socket__raw__socket.py`:
  - `socket(AF_INET, SOCK_RAW)` (no protocol) raises
    `OSError(EPROTONOSUPPORT)`
  - Same for `AF_INET6`
  - The old "ip_proto must default to IP4" test rewritten or
    removed — the default no longer exists.

**§7.2 audit script run before staging.**

**Reference:** RFC 2003 §1 (IPv4-in-IPv4 protocol number 4);
IANA "Assigned Internet Protocol Numbers" registry; BSD
`<netinet/in.h>` (`IPPROTO_IP=0` default-protocol sentinel);
Linux `socket.IPPROTO_IPIP=4`.

**Risk:** wire-byte change for `RawSocket(AF_INET, SOCK_RAW)`
no-protocol callers (today emits `Protocol=0`, which is
already invalid IANA); after Phase -1 the call errors instead.
This is a deliberate Linux-parity fix, not a regression.

**Lint + test gating:** `make lint && make test` clean before
staging.

### Phase 0 — IpProto enum extensions (1 commit)

**Subject:** `packages/net_proto/net_proto/enums: add IP6_HBH/IP6_ROUTING/IP6_DEST_OPTS/IP6_NO_NEXT_HEADER to IpProto`

**Scope:**
- Add 4 enum members to `packages/net_proto/net_proto/lib/enums.py::IpProto`
- Update `__str__` match for human-readable names ("IPv6_HBH",
  "IPv6_Routing", "IPv6_DestOpts", "IPv6_NoNextHeader")
- Update `from_proto` factory to map the new packages once
  Phase 1+ ships them (TYPE_CHECKING import; no runtime
  dispatch added yet)

**Tests-first:**
- `packages/net_proto/net_proto/tests/unit/lib/test__lib__enums.py` extended with
  parametrized cases for each new member: `IpProto.from_int(0)
  == IP6_HBH` / `IpProto.from_int(43) == IP6_ROUTING` / etc.
- Verify `__str__` mapping for each.

**Why first:** every subsequent phase depends on the enum
members existing.

**Commit message template:**
```
packages/net_proto/net_proto/enums: add IP6_HBH/IP6_ROUTING/IP6_DEST_OPTS/IP6_NO_NEXT_HEADER

Extends the IpProto enum with the four IANA-assigned
next-header values that PyTCP's IPv6 RX path will dispatch
on after the extension-header machinery lands. No runtime
behaviour change — IpProto.from_int(0/43/60/59) currently
returns the catch-all unknown variant; this commit just
gives those wire values typed names.

Reference: RFC 8200 §4.3 (Hop-by-Hop Options, next=0).
Reference: RFC 8200 §4.4 (Routing Header, next=43).
Reference: RFC 8200 §4.6 (Destination Options, next=60).
Reference: RFC 8200 §4.7 (No Next Header, next=59).
```

### Phase 1 — `ip6_hbh` package skeleton + Pad1/PadN (1 commit)

**Subject:** `ip6_hbh: package skeleton + Pad1/PadN options`

**Scope:**
- Create `packages/net_proto/net_proto/protocols/ip6_hbh/` mirroring `ip6_frag/`
  (header / base / parser / assembler / errors)
- Wire format per RFC 8200 §4.3:
  - 1-byte Next Header
  - 1-byte Hdr Ext Len (in 8-byte units, header itself
    excluded — actual length = (HdrExtLen + 1) * 8)
  - Variable-length options field
- Constants:
  - `IP6_HBH__HEADER__LEN = 2`  (fixed prefix; total varies)
  - `IP6_HBH__HEADER__STRUCT = "! BB"`
  - `IP6_HBH__OPTIONS__MAX_LEN` — `(255 + 1) * 8 - 2` = 2046
- Frozen dataclass `Ip6HbhHeader(ProtoStruct)` with fields
  `next`, `hdr_ext_len`, plus `options` (Ip6HbhOptions container)
- Parser three-phase pipeline:
  - Integrity: `len(frame) >= IP6_HBH__HEADER__LEN`,
    `(hdr_ext_len + 1) * 8 <= len(frame)`,
    options-block walks cleanly to end
  - Parse: builds `Ip6HbhHeader` + `Ip6HbhOptions`
  - Sanity: HBH-must-be-first enforcement deferred to chain
    walker (Phase 8); intra-HBH sanity is option-walk
    correctness (lengths fit, no out-of-band data)
- Options subdir:
  - `ip6_hbh__option.py` — `Ip6HbhOption` base ABC +
    `Ip6HbhOptionType(ProtoEnumByte)` enum: `PAD1 = 0`,
    `PADN = 1` (more land in Phases 2-4)
  - `ip6_hbh__option__pad1.py` — `Ip6HbhOptionPad1` (1-byte,
    just the type byte, no length/data fields)
  - `ip6_hbh__option__padn.py` — `Ip6HbhOptionPadN` with
    `length: int` and `data: bytes` (data SHOULD be all-zeros
    per RFC 8200 §4.2 but receivers MUST accept any value)
  - `ip6_hbh__option__unknown.py` — opaque catch-all preserving
    `type: int`, `length: int`, `data: bytes` (Phase-2-awareness)
  - `ip6_hbh__options.py` — `Ip6HbhOptions(ProtoOptions)`
    container with TLV walker, action-on-unrecognized
    enforcement (RFC 8200 §4.2 top-2-bits), and accessor
    properties (`router_alert`, `jumbo_payload`, `calipso`
    return-`None`-if-absent — empty until Phases 2-4 land)

**Tests-first (MANDATORY per CLAUDE.md):**
- `packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__header__asserts.py`
  — header dataclass field bounds (`next`, `hdr_ext_len`)
- `test__ip6_hbh__parser__integrity_checks.py` — every integrity
  branch (truncated frame, hdr_ext_len overrun, options-walk
  out-of-bounds)
- `test__ip6_hbh__parser__sanity_checks.py` — option-walk
  correctness violations
- `test__ip6_hbh__parser__operation.py` — happy path: 8-byte HBH
  with one PadN(6) padding option; 16-byte HBH with PadN(N) +
  Pad1 mix; etc.
- `test__ip6_hbh__assembler__operation.py` — symmetry: build,
  serialize, parse, byte-equal assertion
- `test__ip6_hbh__option__pad1.py` — 1-byte format
- `test__ip6_hbh__option__padn.py` — variable-length, length
  byte semantics (length is data length only, header is +2)
- `test__ip6_hbh__options.py` — container composition, walk
  termination, action-on-unrecognized for the 4 top-bit
  encodings (using a synthetic unknown-type with each pattern)

Each test docstring follows §7.1 RFC clause picker — primary
clauses RFC 8200 §4.2 (TLV format), RFC 8200 §4.3 (HBH header).

**§7.2 audit script run before staging — non-negotiable.**

**No wiring:** the IP6 RX dispatch is NOT modified in this
commit. PyTCP's running stack still drops HBH packets via the
unrecognized-next-header path. Phase 8 wires it up.

**Re-exports:** `packages/net_proto/net_proto/__init__.py` adds `Ip6HbhParser`,
`Ip6HbhAssembler`, `Ip6HbhHeader`, `Ip6HbhOptions`,
`Ip6HbhOptionPad1`, `Ip6HbhOptionPadN`,
`Ip6HbhIntegrityError`, `Ip6HbhSanityError` to the public
surface.

**Lint + test gating:** `make lint && make test` clean before
staging.

### Phase 2 — `ip6_hbh` Router Alert option (1 commit)

**Subject:** `ip6_hbh: add Router Alert option (RFC 2711)`

**Scope:**
- `ip6_hbh/options/ip6_hbh__option__router_alert.py`
- Wire format per RFC 2711:
  - Type 0x05 (top-2-bits = 00 = skip-if-unknown — but it's a
    known option, so this matters only for unknown extensions
    of RA)
  - Length 2
  - Value: 16-bit unsigned (well-known values: 0=MLD, 1=RSVP,
    2=Active Networks)
- `Ip6HbhOptions.router_alert` property: returns
  `Ip6HbhOptionRouterAlert | None`
- Update `Ip6HbhOptionType` enum: `ROUTER_ALERT = 0x05`

**Tests-first:**
- `test__ip6_hbh__option__router_alert.py` — full matrix:
  - Pad1/PadN baseline already covered (Phase 1)
  - Header asserts: `value` field in `[0, 0xFFFF]`
  - Assembler operation: serialize Router Alert with value=0 (MLD)
  - Parser operation: parse, recover value, properties
  - Container property: `Ip6HbhOptions.router_alert` returns
    the option when present, `None` when absent
- Reference clauses: RFC 2711 §1 (purpose), RFC 2711 §2 (wire
  format)

**§7.2 audit script run.**

### Phase 3 — `ip6_hbh` Jumbo Payload option (1 commit)

**Subject:** `ip6_hbh: add Jumbo Payload option (RFC 2675)`

**Scope:**
- `ip6_hbh/options/ip6_hbh__option__jumbo_payload.py`
- Wire format per RFC 2675:
  - Type 0xC2 (top-2-bits = 11 = discard + Param Problem if
    dst is unicast)
  - Length 4
  - Jumbo Payload Length: 32-bit unsigned (must be > 65535,
    else integrity error per RFC 2675 §3)
- `Ip6HbhOptions.jumbo_payload` property
- IPv6 length semantics: when `payload_length=0` AND HBH carries
  Jumbo Payload, use the Jumbo length. **Wire-up of this
  semantics deferred to Phase 8 (chain walker)** because it
  affects how `_phrx_ip6` computes the payload length.
  Phase 3 just builds the parser/assembler.

**Tests-first:**
- Constructor asserts: jumbo_length > 65535
- Header asserts already covered (Type byte + length=4)
- Property accessor

**Reference:** RFC 2675 §2 (option format), §3 (length semantics).

### Phase 4 — `ip6_hbh` CALIPSO option (1 commit)

**Subject:** `ip6_hbh: add CALIPSO option (RFC 5570)`

**Scope:**
- `ip6_hbh/options/ip6_hbh__option__calipso.py`
- Wire format per RFC 5570 §4:
  - Type 0x07 (top-2-bits = 00 = skip-if-unknown)
  - Variable length
  - Fields: DOI (uint32), Sensitivity Level (uint8),
    Compartment Length (uint8), Categories (variable)
- Shallow depth: parse DOI + opaque "tag list" (`tags: bytes`).
  Mirrors the IPv4 CIPSO commit `822f5dce` shape.
- Linux NetLabel parity (sysctl
  `net.ipv4.ip6_calipso_doi_default` exists; we just provide
  the parser/assembler so user-space could read/write it).
- `Ip6HbhOptions.calipso` property

**Tests-first:**
- DOI bounds (uint32)
- Tag list round-trip
- Property accessor

**Reference:** RFC 5570 §4 (CALIPSO option format).

### Phase 5 — `ip6_dest_opts` package skeleton + Pad1/PadN (1 commit)

**Subject:** `ip6_dest_opts: package skeleton + Pad1/PadN options`

**Scope:**
- Mirror Phase 1 for Destination Options:
  `packages/net_proto/net_proto/protocols/ip6_dest_opts/` with header / base /
  parser / assembler / errors + `options/` subdir.
- Wire format identical to HBH (RFC 8200 §4.6 references §4.2).
- TLV options: Pad1, PadN, Unknown — mirrors Phase 1 verbatim
  (per §3.4 decision: don't share, duplicate ~30 LOC for
  package self-containment).

**Tests-first:** mirrors Phase 1 test matrix.

### Phase 6 — `ip6_dest_opts` Tunnel Encapsulation Limit (1 commit)

**Subject:** `ip6_dest_opts: add Tunnel Encapsulation Limit option (RFC 2473)`

**Scope:**
- `ip6_dest_opts/options/ip6_dest_opts__option__tunnel_encapsulation_limit.py`
- Wire format per RFC 2473 §4.1.1:
  - Type 0x04
  - Length 1
  - Value: 8-bit "tunnel encapsulation limit"

**Tests-first:** as per option-test pattern.

**Reference:** RFC 2473 §4.1.1 (option format).

### Phase 7 — `ip6_routing` package + RH0 hard-drop (1 commit)

**Subject:** `ip6_routing: package + parser + RH0 hard-drop (RFC 5095 §3)`

**Scope:**
- `packages/net_proto/net_proto/protocols/ip6_routing/` (header / base / parser /
  assembler / errors / `enums.py`)
- Wire format per RFC 8200 §4.4:
  - Next Header (uint8)
  - Hdr Ext Len (uint8, in 8-byte units)
  - Routing Type (uint8)
  - Segments Left (uint8)
  - Type-specific data (variable)
- `Ip6RoutingType(ProtoEnumByte)` with members:
  - `RH0 = 0` (DEPRECATED per RFC 5095 §3 — parser hard-drops)
  - `RH2 = 2` (mobility — parsed as opaque, see §2.2 non-goal)
  - `RH3 = 3` (RPL — parsed as opaque)
  - `RH4 = 4` (Segment Routing — parsed as opaque)
  - Unknown values via dynamic-extend
- Parser integrity:
  - `routing_type == 0` → `Ip6RoutingIntegrityError(
    "RH0 deprecated by RFC 5095 §3", pointer=42)`
  - Standard length sanity
- The RX handler in Phase 8 catches `Ip6RoutingIntegrityError`
  with `pointer != None` and emits Param Problem code 0
  (erroneous header field encountered) at the indicated pointer.
- For non-RH0 types: parse as `Ip6RoutingHeader` preserving all
  wire bytes; transport handoff continues per chain walker.

**Tests-first:**
- Per-type acceptance / rejection matrix: RH0 raises with
  pointer=42; RH2/3/4/unknown parse cleanly.
- Header asserts (Routing Type byte, Segments Left bounds, etc.)
- Parser operation: RH4 with 2 segments, recover the segment
  list as opaque bytes.

**Reference:** RFC 5095 §3 (RH0 hard-drop), RFC 8200 §4.4
(Routing Header wire format).

### Phase 8 — Chain-walker dispatch in IP6 RX (1 commit)

**Subject:** `ip6/rx: chain-walk dispatch with HBH/Routing/DestOpts handlers`

**Scope:**
- Refactor `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py`
  per §3.2 above. Add three new handler methods:
  - `_phrx_ip6_hbh(packet_rx)` — calls `Ip6HbhParser`, advances
    `packet_rx.frame`, sets `packet_rx.ip6_hbh`. Applies RFC
    8200 §4.2 action-on-unrecognized via the parsed
    `Ip6HbhOptions`. On action 10/11, emits Param Problem
    code 2 with pointer at the offending option's Type byte.
  - `_phrx_ip6_routing(packet_rx)` — calls `Ip6RoutingParser`.
    Catches `Ip6RoutingIntegrityError` with pointer set and
    emits Param Problem code 0 (RH0 hard-drop case). For
    non-RH0 types: continues chain walk.
  - `_phrx_ip6_dest_opts(packet_rx)` — same shape as HBH.
- HBH-must-be-first enforcement (§3.5). Counter
  `ip6__hbh__not_first__drop`.
- Jumbo Payload length semantics (§3 Phase 3 deferred work):
  if `packet_rx.ip6.payload_length == 0` AND
  `packet_rx.ip6_hbh.options.jumbo_payload is not None`, use
  `jumbo_payload.value` as the actual payload length.
- IP6_NO_NEXT_HEADER (next=59) handled per RFC 8200 §4.7:
  drop silently with counter `ip6__no_next_header`.
- Update the stale comment at line 175-177 ("PyTCP does not
  currently process IPv6 extension headers") to reflect new
  reality.

**New counters in `packages/pytcp/pytcp/lib/packet_stats.py`:**
- `ip6_hbh__pre_parse`
- `ip6_hbh__failed_parse`
- `ip6_hbh__option__skipped`
- `ip6_hbh__option__discarded`
- `ip6_hbh__option__param_problem`
- `ip6_routing__pre_parse`
- `ip6_routing__failed_parse`
- `ip6_routing__rh0__drop`
- `ip6_dest_opts__pre_parse`
- `ip6_dest_opts__failed_parse`
- `ip6_dest_opts__option__skipped`
- `ip6_dest_opts__option__discarded`
- `ip6_dest_opts__option__param_problem`
- `ip6__hbh__not_first__drop`
- `ip6__no_next_header`

(All increment `field_count` accordingly — the test-suite
guard at `test__lib__packet_stats.py` requires bumping the
constants.)

**Test-framework state additions:**
- `packages/pytcp/pytcp/tests/lib/network_testcase.py` may need updating if
  any new module-level state was introduced. Per the
  `MEMORY.md` rule: every module-level state addition must
  also update `_STACK__PATCHED_ATTRS` in lockstep. (For Phase
  8: probably no module-level state, but check.)

**Tests-first integration matrix (`packages/pytcp/pytcp/tests/integration/protocols/ip6/`):**
- `test__ip6__rx__hbh_router_alert.py` — inbound packet with
  HBH carrying Router Alert; verify it reaches the transport
- `test__ip6__rx__rh0_dropped.py` — RH0 hard-dropped, Param
  Problem code 0 emitted with pointer 42, counter bumped
- `test__ip6__rx__hbh_then_routing.py` — chain walks both
- `test__ip6__rx__hbh_after_routing__dropped.py` — out-of-order
  HBH rejected per RFC 8200 §4.3
- `test__ip6__rx__dest_opts__pad_only.py` — DestOpts containing
  only padding; transport handoff succeeds
- `test__ip6__rx__hbh__unknown_option_action_10.py` — unknown
  option with action-on-unrecognized = 10 (discard + Param
  Problem) → packet dropped, counter bumped
- `test__ip6__rx__hbh__unknown_option_action_11_multicast.py`
  — same with action 11 + multicast destination → packet
  dropped silently
- `test__ip6__rx__no_next_header.py` — chain ends with next=59;
  drop silently, counter bumped
- `test__ip6__rx__jumbogram_via_hbh.py` — payload_length=0 +
  HBH Jumbo Payload → length recovered correctly

**§7.2 audit script run** on every new test file.

**Reference:** RFC 8200 §4.1 (header order), §4.2 (option
action-on-unrecognized), §4.3 (HBH first), §4.7 (No Next
Header).

### Phase 9 — MLDv2 emit HBH Router Alert (1 commit)

**Subject:** `mld2: emit HBH Router Alert on MLDv2 reports (RFC 3810 §5)`

**Scope:**
- Locate the MLDv2 TX path. (Likely
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py`
  or a dedicated MLD subsystem at
  `packages/pytcp/pytcp/protocols/icmp6/icmp6__mld2*.py` — agent: grep for
  "mld" / "MLDv2" / "Mld2" before starting.)
- Build an `Ip6HbhAssembler` carrying a single
  `Ip6HbhOptionRouterAlert(value=0)` (value 0 = MLD per RFC
  2711 §2).
- Pass it via the new `_phtx_ip6(ip6__hbh=...)` kwarg (added
  in Phase 8, §3.9).
- Hop Limit MUST be 1 per RFC 3810 §5.2.13 (already true if
  PyTCP follows convention; verify).

**Tests-first integration:**
- `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__mld2__tx__router_alert.py`
  — Triggers an MLDv2 Report emission (e.g. by joining a
  multicast group or driving a query). Captures the outbound
  frame. Asserts:
  - IPv6 next = IP6_HBH (0)
  - HBH header carries exactly one Router Alert option
    (value=0)
  - HBH next = ICMP6 (58)
  - Hop Limit = 1
  - Byte-equal comparison against an annotated expected frame

**Reference:** RFC 3810 §5 (general MLDv2 message format),
RFC 3810 §5.2.13 (Hop Limit = 1), RFC 2711 (Router Alert
value 0 = MLD).

### Phase 10 — Adherence records for RFC 8200 §4 + RFC 5095 (1 commit)

**Subject:** `docs/rfc/ip6: adherence records for RFC 8200 §4 + RFC 5095`

**Scope:**
- Create `docs/rfc/ip6/rfc8200__ipv6/adherence.md` covering
  every clause in RFC 8200 §4 (extension headers). Per-section
  table cross-referencing the commits that closed each clause.
  Use the `rfc_adherence_audit` skill.
- Create `docs/rfc/ip6/rfc5095__deprecate_rh0/adherence.md`
  with full RH0 hard-drop coverage. Same shape.
- Add cross-references from existing audits where overlapping
  clauses appear (RFC 4443 §3.4 Param Problem codes, RFC 3810
  §5 Router Alert, etc.).
- Update `docs/refactor/icmp_remaining_issues.md` with the
  v6-extension-header section moving from "outstanding" to
  "shipped".

**Test coverage audit:** for each shipped clause, name the
test file and class that pin it (per `MEMORY.md` rule about
adherence records auditing the tests, not just the
implementation).

---

## 5. Open decisions to confirm before starting

These were considered but left open for the executing agent
to decide based on what they find in the code:

1. **`from_proto` factory for new packages.** Currently
   `IpProto.from_proto(proto)` returns the wire value for a
   given protocol object. Should HBH/Routing/DestOpts be
   added? Yes if the assemblers need it; verify in Phase 1.

2. **TX-side TX assembler for Routing / DestOpts.** Phase
   1/5/7 build full assemblers for symmetry, but no caller
   uses them in Phase 1. Acceptable to land as-is per
   Phase-2-readiness rule.

3. **Jumbo Payload TX-side semantics** — does PyTCP ever emit
   payloads > 65535? Currently no (MTU caps it). Phase 3 ships
   the parser/assembler but doesn't wire TX-side
   `payload_length=0 + Jumbo Payload` emission. Defer
   indefinitely.

4. **CALIPSO sysctl knob.** Linux has
   `net.ipv4.ip6_calipso_doi_default`. Should PyTCP add a
   `STACK__IP6__CALIPSO_DEFAULT_DOI` config in
   `packages/pytcp/pytcp/stack/__init__.py`? Defer to Phase 2 — no PyTCP
   consumer yet.

5. **Test counter-bumping discipline.** Each new counter
   added to `packages/pytcp/pytcp/lib/packet_stats.py` requires updating the
   `field_count` constants in the test guard. Phase 8 adds
   ~15 counters; verify the guard is updated in lockstep.

6. **Re-export naming in `packages/net_proto/net_proto/__init__.py`.** Should
   `Ip6HbhOptions`'s individual options be re-exported by
   short name (`Ip6HbhOptionRouterAlert` → `Ip6HbhRA`) or
   full name? Convention from IPv4 options is full name. Use
   full name.

---

## 6. RFC compliance audit

Clauses pinned by this plan, with the phase that closes each:

| RFC | Clause | Pinned by phase |
|---|---|---|
| RFC 8200 | §4.1 (header order) | Phase 8 (HBH-first enforcement) |
| RFC 8200 | §4.2 (TLV action-on-unrecognized) | Phase 1 + Phase 8 |
| RFC 8200 | §4.3 (Hop-by-Hop wire format) | Phase 1 |
| RFC 8200 | §4.4 (Routing wire format) | Phase 7 |
| RFC 8200 | §4.4 (unknown routing type → Param Problem code 0) | Phase 7 + Phase 8 |
| RFC 8200 | §4.5 (atomic frag fast-path) | NOT in this plan — task 282 |
| RFC 8200 | §4.6 (Destination Options wire format) | Phase 5 |
| RFC 8200 | §4.7 (No Next Header) | Phase 8 |
| RFC 5095 | §3 (RH0 hard-drop) | Phase 7 |
| RFC 2675 | §2 (Jumbo Payload format) | Phase 3 |
| RFC 2675 | §3 (length=0 + Jumbo semantics) | Phase 8 |
| RFC 2711 | §1, §2 (Router Alert format) | Phase 2 |
| RFC 5570 | §4 (CALIPSO format) | Phase 4 |
| RFC 2473 | §4.1.1 (Tunnel Encap Limit) | Phase 6 |
| RFC 3810 | §5, §5.2.13 (MLDv2 with Router Alert + Hop Limit 1) | Phase 9 |
| RFC 4443 | §3.4 (Parameter Problem codes 0, 1, 2) | Phase 8 (extends existing) |

---

## 7. Test surface

### 7.1 New unit tests (per phase)

Phase 0: ~5 cases extending `test__lib__enums.py`.
Phase 1: 8 new test files (header / parser×3 / assembler /
options / option×Pad1 / option×PadN). ~80 test methods.
Phase 2: 1 new test file. ~15 test methods.
Phase 3: 1 new test file. ~15 test methods.
Phase 4: 1 new test file. ~12 test methods.
Phase 5: 8 new test files (mirrors Phase 1).
Phase 6: 1 new test file. ~10 test methods.
Phase 7: 5 new test files (RH header / parser × 3 / assembler).
~40 test methods.

### 7.2 New integration tests (Phase 8 + 9)

Phase 8: ~9 integration test files (per §4 Phase 8 list).
Phase 9: 1 integration test file (MLDv2 outbound RA byte-exact).

### 7.3 Existing tests that may need updates

- `packages/net_proto/net_proto/tests/unit/lib/test__lib__enums.py` — add new
  IpProto member coverage (Phase 0).
- `packages/pytcp/pytcp/tests/unit/lib/test__lib__packet_stats.py` — bump
  `field_count` constants for the ~15 new counters (Phase 8).
- `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip6__rx.py`
  — golden frame matrices may need an HBH/DestOpts/Routing
  case added; spot-check after Phase 8.

### 7.4 The §7.2 self-audit script

After EACH commit's tests are written, before staging:

```bash
python3 << 'EOF'
import re, sys
from pathlib import Path
FILES = [
    # list every test file modified or added in this commit
]
violations = []
for path in FILES:
    text = Path(path).read_text()
    for m in re.finditer(r'def (test__\w+)\(self\) -> None:\s*\n\s*"""(.*?)"""',
                         text, re.DOTALL):
        name, body = m.group(1), m.group(2)
        if "Reference:" not in body:
            violations.append(f"{path}::{name} — missing 'Reference:'")
        if not re.search(r'^\s+Ensure ', body):
            violations.append(f"{path}::{name} — must start with 'Ensure '")
        if "[FLAGS BUG]" in body:
            violations.append(f"{path}::{name} — '[FLAGS BUG]'")
        desc = re.sub(r'\n\s*Reference:.*', '', body, flags=re.DOTALL)
        for pat in (r'[Pp]er RFC \d', r'RFC \d+\s*§', r'RFC \d+\s+figure'):
            if re.search(pat, desc):
                violations.append(f"{path}::{name} — inline RFC; pattern={pat!r}")
for v in violations: print(v)
sys.exit(1 if violations else 0)
EOF
```

A non-zero exit BLOCKS the commit. Per CLAUDE.md, this is
non-negotiable.

---

## 8. Risks and tradeoffs

### 8.1 The chain walker's interaction with Frag

Frag's existing re-entry pattern (`_phrx_ip6` invoked
recursively after reassembly) needs to interact correctly
with the new chain walker. The plan: walker hands off to
Frag, Frag does reassembly, Frag re-enters via `_phrx_ip6`,
which calls the walker again on the reassembled packet. The
synthetic-header reconstruction at line 143-145 of
`packet_handler__ip6_frag__rx.py` continues to splice the
inner-next-header into byte 6. Walker handles the resulting
chain (e.g. HBH inside the reassembled packet) correctly.

Test: build a fragmented packet with HBH-Frag-TCP chain,
verify reassembly + chain walk recovers the inner TCP.
(Add to Phase 8 test matrix.)

### 8.2 Counter explosion in `packet_stats.py`

Phase 8 adds ~15 counters. Each requires bumping the
`field_count` constants in
`test__lib__packet_stats.py` AND any handler-level test
guards. Easy to miss — verify with a `grep -nE
"field_count" packages/pytcp/pytcp/tests/`.

### 8.3 Test-framework state (per `MEMORY.md` rule)

If any phase adds module-level state to
`packages/pytcp/pytcp/stack/__init__.py` (config knobs, dicts, etc.), the
same commit MUST update `_STACK__PATCHED_ATTRS` in
`packages/pytcp/pytcp/tests/lib/network_testcase.py`. Failing this leads to
"passes-in-isolation, fails-in-suite" bugs.

This plan doesn't currently introduce module-level state,
but Phase 9 might (e.g. an MLDv2 group cache). Verify before
landing.

### 8.4 RFC 8200 §4.2 action-codes 10/11 ICMP emission

When an HBH/DestOpts option's top-2-bits dictate ICMP
emission, the host must send Param Problem code 2 with
pointer at the offending option's Type byte. Pointer arithmetic:

- Phase 8 must compute pointer = offset of the IPv6 header
  end (40) + offset within HBH/DestOpts (variable, depends
  on chain position) + offset of the option Type byte within
  the options block.

This is fiddly. The walker carries a running offset and the
options-walker reports the option's offset within its
container.

### 8.5 Linux behaviour to mirror in ambiguous cases

Per the Project North Star "Linux as tiebreaker" rule,
unclear or SHOULD/MAY clauses default to Linux behaviour:

- Linux's `net/ipv6/exthdrs.c::ipv6_hop_jumbo` validates
  Jumbo Payload only when `payload_length == 0`. Same for
  PyTCP.
- Linux silently discards HBH options with action-bits 01
  (no ICMP). PyTCP same.
- Linux's `net/ipv6/exthdrs.c::ipv6_destopt_rcv` validates
  Pad1/PadN; PadN data not zero is accepted (RFC 8200 §4.2:
  receivers MUST accept). Same.
- Linux's RH0 handler (`net/ipv6/exthdrs.c::ipv6_rthdr_rcv`)
  drops with `icmpv6_param_prob` and the routing-type
  pointer. PyTCP same.

Cite the Linux file/function in commit bodies when the
choice was a tiebreaker.

---

## 9. Effort + risk

| Phase | LOC source | LOC tests | Risk |
|---|---|---|---|
| 0 | ~10 | ~30 | low |
| 1 | ~600 | ~800 | medium (foundational; chain walker depends) |
| 2 | ~120 | ~150 | low |
| 3 | ~150 | ~150 | low |
| 4 | ~180 | ~200 | low |
| 5 | ~500 | ~700 | low (mirrors Phase 1) |
| 6 | ~100 | ~120 | low |
| 7 | ~400 | ~500 | medium (RoutingType enum + RH0 path) |
| 8 | ~400 | ~600 | high (chain walker touches IP6 RX entry) |
| 9 | ~50 | ~150 | medium (find MLDv2 TX site) |
| 10 | 0 source | 0 | low (docs) |
| **Total** | **~2510** | **~3400** | |

10 commits, multi-day execution. Each commit independently
reviewable and revertable.

---

## 10. Resume prompt (paste verbatim after `/compact` or new conversation)

```
I'm resuming PyTCP's IPv6 extension-header deployment from a
context-compacted state. The plan lives at
docs/refactor/ipv6_extension_headers_plan.md.

Read these in order before any code:

  1. docs/refactor/ipv6_extension_headers_plan.md (the plan,
     end to end — §0 reading order, §1 goal, §2 scope, §3
     architecture, §4 phases, §10 this prompt)
  2. CLAUDE.md (Project North Star: Linux parity in two
     phases; Tests First MUST; coding conventions index)
  3. .claude/rules/feature_implementation.md (commit
     discipline; tests-first procedure; "Linux as tiebreaker"
     rule)
  4. .claude/rules/unit_testing.md (test-authoring rule;
     §7.2 self-audit script is non-negotiable per commit)
  5. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` (source-authoring rule;
     six-file per-protocol layout; license block; dataclass
     conventions)
  6. docs/refactor/icmp_demux_pmtud_plan.md (precedent plan
     from a previous multi-phase project; reference for shape)

After reading, confirm you understand:

  - The 10-phase commit plan (§4) and which phase is next.
  - The chain-walker design (§3.2) and why Frag's re-entry
    is preserved verbatim (§3.3).
  - The §7.2 self-audit script blocks every commit (§7.4).
  - The North Star Phase-2 awareness rule: parse extension
    headers as full typed objects, not opaque blobs.

Then start Phase 0 (IpProto enum extensions). Tests first
per CLAUDE.md MUST. Single commit. Lint clean. Push only when
explicitly asked.

Branch: PyTCP_3_0__pre_release
Tasks: see #271-#286 in the task list (still pending; this
plan supersedes them with phase numbering — task IDs and
phase numbers map per §4 of the plan).

Open questions / decisions: see plan §5. Ask before deciding
anything not covered by the plan.
```

---

## 11. Reference points

- Precedent: `docs/refactor/icmp_demux_pmtud_plan.md`
- Project rules: `CLAUDE.md`, `.claude/rules/*.md`
- IPv4 options precedent (commits to mirror in shape):
  `d9f4c50e`, `995a5587`, `1439bbd6`, `822f5dce`, `19c169de`,
  `00a0ee7b`, `388e035b`
- Existing extension-header implementation:
  `packages/net_proto/net_proto/protocols/ip6_frag/`,
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__rx.py`
- IPv6 RX dispatch entry point:
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py:151-167`
- RFCs in-tree:
  - `docs/rfc/ip6/rfc8200__ipv6/rfc8200.txt`
  - `docs/rfc/ip6/rfc5095__deprecate_rh0/rfc5095.txt`
  - `docs/rfc/ip6/rfc8504__ipv6_node_reqs/rfc8504.txt`
  - `docs/rfc/icmp6/rfc4443__icmp6/rfc4443.txt`
  - `docs/rfc/icmp6/rfc4861__ipv6_nd/rfc4861.txt`
  - `docs/rfc/icmp6/rfc3810__mld2/rfc3810.txt`

---

End of plan.
