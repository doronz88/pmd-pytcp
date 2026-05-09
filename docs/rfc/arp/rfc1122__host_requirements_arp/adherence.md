# RFC 1122 §2.3.2 — Host Requirements (ARP)

| Field       | Value                                                        |
|-------------|--------------------------------------------------------------|
| RFC number  | 1122                                                         |
| Title       | Requirements for Internet Hosts -- Communication Layers      |
| Section     | §2.3.2 (Address Resolution Protocol -- ARP)                  |
| Category    | Internet Standard (STD 3)                                    |
| Date        | October 1989                                                 |
| Source text | [`rfc1122.txt`](rfc1122.txt) §2.3.2                          |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 1122
§2.3.2 (the host-side ARP cache requirements). The §2.3.2.1
(ARP Cache Validation) and §2.3.2.2 (ARP Packet Queue)
sub-sections are audited individually.

The §3 IPv4 and §4 TCP sub-sections of RFC 1122 are audited
under
[`docs/rfc/tcp/rfc1122__host_requirements/`](../../tcp/rfc1122__host_requirements/adherence.md)
and [`docs/rfc/icmp4/rfc1122__host_requirements_icmp/`](../../icmp4/rfc1122__host_requirements_icmp/adherence.md).
The base RFC 826 wire format / algorithm audit lives at
[`../rfc826__arp/adherence.md`](../rfc826__arp/adherence.md);
the RFC 5227 probe / announce / defense audit lives at
[`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under `pytcp/stack/arp_cache.py` and
`pytcp/stack/packet_handler/packet_handler__arp__{rx,tx}.py`
directly. Adherence levels use the canonical descriptive
language: **met**, **not met**, **partial**, **not implemented**,
**vacuous**.

The §2.3.1 (Trailer Encapsulation) sub-section is summarised
inline as out-of-scope: trailer encapsulation is a deprecated
1980s mechanism and PyTCP correctly does not implement it; the
host-requirements compliance summary at RFC 1122 §2.5 lists it
as MUST NOT default-on, MAY support — PyTCP's choice of
"never support" is allowed.

---

## §2.3.2.1 — ARP Cache Validation

> "An implementation of the Address Resolution Protocol
> (ARP) [LINK:2] MUST provide a mechanism to flush
> out-of-date cache entries."

**Adherence:** **met**. PyTCP's `ArpCache._subsystem_loop`
runs a periodic age-based eviction
(`pytcp/stack/arp_cache.py:106-142`): every 100 ms (the
shared `SUBSYSTEM_SLEEP_TIME__SEC = 0.1`) the loop walks
every cached entry and discards any non-permanent entry
whose age exceeds `stack.ARP__CACHE__ENTRY_MAX_AGE = 3600`
seconds. The discard log line is at
`pytcp/stack/arp_cache.py:118-122`. The `permanent`
sentinel on `CacheEntry` is the lone exception
(`pytcp/stack/arp_cache.py:55,113-114`); RFC 1122 §2.3.2.1
mentions "manual flush" as a non-mandatory implementation
detail and PyTCP's approach is consistent.

> "If this mechanism involves a timeout, it SHOULD be
> possible to configure the timeout value."

**Adherence:** **met**. The two timeout values
(`ARP__CACHE__ENTRY_MAX_AGE`,
`ARP__CACHE__ENTRY_REFRESH_TIME`) live in
`pytcp/protocols/arp/arp__constants.py` as the compile-time
defaults (3600 s / 300 s). `pytcp.stack.init()` accepts
`arp_cache_max_age=` and `arp_cache_refresh_time=` kwargs
that override the live constants in place — sysctl-style
mutation of the module attributes — so the cache loop reads
the user value at runtime. The Linux equivalents are
`net.ipv4.neigh.default.base_reachable_time` and
`net.ipv4.neigh.default.gc_stale_time`. The cache loop reads
both via qualified access on `arp__constants` so a mutation
through `stack.init()` is picked up by the next iteration.
A REFRESH_TIME < MAX_AGE invariant is enforced at init
time; configurations that violate it raise `ValueError`.

For RFC 1122 §2.3.2.1's proxy-ARP-on-the-order-of-a-minute
guidance, an operator running on a proxy-ARP-heavy LAN can
now run `stack.init(arp_cache_max_age=60,
arp_cache_refresh_time=15)` to dial in the appropriate
timeout without editing the source.

Per-interface timeouts (Linux's
`net.ipv4.neigh.<iface>.*` namespace) are out of scope
until multi-interface support lands (Phase 2).

> "A mechanism to prevent ARP flooding (repeatedly sending
> an ARP Request for the same IP address, at a high rate)
> MUST be included. The recommended maximum rate is 1 per
> second per destination."

**Adherence:** **not met**. PyTCP's
`ArpCache.find_entry()` issues an ARP Request on every
cache miss (`pytcp/stack/arp_cache.py:161-181`) without
any rate limit, deduplication, or in-flight-resolution
tracking. A burst of TX attempts to an unresolved IP
produces a burst of ARP Requests at the same rate.
Likewise the cache-refresh path
(`pytcp/stack/arp_cache.py:127-139`) fires from the
100 ms subsystem loop with no per-destination rate limit
beyond the loop cadence (which is stricter than 1 / sec
but not by design — it's incidental to the loop period).

This is the **most consequential RFC 1122 §2.3.2 gap** in
PyTCP. A misbehaving local-app sending 100 packets / sec
to an unresolved IP would emit 100 ARP Requests / sec on
the wire. The fix is a per-destination "last sent at"
timestamp on either the in-progress-resolution table (which
PyTCP doesn't have today either — see RFC 1122 §2.3.2.2
below) or directly in the cache as a sentinel "resolution
in progress" entry with a 1-second guard.

Linux's implementation lives in `net/core/neighbour.c` and
gates new probes via `NUD_INCOMPLETE` state, the
`unres_qlen` queue, and the `mcast_solicit` /
`ucast_solicit` per-entry counters; PyTCP has none of
these primitives.

> "DISCUSSION: The ARP specification [LINK:2] suggests but
> does not require a timeout mechanism to invalidate cache
> entries when hosts change their Ethernet addresses. The
> prevalence of proxy ARP ... has significantly increased
> the likelihood that cache entries in hosts will become
> invalid, and therefore some ARP-cache invalidation
> mechanism is now required for hosts."

**Adherence:** **met**. The timeout mechanism described in
the previous paragraph satisfies this. The 1-hour default
is generous for a non-proxy-ARP environment.

> "IMPLEMENTATION: Four mechanisms have been used,
> sometimes in combination, to flush out-of-date cache
> entries. (1) Timeout — Periodically time out cache
> entries, even if they are in use."

**Adherence:** **met**. Implementation (1) is what PyTCP
does
(`pytcp/stack/arp_cache.py:117-122`). The "even if they
are in use" wording is satisfied by the absence of a hit-
count-based reprieve from expiry — the only effect of a
non-zero `hit_count` is to **trigger a refresh attempt**
when the entry crosses the `MAX_AGE - REFRESH_TIME`
threshold (`pytcp/stack/arp_cache.py:127-139`), not to
postpone expiry.

> "(1) ... Note that this timeout should be restarted when
> the cache entry is 'refreshed' (by observing the source
> fields, regardless of target address, of an ARP
> broadcast from the system in question)."

**Adherence:** **met**. `ArpCache.add_entry()` overwrites
the existing entry with a fresh `CacheEntry(...)` whose
`create_time` defaults to `int(time.time())`
(`pytcp/stack/arp_cache.py:144-159`,
`pytcp/stack/arp_cache.py:55-59`). The
`__update_arp_cache` helper in the RX handler runs this
path on every RFC-826-compliant ARP packet (Request **or**
Reply) whose SPA falls in our subnet
(`pytcp/stack/packet_handler/packet_handler__arp__rx.py:120-152,244-247,324`),
which is the "regardless of target address" requirement
satisfied.

> "(2) Unicast Poll — Actively poll the remote host by
> periodically sending a point-to-point ARP Request to it,
> and delete the entry if no ARP Reply is received from N
> successive polls."

**Adherence:** **partial — unicast refresh implemented;
no failed-poll counter**. PyTCP's near-expiry refresh path
now sends the poll as a **unicast** ARP Request via
`stack.packet_handler.send_arp_unicast_request(arp__tpa=...,
ethernet__dst=cached_mac)`
(`pytcp/protocols/arp/arp__cache.py` refresh branch →
`pytcp/stack/packet_handler/packet_handler__arp__tx.py::send_arp_unicast_request`).
RFC 1122 §2.3.2.1 IMPLEMENTATION (2) calls for the
"point-to-point" form so that only the actual cached
neighbour wakes up to reply rather than every host on the
segment; this is what PyTCP does today.

PyTCP still has no "delete after N successive failed polls"
counter; expiry is purely age-driven. The entry is
discarded once `create_time + MAX_AGE` is crossed,
regardless of how many refresh attempts have failed in the
preceding `REFRESH_TIME` window. The complete IMPLEMENTATION
(2) form would add the failure counter; that work folds
naturally into the NUD state machine (FAILED state). The
unicast wire-form half is met.

> "(3) Link-Layer Advice — If the link-layer driver
> detects a delivery problem, flush the corresponding ARP
> cache entry."

**Adherence:** **not implemented**. The TX ring
(`pytcp/stack/tx_ring.py`) does report `os.writev` errors
via `tx_ring__os_error__drop` on the shared
`PacketStatsTx` (post the recent rings refactor), but
there is no plumbing back from "writev failed for a packet
destined to MAC X" to "flush the ARP cache entry that
mapped IP Y to MAC X". RFC 1122 lists this only as one of
four IMPLEMENTATION alternatives (no MUST), so the absence
is RFC-compliant; mentioning it here for the audit trail.

> "(4) Higher-layer Advice — Provide a call from the
> Internet layer to the link layer to indicate a delivery
> problem."

**Adherence:** **not implemented**. Same as (3) — RFC 1122
lists this as an alternative implementation, not a
requirement. PyTCP relies on (1) Timeout exclusively.

---

## §2.3.2.2 — ARP Packet Queue

> "The link layer SHOULD save (rather than discard) at
> least one (the latest) packet of each set of packets
> destined to the same unresolved IP address, and transmit
> the saved packet when the address has been resolved."

**Adherence:** **not met**. PyTCP's TX flow on a cache
miss is to discard the original packet and rely on the
upper-layer retransmit:

- `ArpCache.find_entry` returns `None` and fires an ARP
  Request (`pytcp/stack/arp_cache.py:175-181`).
- The caller — the IPv4 TX path that needed the resolution
  — does not store the packet anywhere; it returns a
  `TxStatus.DROPPED__ETHER__DST_RESOLUTION_FAIL` (or
  similar) up the stack, and the TCP/UDP/ICMP layer's
  retransmit timer is the only thing that drives a retry.

This is a SHOULD-strength deviation, but the practical
impact matches the RFC's explicit warning:
- TCP SYN: the initial SYN is lost, RTT estimate inflated
  by the RFC 6298 `INITIAL_RTO` (1 second);
- UDP-based DNS: the first query is lost, the resolver
  must time out and retry;
- One-shot ICMP echo: the first ping is lost, `ping(1)`
  reports 1/2 packets and a brief delay.

The "save at least one (latest)" formulation maps cleanly
onto a `dict[Ip4Address, ArpAssembler-or-buffer]` in the
ARP cache subsystem with `add_entry()` flushing the queue
for that IP on resolution. The fix has no RFC interaction
beyond §2.3.2.2 itself.

> "DISCUSSION: Failure to follow this recommendation
> causes the first packet of every exchange to be lost.
> Although higher-layer protocols can generally cope with
> packet loss by retransmission, packet loss does impact
> performance."

**Adherence:** N/A (discussion paragraph). The above
analysis matches the discussion's prediction.

---

## §2.3.1 — Trailer Encapsulation (out of scope)

RFC 1122 §2.3.1 describes a 1980s-era optimisation
("trailer encapsulation") for `4.2BSD` and similar systems.
The summary at RFC 1122 §2.5 marks the host requirement as
"Send Trailers by Default Without Negotiation" MUST NOT,
"Send Trailers After Negotiation" MAY. PyTCP correctly
does not send trailer ARP replies and never advertises
trailer support — so the RFC requirement is **vacuously
met (deliberate non-implementation of an optional
feature)**.

---

## Summary of compliance with the RFC 1122 §2.5 host-requirements
## checklist (the table at lines 1513–1516 of `rfc1122.txt`)

The §2.5 summary table lists the §2.3.2 row of the host
requirements; pasting it here for traceability:

| Requirement                                  | RFC ref     | MUST | SHOULD | MAY | PyTCP status                |
|----------------------------------------------|-------------|------|--------|-----|-----------------------------|
| Flush out-of-date ARP cache entries          | 2.3.2.1     | x    |        |     | met                         |
| Prevent ARP floods                           | 2.3.2.1     | x    |        |     | **not met** — see §2.3.2.1  |
| Cache timeout configurable                   | 2.3.2.1     |      | x      |     | met (stack.init kwargs)     |
| Save at least one (latest) unresolved pkt    | 2.3.2.2     |      | x      |     | **not met** — see §2.3.2.2  |

Two of the four requirements (one MUST, one SHOULD) are
not met today. The MUST ("Prevent ARP floods") is the
priority blocker; the SHOULD ("Save at least one ...")
is the highest-leverage user-visible improvement.

---

## Test coverage audit

### §2.3.2.1 — Timeout-based eviction

- **Unit:**
  `pytcp/tests/unit/stack/test__stack__arp_cache.py::TestArpCacheSubsystemLoop::test__arp_cache__loop_skips_permanent_entry`
  — pins that permanent entries are never aged.
- **Unit:**
  `..::test__arp_cache__loop_expires_old_entry` — pins the
  `MAX_AGE` threshold (`stack.ARP__CACHE__ENTRY_MAX_AGE =
  3600`); an entry with `create_time` more than the max
  age in the past is removed.
- **Unit:**
  `..::test__arp_cache__loop_refreshes_near_expiry_used_entry`
  — pins the near-expiry refresh path: an entry with
  `hit_count > 0` and age past the
  `MAX_AGE - REFRESH_TIME` threshold triggers a
  `send_arp_request(arp__tpa=...)` call.

**Status:** **locked in**.

### §2.3.2.1 — "Timeout restarted on refresh"

- **Unit:**
  `pytcp/tests/unit/stack/test__stack__arp_cache.py::TestArpCacheAddFind::test__arp_cache__add_entry_overwrites`
  — pins that re-calling `add_entry` for the same IP
  produces a fresh `CacheEntry` (and therefore a fresh
  `create_time`).

**Status:** **locked in indirectly** (the test asserts
overwrite happened, which implies a fresh `create_time`,
but doesn't directly read `create_time`).

### §2.3.2.1 — ARP flood prevention (MUST, NOT MET)

**No test surface — gap not yet closed.** When the gap is
closed, the natural test is one that:

1. constructs an `ArpCache` with no entry for IP `X`;
2. calls `find_entry(ip4_address=X)` 10 times in rapid
   succession with `time.time()` patched to `t`,
   `t+0.1`, `t+0.2`, ..., `t+0.9`;
3. asserts `send_arp_request` was called at most once
   (or twice with a 1-second boundary), not 10 times.

A second test should cover the per-destination granularity
(IP `X` and `Y` should not throttle each other).

### §2.3.2.1 — Configurable timeout (SHOULD, partial)

**No test surface — gap not yet closed (compile-time only
today).** When the gap is closed, the natural test is one
that confirms the timeout values can be passed via
`stack.init(arp_cache_max_age=...)` (or whichever surface
is chosen) and observes the eviction at the new threshold.

### §2.3.2.1 — Unicast vs broadcast refresh poll

The unicast-refresh behaviour is captured by the
`..._loop_refreshes_near_expiry_used_entry` test (it
asserts `send_arp_unicast_request` is called with
`ethernet__dst=cached_mac`, and that the broadcast
`send_arp_request` is **not** called) and by
`..._unicast_request_targets_cached_mac` in the TX-side
unit tests (which pins the wire-format invariants:
Ethernet dst = cached MAC, ARP REQUEST oper, our SHA/SPA,
target IP as TPA).

**Status:** **locked in**.

### §2.3.2.2 — Save unresolved packet (SHOULD, NOT MET)

**No test surface — gap not yet closed.** When the gap is
closed, the natural test is one that:

1. constructs a `PacketHandler` with no ARP cache entry
   for IP `X`;
2. drives an outbound IPv4 packet destined for `X`
   through `_phtx_ip4`;
3. drives an inbound ARP Reply resolving `X → MAC`;
4. asserts the original IPv4 packet appears in
   `tx_ring._tx_deque` (or equivalent observable) within
   a small bounded window after the Reply is processed.

A second test should pin "only the latest packet is
saved": queue 5 packets to `X` while unresolved, resolve,
assert exactly 1 packet is sent post-resolution.

### Test coverage summary

| §         | Aspect                                                | Coverage                                                   |
|-----------|-------------------------------------------------------|------------------------------------------------------------|
| §2.3.2.1  | Flush out-of-date entries via timeout                 | locked in                                                  |
| §2.3.2.1  | Timeout restarted on refresh                          | locked in indirectly                                       |
| §2.3.2.1  | ARP flood prevention                                  | n/a (gap not closed; add test with fix — see §2.3.2.1)     |
| §2.3.2.1  | Timeout configurable                                  | locked in (unit: TestStackInitArpCacheConfig)              |
| §2.3.2.1  | Refresh-poll form (unicast IMPL (2))                  | locked in (unit: cache loop + arp__tx helper)              |
| §2.3.2.2  | Save at least one unresolved packet                   | n/a (gap not closed; add test with fix — see §2.3.2.2)     |

---

## Overall assessment

| Aspect                                 | Status                                              |
|----------------------------------------|-----------------------------------------------------|
| Flush out-of-date entries (MUST)       | met                                                 |
| Configurable timeout (SHOULD)          | met (stack.init kwargs; per-interface deferred to Phase 2) |
| Prevent ARP floods (MUST)              | **not met**                                         |
| Timeout restarted on refresh           | met                                                 |
| Refresh-poll form                      | met (unicast IMPL (2)); failed-poll counter deferred to NUD work |
| Save unresolved packet (SHOULD)        | **not met**                                         |
| Trailer encapsulation                  | met (deliberate non-implementation; allowed)        |

### Principal compliance gaps

1. **MUST: ARP flood prevention.** A per-destination 1-second
   rate-limit on outbound ARP Requests would satisfy this.
   Two viable architectures:
   - **In-progress-resolution table:** a
     `dict[Ip4Address, float]` on `ArpCache` recording the
     last-request timestamp, checked at the top of
     `find_entry()` before issuing a new Request. Naturally
     extends to the §2.3.2.2 packet-queue: the "in
     progress" entry can also hold the queued packet.
   - **Cache-state extension:** add an `INCOMPLETE` /
     `RESOLVING` state to `CacheEntry` and gate new probes
     by inspecting that state. Closer to Linux's
     `NUD_INCOMPLETE` model and lays groundwork for the
     larger NUD-state-machine refactor that the ARP / ND
     cache redesign is heading toward.

2. **SHOULD: Save the latest unresolved packet.** Naturally
   pairs with the in-progress-resolution table from (1).
   On resolution, drain the queued packet through the TX
   path. Significant TCP and DNS performance win for the
   first connection to a fresh peer.

3. **SHOULD: Configurable timeout.** Either thread the two
   timeouts through `stack.init()` as kwargs, or expose
   them via a sysctl-like API at the `stack` module. Cheap
   and useful for proxy-ARP environments.

4. **(IMPLEMENTATION (2) suggestion, not normative): Unicast
   refresh poll.** Switch the cache-refresh path from
   broadcast Request to unicast Request directed at the
   cached MAC. Reduces broadcast load when the cache is
   large.

The fixes for (1) and (2) are tightly coupled and natural
to ship together; both are blockers for any reasonable
ARP / ND cache redesign and should be the first
implementation phase that follows this audit.
