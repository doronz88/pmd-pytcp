# ICMP — remaining issues / gaps

**Status snapshot at:** `46769bb1` (RFC 1191 §6.5 retransmit walkback).
**Suite:** 9013 passing / 4 skipped, lint clean.

---

## What's already closed

### MUSTs (RFC 1122 §3.2.2 host requirements — ICMP)

All MUSTs across both v4 and v6 inbound paths are met:

- §3.2.2 unknown-type silent discard ✅
- §3.2.2 ICMP-error generation gates (5 MUST NOTs) ✅ (α0 → α1.1)
- §3.2.2 embedded-datagram unchanged ✅
- §3.2.2.1 Destination Unreachable → transport (v4 + v6) ✅
- §3.2.2.4 Time Exceeded → transport (v4 + v6) ✅ (β.1 → β.4)
- §3.2.2.5 Parameter Problem → transport (v4 + v6) ✅ (β.3 → β.5)
- §3.2.2.6 Echo server (with Smurf gate) ✅ (A1)

### Security-critical

- A1 Smurf gate on Echo handler ✅
- A2 rate limit on outbound ICMP errors ✅
- A4 bcast/mcast/src-invalid/non-initial-frag gates ✅
- IP4 source-route gate (LSRR/SSRR drop unless
  `STACK__IP4__ACCEPT_SOURCE_ROUTE`) ✅ (`65b7e5cd`)

### SHOULDs

- #1 — Protocol Unreachable / Param Problem code 1 generation on
  unsupported proto / next-header ✅ (`6f44091e`)
- #2 — Parameter Problem outbound generation on inbound IP-header
  sanity errors ✅ (`dd68e3ac` + `ebbb41f8`)
- #3 — RFC 5927 §6 hard-vs-soft refactor ✅ (FSM-dispatch refactor
  Phases 1-4: `cdcb1808 → b6948c68`)
- #4 — IP options echo on Echo Reply, with LSRR/SSRR reversal ✅
  (`00a0ee7b` + `388e035b`)
- TCP RFC 1191 §6.5 retransmit walkback on PMTU shrink ✅
  (`46769bb1`)

### Code-quality / hygiene closed

- `_phtx_icmp{4,6}` ValueError → drop+counter ✅ (`f5610888`)
- Linux IPv4 option parity in `net_proto`: Router Alert / Record
  Route / Timestamp / CIPSO as first-class option types ✅
  (`d9f4c50e` + `995a5587` + `1439bbd6` + `822f5dce` + `19c169de`)

---

## Deliberately skipped (rationale recorded)

These items were considered during the post-walkback session
and explicitly rejected with reasoning. Each is documented in
the corresponding per-RFC adherence record so a future reader
sees the deliberate-non-implementation rather than an oversight.

### RFC 4884 extended ICMP

Length-field-aware split of ICMP error message bytes into
"original packet" + "extension structures". Used by RFC 4950
MPLS Label Stack info (visible in some `traceroute` output),
RFC 5837 Interface Information, RFC 8335 PROBE.

**Why skipped:** RFC 4884 §4.2 mandates that receivers MUST
ignore extensions they don't understand and treat the message
as if length=full. PyTCP's current "ignore-extensions" path is
spec-compliant. Implementing it would mean ~600-800 LOC across
3 ICMPv4 + 3 ICMPv6 message types for round-trip preservation
of data PyTCP has no consumer for. Linux's kernel handling is
also shallow — actual MPLS-label decoding lives in user-space
`traceroute`.

### RFC 4821 / 8899 PLPMTUD active probing

ICMP-independent path-MTU discovery via probe segments. Closes
the "PMTUD black hole" failure mode where ICMP Frag-Needed is
filtered out entirely.

**Why skipped:** Substantial TCP feature (~800-1200 LOC source
+ extensive tests) — comparable to the FSM-dispatch refactor in
scale. Real value when PyTCP is deployed on networks with
filtered ICMP, low value for educational / lab use. Linux's
`net.ipv4.tcp_mtu_probing` defaults to 0 on most distros even
where the implementation is available. If PyTCP's deployment
profile shifts to production-host or VPN-endpoint, this becomes
top priority — at which point it deserves its own multi-commit
project rather than being slipped into a polish session.

### MSG_ERRQUEUE / IP_RECVERR / SO_ERROR

POSIX + Linux extension socket-API surface for observing ICMP
errors from user space. Used by traceroute (sending UDP probes,
expecting ICMPTime Exceeded back) and by UDP applications that
care about `ECONNREFUSED` on send.

**Why skipped:** PyTCP has no consumer that would use this. No
traceroute-style example, no UDP-based app that needs error
visibility, and TCP error reporting already works via
`ConnError` + Python exceptions on blocked syscalls. Adding it
for "Linux parity" without a consumer would be ~600-900 LOC of
code that nothing in the codebase exercises. Per the scope rule
("Don't add features beyond what the test pins"), this fails
the bar. Becomes valuable if PyTCP grows a UDP-based diagnostic
or application stack — at that point the consumer pulls the
implementation along.

### Inbound IPv4 Redirect handling (Type 5)

RFC 1122 §3.2.2.2 — host accepts a Redirect to update routing
to use a different first-hop gateway for some destination.

**Why skipped:** Architectural blocker. PyTCP has a
single-gateway routing model (`Ip4IfAddr.gateway` is one address
per host); acting on a Redirect requires per-destination route
overrides that PyTCP doesn't have. Implementing the feature
means the routing-table refactor (~1500 LOC) plus the
Icmp4MessageRedirect parser/handler (~400 LOC) — ~2000 LOC
total. Linux's `accept_redirects=0` for hosts is the default
since the late 90s anyway (forged-Redirect MITM attacks), so
even if shipped the feature would be off-by-default and the
code would never run. Defer indefinitely unless a multi-gateway
use case lands first.

---

## Out-of-scope (still true, recorded for completeness)

### Inbound IPv4 Source-Route forwarding semantics

LSRR/SSRR options are now first-class option types
(`00a0ee7b`) and the Echo Reply path reverses them per RFC 1122
§3.2.2.6 (`388e035b`). What's NOT implemented: routing decisions
that consume the LSRR/SSRR pointer (i.e., "next hop is the IP
at the slot indicated by pointer, then write our egress IP into
that slot"). PyTCP isn't a router and doesn't forward, so this
is a non-issue. The default-on `STACK__IP4__ACCEPT_SOURCE_ROUTE
= False` gate (`65b7e5cd`) drops source-routed inbound packets
before they would reach any forwarding logic.
