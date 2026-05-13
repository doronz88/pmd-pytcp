# RFC 6437 — IPv6 Flow Label Specification

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6437                                              |
| Title       | IPv6 Flow Label Specification                     |
| Category    | Standards Track (Updates RFC 2460)                |
| Date        | November 2011                                     |
| Source text | [`rfc6437.txt`](rfc6437.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 6437. The audit was performed by reading the RFC
text fresh and inspecting `pytcp/lib/ip6_flow_label.py`
plus `pytcp/stack/packet_handler/packet_handler__ip6__tx.py`
directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **partially** implements RFC 6437. The generator
algorithm (`compute_ip6_flow_label`) is shipped and
satisfies §3's uniformity + per-flow stability properties;
auto-wiring it into the IPv6 TX path is deferred until the
integration test corpus migrates from "expect flow=0
golden frames" to "expect flow=hash(src,dst) golden
frames" (~38 fixtures would need regeneration; needs the
test harness to patch `IP6__FLOW_SECRET` deterministically
per test).

Callers that need an explicit Flow Label can already pass
`ip6__flow=N` to `Ip6Assembler`; the default-zero behaviour
satisfies RFC 6437 §2's "MUST NOT modify on forward"
guarantee trivially (PyTCP does not forward) and is
RFC-tolerated for hosts that "do not participate in
flow-label-aware operation".

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §2      | Flow Label is 20 bits, set by source, immutable on forward | met (wire format) |
| §3      | Source SHOULD set a Flow Label per flow (uniform random) | partial — generator shipped; auto-wire is a follow-up |
| §5      | Forwarders MUST NOT modify Flow Label              | met (no forwarding today; Phase-2 honour by design) |
| §6.1    | ECMP/LAG using Flow Label                          | n/a (no PyTCP forwarder) |
| §6.2    | Stateful load balancing using Flow Label           | n/a (no PyTCP load balancer) |

---

## §2 Definition

> "The 20-bit Flow Label field in the IPv6 header is used
>  by a source to label sequences of packets to be treated
>  in the network as a single flow."

**Adherence:** met (wire format). The `Ip6Header`
dataclass at `net_proto/protocols/ip6/ip6__header.py`
carries the 20-bit `flow` field; `Ip6Assembler` exposes
`ip6__flow` as a kwarg. The wire codec packs the field
into the version/TC/FL header word per RFC 8200 §3.

> "The Flow Label is set to zero when no specific flow is
>  defined."

**Adherence:** met. The default value of `ip6__flow=0`
satisfies the "no specific flow" form for every PyTCP
emission path that does not opt into the §3 generator.

---

## §3 Flow Label Specification

> "To enable Flow Label based classification, source nodes
>  SHOULD assign each unrelated transport connection and
>  application data stream to a new flow."

**Adherence:** partial. The "deliver unchanged" guarantee
is trivially met (PyTCP does not forward in Phase 1). The
"source SHOULD assign each unrelated flow" requirement is
partially met:

- The **generator algorithm** is shipped at
  `pytcp/lib/ip6_flow_label.py::compute_ip6_flow_label`:
  BLAKE2s-keyed hash of `(src, dst)` with the stack-wide
  16-byte `IP6__FLOW_SECRET`, folded to 20 bits.
- The **TX path auto-wire** is deferred. Today the IPv6
  TX path always emits with `flow=0` (the assembler
  default). The wiring at `_phtx_ip6` is one-liner —
  call `compute_ip6_flow_label(src=ip6__src,
  dst=ip6__dst)` when `ip6__flow is None` — but flipping
  it changes the wire format of every outbound IPv6
  frame, which breaks ~38 integration tests that pin
  specific golden frames with flow=0.

The wire change becomes tractable once the integration
harness patches `IP6__FLOW_SECRET` to a known value per
test (so flow labels are deterministic), at which point
the affected fixtures can be regenerated mechanically.
Tracked as a follow-up under this RFC.

> "The Flow Label value MUST be chosen from an
>  approximation to a discrete uniform distribution."

**Adherence:** met by the generator (when wired). BLAKE2s
output is cryptographically uniform; folding to 20 bits
preserves uniformity. The
`TestIp6FlowLabel::test__lib__ip6_flow_label__fits_in_20_bits`
unit case pins the output-space bound.

> "An implementation SHOULD use the same Flow Label value
>  for all packets of a given flow."

**Adherence:** met by the generator. The generator hashes
(src, dst); same pair → same label. Pinned by
`TestIp6FlowLabel::test__lib__ip6_flow_label__same_flow_same_label`.
The PyTCP "flow" approximation is per-(src, dst) rather
than per-5-tuple — RFC 6437 §3 explicitly allows coarser
flow definitions ("flow could be a single TCP connection
or all of the traffic between two endpoints"). A future
Phase-1 polish item is to refine to per-5-tuple by
plumbing (sport, dport, proto) through the IPv6 TX path;
the (src, dst) approximation is RFC-conformant in the
meantime.

> "An implementation SHOULD use a random Flow Label value
>  to make it difficult for an attacker on the network to
>  inject packets with valid Flow Label values."

**Adherence:** met by the generator. The per-stack
16-byte `IP6__FLOW_SECRET` (generated at module import
via `secrets.token_bytes(16)` at
`pytcp/stack/__init__.py`) ensures the per-(src, dst)
flow label is unguessable to an off-path attacker.
Pinned by
`TestIp6FlowLabel::test__lib__ip6_flow_label__different_secret_different_label`.

---

## §5 Forwarding

> "Forwarding nodes MUST NOT modify the Flow Label."

**Adherence:** met. PyTCP does not forward in Phase 1.
When the Phase-2 forwarding plane lands, the immutability
guarantee will be enforced by design — the forwarder
re-uses the inbound `Ip6Header` value when it constructs
the outbound packet.

---

## §6 Use by Network Elements

> "Routers and intermediate nodes MAY use the Flow Label
>  for ECMP / Link Aggregation, stateful load balancing,
>  flow-based QoS classification, etc."

**Adherence:** n/a. PyTCP has no forwarder, no load
balancer, no QoS classifier today. These are router /
operator concerns; a host stack's responsibility ends at
"set a uniform Flow Label per flow."

---

## Test coverage audit

### §3 Generator algorithm

- **Unit:**
  `pytcp/tests/unit/lib/test__lib__ip6_flow_label.py::TestIp6FlowLabel`
  — 5 tests: fits-in-20-bits, same-flow-same-label,
  different-flows-different-labels, different-secret-
  different-label, different-source-different-label.

**Status:** locked in.

### §3 TX-path auto-wire

**No test surface — follow-up gap.** When the wiring lands,
the natural test:

1. Patch `IP6__FLOW_SECRET` to a known value.
2. Drive an IPv6 emission via `_phtx_ip6`.
3. Assert the on-wire `flow` field equals
   `compute_ip6_flow_label(src=..., dst=...)`.

The harness change (patch `IP6__FLOW_SECRET` per test)
applies to every IPv6 TX integration test — once it
lands, regenerating the golden frames is mechanical.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Generator algorithm (uniform, stable, secret-keyed) | locked in |
| TX-path auto-wire                                   | n/a (follow-up gap) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §2 Flow Label wire format (20 bits, header word)      | met    |
| §3 Source generator (uniform, per-flow stable)        | met (helper shipped) |
| §3 TX-path auto-wire (emit non-zero flow by default)  | not implemented (follow-up — needs golden-frame regeneration) |
| §5 Forwarder immutability                             | met (vacuous — no forwarding today) |
| §6.1 / §6.2 forwarder / load-balancer use             | n/a (no PyTCP forwarder) |

PyTCP ships the RFC 6437 §3 generator algorithm with full
unit-test coverage. The wire-format change (flipping the
default flow label from 0 to `compute_ip6_flow_label(...)`)
is a one-line change at `_phtx_ip6` blocked only on
regenerating the IPv6 TX integration golden frames; that
mechanical refactor lands when the test harness gains the
`patch.object(stack, "IP6__FLOW_SECRET", ...)` slot.

A future per-5-tuple refinement (sport, dport, proto)
would land at the socket layer where the 4-tuple is
known; it is RFC-conformant to start with per-(src, dst)
since RFC 6437 §3 allows flow definitions to vary across
implementations.

## Cross-references

- IPv6 header wire format: [`../rfc8200__ipv6/adherence.md`](../rfc8200__ipv6/adherence.md)
- IPv6 node requirements (RFC 6437 referenced from §5.1
  SHOULD): [`../rfc8504__ipv6_node_reqs/adherence.md`](../rfc8504__ipv6_node_reqs/adherence.md)
- The `IP6__FLOW_SECRET` allocation pattern mirrors
  `TCP__ISS_SECRET` and `TCP__FASTOPEN_SECRET` at the top
  of `pytcp/stack/__init__.py`.
