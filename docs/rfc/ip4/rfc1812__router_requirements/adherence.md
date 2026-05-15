# RFC 1812 — Requirements for IP Version 4 Routers

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 1812                                                 |
| Title       | Requirements for IP Version 4 Routers                |
| Category    | Internet Standard (STD 4)                            |
| Date        | June 1995                                            |
| Updated by  | RFC 2644 (directed broadcast), RFC 6633 (Source Quench deprecation) |
| Source text | [`rfc1812.txt`](rfc1812.txt)                         |

This document records the PyTCP codebase's adherence to RFC 1812.
RFC 1812 is the **router-grade companion** to RFC 1122 — it
defines what an IPv4 router MUST do. PyTCP today is a host
stack; **most of RFC 1812 is n/a (Phase 2)** per the project
north-star (`CLAUDE.md` "Project North Star" → Phase 2:
router-grade parity).

This audit enumerates the §4-§5 normative requirements and
classifies each as one of:

- **n/a (Phase 2):** Forwarder-only requirement; will be
  addressed when the Phase-2 forwarding plane lands.
- **inherited from RFC 1122 host audit:** Requirement that
  also applies to hosts (e.g. RFC 1122 §3.2.1.7 TTL handling);
  audited under the host record.
- **met (host-side):** Requirement that PyTCP satisfies even
  in its current host posture (e.g. ICMP error rate limiting).

The audit was performed by reading the RFC text fresh and
inspecting the IPv4 packet handlers and ICMP machinery
directly. Non-normative content (§1 Introduction, §2 Internet
Architecture, §3 Link Layer, Appendices) is omitted.

---

## Top-line adherence

PyTCP **does not implement** the forwarding plane that RFC 1812
governs. The audit's primary purpose is to enumerate the
Phase-2 gaps so the migration path is greppable.

| Section group | Topic                                            | Status |
|---------------|--------------------------------------------------|--------|
| §4.2.2.1      | IP options on forwarded packets                  | n/a (Phase 2) |
| §4.2.2.2      | Addresses in options (LSRR/SSRR rewrite)         | n/a (Phase 2) |
| §4.2.2.4      | TOS routing                                      | n/a (Phase 2) |
| §4.2.2.5      | Header checksum recomputation                    | n/a (Phase 2) |
| §4.2.2.7      | Fragmentation on forward                         | n/a (Phase 2) |
| §4.2.2.8      | Reassembly (routers MUST NOT reassemble in transit) | met by absence |
| §4.2.2.9      | TTL decrement + Time Exceeded                    | n/a (Phase 2) |
| §4.2.2.10     | Multi-subnet broadcasts                          | n/a (Phase 2) |
| §4.2.3.1      | IP broadcast addresses                           | inherited from RFC 1122 host audit |
| §4.2.3.2      | IP multicasting                                  | inherited (host-side) |
| §4.2.3.3      | Path MTU Discovery (router side: emit Frag-Needed) | partial — host-side PMTUD audited under RFC 1191 |
| §4.3          | ICMP general (TTL, source, error reporting)      | inherited from RFC 1122 host audit + RFC 4884 / RFC 6633 audits |
| §4.3.2.8      | ICMP error rate limiting                         | met (host-side; see icmp4 audit) |
| §4.3.3        | ICMP Destination Unreachable                     | met (RFC 1122 audit) |
| §4.3.3.2      | ICMP Redirect (emission)                         | n/a (Phase 2) |
| §4.3.3.3      | ICMP Source Quench (emission)                    | n/a (deprecated by RFC 6633; audit there) |
| §4.3.3.5      | ICMP Time Exceeded (emission)                    | n/a (Phase 2 — no forwarding to expire TTL) |
| §4.3.3.7      | ICMP Echo Reply                                  | met (RFC 1122 / icmp4 audit) |
| §5            | Forwarding plane                                 | n/a (Phase 2) |

---

## §4.2.2.7 Fragmentation (router-side)

> "A router MUST support fragmenting datagrams that it
> forwards if their length exceeds the next hop's MTU
> (unless they have DF set, in which case it MUST emit ICMP
> Destination Unreachable / Frag-Needed)."

**Adherence:** n/a (Phase 2). PyTCP fragments on the **TX
origination** path (audited under RFC 791 §3.2). Forwarding-
time fragmentation requires the routing plane.

## §4.2.2.8 Reassembly

> "A router MAY perform reassembly of datagrams which it
> forwards, but MUST do so in such a way that does not
> introduce dropped datagrams. ... A router MUST NOT
> reassemble datagrams in transit unless it is the final
> destination."

**Adherence:** met by absence. PyTCP only reassembles
datagrams **destined for itself** (the destination filter at
`packet_handler__ip4__rx.py:149-153` happens **before**
the fragmentation branch at line 171). A datagram in transit
would never reach the fragmentation branch in PyTCP because
forwarding is not implemented.

## §4.2.2.9 Time to Live

> "When forwarding a datagram, a router MUST decrement the
> Time-to-Live field by at least one. If the TTL field is
> decremented to zero, the router MUST discard the datagram
> and MUST send an ICMP Time Exceeded message."

**Adherence:** n/a (Phase 2). PyTCP enforces "TTL=0 on receive
rejects the datagram" host-side (RFC 1122 §3.2.1.7 audit). The
forwarder-side TTL decrement and ICMP Time Exceeded emission
will land with the Phase-2 forwarder.

**`# Phase 2:`** the natural place is a new
`packet_handler__ip4__forward.py` that branches off
`_phrx_ip4` after the destination filter when the dst is not
owned; the decrement + Time-Exceeded emission go there. The
ICMPv4 Time Exceeded message type is already implemented
(`net_proto/protocols/icmp4/messages/icmp4__message__time_exceeded.py`).

## §4.3.2.8 ICMP Error Rate Limiting

> "A router MUST implement a configurable rate-limiting
> mechanism for the generation of ICMP error messages."

**Adherence:** met (host-side; also applies to routers). The
ICMPv4 rate limiter at `pytcp/protocols/icmp/icmp__rate_limiter.py`
is consumed by every ICMP error path in PyTCP
(`packet_handler__ip4__rx.py:233-256` and
`packet_handler__ip4__rx.py:258-300`). Token-bucket parameters
are operator-tunable.

This is a rare host-relevant § from RFC 1812; the host audit
under RFC 1122 §3.2.2 also references it.

## §4.3.3.2 ICMP Redirect Emission

> "A router MUST generate a Redirect message ... when it is
> aware of a better path."

**Adherence:** n/a (Phase 2). Host-side Redirect *processing*
is also n/a in PyTCP (audited under RFC 1122 §3.3.1.5).

## §5 Forwarding

The entire §5 (route lookup, RPF, ICMP Redirect generation,
default-gateway preference, multipath, etc.) is **Phase 2**.

---

## Test coverage audit

### §4.3.2.8 ICMP error rate limiting

- **Unit:**
  `pytcp/tests/unit/protocols/icmp/test__icmp__rate_limiter.py`
  Token-bucket algorithm under sustained / burst load.
- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  ICMP Parameter Problem / Destination Unreachable rate-limit
  suppression paths.

**Status:** locked in.

### §4.2.2.8 Reassembly only on final-destination datagrams

- **Verification by code structure**, not by dedicated test.
  The RX dispatch ordering (destination filter at line 149,
  fragmentation branch at line 171) makes "reassemble in
  transit" structurally impossible until forwarding lands.

**Status:** locked in indirectly.

### All Phase-2 gaps

**No test surface — Phase 2.** When the forwarder lands the
natural matrix is:

1. TTL decrement on forward + Time Exceeded emission on
   decrement-to-zero.
2. Fragmentation on forward + Frag-Needed on DF=1.
3. ICMP Redirect emission when a better path is known.
4. Source-route processing (LSRR/SSRR pointer advance, dst
   rewrite, options preservation across fragments).
5. RPF / ingress-filter checks.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4.3.2.8 ICMP error rate limiting                   | locked in |
| §4.2.2.8 No in-transit reassembly                   | locked in by code structure |
| §4.2.2.7 / §4.2.2.9 / §4.3.3.2 / §5 — forwarder      | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §4.2.2 IP options on forwarded packets              | n/a (Phase 2) |
| §4.2.2.7 Fragmentation on forward                   | n/a (Phase 2) |
| §4.2.2.8 No reassembly in transit                   | met by absence (host-side reassembly intact) |
| §4.2.2.9 TTL decrement + Time Exceeded              | n/a (Phase 2) |
| §4.2.3.1 IP broadcast handling                      | inherited from RFC 1122 host audit |
| §4.2.3.3 PMTUD (router side)                        | host-side audited under RFC 1191 |
| §4.3.2.8 ICMP error rate limiting                   | met    |
| §4.3.3.2 ICMP Redirect emission                     | n/a (Phase 2) |
| §4.3.3.5 ICMP Time Exceeded emission                | n/a (Phase 2) |
| §5 Forwarding plane                                 | n/a (Phase 2) |

PyTCP intentionally defers the bulk of RFC 1812 to Phase 2. The
audit's value is structural — it enumerates the Phase-2 gap
list with a one-to-one map to where each piece will land
(forward handler, source-route forwarder, Redirect emission,
Time Exceeded emission, multipath, RPF). The Phase-1 host
posture is intact and does not foreclose any of these
additions.
