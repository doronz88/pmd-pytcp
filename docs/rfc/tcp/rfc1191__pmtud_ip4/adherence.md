# RFC 1191 — Path MTU Discovery

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | 1191                                 |
| Title       | Path MTU Discovery                   |
| Category    | Standards Track                      |
| Date        | November 1990                        |
| Source text | [`rfc1191.txt`](rfc1191.txt)         |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 1191.

---

## Top-line adherence

PyTCP has **zero PMTUD support** for IPv4. A grep
across `pytcp/`, `net_proto/`, and `net_addr/`
returns no references to PMTUD, Path MTU Discovery,
DF flag handling for MTU probing, or ICMP
"Datagram Too Big" / "Fragmentation Needed"
processing for MTU updates.

---

## §3 Mechanisms — Gaps

### §3 IP DF flag set on outbound TCP segments

> "When an IP datagram is sent with DF=1 ('Don't
> Fragment'), routers that cannot fit it through the
> next link MUST drop it and return an ICMP
> Destination Unreachable / Fragmentation Needed
> message."

**Adherence:** not implemented as a PMTUD mechanism.
PyTCP's outbound IP4 packets have the DF flag set
to 0 by default (allowing in-network fragmentation).

### §3 ICMP "Fragmentation Needed" reception with
Next-Hop MTU field

> "Upon receipt of an ICMP Destination Unreachable /
> Fragmentation Needed message, the host MUST reduce
> its estimate of the path MTU to the value indicated
> in the Next-Hop MTU field (RFC 1191 §4)."

**Adherence:** not implemented. PyTCP's ICMP4
parser (`net_proto/protocols/icmp4/`) supports
parsing the Destination Unreachable + Fragmentation
Needed message type, but the per-route MTU update
path on RX is not wired through to TCP's
`_snd_mss` or to the IP layer's path-MTU cache.

### §6.5 Old-style ICMP detection (non-RFC-1191
routers)

> "Hosts MUST be prepared to fall back to a
> conservative MTU value when the ICMP response does
> not carry the Next-Hop MTU field (i.e. older
> routers without RFC 1191 support)."

**Adherence:** not implemented.

### §7 Path MTU Aging

> "The host's path MTU estimate MUST be aged out
> periodically so that increases in the path MTU
> can be detected."

**Adherence:** not implemented.

---

## Test coverage audit

No PMTUD tests exist; the ICMP parser is tested for
wire-format integrity in
`net_proto/tests/unit/protocols/icmp4/`.

### Test coverage summary

| Aspect                                              | Coverage  |
|-----------------------------------------------------|-----------|
| §3 outbound DF=1 on TCP segments                    | n/a (gap) |
| §4 ICMP Frag-Needed Next-Hop MTU update             | n/a (gap) |
| §6.5 fallback for non-RFC-1191 routers              | n/a (gap) |
| §7 PMTU aging                                       | n/a (gap) |

---

## Overall assessment

| Aspect                                  | Status          |
|-----------------------------------------|-----------------|
| §3 outbound DF=1 + ICMP-driven discovery | not implemented |
| §4 Next-Hop MTU field consumption       | not implemented |
| §6.5 plateau-search fallback            | not implemented |
| §7 path-MTU aging                       | not implemented |

PyTCP relies on the local interface MTU
(`stack.interface_mtu`, default 1500) for outbound
TCP MSS clamping (RFC 6691 §2: MSS = MTU - IP - TCP).
This is sufficient when the entire path can carry
local-MTU-sized datagrams. On paths where a
bottleneck has a smaller MTU and DF=1, PyTCP would
either:
- Send DF=0 (allow router fragmentation) — current
  default behavior.
- If DF=1 were ever enabled, segments larger than
  the path MTU would be dropped silently from
  PyTCP's perspective (no consumption of the
  resulting ICMP Frag-Needed messages).

The simpler RFC 4821 PLPMTUD (Packetization Layer
PMTUD) achieves the same goal without needing to
trust ICMP — see the companion `rfc4821__plpmtud/`
adherence record. Neither is implemented.

Implementing classic RFC 1191 PMTUD would require:
- An IPv4 layer DF=1 on outbound TCP segments.
- An ICMP4 RX path that extracts the Next-Hop MTU
  field and updates a per-destination path-MTU
  cache.
- A `_path_mtu` field on `TcpSession` (or a stack-
  wide path-MTU table keyed by remote address).
- An MSS recalculation hook when path MTU changes.
- A periodic aging timer.

Estimated effort: ~6-8 commits.
