# RFC 8899 — Packetization Layer Path MTU Discovery for Datagram Transports

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| RFC number  | 8899                                                      |
| Title       | Packetization Layer PMTUD for Datagram Transports         |
| Category    | Standards Track                                           |
| Date        | September 2020                                            |
| Source text | [`rfc8899.txt`](rfc8899.txt)                              |

---

## Top-line adherence

After Phases 1-8 of the ICMP demux + PMTUD refactor,
PyTCP has the **substrate** for DPLPMTUD but does
not yet implement active probing.

What is **in place**:

- `stack.pmtu_cache: dict[Ip4Address|Ip6Address, int]`
  — per-destination Path-MTU cache (Phase 3).
- `UdpSocket.notify_pmtu(next_hop_mtu)` — UDP-side
  callback (Phase 4).
- `TcpSession.on_pmtu(next_hop_mtu, ip_version)` —
  TCP-side callback (Phase 6).
- ICMPv4 Frag-Needed and ICMPv6 Packet-Too-Big
  demux feed those callbacks with the embedded-
  4-tuple matching (Phases 4 + 6).
- DF=1 default on outbound TCP/UDP IPv4 (Phase 8).

What is **NOT** in place:

- Active probing: sending probe packets at
  candidate MTUs and observing wire-level acks.
- MIN_PMTU floor enforcement (RFC 8899 §4.2).
- Black-hole detection via repeated probe loss
  (RFC 8899 §4.3).
- The PROBED / SEARCHING / SEARCH_COMPLETE state
  machine (RFC 8899 §5).
- ICMP-blackhole resilience: with active probing
  the host can discover MTU updates without
  trusting ICMP Frag-Needed / Packet-Too-Big.

---

## Why this RFC is included

The substrate added by Phases 1-8 of the refactor
makes a future DPLPMTUD implementation a focused
feature commit rather than a sprawling cross-cutting
change. RFC 8899 is referenced from the per-RFC plan
to document this dependency.

---

## Test coverage audit

No DPLPMTUD-specific tests exist; substrate-level
coverage is provided by:
- `pytcp/tests/unit/stack/test__pmtu_cache.py`
- `pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py`
- `pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py`
- `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_pmtu.py`

---

## Overall assessment

| Aspect                                       | Status              |
|----------------------------------------------|---------------------|
| Per-destination MTU cache                    | **shipped (substrate)** |
| TCP/UDP on_pmtu callbacks                    | **shipped (substrate)** |
| Active PMTUD probing                         | not implemented     |
| MIN_PMTU floor                               | not implemented     |
| Black-hole detection                         | not implemented     |
| RFC 8899 state machine                       | not implemented     |

DPLPMTUD active probing is the natural follow-up to
RFC 1191 / 8201's ICMP-driven discovery. The
substrate is ready; the probing logic is the
remaining work.
