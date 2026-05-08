# RFC 7739 — Security Implications of Predictable Fragment Identification Values

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7739                                              |
| Title       | Security Implications of Predictable Fragment Identification Values |
| Category    | Informational                                     |
| Date        | February 2016                                     |
| Source text | [`rfc7739.txt`](rfc7739.txt)                      |

This adherence record is a **stub**. The audit will be
filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when the Fragment Identification generator is
hardened.

## Status: deferred (SHOULD per RFC 8504 §5.1)

PyTCP's IPv6 TX path uses a stack-wide monotonically-
increasing 32-bit counter (`PacketHandler._ip6_id`) for
the Fragment Identification field. RFC 7739 surveys the
fragmentation-attack vectors enabled by predictable
Fragment IDs and recommends moving to randomized values —
either per-connection PRNG, per-destination PRNG, or
hash(src, dst, secret).

This is a Phase-1 polish item. The fix is small (replace
the counter with a `random.SystemRandom().randrange(...)`
or RFC-recommended hash construction at the emit site)
but does not affect correctness, only resistance to
fragmentation-based DoS / injection attacks. Once
combined with the strict-overlap policy from RFC 5722 §3
(shipped) and atomic-fragment isolation from RFC 6946
(shipped), randomized Fragment IDs close the remaining
ID-collision attack surface.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.1
  — parent classification (SHOULD)
- `docs/rfc/ip6/rfc5722__overlapping_fragments/adherence.md`
  — companion shipped record (overlap detection eliminates
  one of the predictable-ID attack vectors)
- `docs/rfc/ip6/rfc6946__atomic_fragments/adherence.md` —
  companion shipped record (atomic-fragment isolation
  eliminates another predictable-ID vector)
