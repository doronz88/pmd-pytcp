# RFC 6724 — Default Address Selection for IPv6

| Field       | Value                                                            |
|-------------|------------------------------------------------------------------|
| RFC number  | 6724                                                             |
| Title       | Default Address Selection for Internet Protocol Version 6 (IPv6) |
| Category    | Standards Track (Updates RFC 4291; Obsoletes RFC 3484)           |
| Date        | September 2012                                                   |
| Source text | [`rfc6724.txt`](rfc6724.txt)                                     |

## Status: PARTIAL (source-selection rules 1, 2, 3, 8 shipped)

PyTCP runs the RFC 6724 §5 default source-address-selection
algorithm on every outbound IPv6 packet whose source is
unspecified (`::`). The selector is `_select_ip6_source` on
the IPv6 TX mixin
(`pytcp/stack/packet_handler/packet_handler__ip6__tx.py`); it
enumerates candidate sources from `_ip6_host`, applies a
lexicographic sort encoded with rules 1, 2, 3, and 8, and
returns the winner. The pure helpers — RFC 4007/4291 scope
extraction and the §2.2 CommonPrefixLen — live in
`pytcp/lib/ip6_source_selection.py`. Rules 4 (home address),
5 (outgoing interface), 5.5 (next-hop), 6 (matching label),
and 7 (temp-address preference) are tracked separately:
rules 4/5/5.5 are no-ops on a single-interface host stack
and rule 6 needs the §10.3 policy table; rule 7 ships in
the next phase as the §18 RFC 8981 privacy consumer.

The DAD probe (NS with src=:: and no SLLA) and MLDv2 report
(src=::) short-circuit the selector — they MUST keep
`src=::` regardless of the candidate set.

Per-RFC mechanism inventory:

| §          | Mechanism                                                  | Status                             | Where                                                                                            |
|------------|------------------------------------------------------------|------------------------------------|--------------------------------------------------------------------------------------------------|
| §2.1       | Configurable address-selection policy table                | not implemented (Phase §12c.3)     | default policy is implicit; no per-prefix label / precedence table is consulted                  |
| §2.2       | CommonPrefixLen helper                                     | met                                | `common_prefix_len` (`pytcp/lib/ip6_source_selection.py`)                                        |
| §3.1       | Scope comparisons                                          | met                                | `ip6_address_scope` returns RFC 4007 / 4291 codepoints                                           |
| §5 rule 1  | Prefer same address                                        | met                                | `_select_ip6_source` short-circuits when the destination is owned                                |
| §5 rule 2  | Prefer appropriate scope                                   | met                                | sort key encodes `(scope >= dst_scope, -scope)` so the smallest scope ≥ dst wins                 |
| §5 rule 3  | Avoid deprecated addresses                                 | met                                | sort key consults `Icmp6SlaacAddress.state(now) is DEPRECATED`                                   |
| §5 rule 4  | Prefer home addresses                                      | not applicable (out of scope)      | mobility extensions excluded from PyTCP scope (CLAUDE.md project north star)                     |
| §5 rule 5  | Prefer outgoing interface                                  | not applicable (single interface)  | single-interface host stack; multi-interface support is a future Phase 2 concern                 |
| §5 rule 5.5| Prefer source whose first-hop matches next-hop (RFC 8028)  | not implemented (RFC 8028 deferred)| see `docs/refactor/nd_linux_parity.md` §23                                                       |
| §5 rule 6  | Prefer matching label (policy table)                       | not implemented (Phase §12c.3)     | requires §10.3 policy table                                                                      |
| §5 rule 7  | Prefer temporary addresses                                 | not implemented (Phase §12c.2)     | scheduled next; makes the RFC 8981 §18 privacy benefit observable                                |
| §5 rule 8  | Use longest matching prefix                                | met                                | sort-key tiebreak after rules 1/2/3                                                              |
| §6         | Destination address selection                              | not implemented                    | DNS-resolution selection (rules D1-D8) is out of scope at the stack layer                        |
| §10.3      | Default policy table                                       | not implemented (Phase §12c.3)     | required by rules 6 and 8b                                                                       |

## Test coverage

- `pytcp/tests/unit/lib/test__lib__ip6_source_selection.py`
  - `TestIp6AddressScope` — RFC 4007/4291 scope mapping for
    loopback, link-local, ULA, GUA, and the four multicast
    scope codepoints (interface-, link-, site-, global-)
  - `TestCommonPrefixLen` — symmetric, bounded
    `common_prefix_len` matching the §2.2 definition
  - `TestIp6AddressScopeEdgeCases` — unspecified address
    falls through to global scope; scope ordering is
    monotonic
  - `TestCommonPrefixLenInvariants` — `[0, 128]` bounds and
    matching the disagreement-bit definition
- `pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py`
  - `TestRfc6724Rule1SameAddress` — rule 1 short-circuit
  - `TestRfc6724Rule2Scope` — global / link-local scope
    matching, fallback when only smaller scope available
  - `TestRfc6724Rule3Deprecated` — PREFERRED ranks above
    DEPRECATED; non-SLAAC addresses default to PREFERRED
  - `TestRfc6724Rule8LongestMatch` — longest common prefix,
    deterministic outcome for unrelated destinations
  - `TestRfc6724SelectorBoundaries` — empty candidate set
    returns `None`; rule order is preserved
    (rule 1 > rule 3)

## Cross-references

- `docs/refactor/rfc6724_source_selection.md` — multi-commit
  implementation plan (this commit ships §12c.1; §12c.2 next)
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.6 —
  parent classification (MUST)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` §5.5.4 —
  source of the PREFERRED / DEPRECATED state machine the
  rule-3 path consumes
- `docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md` §18d —
  privacy-consumer pin for rule 7 (§12c.2)
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — companion deferred record for rule 5.5
- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md`
  — historical predecessor to RFC 8981 (rule 7 consumer)
