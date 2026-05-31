# IPv6 audit-set parity sweep (item F) — scope

**Authored:** 2026-05-29 on `PyTCP_3_0_6` (HEAD `2835ff07`). Scopes
item F of `ip4_audit_punchlist.md`: *"This session wrote 16 IPv4
audits but didn't refresh IPv6 audits in parallel. Symmetric topics
likely have similar Phase-1 sharpenings worth surfacing."*

> **STATUS 2026-05-29: SHIPPED.** All five items landed:
> `5727911e` (code — the §4.2 / §4443 §2.4 fix), `c8effda6` (IPv6 ECN
> + DSCP records + rfc8504 §5.12 flip), and the Router Alert record.
> One correction to the §3 plan below: implementation found the code
> gap was **larger and two-sided** than scoped. The §4.2 action-11
> multicast suppression was achieved only *accidentally* by an
> RFC 4443 §2.4 **over**-suppression — the option-emit site never set
> `is_param_problem_code_2=True`, so action-10 Parameter Problem to a
> multicast dst was *wrongly dropped* (§2.4(e.3) exception 2 permits
> it). The real fix was two-part: thread the multicast bit for §4.2
> action-11 **and** honour the §2.4 code-2 exception so action-10
> emits to multicast. See `5727911e`.

## 0. Headline — this is mostly a documentation-parity pass

A comparative IPv4↔IPv6 audit-topic diff plus a code investigation of
the highest-value candidates (RFC 8200 base, IPv6 ECN/DSCP, IPv6
Router Alert / extension-header options) found that **the IPv6 data
plane is already well-implemented** — the ND / extension-header /
fragmentation work was thorough. The asymmetry the IPv4 sweep created
is in the **audit records**, not the code.

- **4 documentation items** — IPv6 has shipped, tested behaviour with
  no symmetric adherence record (ECN, DSCP, Router Alert) or a stale
  record claim (RFC 8504 §5.12 ECN).
- **1 small code item** — the RFC 8200 §4.2 action-11
  (discard + ICMP-unless-multicast) path does not suppress the ICMP on
  multicast destinations (see §3). This is the one genuine Phase-1
  sharpening, symmetric to the small fixes the IPv4 sweep surfaced.

No other IPv6-base code gaps were found (unknown-option action
dispatch, min-MTU 1280 floor, hop-limit host semantics, RX header
validation, ext-header typed parsing, RH0 hard-drop, atomic frags —
all correct and, except where noted, audited).

## 1. The IPv4↔IPv6 audit-topic diff

| IPv4 record | IPv6 counterpart | Status |
|---|---|---|
| `rfc791__ip4` (base) | `rfc8200__ipv6` | ✓ audited |
| `rfc1122__host_requirements_ip4` | `rfc8504__ipv6_node_reqs` | ✓ audited (one stale §5.12 claim — §2) |
| `rfc1191__pmtud_ip4` | `rfc8201__pmtud_ip6` | ✓ audited |
| `rfc815__ip4_reassembly` | `rfc5722` + `rfc6946` | ✓ audited |
| `rfc1918__private_addresses` | `rfc4193__unique_local_addresses` | ✓ audited |
| `rfc6864__ip4_id_field` | `rfc7739__fragment_id_randomization` | ✓ audited |
| `rfc6890__special_purpose` | `rfc8190__ipv6_special_purpose` | ✓ audited |
| `rfc1112`/`rfc2236`/`rfc3376` (IGMP) | `rfc3810__mld2` (icmp6) | ✓ shipped |
| `rfc3927__ip4_link_local` | SLAAC `rfc4862` (icmp6) | ✓ shipped |
| **`rfc3168__ecn`** | **— (none)** | **DOC GAP — §2.1** |
| **`rfc2474__dscp`** | **— (none)** | **DOC GAP — §2.2** |
| **`rfc6398__router_alert`** | **— (none; RFC 2711)** | **DOC GAP — §2.3** |
| `rfc6814` / `rfc7126` (IPv4 options filtering) | RFC 8200 §4.2 action model | ✓ audited *inside* `rfc8200` — no clean standalone counterpart; **not** a gap |
| `rfc1812__router_requirements` | — | n/a (Phase 2 / router) |
| `rfc919` / `rfc922` (IPv4 broadcast) | — | n/a (IPv6 has no broadcast) |

The genuine asymmetries are exactly three missing records + one stale
claim + one code path. Everything else is either covered or
legitimately n/a.

## 2. Documentation items

### 2.1 New record — `docs/rfc/ip6/rfc3168__ecn/adherence.md` (IPv6 ECN)
IPv6 ECN has **full code parity** with the audited IPv4 behaviour,
mostly via *shared* code:
- §5 wire codec — `Ip6Header.ecn` 2-bit field
  (`ip6__header.py:101,149,170`).
- §5.3 reassembly aggregation — the shared `aggregate_ecn`
  (`protocols/ip/ip_frag.py:113-148`, Linux `ip_frag_ecn_table`
  semantics) is wired into IPv6 reassembly:
  `packet_handler__ip6_frag__rx.py:110` (per-fragment ECN),
  `:115-122` (`ip6_frag__ecn_mixed__drop`), `:135` (patch byte-1
  bits 5-4 of the reassembled Traffic Class).
- §5/§7 default Not-ECT + socket ECT marking — `_effective_ip_ecn()`
  reads `IPV6_TCLASS & 0x03` (`socket/__init__.py:1129-1138`).

Mirror the IPv4 `rfc3168__ecn` record structure. Cite the existing
locked-in tests (`test__ip__ip_frag.py::TestAggregateEcn` is
family-agnostic; the DSCP/ECN socket tests include v6 cases). **No
new tests required** — documents shipped behaviour.

### 2.2 New record — `docs/rfc/ip6/rfc2474__dscp/adherence.md` (IPv6 DSCP)
IPv6 DSCP shipped in this session's M4 work (`81a86a46` +
`56e96690`): `Ip6Header.dscp` 6-bit field, `ip6__dscp` kwarg through
the TX chain, `_effective_ip_dscp()` reads `IPV6_TCLASS >> 2`,
preserved across fragmentation. The IPv4 `rfc2474__dscp` record was
just refreshed (`2835ff07`) and already names `IPV6_TCLASS`; this
splits the IPv6 half into its own record. PHB tier n/a (same as
IPv4). Cite `TestUdpSocketApiIpDscpOnWire`,
`test__tcp__session__ip_dscp.py`, `TestUdpFragmentationDscp`.

### 2.3 New record — `docs/rfc/ip6/rfc2711__router_alert/adherence.md`
IPv4 has a dedicated `rfc6398__router_alert` record; IPv6 folds RFC
2711 into the RFC 3810 (MLD) and RFC 8200 records. The behaviour is
correct and complete:
- Typed codec `Ip6HbhOptionRouterAlert`
  (`ip6_hbh/options/ip6_hbh__option__router_alert.py`), integrity-gated
  `Opt Data Len == 2` (RFC 2711 §2.1).
- MLDv2 Reports carry it: `packet_handler__icmp6__tx.py:257-270`
  (RA value MLD, hop-limit 1, dst ff02::16).
- RX parses it into the typed object (`ip6_hbh__options.py:229-230`);
  a host correctly does not act on the value.

Author the standalone record for audit-set parity (documents shipped
behaviour; the RFC 3810 record's §5.2.14 cites the test surface).

### 2.4 Fix stale claim — `rfc8504__ipv6_node_reqs` §5.12
Lines 52, 281-289 mark "RFC 3168 ECN — **partial**, IP-layer mark
setting not yet exposed via the socket API. Phase-1 polish." This is
**now false**: `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, …)` threads
ECN+DSCP onto every outbound packet via `_effective_ip_ecn` /
`_effective_ip_dscp` (commits `81a86a46`, `56e96690`). Flip to
**met / shipped**, cross-referencing the new §2.1/§2.2 records.

## 3. Code item — RFC 8200 §4.2 action-11 multicast suppression

**The gap.** RFC 8200 §4.2 encodes the action for an unrecognized
extension-header option in the option type's high 2 bits:
`00`=skip, `01`=discard, `10`=discard + ICMP Parameter Problem,
`11`=discard + ICMP Parameter Problem **only if the destination is
not a multicast address**.

PyTCP's option-action dispatch (`ip6_hbh__options.py:153-207`,
mirrored in `ip6_dest_opts`) correctly implements all four codes and
*accepts* an `ip6_dst_is_multicast` flag that suppresses the ICMP for
code 11. **But the flag is never passed in:** the HBH/DestOpts parser
calls `Ip6HbhOptions.validate_sanity(buffer=…)` with the default
`ip6_dst_is_multicast=False` (`ip6_hbh__parser.py:135-137`), because
the parser layer doesn't have the IPv6 destination in hand. The
parser's own docstring (`:128-132`) acknowledges this and says "the
chain-walker may re-run sanity validation with
`ip6_dst_is_multicast=True` once it has the IPv6 header" — but the
chain-walker (`packet_handler__ip6__rx.py`) does **not** re-run it.

**Consequence.** A multicast-destined packet (e.g. to `ff02::*`)
carrying an unknown action-11 option elicits an ICMPv6 Parameter
Problem code 2, which RFC 8200 §4.2 says MUST be suppressed for
multicast destinations. Narrow (needs a hostile/unusual option on a
multicast packet) but a real conformance deviation, and exactly the
class of Phase-1 sharpening this sweep exists to surface.

**Fix (tests-first).** Thread the destination's multicast bit into
the sanity validation. Two viable shapes:
- **(a)** Walker re-runs `Ip6HbhOptions.validate_sanity(buffer=…,
  ip6_dst_is_multicast=packet_rx.ip6.dst.is_multicast)` after the
  parser raises — it has the IPv6 header at that point; OR
- **(b)** the chain-walker passes the dst-multicast bit into the
  `Ip6HbhParser` / `Ip6DestOptsParser` constructor so the parse-time
  sanity call uses it directly (parent-layer-prefix idiom, like
  `_ip__pshdr_sum`).

(b) is cleaner — it keeps the single parse-time sanity pass and uses
the established parent-input threading pattern. Tests: an integration
case driving a multicast-destined frame with an unknown action-11 HBH
option asserts **no** ICMPv6 Parameter Problem is emitted (and the
packet is dropped), plus the existing unicast case still emits one.
Reconcile the stale "partial / not threaded" claim in
`rfc8200__ipv6/adherence.md:89-98` and the RX docstring
(`packet_handler__ip6__rx.py:376-381`) in the same commit.

## 4. Plan / commits
- **Commit 1 (code) — §4.2 action-11 multicast suppression.** The §3
  fix, tests-first (failing multicast-no-ICMP integration test →
  thread the bit → green), + reconcile the RFC 8200 adherence claim.
- **Commit 2 (docs) — IPv6 ECN + DSCP records.** New
  `rfc3168__ecn` + `rfc2474__dscp` ip6 records (§2.1, §2.2),
  documenting shipped+tested behaviour; flip `rfc8504` §5.12 (§2.4)
  in the same commit.
- **Commit 3 (docs) — IPv6 Router Alert record.** New `rfc2711`
  ip6 record (§2.3).

Each: `make lint` + full `make test` + §7.2 docstring audit (commit 1
only — it adds a test) clean; commit trailer `Co-Authored-By: Claude
Opus 4.8 (1M context) <noreply@anthropic.com>`; push only on explicit
request. Use the `rfc_adherence_audit` skill for the three new records
so they match the house format, and **re-derive each from the code +
RFC**, not from this scope doc (per the adherence-record discipline).

## 5. Out of scope
- **RFC 6814 / RFC 7126 IPv6 counterparts** — the IPv4 options
  *filtering-policy* model has no clean IPv6 standalone; the IPv6
  equivalent (RFC 8200 §4.2 action-on-unrecognized) is already
  audited inside the RFC 8200 record. No new record.
- **MLD querier role / MLD Query generation** — router/Phase-2.
- **Sub-1280 link-MTU rejection** (RFC 8200 §5) — a defensible
  Phase-1 omission already flagged in `stack/link.py:93-95`; not a
  data-plane gap. Note only.
- **Jumbograms (RFC 2675)** — the integrity check rejects a genuine
  `Payload Length = 0` jumbogram; acknowledged edge case, separate
  track if a consumer appears.

## 6. Effort / risk
- **Effort:** ~1–1.5 days. The three new records are the bulk
  (documenting existing tested behaviour); the §3 code fix is a
  half-day with its test.
- **Risk:** low. The code fix is additive (threads a bit that
  currently defaults to the conservative "emit ICMP" behaviour →
  becomes RFC-correct suppression for multicast); the doc records
  pin already-shipped, already-tested behaviour.
- **Matches the punch-list estimate** (1–2 days, 3–5 items): 5 items,
  4 doc + 1 code.
