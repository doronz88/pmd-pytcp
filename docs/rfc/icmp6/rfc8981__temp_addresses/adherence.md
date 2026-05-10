# RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6

| Field       | Value                                                                            |
|-------------|----------------------------------------------------------------------------------|
| RFC number  | 8981                                                                             |
| Title       | Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6     |
| Category    | Standards Track (Obsoletes RFC 4941)                                             |
| Date        | February 2021                                                                    |
| Source text | (RFC text not yet copied locally — fetch from https://www.rfc-editor.org/rfc/rfc8981.txt when filling in the audit) |

## Status: §18a (wire-format generator) shipped; full feature deferred

### What ships now (§18a)

`Ip6Host.from_rfc8981_temp(*, ip6_network)` at
`net_addr/ip6_host.py` — the random-IID generator the spec's
§3.3.2 algorithm requires. Each call produces a fresh 64-bit
random IID via `secrets.token_bytes(8)`, regenerates if the
draw lands in the RFC 5453 / RFC 2526 §3 reserved range
(Subnet-Router Anycast IID==0 or 0xfdff_ffff_ffff_ff80..ffff
Reserved Subnet Anycast), and gives up after 10 retries
(safeguard against a broken random source — at 64 bits the
expected hit rate is ~7e-18).

A shared `_is_reserved_iid()` helper at module scope is
exposed for §17's RFC 7217 generator to reuse when its own
reserved-IID check lands.

This is forward-compat utility — nothing in the stack calls
the generator yet. The full feature requires §18b/c below.

### What remains deferred (§18b, §18c)

The `from_rfc8981_temp` generator alone does NOT make PyTCP
issue temporary addresses. The remaining work, in priority
order:

- **§18b — SLAAC integration**. New per-prefix temp-address
  table parallel to `_icmp6_slaac_addresses` (§12a). When a
  PI is admitted AND `icmp6.use_tempaddr` is non-zero,
  generate a temp address, claim it via DAD, and insert into
  `_ip6_host`. RFC 8981 §3.4 lifetimes (TEMP_PREFERRED_LIFETIME
  default 1 day; TEMP_VALID_LIFETIME default 7 days) clamp
  the PI's advertised lifetimes.
- **§18c — Regeneration subsystem**. Background thread
  rotates the temp address before its preferred lifetime
  expires (RFC 8981 §3.4 regeneration cycle, with the
  DESYNC_FACTOR random offset to prevent host-fleet
  synchronisation).
- **§18d — RFC 6724 source-address selection consumer**.
  Without this, the temp address is created and DADed but
  TX still picks the stable RFC 7217 address. RFC 6724 rule 7
  ("prefer temporary addresses") makes the privacy benefit
  observable. Tracked under nd_linux_parity §12c — its own
  separate phase since RFC 6724 also affects IPv4 source
  selection.

The host still has the stable opaque IID from RFC 7217
(§17 shipped) by default, which already mitigates
cross-network correlation. RFC 8981 layered on top would
add additional unlinkability for outbound flows by
rotating the IID independently of the prefix.

### Tests

`net_addr/tests/unit/test__ip6_host.py::TestNetAddrIp6HostFromRfc8981Temp`:

- Output keeps source /64 prefix.
- Two consecutive calls yield different IIDs.
- /64 mask required.
- Reserved-IID values regenerated to non-reserved.
- Retry exhaustion raises RuntimeError.

## Cross-references

- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md` —
  predecessor RFC; deferred for the same reason.
- `docs/rfc/icmp6/rfc7217__stable_iid/adherence.md` —
  the orthogonal "stable but opaque IID" approach; the
  modern recommendation is **both** (stable IID for the
  long-lived address, RFC 8981 temporary IIDs for
  outbound flows).
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` —
  §6.4 RECOMMENDS implementation.
