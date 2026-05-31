# RFC 7217 — A Method for Generating Semantically Opaque Interface Identifiers with IPv6 SLAAC

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7217                                              |
| Title       | A Method for Generating Semantically Opaque Interface Identifiers with IPv6 Stateless Address Autoconfiguration (SLAAC) |
| Category    | Standards Track                                   |
| Date        | April 2014                                        |
| Source text | [`rfc7217.txt`](rfc7217.txt)                      |

## Status: SHIPPED (default-on, Linux parity)

PyTCP generates SLAAC IIDs via the RFC 7217 §5 algorithm by
default, mirroring Linux's modern `addr_gen_mode = 2`. The
helper is `Ip6IfAddr.from_rfc7217(...)` at
`packages/net_addr/net_addr/ip6_ifaddr.py`; the packet handler exposes it through
`_derive_ip6_host(ip6_network=...)` which gates on the
`icmp6.use_rfc7217` sysctl (default 1; 0 falls back to EUI-64).

### Algorithm

The RFC 7217 §5 PRF is implemented as:

```
RID = SHA-256(Prefix || Net_Iface || Network_ID || DAD_Counter || secret_key)
IID = least-significant 64 bits of RID
```

with these PyTCP-specific bindings:

- **Prefix**: 16-byte big-endian network address (IPv6
  prefix, including the host bits which are zero in the
  network address).
- **Net_Iface**: 6-byte MAC address (per RFC 7217 §5
  Appendix A "MAC address" recommendation).
- **Network_ID**: optional kwarg, defaults to empty bytes
  (PyTCP doesn't have an L2 layer that exposes SSID etc.;
  the 64-bit Prefix already varies per network).
- **DAD_Counter**: defaults to 0; bumped by the caller on a
  DAD conflict per RFC 7217 §6 (consumer wiring deferred —
  see "Deferred refinements" below).
- **secret_key**: 16-byte random value generated at
  `PacketHandler.__init__` via `secrets.token_bytes(16)`.
  RFC 7217 §5 requires ≥ 128 bits; PyTCP generates exactly
  128. The secret is per-process and lost across restarts —
  Linux's persistent `stable_secret` is out of scope for a
  library-style stack.

### Sysctl

`icmp6.use_rfc7217` registered at `pytcp.protocols.icmp6.nd.nd__constants`
with default 1. Setting 0 reverts SLAAC to legacy EUI-64
derivation, useful for tests or for deployments needing MAC-
embedded addresses for legacy interop.

### Deferred refinements

- **DAD_counter increment on conflict**. RFC 7217 §6 says
  the host should bump the counter and re-derive on a
  duplicate-address detection failure. PyTCP currently
  abandons the address on conflict (the existing DAD-failure
  path); §6 retry is a small follow-up, not yet wired.
- **Persistent secret_key**. Linux exposes
  `/proc/sys/net/ipv6/conf/<iface>/stable_secret`; PyTCP
  regenerates per-process. A persistent file would let
  addresses survive process restarts, but PyTCP's typical
  deployment (test bench, pinned-MAC TAP) doesn't need it.

### Tests

`packages/net_addr/net_addr/tests/unit/test__ip6_ifaddr.py::TestNetAddrIp6HostFromRfc7217`:
- Deterministic output for identical inputs.
- Different prefix → different IID (cross-network unlinkability).
- Different MAC → different IID.
- Different secret → different IID.
- DAD counter input changes IID (RFC 7217 §6 retry path).
- /64 mask required.
- Constructor rejects secret_key < 128 bits.

`packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc7217_slaac.py`:
- Default sysctl produces RFC 7217 form (not EUI-64).
- `use_rfc7217=0` reverts to EUI-64.
- Handler initialises secret_key to exactly 16 bytes.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (RECOMMENDED via RFC 8064)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC record
- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md`
  — companion deferred record (orthogonal privacy approach)
