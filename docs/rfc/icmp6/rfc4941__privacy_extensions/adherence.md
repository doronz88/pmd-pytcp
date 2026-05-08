# RFC 4941 — Privacy Extensions for Stateless Address Autoconfiguration in IPv6

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4941                                              |
| Title       | Privacy Extensions for Stateless Address Autoconfiguration in IPv6 |
| Category    | Standards Track (Obsoletes RFC 3041)              |
| Date        | September 2007                                    |
| Source text | [`rfc4941.txt`](rfc4941.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when temporary-address generation is wired into
the SLAAC path.

## Status: deferred (SHOULD per RFC 8504 §6.4)

PyTCP's SLAAC code derives the Interface Identifier from
the MAC address using EUI-64 (`Ip6Host.from_eui64`);
because the IID stays constant across visited networks,
third-party devices can correlate the host's activity
across prefix changes. RFC 4941 §3 mitigates this by
generating an additional **temporary address** with a
randomised IID per interface, and §3.5 specifies a
periodic regeneration cycle.

Implementation requires:

- Random IID generation that avoids RFC 5453 reserved
  IIDs.
- Per-prefix temporary-address state (creation time,
  preferred lifetime, valid lifetime, regeneration timer).
- A toggle (per RFC 8504 §6.4: "MUST provide a way for the
  end user to explicitly enable or disable").
- Source-address selection awareness (temporary addresses
  preferred for new connections initiated by the host;
  paired with RFC 6724).

PyTCP's typical operating profile is a server-style host
with stable addresses — the privacy benefit is limited.
Marked SHOULD by RFC 8504 §6.4 with explicit acknowledgment
that some scenarios (data centre, dedicated server) gain
no benefit.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.4
  — parent classification (SHOULD with opt-out)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC record
- `docs/rfc/icmp6/rfc7217__stable_iid/adherence.md` —
  alternative approach (stable, opaque, prefix-dependent
  IIDs)
- `docs/rfc/ip6/rfc6724__default_address_selection/adherence.md`
  — temporary-address preference handling
