# RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6

| Field       | Value                                                                            |
|-------------|----------------------------------------------------------------------------------|
| RFC number  | 8981                                                                             |
| Title       | Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6     |
| Category    | Standards Track (Obsoletes RFC 4941)                                             |
| Date        | February 2021                                                                    |
| Source text | (RFC text not yet copied locally — fetch from https://www.rfc-editor.org/rfc/rfc8981.txt when filling in the audit) |

This adherence record is a **stub**. The audit will be
filled in when temporary-address generation is wired into
the SLAAC path.

## Status: deferred (RECOMMENDED per RFC 8504 §6.4)

RFC 8981 obsoletes RFC 4941 (Privacy Extensions) and is the
current standards-track recommendation for temporary IPv6
address generation. Linux honours RFC 8981 by default on
modern kernels.

PyTCP's SLAAC code derives the Interface Identifier from
the MAC address using EUI-64 (`Ip6Host.from_eui64`); the
IID stays constant across visited networks, so third-party
devices can correlate the host's activity across prefix
changes. RFC 8981 §3 mitigates this by generating an
additional **temporary address** with a randomised IID per
prefix, and §3.4 specifies a periodic regeneration cycle.

Implementation requires:

- A separate temporary-address table parallel to the
  preferred SLAAC address.
- Random IID generation that avoids RFC 5453 reserved
  IIDs and produces no DAD failures (§3.3.1).
- Per-prefix temporary-address state (creation time,
  preferred lifetime, valid lifetime, regeneration
  schedule) — see §3.4.
- Source-address selection that prefers temporary
  addresses for outbound connections (RFC 6724 rule 7;
  PyTCP's Ip6Host source-selection code already
  acknowledges the rule).

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
