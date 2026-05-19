# RFC 4436 — Detecting Network Attachment in IPv4 (DNAv4)

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 4436                                                 |
| Title       | Detecting Network Attachment in IPv4 (DNAv4)         |
| Category    | Standards Track                                      |
| Date        | March 2006                                           |
| Source text | [`rfc4436.txt`](rfc4436.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 4436. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 4436 specifies DNAv4 — a performance optimization
that lets a DHCPv4 client with a previously-leased
address skip the full INIT-REBOOT round-trip by
unicasting an ARP Request to the previously-known
default router. If the unicast-ARP reply arrives, the
client knows it is back on the same link and can
re-activate the cached lease without DHCP traffic.

**PyTCP implements DNAv4** as of Phase 6 (built on the
Phase 5 cached-lease persistence layer):

- Cached-lease state — `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__lease_cache.py`
  persists every BOUND lease (including the gateway IP +
  gateway link-layer address) to a JSON file at
  `dhcp.lease_cache_path` for the next boot to consume.
- INIT-REBOOT path — `Dhcp4State.INIT_REBOOT` +
  `_do_init_reboot` (Phase 5; see
  [`rfc2131__dhcp`](../rfc2131__dhcp/adherence.md)
  §4.4.2 audit).
- Unicast-ARP probe to prior gateway —
  `Dhcp4Client._dnav4_probe` emits a single
  `send_arp_unicast_request` to the cached
  `(gateway_ip, gateway_mac)` pair and polls the ARP
  cache's `state_changed_at` for up to
  `dhcp.dnav4_timeout_ms` (default 1000 ms = the RFC's
  recommended 1-second window).
- Operator switch — `dhcp.dnav4` (default 1; set 0 to
  force the standard INIT-REBOOT path).

What PyTCP does NOT implement:

- Multi-candidate parallel-trial machinery (§4.2) —
  PyTCP caches exactly one prior lease. Multiple cached
  candidates would need the cache format extended to a
  list; it remains unimplemented because Phase-1 host
  scope assumes a single home network per host.

Sections without normative content (§1 Introduction,
§1.1 Motivation discussion, §1.2 Requirements
boilerplate, §1.3 Terminology, §6 Acknowledgments, §7
References, §8 Security Considerations, §9 Author's
Addresses) are omitted.

---

## §2 Conceptual Model

> "When a node attaches to a link, it MAY apply one or
>  more probing techniques to attempt to ascertain
>  which network it is on. ... If one or more probes
>  succeeds, the host MAY use the information from a
>  successful probe to configure its IP layer."

**Adherence:** met (Phase 6). On startup the
`Dhcp4Client` constructor consults
`dhcp.lease_cache_path`; when a valid cached lease is
present the FSM starts in `INIT_REBOOT` and runs the
RFC 4436 probe before any DHCP traffic. On success the
cached lease is adopted and IPv4 boot completes without
DHCP. On failure the FSM falls through to the standard
RFC 2131 §4.4.2 INIT-REBOOT REQUEST.

---

## §3 Operational Overview

> "The host SHOULD reuse a previously configured
>  address only if it can demonstrate that the host is
>  still on the same link where this address is valid
>  for use."

**Adherence:** met (Phase 6). The "demonstration" is
the unicast-ARP probe in `_dnav4_probe`: the cached
lease is only adopted when the cached gateway answers
the unicast ARP Request at its cached MAC. A failed
probe falls through to the standard RFC 2131 §4.4.2
INIT-REBOOT REQUEST, which gives the server the
opportunity to reject the cached address with a
DHCPNAK.

> "If the host has the same link-layer address as
>  previously, and the link-layer mechanism still
>  considers the link to be 'up' (i.e., link-up indication),
>  then the host MAY assume it has not changed links,
>  and continue to use the same address."

**Adherence:** N/A. PyTCP has no link-up event consumer
that would trigger address re-validation independently
of a boot; the DNAv4 probe is gated on the
constructor's cache-read path.

---

## §4 Algorithm

> "If the host does not retain prior IP configuration,
>  or if it does and it judges that link-layer or
>  Internet-layer signaling suggests it may have moved
>  to a different link, then the host SHOULD discard
>  retained configuration and proceed with normal DHCPv4
>  operation."

**Adherence:** met (Phase 6). The cache reader at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__lease_cache.py:read_cached_lease`
returns `None` when the cache file is missing, malformed,
unknown-version, or the lease has expired by wall-clock
time — every "discard and proceed with DHCP" failure
mode falls back cleanly to INIT.

> "Otherwise, the host begins the DNAv4 reachability
>  test. ... The host sends a unicast ARP Request
>  packet for the address of the router(s) on the
>  previously known link, addressed to the MAC
>  address(es) of those router(s)."

**Adherence:** met (Phase 6). `Dhcp4Client._dnav4_probe`
calls
`stack.packet_handler.send_arp_unicast_request(arp__tpa=gateway_ip, ethernet__dst=gateway_mac)` —
a unicast ARP Request to the cached gateway IP at the
cached gateway MAC.

> "If the host's TCP/IP stack supports it, the host MAY
>  send unicast ARP Requests to multiple routers in
>  parallel."

**Adherence:** N/A (single-router cache). PyTCP stores
exactly one gateway in `Dhcp4Lease.ip4_host.gateway`,
so the parallel-probe optimisation has nothing to fan
out across. The MAY is satisfied trivially; multi-
router support would require a list-shaped cache that
Phase-1 host scope does not need.

> "If a unicast ARP Reply is received from the expected
>  router, then DNAv4 has succeeded. ..."

**Adherence:** met (Phase 6). The probe loop polls the
ARP cache entry's `state_changed_at` for an advance
attributable to the inbound Reply, and additionally
verifies the entry's MAC still equals the cached
`gateway_mac` (a different MAC at the same IP means a
different physical gateway → fail the probe).

> "If no unicast ARP Reply is received within the
>  timeout period, then DNAv4 has failed for that
>  configuration. The host SHOULD try the next candidate
>  configuration (if any), or fall through to DHCPv4 if
>  there is no other candidate."

**Adherence:** met (Phase 6 — fall-through arm). On
timeout, `_dnav4_probe` returns `False` and
`_do_init_reboot` runs the standard RFC 2131 §4.4.2
broadcast REQUEST. PyTCP has only one cached
configuration, so the "try the next candidate" arm is
N/A.

---

## §4.1 Recommended Behaviors — timeouts

> "The recommended timeout for the unicast ARP Request
>  is one second."

**Adherence:** met (Phase 6). The sysctl
`dhcp.dnav4_timeout_ms` defaults to 1000 — the RFC's
one-second recommendation exactly. Operators can tune
it down for tight-boot scenarios or up for high-jitter
links.

> "The host SHOULD send unicast ARP Requests to all
>  default routers on the previously known link in
>  parallel."

**Adherence:** N/A (single cached gateway). See §4
parallel-probe entry above; PyTCP stores one gateway
and the SHOULD has no candidate set to fan out over.

---

## §4.2 Multiple Candidate Configurations

> "If the host has multiple cached configurations to
>  try, it SHOULD try all of them in parallel, sending
>  one or more unicast ARP Requests for each."

**Adherence:** not implemented (single-lease cache).
PyTCP caches exactly one lease at
`dhcp.lease_cache_path`. Multi-candidate support would
require the cache format extended to a list and the
probe loop fanning out one ARP Request per candidate;
deferred because Phase-1 host scope assumes a single
home network per host. Multi-link scenarios (laptop
moving between office and home) would benefit from
implementing this; not currently a Phase-1 priority.

---

## §5 Interaction with DHCPv4

> "DNAv4 is intended to be a performance optimization
>  to be used in combination with DHCPv4. ..."

**Adherence:** met (Phase 6). DNAv4 is invoked from
`_do_init_reboot` strictly as an early-exit on the
Phase 5 INIT-REBOOT path; on miss / disabled the
standard RFC 2131 §4.4.2 REQUEST exchange runs as
before.

> "If DNAv4 succeeds, the client MAY use the cached
>  DHCPv4 configuration without further communication
>  with the DHCPv4 server, except as required by
>  ongoing lease maintenance (RFC 2131)."

**Adherence:** met (Phase 6 — the MAY is taken). On a
successful probe, `_do_init_reboot` calls
`_on_bound(cached_lease)` and returns; the next
RFC 2131 §4.4.5 T1 timer drives the standard RENEWING
unicast REQUEST when due.

> "If DNAv4 fails, the client SHOULD proceed with
>  DHCPv4 INIT-REBOOT or INIT state processing as
>  appropriate."

**Adherence:** met (Phase 6 — fall-through to
INIT-REBOOT). On a False probe result,
`_do_init_reboot` continues past the early-exit and
runs the broadcast REQUEST. The Phase 5 outcome
matrix (ACK → BOUND, NAK → INIT, timeout → adopt
cached lease per the §4.4.2 MAY) takes over from
there.

---

## Test coverage audit

### §4 / §5 — DNAv4 probe + INIT-REBOOT integration (Phase 6)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientDnav4`
  - `dnav4_disabled_by_default_for_lease_without_mac` —
    no recorded `gateway_mac` → probe returns False, no
    ARP traffic.
  - `dnav4_disabled_by_sysctl_returns_false` —
    `dhcp.dnav4=0` short-circuits to False without
    emitting a Request.
  - `dnav4_returns_true_when_gateway_answers` —
    cache mock advances `state_changed_at` post-send →
    probe returns True; the one and only TX is the
    unicast ARP Request.
  - `dnav4_returns_false_on_silent_gateway` —
    `state_changed_at` never advances within the
    50 ms test window → probe returns False.
  - `init_reboot_short_circuits_on_dnav4_success` —
    FSM transitions to BOUND with zero DHCP TX when
    `_dnav4_probe` returns True.
  - `init_reboot_falls_through_when_dnav4_fails` —
    FSM runs the standard INIT-REBOOT REQUEST when
    `_dnav4_probe` returns False; ACK → BOUND.

### Cache format v2 — gateway_mac round-trip

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__lease_cache.py`
  - `round_trip_persists_gateway_mac` — explicit
    `gateway_mac` survives the JSON serialisation.
  - `round_trip_with_no_gateway_mac` — None / missing
    gateway_mac serialises as JSON null and reads
    back as None.

**Status:** locked in (Phase 6).

### Test coverage summary

| Aspect                                | Coverage                                           |
|---------------------------------------|----------------------------------------------------|
| Cached-lease storage with gateway_mac | locked in (Phase 6 — `test__dhcp4__lease_cache.py`)|
| Unicast ARP to prior gateway          | locked in (Phase 6 — `TestDhcp4ClientDnav4`)       |
| 1-second timeout default              | locked in (sysctl `dhcp.dnav4_timeout_ms`)         |
| Fallback to INIT-REBOOT on timeout    | locked in (Phase 6 — fall-through test)            |
| Parallel trial of multiple candidates | not implemented; single-lease cache by design      |

---

## Overall assessment

| Aspect                                              | Status                                       |
|-----------------------------------------------------|----------------------------------------------|
| §2 Conceptual model (probe-on-attach)               | met (Phase 6)                                |
| §3 Operational overview (same-link reuse)           | met (Phase 6)                                |
| §4 Unicast ARP to prior router                      | met (Phase 6)                                |
| §4.1 1-second timeout                               | met (Phase 6 — `dhcp.dnav4_timeout_ms=1000`) |
| §4.1 Parallel probes to multiple routers            | N/A (single cached gateway)                  |
| §4.2 Multiple candidate configurations              | not implemented (single-lease cache)         |
| §5 Integration with DHCPv4 INIT-REBOOT              | met (Phase 6 — early-exit on probe success)  |
| Cached-lease persistence across boot                | met (Phase 5)                                |

**Principal compliance note.** DNAv4 was unblocked
once Phase 5 added cached-lease persistence and Phase 6
extended the cache schema with `gateway_mac`. The
unicast-ARP API has been part of the ARP cache since the
PROBE-state implementation
(`stack.packet_handler.send_arp_unicast_request`); Phase
6 routes one such Request to the cached gateway on
INIT-REBOOT entry and polls the ARP entry's
`state_changed_at` for the inbound Reply.

The single remaining gap is §4.2 — multiple-candidate
parallel probing. PyTCP caches exactly one lease, so the
fan-out has nothing to fan out across. Multi-link
scenarios (host that genuinely roams between distinct
networks) would benefit from extending the cache to a
list of candidates; not currently a Phase-1 priority.

Operator dial: `dhcp.dnav4` (default 1) is the kill
switch — set 0 to force the standard RFC 2131 §4.4.2
INIT-REBOOT REQUEST in every case (useful for testing
the slow path or working around a DNAv4-hostile L2).
