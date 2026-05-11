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
under `pytcp/` and `net_proto/` directly.

RFC 4436 specifies DNAv4 — a performance optimization
that lets a DHCPv4 client with a previously-leased
address skip the full INIT-REBOOT round-trip by
unicasting an ARP Request to the previously-known
default router. If the unicast-ARP reply arrives, the
client knows it is back on the same link and can
re-activate the cached lease without DHCP traffic.

**PyTCP does not implement DNAv4** at any level:

- No cached-lease state — every boot starts from INIT
  with a fresh DHCPDISCOVER (`pytcp/protocols/dhcp4/dhcp4__client.py:87`).
- No INIT-REBOOT path (see [`rfc2131__dhcp`](../rfc2131__dhcp/adherence.md)
  §4.4.2 audit).
- No unicast ARP for prior-gateway reachability check.
- No multi-candidate parallel-trial machinery.

The audit therefore consists almost entirely of
"not implemented" entries. Sections without normative
content (§1 Introduction, §1.1 Motivation discussion,
§1.2 Requirements boilerplate, §1.3 Terminology, §6
Acknowledgments, §7 References, §8 Security
Considerations, §9 Author's Addresses) are omitted.

---

## §2 Conceptual Model

> "When a node attaches to a link, it MAY apply one or
>  more probing techniques to attempt to ascertain
>  which network it is on. ... If one or more probes
>  succeeds, the host MAY use the information from a
>  successful probe to configure its IP layer."

**Adherence:** not implemented. PyTCP has no
probing-on-attach machinery. The Phase-1 boot path
calls `_create_stack_ip4_addressing` once and either
gets a fresh DHCP lease or has a static config — no
"reattach to known link" fast path.

---

## §3 Operational Overview

> "The host SHOULD reuse a previously configured
>  address only if it can demonstrate that the host is
>  still on the same link where this address is valid
>  for use."

**Adherence:** N/A (no address re-use).

> "If the host has the same link-layer address as
>  previously, and the link-layer mechanism still
>  considers the link to be 'up' (i.e., link-up indication),
>  then the host MAY assume it has not changed links,
>  and continue to use the same address."

**Adherence:** N/A. PyTCP has no link-up event consumer
that would trigger address re-validation.

---

## §4 Algorithm

> "If the host does not retain prior IP configuration,
>  or if it does and it judges that link-layer or
>  Internet-layer signaling suggests it may have moved
>  to a different link, then the host SHOULD discard
>  retained configuration and proceed with normal DHCPv4
>  operation."

**Adherence:** N/A. PyTCP does not retain prior
configuration; the "discard and proceed with DHCP"
fallback is the only path PyTCP runs.

> "Otherwise, the host begins the DNAv4 reachability
>  test. ... The host sends a unicast ARP Request
>  packet for the address of the router(s) on the
>  previously known link, addressed to the MAC
>  address(es) of those router(s)."

**Adherence:** not implemented. The unicast-ARP-to-prior-router
probe is absent.

> "If the host's TCP/IP stack supports it, the host MAY
>  send unicast ARP Requests to multiple routers in
>  parallel."

**Adherence:** N/A.

> "If a unicast ARP Reply is received from the expected
>  router, then DNAv4 has succeeded. ..."

**Adherence:** N/A.

> "If no unicast ARP Reply is received within the
>  timeout period, then DNAv4 has failed for that
>  configuration. The host SHOULD try the next candidate
>  configuration (if any), or fall through to DHCPv4 if
>  there is no other candidate."

**Adherence:** N/A.

---

## §4.1 Recommended Behaviors — timeouts

> "The recommended timeout for the unicast ARP Request
>  is one second."

**Adherence:** N/A.

> "The host SHOULD send unicast ARP Requests to all
>  default routers on the previously known link in
>  parallel."

**Adherence:** N/A.

---

## §4.2 Multiple Candidate Configurations

> "If the host has multiple cached configurations to
>  try, it SHOULD try all of them in parallel, sending
>  one or more unicast ARP Requests for each."

**Adherence:** N/A (no candidate cache).

---

## §5 Interaction with DHCPv4

> "DNAv4 is intended to be a performance optimization
>  to be used in combination with DHCPv4. ..."

**Adherence:** N/A.

> "If DNAv4 succeeds, the client MAY use the cached
>  DHCPv4 configuration without further communication
>  with the DHCPv4 server, except as required by
>  ongoing lease maintenance (RFC 2131)."

**Adherence:** N/A.

> "If DNAv4 fails, the client SHOULD proceed with
>  DHCPv4 INIT-REBOOT or INIT state processing as
>  appropriate."

**Adherence:** N/A.

---

## Test coverage audit

### DNAv4 reachability test

**No test surface — gap not yet closed.** The full fix
is a feature-implementation project rather than a
single test. When the gap is fixed, the natural test
plan:

1. Provide a "cached prior lease" sysctl or fixture
   that pre-populates the packet handler with a
   previous-IP + previous-gateway-MAC tuple.
2. On boot, trigger the DNAv4 helper to emit a unicast
   ARP Request to the cached gateway MAC for the
   cached gateway IP.
3. Stub an ARP Reply from the test harness and assert
   the cached IPv4 lease is reinstated WITHOUT a DHCP
   exchange.
4. Negative test: send no ARP Reply (timeout 1 s);
   assert fallback to full DHCP DISCOVER path.

### Test coverage summary

| Aspect                                | Coverage                          |
|---------------------------------------|-----------------------------------|
| Cached-lease storage                  | not implemented; no test          |
| Unicast ARP to prior gateway          | not implemented; no test          |
| Parallel trial of multiple candidates | not implemented; no test          |
| Fallback to full DHCP on timeout      | not implemented; no test          |

---

## Overall assessment

| Aspect                                              | Status               |
|-----------------------------------------------------|----------------------|
| §2 Conceptual model (probe-on-attach)               | not implemented      |
| §3 Operational overview (same-link reuse)           | not implemented      |
| §4 Unicast ARP to prior router                      | not implemented      |
| §4.1 1-second timeout                               | not implemented      |
| §4.1 Parallel probes to multiple routers            | not implemented      |
| §4.2 Multiple candidate configurations              | not implemented      |
| §5 Integration with DHCPv4 INIT-REBOOT              | not implemented      |
| Cached-lease persistence across boot                | not implemented      |

**Principal compliance note.** DNAv4 is a pure
performance optimization layered on top of RFC 2131
INIT-REBOOT. Since PyTCP does not implement
INIT-REBOOT, DNAv4 has no scaffolding to attach to.

Implementing DNAv4 requires two prerequisites:

1. **Cached lease persistence** (see
   [`rfc2131__dhcp`](../rfc2131__dhcp/adherence.md)
   §3.2 / §4.4.2 audit). Without a stored prior-IP +
   prior-gateway-MAC, there is nothing to probe for.
2. **Unicast ARP API**. PyTCP's ARP cache
   (`pytcp/protocols/arp/arp__cache.py`) issues
   broadcast ARP Requests for cache misses; DNAv4
   needs a unicast variant. Both exist on the wire
   format (ARP can be unicast); the cache machinery
   doesn't currently emit unicast Requests.

For Phase 1 host parity, DNAv4 is a quality-of-life
optimization rather than a correctness requirement.
A reasonable prioritization is: implement INIT-REBOOT
first (closes the RFC 2131 §4.4.2 gap), then layer
DNAv4 on top once cached-lease + unicast-ARP exist.
