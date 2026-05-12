# RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3927                                                 |
| Title       | Dynamic Configuration of IPv4 Link-Local Addresses   |
| Category    | Standards Track                                      |
| Date        | May 2005                                             |
| Source text | [`rfc3927.txt`](rfc3927.txt)                         |

This document records the PyTCP codebase's adherence to RFC 3927
clause by clause. RFC 3927 defines the IPv4 Link-Local
mechanism (169.254/16) — pseudo-random address selection, ARP
Probe / Announce, conflict detection / defense. PyTCP today
recognises 169.254/16 at the address-classification layer
(`Ip4Address.is_link_local`) and uses it in the IPv4 source-
selection scope ordering, but **does not autoconfigure** a
link-local address. The full RFC 3927 state machine is **not
implemented**.

The audit was performed by reading the RFC text fresh and
inspecting `net_addr/ip4_address.py`,
`pytcp/lib/ip4_source_selection.py`, and the IPv4 packet
handlers directly. Non-normative content (§1 Introduction,
§1.1-§1.9 Requirements / Applicability, §3 Considerations, §4
Security, §5 Acknowledgements) is omitted.

---

## Top-line adherence

PyTCP **partial — Phase 1**: the 169.254/16 range is
recognised at the address-classification layer
(`is_link_local`) and feeds the source-selection scope
ordering. The autoconfiguration state machine (pseudo-random
address selection + ARP Probe + conflict resolution + ARP
Announce + defense) is not implemented because PyTCP's
primary address-acquisition path is **DHCPv4** (RFC 2131,
audited under `docs/rfc/dhcp4/`); link-local autoconfiguration
would be the DHCP-failure fallback per RFC 3927 §1.9.

| Section | Topic                                                  | Status |
|---------|--------------------------------------------------------|--------|
| §1.9    | When to configure a Link-Local address (after DHCP fails) | not implemented |
| §2.1    | Random address selection from 169.254.1.0 - 169.254.254.255 | not implemented |
| §2.2    | Claim via ARP Probe                                    | not implemented |
| §2.4    | Announce via gratuitous ARP                            | not implemented |
| §2.5    | Conflict detection / defense                           | not implemented |
| §2.6    | Source / destination address usage rules               | met (`_phtx_ip4` scope-mismatch gate) |
| §2.7    | Link-local packets are not forwarded                   | n/a (no forwarding) |
| §2.8    | Link-local packets are local-only                      | met (subsumed by §2.6) |
| §2.11   | DHCPv4 client interaction                              | n/a (no link-local autoconfig) |

---

## §1.9 When to Configure an IPv4 Link-Local Address

> "A host SHOULD NOT configure an IPv4 Link-Local address if it
> already has an IPv4 address assigned through a means other
> than IPv4 Link-Local address autoconfiguration."

**Adherence:** met (vacuously). PyTCP never auto-assigns a
link-local address. Static configuration via the address API
or DHCP-acquired addresses always take precedence.

> "An IPv4 host that is configured with a routable address
> obtained via PPP or some other means and is then attached to
> a different link that does not have a DHCP server, may need
> to obtain an IPv4 Link-Local address ..."

**Adherence:** not implemented. PyTCP's DHCP client logic
treats DHCP failure as terminal (the stack runs without an
IPv4 address until the operator intervenes or DHCP recovers).
Link-local fallback is a Phase-2 consideration.

## §2.1 Link-Local Address Selection

> "When a host wishes to configure an IPv4 Link-Local address,
> it selects an address using a pseudo-random number
> generator with a uniform distribution in the range from
> 169.254.1.0 to 169.254.254.255 inclusive."

**Adherence:** not implemented. No PyTCP code path generates
a candidate link-local address.

## §2.2 Claiming a Link-Local Address — ARP Probe

> "Before using the IPv4 Link-Local address (e.g., using it as
> the source address in an IPv4 packet, or as the Sender IPv4
> address in an ARP packet) a host MUST perform the probing
> test described below ..."

**Adherence:** not implemented. The ARP-probe machinery
itself does exist in `pytcp/protocols/arp/` for DHCPv4 IPv4
Address Conflict Detection (RFC 5227 — used by DHCP), but it
is not wired to a link-local autoconfig consumer.

When link-local autoconfig lands, the natural integration
point is a new `pytcp/protocols/ip4_link_local/` subsystem
that:

1. Generates a candidate address from a seeded RNG (use the
   MAC address per §2.1 recommendation).
2. Calls the existing ARP-probe API.
3. On conflict, regenerates and retries.
4. On success, registers the address in `_ip4_host` and
   schedules ARP Announce.

## §2.5 Conflict Detection and Defense (post-claim)

> "Address conflict detection is an ongoing process that is in
> effect for as long as a host is using an IPv4 Link-Local
> address."

**Adherence:** not implemented (no link-local autoconfig).
Note that PyTCP's ARP cache does include conflict detection
for the duplicate-MAC case but the link-local-specific
defend-or-reconfigure decision tree (§2.5(a)/(b)) is absent.

## §2.6 Source Address Usage

> "A host MUST NOT send packets with an IPv4 Link-Local source
> address to any destination that is not itself an IPv4 Link-
> Local destination."

**Adherence:** met.
`packet_handler__ip4__tx.py::_phtx_ip4` rejects any datagram
where `ip4__src.is_link_local != ip4__dst.is_link_local` with
`TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH` and the
`ip4__link_local_scope_mismatch__drop` counter bump. The gate
sits between destination validation and assembly so it fires
after `__validate_src_ip4_address` has confirmed the source
is owned. Both halves of the rule are symmetric (the
`!=` check catches both link-local→global and global→
link-local mixes). The DHCP-client path
(src=0.0.0.0, dst=255.255.255.255) is naturally exempt
because neither address is link-local.

## §2.7 Link-Local Packets Are Not Forwarded

> "Routers MUST NOT forward a packet with an IPv4 Link-Local
> source or destination address, irrespective of the router's
> default route configuration or routes obtained from dynamic
> routing protocols."

**Adherence:** n/a (host stack; no forwarding). The Phase-2
forwarder will need this rule; the predicate is ready.

## §2.8 Link-Local Packets Are Local

> "A host MUST NOT send a packet with an IPv4 Link-Local
> destination address to any router for forwarding."

**Adherence:** met (subsumed by §2.6). The §2.6 scope-
mismatch gate at the IPv4 layer rejects every send where
src and dst differ in link-local scope. The only paths that
reach `_phtx_ethernet` with a link-local destination are:

1. **Link-local-to-link-local sends** — both src and dst are
   in 169.254/16. When a link-local source is owned the
   host has an `Ip4Host("169.254.x.y/16")` configured, so
   the link-local destination IS in the host's network and
   the Ethernet-layer gateway path is naturally skipped
   (the `ip4_dst not in ip4_host.network` branch fails).
2. **Caller-supplied broadcast** — not a §2.8 scenario.

So §2.8 cannot fire independently of §2.6 in PyTCP's
host-stack model — the gate at the IPv4 layer is necessary
and sufficient. An explicit Ethernet-layer short-circuit
would be dead code and is intentionally omitted. The
adherence is observable via the §2.6 test class
(`TestPacketHandlerIp4TxRfc3927ScopeGate`) which proves
every non-link-local-to-link-local path is rejected before
reaching the gateway-selection logic.

## §2.11 DHCPv4 Client Interaction

> "A host that has obtained an IPv4 Link-Local address MAY
> attempt to use DHCP to obtain a routable address."

**Adherence:** n/a (no link-local autoconfig). The DHCP
client (`pytcp/protocols/dhcp4/dhcp4__client.py`) operates
without any link-local fallback.

---

## Test coverage audit

### Link-local predicate (Ip4Address.is_link_local)

- **Unit:**
  `net_addr/tests/unit/test__ip4_address.py`
  Parametric cases verifying `is_link_local` on
  169.254.0.0, 169.254.255.255, and boundary addresses just
  outside.

**Status:** locked in.

### Link-local scope in IPv4 source selection (RFC 6724-style)

- **Integration:**
  `pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  Verifies that the link-local scope value
  `IP4__SCOPE__LINK_LOCAL = 0x2`
  (`pytcp/lib/ip4_source_selection.py:49`) is consulted by
  the rule-2 source-scope sort key.

**Status:** locked in.

### §2.6 TX-side scope-mismatch gate

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__ip4__tx.py::TestPacketHandlerIp4TxRfc3927ScopeGate`
  Five cases: link-local src + global dst → drop with new
  TxStatus + counter bump; symmetric global src + link-
  local dst → same drop; link-local src + link-local dst →
  passes the gate; global src + global dst → unaffected;
  DHCP-client path (src=0.0.0.0 + dst=255.255.255.255) →
  unaffected.

**Status:** locked in.

### Phase-2 gaps (autoconfig state machine, source/dst gating)

**No test surface — Phase 2.** When link-local autoconfig
lands:

1. Address-selection PRNG seeded from MAC produces a stable
   per-boot candidate.
2. ARP probe round-trip with mock conflicting peer →
   regenerate.
3. ARP Announce after successful probe.
4. Conflict-during-use → defense-or-reconfigure decision.
5. TX-side gate rejects mismatched-scope sends.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Link-local predicate (169.254/16 recognition)         | locked in |
| Link-local scope in source selection                  | locked in |
| §2.1-§2.5 Link-local autoconfig state machine         | n/a (not implemented) |
| §2.6 TX-side scope-mismatch gate                      | locked in |
| §2.8 Link-local-not-to-router                         | locked in (subsumed by §2.6) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §1.9 Link-local fallback when DHCP fails            | not implemented (Phase 2) |
| §2.1 Random address selection from 169.254.1-254/24  | not implemented |
| §2.2 ARP Probe                                       | not implemented (ARP-probe machinery exists for ACD/DHCP) |
| §2.4 ARP Announce                                    | not implemented for link-local |
| §2.5 Conflict detection / defense                   | not implemented |
| §2.6 TX-side scope-mismatch gate                    | met (Phase 0 of RFC 3927 track) |
| §2.7 / §2.8 No forwarding / local-only              | n/a (host) / met (subsumed by §2.6) |
| §2.11 DHCP client interaction                       | n/a (no autoconfig) |

PyTCP recognises 169.254/16 at the address layer but does not
auto-acquire link-local addresses. The full Phase-2 work would
be a new `pytcp/protocols/ip4_link_local/` subsystem driven by
DHCPv4 failure timeouts, mirroring the structural pattern of
the existing DHCPv4 client. Until a consumer materialises this
remains deferred.
