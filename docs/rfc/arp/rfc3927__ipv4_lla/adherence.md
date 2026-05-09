# RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3927                                                 |
| Title       | Dynamic Configuration of IPv4 Link-Local Addresses   |
| Category    | Standards Track                                      |
| Date        | May 2005                                             |
| Source text | [`rfc3927.txt`](rfc3927.txt)                         |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 3927
(IPv4 link-local address autoconfiguration in `169.254/16`).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under `pytcp/stack/`,
`pytcp/stack/packet_handler/`, and
`net_addr/ip4_address.py` directly.

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**, or **deliberate non-implementation**.

---

## Scope and PyTCP North-Star alignment

RFC 3927 specifies an **autoconfiguration** mechanism: when a
host has no other source of an IPv4 address (no DHCP, no
manual config), it picks a pseudo-random address from
`169.254.1.0`–`169.254.254.255`, probes it via the
RFC-5227-style ARP probe / announce / defend mechanism, and
uses it for on-link communication only.

PyTCP today does **not** auto-configure link-local IPv4
addresses. The address-acquisition flow at
`pytcp/stack/packet_handler/__init__.py::_create_stack_ip4_addressing`
(lines 649–695) supports two paths:

1. **Manual** — the user passes an `Ip4Host` to
   `stack.init()`. PyTCP probes the candidate via RFC 5227
   and announces it.
2. **DHCPv4** — if no manual host is supplied and DHCP is
   enabled, `Dhcp4Client(...).fetch()` requests one. PyTCP
   probes the DHCP-offered address via RFC 5227 and
   announces it.

If both paths fail, IPv4 support is disabled
(`packet_handler/__init__.py:688-695`). There is no third
"fall back to RFC 3927 link-local" path.

`net_addr.Ip4Address.is_link_local`
(`net_addr/ip4_address.py:147-151`) recognises
`169.254.0.0/16` and contributes to the `is_global`
aggregator; nothing else in the stack consumes it.

Because the autoconfiguration mechanism is the entire
purpose of this RFC, **most normative requirements in
RFC 3927 are "not implemented"** — PyTCP does not enter the
algorithm at all. A small number of forwarding-rule
requirements (§2.7) are **vacuous** because PyTCP is a host
stack and never forwards. A small number of "do not
intermix" requirements (§1.6, §2.11) are **vacuous** because
PyTCP doesn't have any LLA path that could intermix.

This audit walks the normative content for completeness,
flagging the small number of host-side cross-references
that *are* relevant today and the requirements that would
become live if RFC 3927 support is later added.

The shared probe / announce / defend infrastructure that
RFC 3927 §2.2.1 / §2.4 / §2.5 reuses from RFC 5227 §2.1.1 /
§2.3 / §2.4 is audited at
[`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md).
That audit reports several gaps in PyTCP's RFC 5227
implementation (RX-vs-DAD set disconnect, missing
ANNOUNCE_NUM = 2, missing DEFEND_INTERVAL rate-limit) that
would need to be fixed *before* RFC 3927 could be
implemented soundly on top of them.

The constants table at RFC 3927 §9 — `PROBE_WAIT = 1`,
`PROBE_NUM = 3`, `PROBE_MIN = 1`, `PROBE_MAX = 2`,
`ANNOUNCE_WAIT = 2`, `ANNOUNCE_NUM = 2`,
`ANNOUNCE_INTERVAL = 2`, `MAX_CONFLICTS = 10`,
`RATE_LIMIT_INTERVAL = 60`, `DEFEND_INTERVAL = 10` — is
shared with RFC 5227 §1.1 verbatim, and the gaps PyTCP has
against those values are recorded in the RFC 5227 audit.

Sections without normative content — Abstract, §1 (mostly
narrative), §6 (Router Considerations narrative), §10
(References), §A / §B / §C (appendices) — are summarised
inline only where relevant.

---

## §1.5 — Autoconfiguration Issues

> "Implementations of IPv4 Link-Local address
> autoconfiguration MUST expect address conflicts, and MUST
> be prepared to handle them gracefully by automatically
> selecting a new address whenever a conflict is detected
> ... This requirement to detect and handle address
> conflicts applies during the entire period that a host is
> using a 169.254/16 IPv4 Link-Local address ..."

**Adherence:** **not implemented (no LLA path)**. PyTCP has
no LLA selection or LLA-specific conflict-handling path.
The MUST is conditional on "implementations of [LLA
autoconfiguration]"; PyTCP is not such an implementation,
so the MUST does not apply. If RFC 3927 support is later
added, this becomes one of the most consequential
requirements: the conflict handler must transition to a
fresh random LLA, not just defend the current one.

---

## §1.6 — Alternate Use Prohibition

> "Note that addresses in the 169.254/16 prefix SHOULD NOT
> be configured manually or by a DHCP server."

**Adherence:** **not enforced**. PyTCP's
`stack.init(ip4_host=Ip4Host("169.254.x.y/16"))` accepts
the address without warning; the parameter is fed into the
same RFC 5227 probe / announce path used for any manual
`Ip4Host`. There is no gate at
`packet_handler/__init__.py::_create_stack_ip4_addressing`
or at the `Ip4Host` constructor that flags
`address.is_link_local`. Likewise, a DHCP server returning
a `169.254/16` lease is accepted by `Dhcp4Client.fetch()`
without rejection (the DHCP client is not in this
audit's scope, but the SHOULD does flow downstream).

This is a SHOULD-strength deviation; non-compliance is
silent rather than disruptive. The fix is a one-line check
at the top of `_create_stack_ip4_addressing` that warns
when `ip4_host.address.is_link_local` and rejects /
demotes the host (or consults a future "I am explicitly
opting in to RFC 3927" knob).

> "While the DHCP specification [RFC2131] indicates that a
> DHCP client SHOULD probe a newly received address with
> ARP, this is not mandatory."

**Adherence:** **met**. PyTCP does probe DHCP-offered
addresses via RFC 5227 — the same `_create_stack_ip4_addressing`
loop runs `_send_arp_probe` for any `_ip4_host_candidate`,
whether the candidate came from manual config or DHCP
(`packet_handler/__init__.py:657-686`).

---

## §1.7 — Multiple Interfaces

> "Additional considerations apply to hosts that support
> more than one active interface where one or more of these
> interfaces support IPv4 Link-Local address configuration."

**Adherence:** **vacuous (single interface)**. PyTCP
supports exactly one TAP/TUN interface today; multi-homed
considerations are out of scope until Phase 2 multi-
interface support lands.

---

## §1.9 — When to configure an IPv4 Link-Local address

> "A host SHOULD NOT have both an operable routable address
> and an IPv4 Link-Local address configured on the same
> interface."

**Adherence:** **vacuous (no LLA path)**. PyTCP cannot
have an LLA configured because it has no LLA path; the
"do not coexist" rule has no implementation surface today.

> "1. The assignment of an IPv4 Link-Local address on an
> interface is based solely on the state of the interface,
> and is independent of any other protocols such as DHCP.
> A host MUST NOT alter its behavior and use of other
> protocols such as DHCP because the host has assigned an
> IPv4 Link-Local address to an interface."

**Adherence:** **vacuous (no LLA path)**.

> "2. If a host finds that an interface that was previously
> configured with an IPv4 Link-Local address now has an
> operable routable address available, the host MUST use
> the routable address when initiating new communications
> ..."

**Adherence:** **vacuous (no LLA path)**.

> "3. If a host finds that an interface no longer has an
> operable routable address available, the host MAY
> identify a usable IPv4 Link-Local address ..."

**Adherence:** **not implemented (MAY not exercised)**.
PyTCP does not fall back to LLA on routable-address loss;
it disables IPv4 entirely
(`packet_handler/__init__.py:688-695`). The MAY is
permissive, so the absence is allowed.

---

## §2.1 — Link-Local Address Selection

> "When a host wishes to configure an IPv4 Link-Local
> address, it selects an address using a pseudo-random
> number generator with a uniform distribution in the
> range from 169.254.1.0 to 169.254.254.255 inclusive."
>
> "The first 256 and last 256 addresses in the 169.254/16
> prefix are reserved for future use and MUST NOT be
> selected by a host using this dynamic configuration
> mechanism."

**Adherence:** **not implemented**. PyTCP has no LLA
selection routine. If implemented, the natural API is a
helper at `net_addr/ip4_address.py` that returns a random
`Ip4Address` in the legal range, seeded per §2.1.

> "The pseudo-random number generation algorithm MUST be
> chosen so that different hosts do not generate the same
> sequence of numbers. If the host has access to persistent
> information that is different for each host, such as its
> IEEE 802 MAC address, then the pseudo-random number
> generator SHOULD be seeded using a value derived from
> this information."

**Adherence:** **not implemented**. The host's MAC address
is available (`self._mac_unicast`) and would be the natural
seed source, but no PRNG path consumes it for this purpose.

---

## §2.2 — Claiming a Link-Local Address

> "After it has selected an IPv4 Link-Local address, a host
> MUST test to see if the IPv4 Link-Local address is
> already in use before beginning to use it."

**Adherence:** **vacuous (no LLA path)**. The MUST applies
once an address is selected; PyTCP doesn't select.

> "A host MUST NOT perform this check periodically as a
> matter of course."

**Adherence:** **met**. PyTCP doesn't probe periodically
under any circumstance — the probe loop runs only inside
the synchronous `_create_stack_ip4_addressing` path at
startup.

---

## §2.2.1 — Probe details

> "On a link-layer such as IEEE 802 that supports ARP,
> conflict detection is done using ARP probes."

**Adherence:** **met (mechanism reused)**. PyTCP's
`_send_arp_probe` and the surrounding RFC 5227-flavoured
probe loop are protocol-agnostic — they would handle a
169.254/16 candidate identically to a manual or DHCP one.
The wire format is identical (the probe is the same RFC
826 broadcast Request with `spa = 0.0.0.0`).

The detailed probe-format / probe-count / probe-spacing
text in §2.2.1 is a verbatim repeat of RFC 5227 §2.1.1; the
adherence picture is therefore identical to the RFC 5227
audit (probe wire format met; PROBE_NUM / PROBE_MIN /
PROBE_MAX met; PROBE_WAIT initial random delay not
implemented; ANNOUNCE_WAIT post-probe quiet period not
implemented; MAX_CONFLICTS / RATE_LIMIT_INTERVAL not
implemented; RX-side conflict detection has the disconnect
bug — see [`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md)).

---

## §2.4 — Announcing an Address

> "Having probed to determine a unique address to use, the
> host MUST then announce its claimed address by
> broadcasting ANNOUNCE_NUM ARP announcements, spaced
> ANNOUNCE_INTERVAL seconds apart."

**Adherence:** **partial (mechanism reused; count = 1)**.
The same `_send_arp_announcement` helper would fire for an
LLA candidate, with the same RFC 5227 audit gaps:
single-shot announcement instead of `ANNOUNCE_NUM = 2`. See
[`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md)
§2.3.

---

## §2.5 — Conflict Detection and Defense

> "Address conflict detection is an ongoing process that is
> in effect for as long as a host is using an IPv4 Link-
> Local address. ... A host MUST respond to a conflicting
> ARP packet as described in either (a) or (b) below ..."

**Adherence:** **vacuous (no LLA path) but mechanism
reused**. PyTCP's RFC 5227 §2.4 implementation
(`packet_handler__arp__rx.py:175-183,268-276`) would fire
for any IP it has claimed, including an LLA. The same gaps
apply (no DEFEND_INTERVAL rate-limit, no abandon path) —
see the RFC 5227 audit.

The RFC 3927 §2.5 (a) / (b) options are slightly tighter
than RFC 5227 §2.4 (a) / (b) / (c): RFC 3927 lists only (a)
"abandon and pick new LLA" and (b) "defend with rate
limit", omitting the RFC 5227 (c) "defend indefinitely"
variant. This is because LLAs are by design ephemeral and
cheap to renumber. PyTCP's current behaviour (defend
forever, no rate limit) is closer to a malformed (c) and
would need to be redesigned for any RFC 3927-compliant
LLA, switching to (a) automatic renumbering on any
conflict in the LLA range.

> "A host MUST NOT ignore conflicting ARP packets."

**Adherence:** **met**. PyTCP detects and acts on every
conflicting ARP packet — see RFC 5227 §2.4 audit.

> "Before abandoning an address due to a conflict, hosts
> SHOULD actively attempt to reset any existing connections
> using that address."

**Adherence:** **vacuous (no abandon path)**. Same as
RFC 5227 §2.4 final SHOULD; needs an ABORT-bound-sockets
plumbing when abandon is implemented.

> "All ARP packets (*replies* as well as requests) that
> contain a Link-Local 'sender IP address' MUST be sent
> using link-layer broadcast instead of link-layer unicast.
> This aids timely detection of duplicate addresses."

**Adherence:** **not implemented**. PyTCP's
`_send_arp_reply`
(`pytcp/stack/packet_handler/packet_handler__arp__tx.py:209-218`)
unconditionally unicasts to the requester
(`ethernet__dst = arp__tha`). RFC 3927 §2.5 mandates
broadcasting the Reply when the SPA is link-local, even
though RFC 5227 §2.6 says "broadcast Replies SHOULD NOT be
used universally". This would be one of the more invasive
RFC 3927 fixes — it's a per-reply branch in the TX path
based on `arp__spa.is_link_local`, and it's also the rule
that makes "joined networks heal" reliably (§4 below).

---

## §2.6 — Address Usage and Forwarding Rules

### §2.6.1 — Source Address Usage

> "Where both an IPv4 Link-Local and a routable address are
> available on the same interface, the routable address
> should be preferred as the source address for new
> communications ..."

**Adherence:** **vacuous (single source per interface)**.
PyTCP's source-address selection is "use whatever IP is
configured"; with only one IP per interface today, no
preference logic is needed.

### §2.6.2 — Forwarding Rules

> "Whichever interface is used, if the destination address
> is in the 169.254/16 prefix (excluding the address
> 169.254.255.255, which is the broadcast address for the
> Link-Local prefix), then the sender MUST ARP for the
> destination address and then send its packet directly to
> the destination on the same physical link."

**Adherence:** **met (vacuously, single-interface)**. PyTCP
ARPs for any IPv4 destination on its local subnet that
doesn't go through the gateway, including 169.254/16 if
the local subnet happens to be 169.254/16. With only one
interface and no routing table, "send directly to the
destination on the same physical link" is the only thing
the stack can do anyway.

> "The host MUST NOT send a packet with an IPv4 Link-Local
> destination address to any router for forwarding."

**Adherence:** **not enforced (silent risk)**. PyTCP's
`_phtx_ip4` (and the IPv6 sibling) routes off-subnet
destinations to the configured gateway without checking
`destination.is_link_local`. A user who manually configures
a routable subnet alongside a 169.254-flavoured destination
would send LLA packets to the gateway — which violates the
MUST. The fix is a one-line gate at the IPv4 TX path that
treats `destination.is_link_local` as "must be on-subnet"
(or drop with an ICMP Destination Unreachable).

The risk in PyTCP today is small because the typical
deployment doesn't have any LLA destination on the wire,
but the gate is the cleanest way to enforce the MUST.

---

## §2.7 — Link-Local Packets Are Not Forwarded

> "An IPv4 packet whose source and/or destination address
> is in the 169.254/16 prefix MUST NOT be sent to any
> router for forwarding, and any network device receiving
> such a packet MUST NOT forward it, regardless of the TTL
> in the IPv4 header."

**Adherence:** **vacuous (host-only stack)**. The
"receiving device MUST NOT forward" half is router-side and
PyTCP doesn't forward. The "MUST NOT send to any router"
half is the host-side restatement of §2.6.2 above; same
not-enforced status applies.

> "Similarly, a router or other host MUST NOT
> indiscriminately answer all ARP Requests for addresses in
> the 169.254/16 prefix."

**Adherence:** **met (vacuously)**. PyTCP only answers ARP
Requests for `tpa in self._ip4_unicast`
(`packet_handler__arp__rx.py:207-242`); it does not
indiscriminately answer for any 169.254/16 TPA.

---

## §2.8 — Link-Local Packets are Local

> "The 169.254/16 address prefix MUST NOT be subnetted."

**Adherence:** **not enforced (silent risk)**. PyTCP's
`Ip4Host` constructor accepts any valid `prefix_len`,
including a `/24` mask on a 169.254 address. The MUST NOT
is silently violable. As with §1.6, the fix is a check at
the address-config path. Low-priority because no real
deployment subnets 169.254.

---

## §2.9 — Higher-Layer Protocol Considerations

> "As IPv4 Link-Local addresses may change at any time and
> have limited scope, IPv4 Link-Local addresses MUST NOT be
> stored in the DNS."

**Adherence:** **vacuous (no DNS implementation)**. PyTCP
has no DNS server or DNS-write path; the MUST NOT is
trivially satisfied. The RFC clause is aimed at host
applications and operators, not the stack itself.

---

## §2.10 — Privacy Concerns

Informational paragraph, no normative content. **N/A.**

---

## §2.11 — Interaction between DHCPv4 client and IPv4 Link-Local State Machines

> "A device that implements both IPv4 Link-Local and a
> DHCPv4 client should not alter the behavior of the DHCPv4
> client to accommodate IPv4 Link-Local configuration."

**Adherence:** **vacuous (no LLA path)**. PyTCP's
`Dhcp4Client` does not have any LLA-specific code, so the
SHOULD NOT is satisfied trivially.

---

## §3 — Considerations for Multiple Interfaces (entire section)

**Adherence:** **vacuous (single-interface stack)**.
§3.1 (Scoped Addresses), §3.2 (Address Ambiguity), §3.3
(Interaction with Hosts with Routable Addresses), §3.4
(Unintentional Autoimmune Response) are all conditional on
multi-homing; PyTCP supports a single TAP/TUN interface
today.

---

## §4 — Healing of Network Partitions

Largely informational; the only normative statement
(buried at §4 last paragraph) is:

> "Hosts SHOULD NOT send periodic gratuitous ARPs."

**Adherence:** **met**. PyTCP does not send periodic
gratuitous ARPs. The only paths that emit gratuitous ARP
are:
1. RFC 5227 §2.3 announce-after-probe at startup
   (`packet_handler/__init__.py:678-685` →
   `_send_arp_announcement`); a one-shot, not periodic.
2. RFC 5227 §2.4 conflict-defense gratuitous Reply
   (`packet_handler__arp__rx.py:182,275` →
   `_send_gratuitous_arp`); reactive, not periodic.

Neither qualifies as "periodic gratuitous ARP".

---

## §5 — Security Considerations

Narrative; no normative requirements. **N/A.**

---

## §8 — IANA Considerations

The §8 paragraphs reserve `169.254.0.0/16` and the
`169.254.255.255` broadcast — purely IANA / address-space
allocation. **N/A** for code.

---

## §9 — Constants

Lists the timer / counter constants reused by the algorithm.
PyTCP would need these as module-level constants if RFC
3927 is implemented; today none of them appear in source.

---

## Test coverage audit

PyTCP has no RFC 3927 implementation. The relevant
**negative** behaviour ("PyTCP does not auto-configure LLA
and does not respond to LLA TPAs we don't own") is locked
in by:

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__arp__rx.py`
  — "request, unknown TPA on local network" and "request,
  unknown TPA on another network" cases assert that any
  Request for a TPA we haven't claimed is dropped silently.
- **Unit:**
  `net_addr/tests/unit/test__ip4_address.py` — pins
  `is_link_local` for any address in `169.254.0.0/16`
  (boundary tests at `169.254.0.0`, `169.254.255.255`,
  and a midrange value).

When RFC 3927 support is later added, the natural test
matrix is:

1. **Selection algorithm:** seeded PRNG produces the same
   address from the same MAC; uniform-distribution across
   the legal range; never returns an address in
   `169.254.0.0/24` or `169.254.255.0/24`.
2. **Probe / announce:** identical to the existing RFC
   5227 matrix (the same `_send_arp_probe` /
   `_send_arp_announcement` are reused).
3. **§2.5 conflict-on-LLA:** select option (a) (renumber)
   not (c) (defend forever) for any LLA conflict; pin
   that the new candidate is freshly seeded from the PRNG.
4. **§2.5 broadcast Replies for LLA SPA:** when the SPA
   of the Reply is a configured LLA, the L2 destination
   must be `FF:FF:FF:FF:FF:FF`, not the requester's MAC.
5. **§2.6.2 / §2.7 forwarding gate:** an LLA-destination
   packet sent from a host with a routable IP is dropped
   (or sent on-link, never via the gateway).
6. **§1.6 prohibition warning:** a manual or DHCP-supplied
   `169.254/16` host triggers a warning log and is
   treated specially (or rejected, depending on policy).

### Test coverage summary

| Aspect                                         | Coverage                                            |
|------------------------------------------------|-----------------------------------------------------|
| `is_link_local` predicate                      | locked in (`net_addr/tests/unit/test__ip4_address.py`) |
| LLA auto-configuration absent                  | locked in (negative path; integration tests)        |
| Selection algorithm                            | n/a (not implemented)                               |
| Probe / announce mechanism (when applied)      | locked in via RFC 5227 audit                        |
| §2.5 broadcast Replies for LLA SPA             | n/a (not implemented)                               |
| §2.6.2 / §2.7 LLA forwarding gate              | n/a (not implemented)                               |
| §1.6 prohibition warning                       | n/a (not implemented)                               |
| §2.8 do-not-subnet check                       | n/a (not implemented)                               |

---

## Overall assessment

| Aspect                                              | Status                                         |
|-----------------------------------------------------|------------------------------------------------|
| LLA selection (§2.1)                                | not implemented                                |
| LLA probe before use (§2.2 / §2.2.1)                | not implemented (mechanism reusable from RFC 5227) |
| LLA announcement (§2.4)                             | not implemented (mechanism reusable from RFC 5227) |
| LLA conflict response (§2.5)                        | not implemented (would need (a) renumber path) |
| Broadcast Replies for LLA SPA (§2.5 final MUST)     | not implemented                                |
| Forwarding gate (§2.6.2 / §2.7)                     | not enforced (silent risk)                     |
| Subnetting prohibition (§2.8)                       | not enforced (silent risk)                     |
| LLA in DNS prohibition (§2.9)                       | vacuous (no DNS path)                          |
| LLA / DHCP state-machine interaction (§2.11)        | vacuous (no LLA path)                          |
| Multi-interface considerations (§3)                 | vacuous (single interface)                     |
| No periodic gratuitous ARP (§4)                     | met                                            |
| `is_link_local` predicate exists                    | met                                            |
| §1.6 prohibition (manual / DHCP-supplied LLA)       | not enforced                                   |

PyTCP today is **not an RFC 3927 implementation**. The bulk
of the RFC's normative content is therefore "not
implemented" — that is the deliberate, North-Star-aligned
position for a Phase 1 host stack that targets
default-Linux behaviour (Linux supports RFC 3927 only as an
opt-in via NetworkManager / `avahi-autoipd`, never by
default in the kernel).

If RFC 3927 support is later added — for example to allow
PyTCP to come up on an isolated LAN with no DHCP server —
the implementation can reuse the existing RFC 5227 probe /
announce / defend infrastructure, but two RFC 3927-specific
clauses need new code:

1. **§2.5 broadcast ARP Replies when SPA is LLA.** Branch
   in `_send_arp_reply` based on
   `arp__spa.is_link_local`.
2. **§2.5 (a) renumber-on-conflict path.** A new
   "abandon and re-select" code path that drives a fresh
   PRNG draw and re-enters the probe loop. Pairs with the
   §2.5 abandon-path SHOULD that already exists as a gap
   in the RFC 5227 audit.

The most consequential **silent** gap today is **§2.6.2 /
§2.7 forwarding rule**: if a user ever configures an LLA
destination with a routable source on a different subnet,
the packet would be sent to the gateway. Adding a one-line
gate (`if destination.is_link_local: route_on_link()`) at
the IPv4 TX path closes the gap with negligible cost. The
fix should ride along with any LLA implementation work and
is not a Phase 1 priority on its own.

The host-side cross-references that already affect Phase 1
PyTCP without an LLA path:

- `is_link_local` is part of the `is_global` aggregator in
  `Ip4Address`, which means an LLA address is correctly
  classified as non-global for any future code that
  consults `is_global` (e.g. RPF checks, source-address
  selection).
- `_create_stack_ip4_addressing` accepts `169.254/16`
  manual config without warning — a SHOULD-strength gap
  flagged at §1.6.
