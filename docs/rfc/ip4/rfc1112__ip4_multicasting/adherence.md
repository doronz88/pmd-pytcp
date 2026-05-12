# RFC 1112 — Host Extensions for IP Multicasting

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 1112                                           |
| Title       | Host Extensions for IP Multicasting            |
| Category    | Internet Standard (STD 5)                      |
| Date        | August 1989                                    |
| Source text | [`rfc1112.txt`](rfc1112.txt)                   |

This document records the PyTCP codebase's adherence to RFC 1112
clause by clause. RFC 1112 defines three conformance levels:

- **Level 0:** no multicast support; class D destinations
  silently discarded.
- **Level 1:** send-only multicast support.
- **Level 2:** full multicast support (send + receive + IGMP
  group membership).

PyTCP today is **Level 1+**: it can send and receive multicast
IP datagrams for the configured groups, but does not implement
IGMP group management (RFC 2236 / RFC 3376). The all-hosts
group (224.0.0.1) is preconfigured at boot. Group join / leave
beyond the all-hosts default is Phase 2.

The audit was performed by reading the RFC text fresh and
inspecting `net_addr/ip4_address.py`,
`pytcp/stack/__init__.py`, and the IPv4 packet handlers
directly. Non-normative content (§1 Status, §2 Introduction,
§9 ICMP, §10 IANA / Appendices) is omitted.

---

## Top-line adherence

| Section | Topic                                                    | Status |
|---------|----------------------------------------------------------|--------|
| §3      | Conformance Level 0/1/2                                  | Level 1+ (send + receive, no IGMP) |
| §4      | Class D host-group addresses (224.0.0.0 - 239.255.255.255) | met |
| §4      | 224.0.0.1 = all hosts (permanent)                        | met (preconfigured) |
| §6      | Sending multicast datagrams                              | met (with caveats — see §6 below) |
| §7      | Receiving multicast datagrams                            | met (for joined groups) |
| §7      | IGMP group management                                    | not implemented (Phase 2) |
| §6.4    | Ethernet mapping (high-23-bits)                          | met    |

---

## §4 Host Group Addresses

> "Host groups are identified by class D IP addresses, i.e.,
> those with '1110' as their high-order four bits."

**Adherence:** met. `Ip4Address.is_multicast` recognises 224/4
(`net_addr/ip4_address.py:164-169`):

```python
return self._address & 0xF0_00_00_00 == 0xE0_00_00_00
```

> "224.0.0.1 is assigned to the permanent group of all IP
> hosts (including gateways)."

**Adherence:** met. The all-hosts group is preconfigured in
the stack's `_ip4_multicast` list at boot
(`pytcp/stack/packet_handler/__init__.py`).

## §6.1 Sending — IP Service Interface

> "First, the service interface should provide a way for the
> upper-layer protocol to specify the IP time-to-live of an
> outgoing multicast datagram, if such a capability does not
> already exist. If the upper-layer protocol chooses not to
> specify a time-to-live, it should default to 1 for all
> multicast IP datagrams."

**Adherence:** partial — TTL default. The TX entry point
`_phtx_ip4` accepts an arbitrary `ip4__ttl: int = IP4__DEFAULT_TTL`
(default 64). Multicast does **not** get a different default
TTL; the multicast-specific "default to 1" recommendation is
not honoured. Callers that want multicast-scope TTL=1 must
pass it explicitly.

**`# Phase 2:`** the natural fix is a dst-classification
branch in `_phtx_ip4` that overrides the TTL default when
`ip4__dst.is_multicast and not caller_provided_ttl`. Mark in
`packet_handler__ip4__tx.py` near line 100.

> "For hosts that may be attached to more than one network,
> the service interface should provide a way for the upper-
> layer protocol to identify which network interface is be
> used for the multicast transmission."

**Adherence:** n/a — single interface (Phase 1).

## §6.2 Sending — IP Module

> "When the IP module sees an upper-layer 'send IP datagram'
> request whose destination is a class D address, it must
> translate the address to the corresponding local network
> multicast address before passing the datagram and address to
> the local network module."

**Adherence:** met. `Ip4Address.multicast_mac` maps the
high-23-bits of the IPv4 multicast address into the
`01:00:5E:` MAC prefix (`net_addr/ip4_address.py:108-126`). The
Ethernet TX path consumes this when resolving the destination
MAC for multicast frames
(`packet_handler__ethernet__tx.py`).

## §6.3 / §6.4 Local Network Module Extensions (Ethernet mapping)

> "An IP host group address is mapped to an Ethernet multicast
> address by placing the low-order 23 bits of the IP address
> into the low-order 23 bits of the Ethernet multicast address
> 01-00-5E-00-00-00 (hex)."

**Adherence:** met. `Ip4Address.multicast_mac`
(`net_addr/ip4_address.py:108-125`) returns
`MacAddress(MAC__IP4_MULTICAST_PREFIX | self._address & 0x0000_007F_FFFF)`
which is exactly the high-23-bits mapping.

## §7 Receiving Multicast IP Datagrams

> "[Level 2] In order to receive multicast datagrams sent to a
> particular host group, the host must JOIN the group."

**Adherence:** partial. PyTCP's `_ip4_multicast` list is
populated at boot with the all-hosts group; the RX path
(`packet_handler__ip4__rx.py:149-153`) accepts any inbound
datagram whose destination is in this list. There is **no
runtime API** to JOIN or LEAVE a group; the list is fixed at
boot.

For Phase 1 host-stack scope (where the only multicast group
of practical interest is 224.0.0.1) this is sufficient.
Application-level multicast subscription (e.g. multicast UDP
sockets, MDNS / SSDP receivers) is Phase 2.

> "Level 2 ... requires implementation of the Internet Group
> Management Protocol (IGMP)."

**Adherence:** not implemented (Phase 2). IGMP would
publish group memberships upstream so multicast routers learn
to forward the relevant groups to PyTCP's subnet. Out of scope
for the current Phase-1 host posture (which is reachable on
the local subnet without router cooperation).

## §9 ICMP

The original RFC 1112 §9 noted that ICMP error generation in
response to multicast packets needs special-case rules.
RFC 1122 §3.2.2 and the ICMP audit
(`docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`)
cover the canonical "do not emit ICMP error to a multicast
source / multicast destination" rules. PyTCP's
`pytcp/protocols/icmp/icmp__inbound_classifier.py` enforces
these gates.

---

## Test coverage audit

### §4 Class D multicast predicate

- **Unit:**
  `net_addr/tests/unit/test__ip4_address.py`
  Parametric matrix verifying `is_multicast` for addresses
  inside and outside 224/4.

**Status:** locked in.

### §6.4 IP-to-Ethernet multicast MAC mapping

- **Unit:**
  `net_addr/tests/unit/test__ip4_address.py`
  Multicast MAC mapping cases (e.g., 224.0.0.1 →
  01:00:5e:00:00:01).

**Status:** locked in.

### §7 RX admission of joined multicast groups

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__ip4__rx.py`
  All-hosts (224.0.0.1) admission path.

**Status:** locked in.

### Phase-2 gaps

**No test surface — Phase 2 (IGMP, runtime JOIN/LEAVE):**

1. Adding a non-default group to `_ip4_multicast` via a
   socket-level `IP_ADD_MEMBERSHIP` (BSD socket option).
2. Emitting IGMPv2 Membership Reports per RFC 2236.
3. Honouring General Query / Group-Specific Query.

When IGMP lands, the natural test surface is at the integration
level using the `IcmpTestCase` (or a new `IgmpTestCase`)
harness.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4 Multicast (224/4) predicate                      | locked in |
| §4 All-hosts (224.0.0.1) preconfigured              | locked in indirectly (RX integration) |
| §6.4 Ethernet MAC mapping                           | locked in |
| §7 RX admission of joined groups                    | locked in |
| §7 IGMP group management                            | n/a (Phase 2) |
| §6.1 Multicast-default TTL=1                        | gap (currently uses IP4__DEFAULT_TTL=64) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3 Conformance level                                | Level 1+ (send + receive, no IGMP) |
| §4 Class D multicast addressing                     | met    |
| §4 All-hosts (224.0.0.1) preconfigured             | met    |
| §6.1 Multicast-default TTL=1                       | gap (Phase 1 fix candidate) |
| §6.2 / §6.4 IP-to-Ethernet MAC mapping             | met    |
| §7 RX admission for joined groups                  | met    |
| §7 IGMP group management                            | not implemented (Phase 2) |

The principal Phase-1 sharpening identified is the
multicast-default TTL=1 §6.1 recommendation. The Phase-2 work
(IGMP + runtime group JOIN/LEAVE + socket-level multicast
membership API) is on the project north-star but not
scheduled.
