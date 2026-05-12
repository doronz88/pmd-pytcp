# RFC 919 — Broadcasting Internet Datagrams

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 919                                            |
| Title       | Broadcasting Internet Datagrams                |
| Category    | Internet Standard (STD 5)                      |
| Date        | October 1984                                   |
| Source text | [`rfc919.txt`](rfc919.txt)                     |

This document records the PyTCP codebase's adherence to RFC 919
clause by clause. RFC 919 defines the IPv4 broadcast addressing
forms and the broadcast forwarding/reception rules. PyTCP
implements the host-side reception and source-address-
replacement aspects; the gateway-side broadcast forwarding
rules are Phase 2 (covered by RFC 1812 audit when forwarding
lands).

The audit was performed by reading the RFC text fresh and
inspecting `net_addr/ip4_address.py`,
`net_addr/ip4_network.py`,
`pytcp/stack/packet_handler/packet_handler__ip4__rx.py`, and
`pytcp/stack/packet_handler/packet_handler__ip4__tx.py`
directly; no prior memory or rule-file content was reused.
Non-normative content (§1 Introduction, §2 Why Broadcasts, §3
History, §4 Broadcast Classes discussion, §8 Acknowledgments)
is omitted.

---

## Top-line adherence

PyTCP **meets** the host-side broadcast rules from RFC 919:

- The limited-broadcast address `255.255.255.255` is
  recognised on receive and rejected as a source address.
- Network-broadcast `{net, -1}` addresses are recognised
  per-`Ip4Host` and admitted on receive.
- TX-side source replacement honours the host-stack policy
  (replace bcast/mcast source with primary unicast).

The §6 gateway broadcast-forwarding rules are Phase 2.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §5      | Host MUST recognise broadcast destinations         | met    |
| §6      | Gateway broadcast forwarding rules                 | n/a (Phase 2) |
| §7      | All-ones host-number = broadcast                   | met    |
| §7      | `255.255.255.255` = local hardware broadcast       | met    |
| §7      | `255.255.255.255` MUST NOT be forwarded            | n/a (no forwarding) |

---

## §5 Broadcast Methods (host-side reception)

> "A host's IP receiving layer must be modified to support
> broadcasting. ... With broadcasting, a host must compare the
> destination address not only against the host's addresses,
> but also against the possible broadcast addresses for that
> host."

**Adherence:** met. The RX handler
(`packet_handler__ip4__rx.py:149-153`) tests the destination
against the union of `_ip4_unicast ∪ _ip4_multicast ∪
_ip4_broadcast` — admitting any of the three. The
`_ip4_broadcast` set is populated at boot from each
`Ip4Host.network.broadcast` (`Ip4Network.broadcast` is the
{net, subnet, -1} address) plus the limited broadcast
`255.255.255.255`.

## §7 Broadcast IP Addressing — All-Ones host-number

> "The number whose bits are all ones ... is the broadcast
> host number."

**Adherence:** met. `Ip4Network.broadcast` is computed as
"network | ~mask" — yielding the all-ones host-number form.
`Ip4Address.is_limited_broadcast` recognises the
`255.255.255.255` special case.

> "The address 255.255.255.255 denotes a broadcast on a local
> hardware network, which must not be forwarded."

**Adherence:** met for the host-side half: PyTCP does not
forward, so the "must not be forwarded" constraint is
vacuously satisfied. The receive path admits frames addressed
to `255.255.255.255` when it appears in `_ip4_broadcast`.

On send, `255.255.255.255` is the canonical DHCPv4
broadcast address; the TX path admits it as a destination
(`packet_handler__ip4__tx.py:251-265`) and the DHCPv4 client
uses it for the DISCOVER / REQUEST messages.

## §7 Limited-broadcast as source-address ban

> "[Limited broadcast] MUST NOT be used as a source address."
> (cross-reference RFC 1122 §3.2.1.3)

**Adherence:** met. `Ip4Parser._validate_sanity` rejects any
inbound frame whose source matches `Ip4Address.is_limited_broadcast`
with `Ip4SanityError(pointer=12)`
(`ip4__parser.py:154-158`). The handler emits ICMP
Parameter Problem subject to the rate limit.

On send, a caller-supplied broadcast source is replaced with
the stack's primary unicast address before assembly
(`packet_handler__ip4__tx.py:289-306`); if no replacement is
possible the frame is dropped with the documented counter.

## §6 Gateway broadcast forwarding (Phase 2)

> "When a gateway receives a local broadcast datagram, there
> are several things it might have to do with it. ... The
> primary rule for avoiding loops is 'never broadcast a
> datagram on the hardware network it was received on'."

**Adherence:** n/a (PyTCP does not forward). When forwarding
lands, these rules become relevant. See RFC 1812 audit (Phase
2) for the router-grade broadcast handling.

---

## Test coverage audit

### §5 / §7 RX admission of broadcast destinations

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__ip4__rx.py`
  Covers limited-broadcast and network-broadcast destination
  admission paths.

**Status:** locked in.

### §7 Source-address sanity (limited-broadcast ban)

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Per-branch rejection with `pointer=12`.

**Status:** locked in.

### TX source-address replacement (broadcast source → primary unicast)

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__ip4__tx.py`
  Matrix for src=limited-broadcast, src=network-broadcast.

**Status:** locked in.

### Phase-2 gateway broadcast rules

**No test surface — n/a (Phase 2).**

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §5 RX admission of broadcast destinations           | locked in |
| §7 Limited-broadcast source rejection (RX)          | locked in |
| §7 Broadcast source replacement (TX)                | locked in |
| §6 Gateway broadcast forwarding                     | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §5 Host-side broadcast reception                    | met    |
| §7 All-ones broadcast address recognised            | met    |
| §7 Limited-broadcast source ban                     | met    |
| §6 Gateway broadcast forwarding rules               | n/a (Phase 2) |

RFC 919 is fully covered for the host-stack portion. The
subnetting refinement in RFC 922 (audited separately) extends
this picture; the gateway-side rules in §6 are Phase-2 router
work tracked under RFC 1812.
