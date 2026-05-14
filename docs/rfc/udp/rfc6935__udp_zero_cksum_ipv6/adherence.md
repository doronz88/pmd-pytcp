# RFC 6935 / 6936 — IPv6 UDP Zero-Checksum for Tunneled Packets

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6935 (spec update) + 6936 (applicability)      |
| Title       | RFC 6935: IPv6 and UDP Checksums for Tunneled Packets; RFC 6936: Applicability Statement for the Use of IPv6 UDP Datagrams with Zero Checksums |
| Authors     | M. Eubanks, P. Chimento, M. Westerlund (6935); G. Fairhurst, M. Westerlund (6936) |
| Category    | Standards Track                                |
| Date        | April 2013                                     |
| Updates     | RFC 2460 (via 6935)                            |
| Source text | [`rfc6935.txt`](rfc6935.txt) / [`rfc6936.txt`](rfc6936.txt) |

RFC 6935 amends the RFC 2460 §8.1 "IPv6 receivers MUST
discard UDP packets containing a zero checksum"
requirement by allowing a per-port opt-in. RFC 6936 is
the companion applicability statement spelling out the
ten implementation constraints (§4) and ten usage
requirements (§5) that a stack supporting the opt-in
must satisfy.

This audit treats the pair as one unit. The two
documents are inseparable in practice — RFC 6935 §5
states "Any node implementing zero-checksum mode MUST
follow the node requirements specified in Section 4 of
[RFC6936]."

**Headline finding: PyTCP is non-conformant with the
default-disabled IPv6 RX rule (RFC 6936 §4, constraint
5).** The UDP parser at `udp__parser.py:91-94` accepts
cksum=0 on every UDP port, on both IPv4 and IPv6.
RFC 2460 + RFC 6935 require IPv6 receivers to discard
cksum=0 UDP packets unless a specific port is enabled.

---

## §1-§4 of RFC 6935 (Introduction, Discussion, Tunnel
## Limitation, Middleboxes)

These sections are background and rationale (corruption
analysis, tunnel-protocol constraints, middlebox
behaviour). No normative obligations on a host UDP
stack. Skipped.

---

## §5 of RFC 6935 — The Zero UDP Checksum Update

RFC 6935 §5 replaces the RFC 2460 §8.1 fourth bullet
with a longer one specifying a per-port mode model.

> "An IPv6 node associates a mode with each used UDP
>  port (for sending and/or receiving packets)."

**Adherence:** **not implemented.** PyTCP has no
per-port mode model for UDP zero-cksum. The behaviour
is uniformly "accept cksum=0 RX, always compute cksum
TX" with no port-keyed configuration.

> "Whenever originating a UDP packet for a port in the
>  default mode, an IPv6 node MUST compute a UDP
>  checksum over the packet and the pseudo-header, and,
>  if that computation yields a result of zero, the
>  checksum MUST be changed to hex FFFF for placement in
>  the UDP header, as specified in [RFC2460]."

**Adherence (compute):** met — PyTCP always computes the
UDP cksum on TX.

**Adherence (zero-to-all-ones substitution):** **not
met** — same gap flagged in the
[RFC 768 audit](../rfc768__udp/adherence.md) §"Fields —
Checksum." The assembler at
`net_proto/protocols/udp/udp__assembler.py:79-83` writes
the raw `inet_cksum` result without substituting `0xFFFF`
for a computed zero. The IPv4 side allows this
ambiguity (cksum=0 means "no cksum"); the IPv6 side does
not — RFC 6935 explicitly preserves the RFC 2460 MUST.

> "IPv6 receivers MUST by default discard UDP packets
>  containing a zero checksum and SHOULD log the error."

**Adherence:** **not met.** PyTCP's RX parser at
`net_proto/protocols/udp/udp__parser.py:91-94`:

```python
if int.from_bytes(self._frame[6:8]) != 0 and inet_cksum(
    self._frame[: self._ip__payload_len], init=self._ip__pshdr_sum
):
    raise UdpIntegrityError("The packet checksum must be valid.")
```

The `!= 0` guard means a packet with `cksum=0` field
**skips validation and is delivered** — on both IPv4 and
IPv6. The IPv6 MUST-discard-by-default is silently
violated. There is no per-port opt-in to selectively
enable cksum=0 RX either.

> "As an alternative, certain protocols that use UDP as
>  a tunnel encapsulation MAY enable zero-checksum mode
>  for a specific port (or set of ports) for sending
>  and/or receiving."

**Adherence:** **not implemented** (PyTCP has no
per-port enable mechanism, so the "MAY enable" is moot —
neither the default NOR the override is in place; the
codebase is stuck in a hybrid that accepts zero-cksum
universally with no way to enforce the spec default).

> "Any node implementing zero-checksum mode MUST follow
>  the node requirements specified in Section 4 of
>  [RFC6936]."

See per-clause audit of RFC 6936 §4 below.

> "Any protocol that enables zero-checksum mode for a
>  specific port or ports MUST follow the usage
>  requirements specified in Section 5 of [RFC6936]."

**N/A** — PyTCP does not implement any protocol that
enables zero-cksum mode (no LISP, no MPLS-in-UDP, no
GUE, etc.). The §5 usage requirements apply to
**transported protocols** layered on top of UDP, which
is application-side responsibility.

> "Middleboxes supporting IPv6 MUST follow requirements
>  9, 10, and 11 of the usage requirements specified in
>  Section 5 of [RFC6936]."

**N/A** — PyTCP is not a middlebox.

---

## RFC 6936 §4 — Implementation Constraints

RFC 6936 §4 enumerates ten requirements on IPv6 nodes
that **support** zero-cksum mode. Since PyTCP does **not
yet support** zero-cksum mode (no per-port opt-in
mechanism), this section reads as a punch list of what
the eventual implementation would need to satisfy. The
"not implemented" status below is the natural state when
the feature isn't yet built.

| #   | Requirement                                                                                              | PyTCP status |
|-----|----------------------------------------------------------------------------------------------------------|--------------|
| 1   | Sending node MAY use a calculated checksum for all datagrams                                             | met (vacuous — PyTCP always computes) |
| 2   | IPv6 nodes SHOULD, by default, NOT allow zero-cksum TX                                                   | met (no opt-out exists) |
| 3   | MUST provide a way for app to enable zero-cksum TX on specific port set (socket API call or similar)     | **not implemented** (no socket option) |
| 4   | MUST provide a way for app to indicate that a particular datagram is required to be sent with a cksum    | **not implemented** (the symmetric per-datagram opt-out doesn't exist either) |
| 5   | Default RX behavior MUST be to discard zero-cksum UDP                                                    | **NOT MET** — accepts on every port |
| 6   | MUST provide a way for app to enable zero-cksum RX on specific port set                                  | **not implemented** |
| 7   | MUST also allow reception using calculated checksum on zero-cksum-enabled ports                          | met (vacuous — non-zero cksum is always validated) |
| 8   | RFC 2460 SHOULD log received zero-cksum datagrams; zero-cksum-enabled port MUST NOT log solely on that   | not implemented (PyTCP has no log facility for cksum=0 RX in either direction) |
| 9   | MAY separately identify discarded zero-cksum datagrams                                                   | not implemented (no counter) |
| 10  | ICMPv6 referring to zero-cksum packets MUST be consistency-checked before acting on                       | **vacuous** (no zero-cksum packets sent, so no ICMPv6 references them; PyTCP's general ICMP error demux at `pytcp/protocols/icmp/icmp__error_demux.py` does perform embedded-datagram consistency checks per the [RFC 5927 audit](../../tcp/rfc5927__icmp_tcp_attacks/adherence.md)) |

**Constraint 5 is the conformance gap.** Constraints
3, 4, 6, 8, 9 are "feature not implemented" — they
become MUSTs only IF PyTCP eventually adds zero-cksum
support. Constraint 5 is normative on **every** IPv6
UDP stack, whether or not it supports the opt-in.

---

## RFC 6936 §5 — Usage Requirements

These are constraints on **transported protocols** (the
tunnel encapsulations that ride on UDP and use the
zero-cksum mode). They do not apply to PyTCP as a UDP
stack — they apply to applications that would be the
"app" in `UDP_NO_CHECK6_*` setsockopt calls.

PyTCP does not implement any zero-cksum-using transported
protocol (no LISP, no MPLS-in-UDP, no Geneve, no GTP
tunneling). Section §5 is **N/A**.

---

## Fix sketch

A minimal Phase-1 fix that closes the conformance gap on
constraint 5 without adding the full opt-in machinery:

1. **Plumb the IP version into the UDP parser.** Today
   `udp__parser.py:60-61` reads
   `packet_rx.ip.payload_len` and `pshdr_sum` but not
   `ip.ver`. Add it.
2. **Reject IPv6 cksum=0 by default.** Change the
   integrity check:

   ```python
   raw_cksum = int.from_bytes(self._frame[6:8])
   if raw_cksum == 0:
       if self._ip__ver is IpVersion.IP6:
           # Default-mode RFC 6935 §5 + RFC 6936 §4 #5:
           # IPv6 receivers MUST discard UDP packets
           # containing a zero checksum.
           raise UdpIntegrityError(
               "IPv6 UDP datagram with zero checksum on a "
               "port not configured for RFC 6935 zero-cksum mode."
           )
       # IPv4 path: RFC 768 cksum=0 means "no cksum",
       # accept and skip validation.
   elif inet_cksum(self._frame[: self._ip__payload_len], init=self._ip__pshdr_sum):
       raise UdpIntegrityError("The packet checksum must be valid.")
   ```
3. **Add the all-ones-substitution on TX** (the
   companion fix flagged in the RFC 768 audit).
4. **Add a new RX stat counter**
   `udp__ip6_zero_cksum__drop` so the gap is observable.

A full Phase-3 implementation that exposes `UDP_NO_CHECK6_RX`
/ `UDP_NO_CHECK6_TX` socket options (matching Linux's
surface) would land later — it is the "MAY enable" half
of constraint 5/6 and is not required for default
conformance.

---

## Test coverage audit

### RFC 6935 §5 / RFC 6936 §4 constraint 5 — default-discard

**No test surface — gap not yet closed.** When the fix
above lands, the natural tests are:

1. **IPv6 cksum=0 RX drop**: drive an inbound Ethernet/
   IPv6/UDP frame whose UDP cksum field is `0x0000`,
   assert the packet is dropped via `UdpIntegrityError`
   and the new `udp__ip6_zero_cksum__drop` counter
   bumps.
2. **IPv4 cksum=0 RX accept**: drive the same scenario
   over IPv4, assert the packet still parses (RFC 768
   compatible behaviour).
3. **TX zero-to-all-ones**: construct a UDP datagram
   whose payload + pseudo-header sums to one's-
   complement zero, assemble + inspect the on-wire
   cksum field, assert it equals `0xFFFF` not
   `0x0000`. Same test mentioned in the
   [RFC 768 audit](../rfc768__udp/adherence.md).

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Default IPv6 cksum=0 RX → discard                     | **n/a (gap not closed; add test with fix)** |
| Default IPv6 cksum=0 TX → never emitted (compute on)  | locked in (via `test__udp__assembler__operation.py` which always sees non-zero cksum) |
| Zero-compute → all-ones substitution                  | **n/a (gap not closed; add test with fix)** |
| Per-port zero-cksum opt-in (`UDP_NO_CHECK6_*`)        | **n/a (not implemented; Phase-3 socket-parity work)** |
| RFC 6936 §4 constraints 3/4/6 (opt-in mechanism)      | **n/a (not implemented)** |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| RFC 6935 §5: per-port mode association                | not implemented |
| RFC 6935 §5: default-mode TX MUST compute cksum       | met |
| RFC 6935 §5: zero-compute → 0xFFFF substitution       | not met (inherits from RFC 768 audit) |
| RFC 6935 §5: IPv6 RX default MUST discard zero-cksum  | **NOT MET** (silent accept) |
| RFC 6936 §4 #1: MAY always compute (off-load wording) | met (vacuous) |
| RFC 6936 §4 #2: default SHOULD NOT allow zero-cksum TX | met |
| RFC 6936 §4 #3: app-enable zero-cksum TX              | not implemented |
| RFC 6936 §4 #4: app-override per-datagram cksum-on    | not implemented |
| RFC 6936 §4 #5: default RX MUST discard zero-cksum    | **NOT MET** |
| RFC 6936 §4 #6: app-enable zero-cksum RX              | not implemented |
| RFC 6936 §4 #7: zero-cksum-enabled port MUST also accept calculated | met (vacuous) |
| RFC 6936 §4 #8-9: logging / counter discipline        | not implemented |
| RFC 6936 §4 #10: ICMPv6 consistency check             | met (general ICMP demux validates embedded datagram) |
| RFC 6936 §5: transported-protocol usage constraints   | N/A (no consumer) |

**Principal gap:** RFC 6936 §4 constraint 5. The fix is
~10 lines in the UDP parser + 3 lines in the assembler
+ one new stat counter. The full opt-in machinery
(constraints 3/4/6) can wait until a tunnel protocol
needs it.

**Why this is greppable:** the IPv6 zero-cksum default
gap is referenced from four audits — RFC 768, RFC 1122
§4.1, RFC 8085, and this one. Closing it would update
all four to "met."

---

## Cross-references

- Base UDP spec: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md) — §"Fields — Checksum" flags the same TX zero-to-all-ones gap
- UDP host requirements: [`../rfc1122__host_requirements_udp/adherence.md`](../rfc1122__host_requirements_udp/adherence.md) — §4.1.3.4 cross-references RFC 6935
- UDP usage guidelines: [`../rfc8085__udp_usage_guidelines/adherence.md`](../rfc8085__udp_usage_guidelines/adherence.md) — §3.4.1 directly invokes RFC 6935/6936
- IPv6 base spec: [`../../ip6/rfc8200__ipv6/adherence.md`](../../ip6/rfc8200__ipv6/adherence.md) — RFC 2460's §8.1 is the rule RFC 6935 amends
- ICMP demux for embedded-datagram consistency: `pytcp/protocols/icmp/icmp__error_demux.py` + [RFC 5927 audit](../../tcp/rfc5927__icmp_tcp_attacks/adherence.md)
- Socket-API parity (`UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`): `docs/refactor/socket_linux_parity_audit.md`
