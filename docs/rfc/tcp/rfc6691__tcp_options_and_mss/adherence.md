# RFC 6691 — TCP Options and Maximum Segment Size (MSS)

| Field       | Value                                      |
|-------------|--------------------------------------------|
| RFC number  | 6691                                       |
| Title       | TCP Options and Maximum Segment Size (MSS) |
| Category    | Informational                              |
| Date        | July 2012                                  |
| Updates     | RFC 879, RFC 2385                          |
| Source text | [`rfc6691.txt`](rfc6691.txt)               |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 6691. The audit was performed by reading the RFC
text fresh and inspecting the codebase under `pytcp/` and
`net_proto/` directly; no prior memory or rule-file content
was reused. Adherence levels are described in plain
language. Sections that contain no normative content
(Introduction, Terminology, References, historical
commentary in §3 and §4, Security Considerations) are
omitted.

---

## §2. The Short Statement

This is the central normative section.

**Requirement A — MSS option value uses fixed headers only:**

> "When calculating the value to put in the TCP MSS option,
> the MTU value SHOULD be decreased by only the size of the
> fixed IP and TCP headers and SHOULD NOT be decreased to
> account for any possible IP or TCP options."

**Adherence:** fully met. The MSS value advertised on
outbound SYN / SYN+ACK is computed in
`pytcp/protocols/tcp/tcp__session.py:144-147`:

```python
self._ip_tcp_overhead = (40 if isinstance(local_ip_address, Ip6Address) else 20) + 20
self._rcv_mss = stack.interface_mtu - self._ip_tcp_overhead
```

`_ip_tcp_overhead` is the sum of the fixed IPv4 (20) or
fixed IPv6 (40) header plus the fixed TCP header (20). No
TCP option overhead (timestamps, SACK, WSCALE, etc.) is
subtracted from this value. The `_rcv_mss` field is then
emitted on the SYN via the MSS option assembler at
`pytcp/protocols/tcp/tcp__session.py:1524`.

**Requirement B — sender reduces data length for options:**

> "Conversely, the sender MUST reduce the TCP data length
> to account for any IP or TCP options that it is including
> in the packets that it sends."

**Adherence:** NOT met. The sender's per-segment
data-length cap at
`pytcp/protocols/tcp/tcp__session.py:2346`:

```python
transmit_data_len = min(self._snd_mss, usable_window, remaining_data_len)
```

caps at `_snd_mss` directly without subtracting the byte
count of TCP options that will be appended at the
`packet_handler__tcp__tx.py` layer (timestamps option = 12
bytes, SACK blocks = up to 32 bytes, etc.). When such
options are present, the on-wire segment is
`fixed_ip_header + fixed_tcp_header + option_bytes +
_snd_mss bytes of data`, which exceeds the MTU by exactly
the option-bytes amount and forces IP-layer fragmentation
(or path-MTU-discovery drop).

**Fixed-header constants:**

> "The size of the fixed TCP header is 20 bytes [RFC793],
> the size of the fixed IPv4 header is 20 bytes [RFC791],
> and the size of the fixed IPv6 header is 40 bytes
> [RFC2460]."

**Adherence:** met. The constants are encoded in
`pytcp/protocols/tcp/tcp__session.py:144` (20+20=40 for
IPv4, 40+20=60 for IPv6) and reaffirmed in
`pytcp/protocols/tcp/tcp__fsm__syn_sent.py:136-141`
("at most 'mtu - 40'").

---

## §5.1. Path MTU Discovery

> "The TCP MSS option specifies an upper bound for the size
> of packets that can be received. Hence, setting the value
> in the MSS option too small can impact the ability for
> Path MTU Discovery to find a larger path MTU."

**Adherence:** PyTCP does not implement Path MTU Discovery
(RFC 1191 / RFC 4821) — there is no PMTU cache, no DF-bit
manipulation logic, no ICMP "fragmentation needed" handler
that adjusts the per-destination MSS. The advertised MSS
is bounded only by the local interface MTU (which the §2
audit confirms is computed correctly), so PyTCP does not
artificially constrain a peer's PMTUD attempts.

---

## §5.2. Interfaces with Variable MSS Values

> "When the effective MTU of an interface varies, TCP
> SHOULD use the smallest effective MTU of the interface
> to calculate the value to advertise in the MSS option."

**Adherence:** vacuously satisfied. `stack.interface_mtu`
is a single integer set at startup
(`pytcp/stack/__init__.py:189`) and not subsequently
varied. There is no ROHC-style compression layer or
variable-MSS interface abstraction, so "use smallest"
holds trivially because there is only one value.

---

## §5.3. IPv6 Jumbograms

> "In order to support TCP over IPv6 jumbograms,
> implementations need to be able to send TCP segments
> larger than 64K. RFC 2675 defines that a value of 65,535
> is to be treated as infinity, and Path MTU Discovery is
> used to determine the actual MSS."

**Adherence:** not implemented. PyTCP does not support
IPv6 jumbograms — there is no Hop-by-Hop jumbogram option
support under `net_proto/protocols/ip6/`, no path-MTU
discovery, and no segment-emission path for payloads
larger than 64K. The MSS option emitter does cap at
`min(self._rcv_mss, 0xFFFF)` (`tcp__session.py:1524`),
which prevents a `uint16` overflow assert if the operator
configures an unrealistically large `interface_mtu`. The
inline comment at that site cites RFC 2675 §5, but the
cap functions as a wire-field overflow guard rather than
deliberate jumbogram signaling — a peer receiving the
65535 value from PyTCP will not actually receive
super-64K segments because the data-emission cap on line
2346 is also bounded by `_snd_mss`. Reception likewise
has no jumbogram-segment path.

---

## §5.4. Avoiding Fragmentation

> "Packets that are too long will either be fragmented or
> dropped. ... it is best to avoid generating fragments."

**Adherence:** the goal is undermined by the §2
Requirement B gap. With timestamps or SACK negotiated, a
full-MSS segment becomes `fixed_headers + options + MSS
data`, which exceeds the link MTU by `len(options)` bytes
and triggers IPv4 fragmentation at
`pytcp/stack/packet_handler/packet_handler__ip4__tx.py:156-169`.
PyTCP never sets the IPv4 DF bit on outbound packets (no
`flag_df=` assignment anywhere in the TX path), so the
"or dropped" alternative does not occur — every option-
bearing data segment that would exceed MTU is silently
fragmented. The fragment emitter handles the split
correctly, so the connection does not fail; it simply
pays the per-fragment overhead and increases the chance
of mid-path drop on networks where firewalls discard
fragments.

---

## Appendix A. Details from RFC 793 and RFC 1122

**Default send MSS:**

> RFC 1122: "If an MSS option is not received at connection
> setup, TCP MUST assume a default send MSS of 536 (576-40)."

**Adherence:** met. The MSS-option container's `mss`
property at
`net_proto/protocols/tcp/options/tcp__options.py:247-253`
returns `TCP__MIN_MSS` (= 536, defined at
`net_proto/protocols/tcp/tcp__header.py:67` with the RFC
879 citation) when the parsed peer's SYN does not include
an MSS option. The `_snd_mss` clamp at
`tcp__fsm__syn_sent.py:142-145` then runs
`max(TCP__MIN_MSS, min(...))`, so any peer-advertised value
strictly below 536 (including the malformed 0) is also
floored to 536.

**MSS option upper bound formula:**

> "The MSS value to be sent in an MSS option must be less
> than or equal to: EMTU_R - FixedIPhdrsize -
> FixedTCPhdrsize, where FixedTCPhdrsize is 20, and
> FixedIPhdrsize is 20 for IPv4 and 40 for IPv6."

**Adherence:** met. The advertised value is exactly
`stack.interface_mtu - (20|40 IP) - 20 TCP`, capped at
0xFFFF for the wire field (see §2 / §5.3 audits).

---

## Test coverage audit

For each requirement claimed as met above, this section
identifies the unit / integration tests that lock the
behaviour in. Requirements that PyTCP does not implement
have no test surface to audit.

### §2 Req A — MSS option value uses fixed-header sizes

- **Integration (IPv4 active):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__active.py::test__active_open__outbound_syn_carries_tsopt_wscale_sackperm_together`
  asserts `syn.mss == 1460` on a 1500-MTU IPv4 link
  (= MTU − 20 IPv4 − 20 TCP, fixed-headers only, no
  option subtraction even though the SYN also carries
  WSCALE / TSopt / SACK-Permitted).
- **Integration (IPv6 active):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__ipv6.py::test__ipv6__outbound_syn_advertises_mss_mtu_minus_60`
  asserts the IPv6 outbound SYN advertises 1440 = 1500 −
  40 IPv6 − 20 TCP.
- **Wire-level option encoding:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__option__mss.py::TestTcpOptionMssAssembler` (parameterised over the 0 / 0xFFFF / mid-range matrix) covers the option's `__bytes__`, `__len__`, `__str__`, `__repr__` shape.

**Status: locked in.** The two protocol-level tests cover
both address families and the four-option co-emission
case (WSCALE / TSopt / SACK-Permitted / MSS together);
the wire-level tests cover the assembler/parser surface.

### §2 fixed-header constants (20 IPv4, 40 IPv6, 20 TCP)

Implicitly covered by §2 Req A's IPv4 (= 1460) and IPv6
(= 1440) tests. No dedicated test pins the constants
themselves; their correctness is inferred from the
correct MSS values.

**Status: locked in indirectly.** A dedicated test
asserting `_ip_tcp_overhead == 40` on IPv4 sessions and
`== 60` on IPv6 sessions would make the regression-guard
explicit, but the current indirect coverage would catch
any deviation through the MSS-value assertions.

### §2 Req B — sender reduces data length for options

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test is one that:

1. Drives the active-open handshake to ESTABLISHED with
   timestamps negotiated bilaterally (so each data
   segment will carry the 12-byte TSopt + 2 NOPs = 12).
2. Issues `session.send(data=b"X" * 2000)`.
3. Asserts the resulting on-wire segment length is
   `≤ link_MTU` (fixed_headers + options + data ≤ MTU).

The current code would emit a 1500-byte data segment
plus 12 bytes of options = 1512 bytes, fragmenting at
the IP layer. A regression-guard test should be added
alongside the fix.

### §5.3 IPv6 jumbograms

Not implemented; no test surface. The 0xFFFF wire-field
overflow guard at `tcp__session.py:1524` is exercised
implicitly by every IPv6 SYN test (the cap never fires
because `_rcv_mss < 65535` for any realistic MTU).

### Appendix A — default send MSS = 536

- **Integration (passive open, no MSS option):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__passive.py::test__passive_open__syn_without_mss_option_defaults_send_mss_to_536`
  drives a peer SYN that omits the MSS option entirely
  and asserts the child session's `_snd_mss == 536`.
- **Integration (peer MSS=0 clamped to floor):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__options.py::test__options__peer_mss_zero_clamped_to_tcp_min_mss`
  drives a peer SYN+ACK with MSS=0 and asserts
  `_snd_mss` is clamped to `TCP__MIN_MSS` (536), not
  accepted verbatim.

**Status: locked in.** Both the "option absent" and
"option present but malformed (zero)" branches are
pinned.

### Appendix A — `MSS = MTU − fixed_ip − fixed_tcp`

- **Integration (peer MSS above local MTU, IPv4):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__options.py::test__options__peer_mss_above_local_mtu_clamped_to_mtu_minus_40`
  drives a peer SYN+ACK with MSS=9000 on a 1500-MTU
  IPv4 link and asserts `_snd_mss == 1460`.
- **Integration (peer MSS above local MTU, IPv6):**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__ipv6.py::test__ipv6__active_handshake_completes_to_established_with_ipv6_correct_snd_mss`
  drives a peer SYN+ACK with MSS=9000 on a 1500-MTU
  IPv6 link and asserts `_snd_mss == 1440`.

**Status: locked in.** Both address families have an
explicit ceiling-clamp test.

### MSS option asserts and wire format

`net_proto/tests/unit/protocols/tcp/test__tcp__option__mss.py`
contains `TestTcpOptionMssAsserts` (rejects under-min /
over-max integers via the dataclass `__post_init__`)
and `TestTcpOptionMssAssembler` (parameterised matrix
over `__len__`, `__str__`, `__repr__`, `__bytes__` for
mss=0, mss=0xFFFF, mid-range). This covers the
`_validate_integrity` / `from_buffer` round-trip needed
by §2 Req A's wire-level layer.

**Status: locked in.**

### Test coverage summary

| Aspect                                                | Coverage                                |
|-------------------------------------------------------|-----------------------------------------|
| §2 Req A: MSS option value uses fixed-header sizes    | locked in (IPv4 + IPv6 integration)     |
| §2 Req B: sender reduces data length for options      | n/a (gap not closed; add test with fix) |
| §2: fixed header constants                            | locked in indirectly (via Req A)        |
| §5.1 / §5.2 / §5.3                                    | n/a (not implemented)                   |
| §5.4 fragmentation goal                               | n/a (gap inherits from §2 Req B)        |
| Appendix A: default send MSS = 536                    | locked in (passive + MSS=0 cases)       |
| Appendix A: MSS = MTU − fixed_ip − fixed_tcp          | locked in (IPv4 + IPv6 integration)     |
| Wire-level MSS option encoding                        | locked in (asserts + assembler matrix)  |

---

## Overall assessment

| Aspect                                                | Status                               |
|-------------------------------------------------------|--------------------------------------|
| §2 Req A: MSS option value uses fixed-header sizes    | met                                  |
| §2 Req B: sender reduces data length for options      | not met                              |
| §2: fixed header constants (20 IPv4, 40 IPv6, 20 TCP) | met                                  |
| §5.1 Path MTU Discovery                               | not implemented                      |
| §5.2 variable MSS interfaces                          | vacuous (single MTU)                 |
| §5.3 IPv6 jumbograms                                  | not implemented                      |
| §5.4 avoiding fragmentation                           | partial (undermined by §2 Req B gap) |
| Appendix A: default send MSS = 536                    | met                                  |
| Appendix A: `MSS = MTU - fixed_ip - fixed_tcp`        | met                                  |

The principal compliance gap is §2 Requirement B: when the
session emits TCP options on data segments, the sender does
not subtract the option byte count from the per-segment
data-length cap. The fix is small and localised — replace
`min(self._snd_mss, usable_window, remaining_data_len)`
at `pytcp/protocols/tcp/tcp__session.py:2346` with
`min(self._snd_mss - emitted_options_len, usable_window,
remaining_data_len)`, where `emitted_options_len` is the
total byte count (NOP-padded) of the options that
`_transmit_packet` will append for this segment. The other
items either fall outside the implementation's scope
(PMTUD, multi-homing, ROHC, jumbograms) or are met
correctly.
