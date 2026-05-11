# RFC 2131 — Dynamic Host Configuration Protocol

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | 2131                                 |
| Title       | Dynamic Host Configuration Protocol  |
| Category    | Standards Track                      |
| Date        | March 1997                           |
| Obsoletes   | RFC 1541                             |
| Source text | [`rfc2131.txt`](rfc2131.txt)         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 2131. The audit was performed by reading the RFC
text fresh and inspecting the codebase under `pytcp/` and
`net_proto/` directly; no prior memory or rule-file content
was reused. Adherence levels are described in plain
language. Sections that contain no normative content
(§1 Introduction, §1.1–§1.3, §1.6 Design goals, §2.1–§2.2
narrative, §3.1/§3.2 narrative, §3.6 multi-interface
narrative, §3.7 narrative, §4.2 administrative narrative,
§5 Acknowledgments, §6 References, §7 Security
boilerplate, §8 Author's Address) are omitted.

PyTCP's DHCPv4 implementation is intentionally minimal:
the client at `pytcp/lib/dhcp4_client.py` (229 lines)
performs a single linear `DHCPDISCOVER → DHCPOFFER →
DHCPREQUEST → DHCPACK` exchange to obtain a lease, then
returns the resulting `Ip4Host` to the caller and exits.
There is no FSM, no T1/T2 timers, no
RENEW/REBIND/INIT-REBOOT/DECLINE/RELEASE/INFORM, no
retransmission backoff, no ARP probe after ACK, and no
lease management. Most of RFC 2131's normative
requirements are therefore "not implemented"; the audit
documents the gap inventory.

The wire-format library at
`net_proto/protocols/dhcp4/` is comprehensive — full
BOOTP-shape header, 11 option codecs, integrity-validated
parser — and most paragraphs about message format are met.

---

## §1.4 Requirements

> "DHCP must coexist with statically configured,
>  non-participating hosts and with existing network
>  protocol implementations."

**Adherence:** met. The DHCP client is opt-in: it is
invoked only from
`pytcp/stack/packet_handler/__init__.py:1853-1856`
(`_create_stack_ip4_addressing`) when
`self._ip4_dhcp` is true and no static address is
configured. Static IPv4 hosts pass through DHCP entirely.

> "A DHCP client must be prepared to receive multiple
>  responses to a request for configuration parameters."

**Adherence:** not met. The client at
`pytcp/lib/dhcp4_client.py:155-174` (`_recv_offer`)
accepts the first DHCPOFFER and proceeds to REQUEST.
There is no "collect offers for N seconds, pick best"
loop. Linux dhcpcd waits ~3 s for multiple OFFERs;
PyTCP races on the first.

---

## §2 Protocol Summary — message format

> "Figure 1 gives the format of a DHCP message ...
>  fields op, htype, hlen, hops, xid, secs, flags,
>  ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file,
>  options."

**Adherence:** met. The header dataclass at
`net_proto/protocols/dhcp4/dhcp4__header.py:136-168`
defines every field at the wire offsets in Figure 1.
Wire layout is `! BBBB L HH L L L L 16s 64s 128s 4s`
(`dhcp4__header.py:129`), totalling 240 bytes
(`DHCP4__HEADER__LEN = 240`).

> "The first four octets of the 'options' field of the
>  DHCP message contain the (decimal) values 99, 130, 83
>  and 99, respectively (this is the same magic cookie
>  as is defined in RFC 1497)."

**Adherence:** met. The constant at
`dhcp4__header.py:130` is
`DHCP4__HEADER__MAGIC_COOKIE = b"\x63\x82\x53\x63"`
(99, 130, 83, 99) and is packed as the final field of
the header struct
(`dhcp4__header.py:254`). The parser
asserts the cookie on every inbound frame
(`dhcp4__header.py:292-294`).

> "One particular option — the 'DHCP message type'
>  option — must be included in every DHCP message."

**Adherence:** met by the client. Both DISCOVER and
REQUEST emit `Dhcp4OptionMessageType(...)` as the first
option (`pytcp/lib/dhcp4_client.py:140`, `:194`). RX
validation does not enforce its presence — a malformed
inbound without Message Type would parse and surface
`message_type = None`; the client checks for the
expected type at
`dhcp4_client.py:167-172` and `:222-227`.

> "The 'client identifier' chosen by a DHCP client MUST
>  be unique to that client within the subnet to which
>  the client is attached. If the client uses a 'client
>  identifier' in one message, it MUST use that same
>  identifier in all subsequent messages."

**Adherence:** met (legacy form). The client emits
`Dhcp4OptionClientId(self._expected_client_id)` —
`b"\x01" + bytes(self._mac_address)` — in BOTH DISCOVER
(`pytcp/lib/dhcp4_client.py` `_send_discover`) and
REQUEST (`_send_request`). The MAC-based form
(type=1 + 6-byte hardware address) is the RFC 2131
legacy form (RFC 4361 requires DUID-based form for new
clients; see `rfc4361__node_specific_client_id`). The
CID is shared via `self._expected_client_id`, which is
also the value validated against the server's echo per
RFC 6842 §3 (see `rfc6842__client_id_echo`).

> "The 'options' field is now variable length. A DHCP
>  client must be prepared to receive DHCP messages with
>  an 'options' field of at least length 312 octets.
>  This requirement implies that a DHCP client must be
>  prepared to receive a message of up to 576 octets."

**Adherence:** met. The integrity check at
`dhcp4__parser.py:69-72` accepts any
frame ≥ 240 bytes (header). The options-parsing loop at
`net_proto/protocols/dhcp4/options/dhcp4__options.py`
walks until END or end-of-frame. The 576-byte minimum is
satisfied trivially.

> "DHCP clients may negotiate the use of larger DHCP
>  messages through the 'maximum DHCP message size'
>  option."

**Adherence:** not implemented. PyTCP does not emit or
parse the Maximum DHCP Message Size option (52). The
client never requests larger messages and the server's
default 576-octet ceiling applies.

> "The leftmost bit is defined as the BROADCAST (B)
>  flag. ... The remaining bits of the flags field are
>  reserved for future use. They MUST be set to zero by
>  clients and ignored by servers and relay agents."

**Adherence:** met. The header packs `flag_b << 15` into
the flags word (`dhcp4__header.py:246`),
leaving every other bit cleared. On RX, only the top bit
is decoded back into a bool
(`dhcp4__header.py:301`).

---

## §3 Client-Server Protocol — packet shape

> "DHCP uses the BOOTP message format defined in RFC
>  951 ... The 'op' field of each DHCP message sent from
>  a client to a server contains BOOTREQUEST. BOOTREPLY
>  is used in the 'op' field of each DHCP message sent
>  from a server to a client."

**Adherence:** met. The enum at
`net_proto/protocols/dhcp4/dhcp4__enums.py:38-44`
defines `Dhcp4Operation.REQUEST = 0x01` and
`Dhcp4Operation.REPLY = 0x02`. The client builds every
outbound message with
`dhcp4__operation=Dhcp4Operation.REQUEST`
(`dhcp4_client.py:135`, `:189`).

The parser at `dhcp4__parser.py:82-86`
does not validate that inbound frames carry REPLY — a
malformed REQUEST-with-server-reply could in principle
parse. The client's `message_type` filter
(`dhcp4_client.py:167-172`, `:222-227`)
catches the substantive case.

---

## §3.1 Client-server interaction — allocating a network address

> "1. The client broadcasts a DHCPDISCOVER message on
>  its local physical subnet. The DHCPDISCOVER message
>  MAY include options that suggest values for the
>  network address and lease duration."

**Adherence:** met for the broadcast; lease-time hint
not used. `_send_discover` at
`dhcp4_client.py:129-153` builds the
DISCOVER with a Param Request List (option 55)
requesting SUBNET_MASK and ROUTER, and a Host Name
option. It does NOT include 'requested IP address'
(option 50) or 'IP address lease time' (option 51) —
both are MAY clauses, so this is compliant. The
DISCOVER is sent via the BSD-socket-style
`connect(("255.255.255.255", 67))` at
`dhcp4_client.py:92`.

> "3. The client receives one or more DHCPOFFER messages
>  ... The client chooses one server from which to
>  request configuration parameters ... The client
>  broadcasts a DHCPREQUEST message that MUST include
>  the 'server identifier' option to indicate which
>  server it has selected, and that MAY include other
>  options specifying desired configuration values. The
>  'requested IP address' option MUST be set to the
>  value of 'yiaddr' in the DHCPOFFER message from the
>  server."

**Adherence:** met (the MUSTs). `_send_request` at
`dhcp4_client.py:176-208` includes
`Dhcp4OptionServerId(srv_id)` (option 54, line 201)
sourced from the DHCPOFFER's `srv_id` property and
`Dhcp4OptionReqIpAddr(yiaddr)` (option 50, line 202)
sourced from the DHCPOFFER's `yiaddr` header field. The
client validates that the OFFER contained a Server ID
before proceeding (`dhcp4_client.py:98-103`).

The "broadcasts" requirement is met by the socket
configuration: the client binds to `0.0.0.0:68` and
sends to `255.255.255.255:67`
(`dhcp4_client.py:91-92`).

> "... the DHCPREQUEST message MUST use the same value
>  in the DHCP message header's 'secs' field and be sent
>  to the same IP broadcast address as the original
>  DHCPDISCOVER message."

**Adherence:** vacuous on `secs`, met on destination.
The client does not track elapsed time across messages
— `secs` defaults to 0 in the assembler. Since
DISCOVER's `secs` is 0 and REQUEST's `secs` is 0 the
"same value" requirement is trivially satisfied. The
destination address is identical (broadcast) because
the same `connect(("255.255.255.255", 67))` socket is
reused for both sends.

> "The client times out and retransmits the
>  DHCPDISCOVER message if the client receives no
>  DHCPOFFER messages."

**Adherence:** not met. The client at
`dhcp4_client.py:94-96` returns `None`
on `recv_offer` timeout — there is no retransmission.
The caller (`_create_stack_ip4_addressing` at
`packet_handler/__init__.py:1853-1856`)
proceeds without an IPv4 host if `fetch()` returns None.

> "5. The client receives the DHCPACK message ... The
>  client SHOULD perform a final check on the
>  parameters (e.g., ARP for allocated network address)
>  ... If the client detects that the address is already
>  in use (e.g., through the use of ARP), the client
>  MUST send a DHCPDECLINE message to the server and
>  restarts the configuration process."

**Adherence:** not met. The client at
`dhcp4_client.py:111-125` accepts the
ACK and constructs the `Ip4Host` without performing
DAD-style ARP probing on the offered address. Note
that `_create_stack_ip4_addressing` does run RFC 5227
ARP DAD on the assembled IPv4 host address afterwards
(`packet_handler/__init__.py:1864-1903`),
so a conflict is detected — but the conflict response
is "drop the address silently and disable IPv4 support",
not "send DHCPDECLINE and restart". **MUST gap.**

> "The client SHOULD wait a minimum of ten seconds
>  before restarting the configuration process to avoid
>  excessive network traffic in case of looping."

**Adherence:** not implemented. Since the client does
not restart the configuration process at all, the
10-second debounce is moot.

> "If the client receives a DHCPNAK message, the client
>  restarts the configuration process."

**Adherence:** met (bounded). `_recv_ack` detects
`Dhcp4MessageType.NAK` and returns the internal
`_NAK_RESTART` sentinel; `fetch()` re-enters
`_discover_request_once` up to `DHCP4__NAK_MAX_RESTARTS`
times (default 3, total 4 attempts) before returning
None. The NAK itself is gated on the same xid + CID-echo
validation as ACK so a stray NAK for an unrelated
transaction cannot stampede the client into a restart
loop.

Phase 1 (retransmission backoff) will tighten this to
match the RFC's 10-second SHOULD-wait before the
restart DISCOVER (§3.1 step 5 / §4.4.1).

> "The client times out and retransmits the DHCPREQUEST
>  message if the client receives neither a DHCPACK or a
>  DHCPNAK message. ... a client retransmitting as
>  described in section 4.1 might retransmit the
>  DHCPREQUEST message four times, for a total delay of
>  60 seconds, before restarting the initialization
>  procedure."

**Adherence:** not met. As with DISCOVER, the REQUEST
path at `dhcp4_client.py:215-228` does
not retransmit on timeout.

> "6. The client may choose to relinquish its lease on a
>  network address by sending a DHCPRELEASE message to
>  the server."

**Adherence:** not implemented. The client has no
DHCPRELEASE path. PyTCP's lifecycle (`stack.stop()` →
process exit) is not wired to release the lease back
to the server.

---

## §3.2 Client-server interaction — reusing a previously allocated network address

> "If a client remembers and wishes to reuse a
>  previously allocated network address, a client may
>  choose to omit some of the steps described in the
>  previous section."

**Adherence:** not implemented. PyTCP has no
persistent storage for prior leases — every fetch
starts from INIT (DISCOVER → REQUEST → ACK). The
INIT-REBOOT shortcut is absent.

---

## §3.3 Interpretation and representation of time values

> "Throughout the protocol, times are to be represented
>  in units of seconds. The time value of 0xffffffff is
>  reserved to represent 'infinity'."

**Adherence:** met by wire format. The Lease Time
option at
`net_proto/protocols/dhcp4/options/dhcp4__option__lease_time.py`
stores `lease_time: int` as `uint32`. The PyTCP client
surfaces the value through `Dhcp4Lease.lease_time__sec`
(`pytcp/lib/dhcp4_client.py` `_discover_request_once`)
alongside `acquired_at_monotonic = time.monotonic()` so
the Phase-4 lifecycle thread can schedule T1/T2 against
absolute monotonic deadlines. The Phase-0 client now
strictly rejects an ACK that omits Lease Time (MUST per
RFC 2131 Table 3), but does not yet interpret the
0xFFFFFFFF infinity sentinel — that becomes meaningful
in Phase 4 once renewal timers exist.

---

## §3.4 Obtaining parameters with externally configured network address

> "If a client has obtained a network address through
>  some other means (e.g., manual configuration), it
>  may use a DHCPINFORM request message to obtain other
>  local configuration parameters."

**Adherence:** not implemented. `Dhcp4MessageType.INFORM
= 0x08` is declared at
`dhcp4__enums.py:70` but the client
never emits an INFORM. Statically-configured PyTCP
hosts get no DHCP-supplied parameters.

---

## §3.5 Client parameters in DHCP

> "If the client includes a list of parameters in a
>  DHCPDISCOVER message, it MUST include that list in
>  any subsequent DHCPREQUEST messages."

**Adherence:** met. Both DISCOVER
(`dhcp4_client.py:142-147`) and REQUEST
(`dhcp4_client.py:195-200`) include the
same `Dhcp4OptionParamReqList([SUBNET_MASK, ROUTER])`.

> "The client SHOULD include the 'maximum DHCP message
>  size' option to let the server know how large the
>  server may make its DHCP messages."

**Adherence:** not implemented. Option 57 is absent
from the option catalogue
(`dhcp4__option.py:43-54`).

> "The 'requested IP address' option is to be filled in
>  only in a DHCPREQUEST message when the client is
>  verifying network parameters obtained previously."

**Adherence:** partial deviation. The client fills the
'requested IP address' option in the SELECTING-state
REQUEST (`dhcp4_client.py:202`), which
is also where Table 4 of §4.3.6 says "MUST". The
"verifying previously" wording in §3.5 conflates
SELECTING with INIT-REBOOT; §4.3.6 is the authoritative
table. PyTCP matches the §4.3.6 SELECTING row.

> "The client fills in the 'ciaddr' field only when
>  correctly configured with an IP address in BOUND,
>  RENEWING or REBINDING state."

**Adherence:** met. The client never sets `ciaddr` on
outbound DHCP messages
(`dhcp4_client.py:134-151`, `:188-205` —
the assembler default of `Ip4Address()` = 0.0.0.0
applies). Since PyTCP has no BOUND/RENEWING/REBINDING
states, the "only when ..." clause is vacuously
satisfied.

---

## §4.1 Constructing and sending DHCP messages — wire format

> "The options area includes first a four-octet 'magic
>  cookie' (which was described in section 3), followed
>  by the options. The last option must always be the
>  'end' option."

**Adherence:** met. Both DISCOVER and REQUEST end with
`Dhcp4OptionEnd()` (`dhcp4_client.py:149`,
`:204`). The header packs the magic
cookie as the final fixed field
(`dhcp4__header.py:254`).

> "DHCP uses UDP as its transport protocol. DHCP
>  messages from a client to a server are sent to the
>  'DHCP server' port (67), and DHCP messages from a
>  server to a client are sent to the 'DHCP client'
>  port (68)."

**Adherence:** met. Client binds 68 and sends to 67
(`dhcp4_client.py:91-92`).

> "DHCP clients MUST use the IP address provided in the
>  'server identifier' option for any unicast requests
>  to the DHCP server."

**Adherence:** vacuous. The client never unicasts —
all REQUEST messages are sent via the same broadcast
socket (`dhcp4_client.py:92`). The
RENEW/REBIND unicast paths are not implemented.

> "DHCP messages broadcast by a client prior to that
>  client obtaining its IP address must have the source
>  address field in the IP header set to 0."

**Adherence:** met. The client binds to
`("0.0.0.0", 68)`
(`dhcp4_client.py:91`); outbound UDP
datagrams have source IP 0.0.0.0.

> "DHCP clients are responsible for all message
>  retransmission. The client MUST adopt a
>  retransmission strategy that incorporates a
>  randomized exponential backoff algorithm to determine
>  the delay between retransmissions. ... in a 10Mb/sec
>  Ethernet internetwork, the delay before the first
>  retransmission SHOULD be 4 seconds randomized by the
>  value of a uniform random number chosen from the
>  range -1 to +1. ... The retransmission delay SHOULD
>  be doubled with subsequent retransmissions up to a
>  maximum of 64 seconds."

**Adherence:** not met. **MUST gap.** The client has no
retransmission — a single `_timeout__sec = 5` (default,
`dhcp4_client.py:74`) timeout on each
recv and the fetch fails. No backoff, no jitter, no
retries.

> "The 'xid' field is used by the client to match
>  incoming DHCP messages with pending requests. A DHCP
>  client MUST choose 'xid's in such a way as to
>  minimize the chance of using an 'xid' identical to
>  one used by another client."

**Adherence:** met. The client generates `xid` once per
`_discover_request_once()` via
`random.randint(0, 0xFFFFFFFF)`. The full 32-bit range
is used; each NAK-driven restart draws a fresh xid so a
stale OFFER from a previous attempt cannot match the
restarted DISCOVER. xid uniqueness across PyTCP
processes is sourced from CPython's default `random`
seed.

The client validates inbound xid against the outbound:
`_recv_offer` and `_recv_ack` both drop any frame whose
xid does not match the value the client emitted. A stray
DHCP reply for an unrelated transaction is silently
discarded (return None) rather than being honoured.

> "A client that cannot receive unicast IP datagrams
>  until its protocol software has been configured with
>  an IP address SHOULD set the BROADCAST bit in the
>  'flags' field to 1 in any DHCPDISCOVER or DHCPREQUEST
>  messages that client sends."

**Adherence:** met. Both DISCOVER and REQUEST set
`dhcp4__flag_b=True`
(`dhcp4_client.py:137`, `:191`). PyTCP's
UDP path can in fact receive unicast before the address
is bound (the socket is bound on
`("0.0.0.0", 68)` which matches any destination), so
the SHOULD-clear branch would also be valid; PyTCP
takes the conservative SHOULD-set path.

---

## §4.3 DHCP server behavior

**Adherence:** out of scope. PyTCP is a host stack with
a DHCP client only; the server-behaviour normative
text in §4.3 has no audit surface.

---

## §4.3.6 Client messages — Table 4 cross-reference

| State        | Mode      | server-id | requested-ip | ciaddr     | PyTCP                                     |
|--------------|-----------|-----------|--------------|------------|-------------------------------------------|
| INIT-REBOOT  | broadcast | MUST NOT  | MUST         | zero       | not implemented (no cached lease)         |
| SELECTING    | broadcast | MUST      | MUST         | zero       | met (`dhcp4_client.py:188-205`)           |
| RENEWING     | unicast   | MUST NOT  | MUST NOT     | IP address | not implemented (no BOUND/RENEWING state) |
| REBINDING    | broadcast | MUST NOT  | MUST NOT     | IP address | not implemented (no REBINDING state)      |

Only the SELECTING row corresponds to the path PyTCP
exercises.

---

## §4.4 DHCP client behavior — state machine

> "Figure 5 gives a state-transition diagram for a DHCP
>  client. A client can receive the following messages
>  from a server: DHCPOFFER, DHCPACK, DHCPNAK."

**Adherence:** not implemented. The seven states in
Figure 5 (INIT, INIT-REBOOT, SELECTING, REQUESTING,
REBOOTING, BOUND, RENEWING, REBINDING) are not modelled
in PyTCP. The client is a single linear function
`fetch()` that emits DISCOVER, waits for OFFER, emits
REQUEST, waits for ACK, returns. There is no state
that persists past the function return.

NAK is handled by an explicit restart loop in `fetch()`
(see §3.1 step 4 above) — bounded by
`DHCP4__NAK_MAX_RESTARTS` — but the post-ACK BOUND state
and the renewal subgraph remain Phase-4 work.

---

## §4.4.1 Initialization and allocation of network address

> "The client begins in INIT state and forms a
>  DHCPDISCOVER message. The client SHOULD wait a random
>  time between one and ten seconds to desynchronize the
>  use of DHCP at startup."

**Adherence:** not met. The client invokes `fetch()`
synchronously at boot
(`packet_handler/__init__.py:1853-1856`)
with no initial random delay. A fleet of PyTCP hosts
booting simultaneously would all DISCOVER at the same
instant.

> "The client generates and records a random transaction
>  identifier and inserts that identifier into the 'xid'
>  field."

**Adherence:** met. A fresh xid is drawn at the top of
each `_discover_request_once()` round-trip.

> "The client records its own local time for later use
>  in computing the lease expiration."

**Adherence:** not implemented. No lease-expiration
tracking.

> "The client then broadcasts the DHCPDISCOVER on the
>  local hardware broadcast address to the 0xffffffff
>  IP broadcast address and 'DHCP server' UDP port."

**Adherence:** met
(`dhcp4_client.py:92`, `:153`).

> "If the 'xid' of an arriving DHCPOFFER message does
>  not match the 'xid' of the most recent DHCPDISCOVER
>  message, the DHCPOFFER message must be silently
>  discarded."

**Adherence:** met. `_recv_offer` validates
`offer.xid == xid` against the locally generated xid and
returns None (silent discard) on mismatch. The matching
guard in `_recv_ack` covers the REQUEST → ACK leg.

> "The client collects DHCPOFFER messages over a period
>  of time, selects one DHCPOFFER message from the
>  (possibly many) incoming DHCPOFFER messages."

**Adherence:** not met. PyTCP accepts the first OFFER
and immediately proceeds to REQUEST
(`dhcp4_client.py:94-110`). There is no
collection window or selection policy.

> "The client SHOULD perform a check on the suggested
>  address to ensure that the address is not already in
>  use. ... If the network address appears to be in use,
>  the client MUST send a DHCPDECLINE message to the
>  server."

**Adherence:** partial / MUST gap. RFC 5227 ARP DAD
runs against the leased address downstream
(`packet_handler/__init__.py:1864-1903`),
detecting conflicts via gratuitous ARP and address
probes. But the conflict response is NOT DHCPDECLINE
— PyTCP simply drops the candidate from
`_ip4_host_candidate` and disables IPv4 if no
candidate survives. **The MUST DECLINE-and-restart
path is not implemented.**

> "The client SHOULD broadcast an ARP reply to announce
>  the client's new IP address."

**Adherence:** met (indirectly). The same
`_create_stack_ip4_addressing` path
(`packet_handler/__init__.py:1893-1903`)
emits `ANNOUNCE_NUM=2` gratuitous ARP Announcements
after successful claim. The trigger is RFC 5227 §2.3,
not the DHCP path directly, but the user-visible
behaviour matches the SHOULD.

---

## §4.4.2 Initialization with known network address

> "The client begins in INIT-REBOOT state and sends a
>  DHCPREQUEST message. The client MUST insert its known
>  network address as a 'requested IP address' option in
>  the DHCPREQUEST message. ... The client MUST NOT
>  include a 'server identifier' in the DHCPREQUEST
>  message."

**Adherence:** not implemented. PyTCP does not cache
prior leases, so INIT-REBOOT is never entered.

---

## §4.4.3 Initialization with an externally assigned network address (DHCPINFORM)

**Adherence:** not implemented. See §3.4 above.

---

## §4.4.4 Use of broadcast and unicast

> "The DHCP client broadcasts DHCPDISCOVER, DHCPREQUEST
>  and DHCPINFORM messages, unless the client knows the
>  address of a DHCP server."

**Adherence:** met for DISCOVER and REQUEST; INFORM
not implemented. PyTCP always broadcasts; it does not
implement the unicast-to-known-server optimization.

> "The client unicasts DHCPRELEASE messages to the
>  server."

**Adherence:** not implemented (no RELEASE path).

> "Because the client is declining the use of the IP
>  address supplied by the server, the client broadcasts
>  DHCPDECLINE messages."

**Adherence:** not implemented (no DECLINE path).

---

## §4.4.5 Reacquisition and expiration

> "The client maintains two times, T1 and T2, that
>  specify the times at which the client tries to extend
>  its lease on its network address."

**Adherence:** not implemented. No timer machinery.
The lease lives until the OS process exits or the
operator manually re-runs the stack.

> "T1 MUST be earlier than T2, which, in turn, MUST be
>  earlier than the time at which the client's lease
>  will expire."

**Adherence:** vacuous (no T1/T2).

> "If the lease expires before the client receives a
>  DHCPACK, the client moves to INIT state, MUST
>  immediately stop any other network processing and
>  requests network initialization parameters as if the
>  client were uninitialized."

**Adherence:** not implemented. The lease has no
expiry consumer. PyTCP keeps using the leased IPv4
address indefinitely.

---

## §4.4.6 DHCPRELEASE

**Adherence:** not implemented. See §3.1 step 6 above.

---

## Test coverage audit

### §2 Message format

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py` (785 lines)
  Pin field-level invariants on every header field
  (under_min / over_max for integer fields; type checks
  for enums and addresses).
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__integrity_checks.py` (155 lines)
  Pin integrity error paths (frame too short, bad
  magic cookie, bad hardware type, bad hardware
  length).
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py` (690 lines)
  Pin parser happy path: full round-trip of a DISCOVER
  / OFFER / REQUEST / ACK frame through Dhcp4Parser
  exposing every header field and option.
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py` (441 lines)
  Pin assembler happy path: every field round-trips
  byte-for-byte.

**Status:** locked in (wire-format compliance).

### §3.1 DISCOVER → REQUEST flow

- **Unit:**
  `pytcp/tests/unit/lib/test__lib__dhcp4_client.py`
  Exercises `fetch()` end-to-end with a mocked socket:
  the client emits a DISCOVER with the right options,
  receives a stubbed OFFER, emits a REQUEST with the
  right `server-id`, `requested-ip`, and `client-id`,
  receives a stubbed ACK, and returns a `Dhcp4Lease`.

**Status:** locked in (happy-path lease).

### §2 / §4.4.1 / §3.1 step 4 — Phase 0 Client Identifier + xid + NAK

- **Unit:** `pytcp/tests/unit/lib/test__lib__dhcp4_client.py`
  - `TestDhcp4ClientFetchClientIdInRequest` —
    round-trips the emitted REQUEST through the real
    Dhcp4Parser and asserts `request.client_id` equals
    `b"\x01" + bytes(mac)`. Pins the §2 CID-in-REQUEST
    MUST.
  - `TestDhcp4ClientFetchXidMismatch` — OFFER and ACK
    each carry an xid different from the locally
    generated value; the client must drop both
    (§4.4.1 silent-discard MUST).
  - `TestDhcp4ClientFetchNakRestart` — a NAK in
    response to REQUEST triggers a fresh DISCOVER on
    the next iteration of the bounded restart loop
    (§3.1 step 4); four NAK rounds exhaust the
    budget and `fetch()` returns None.
  - `TestDhcp4ClientFetchLeaseReturn` and
    `TestDhcp4ClientFetchAckMissingLeaseTime` — pin
    that Lease Time is surfaced via
    `Dhcp4Lease.lease_time__sec` and that an ACK
    without Lease Time is rejected.

**Status:** locked in (Phase 0).

### §3.1 step 5 — DHCPDECLINE on ARP conflict

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test is one that:

1. Drives `fetch()` to ACK with a `yiaddr` that is
   simulated as already in use (inject a gratuitous
   ARP via the RX harness during the post-ACK ARP
   probe).
2. Asserts that `_send_decline` was called with the
   conflicted address and that `fetch()` returned
   None or restarted the configuration process.

### §4.1 — Retransmission backoff

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test is one that:

1. Holds the recv side silent for the full backoff
   window.
2. Asserts that DISCOVER is retransmitted at the
   spec'd intervals (4s, 8s, 16s, 32s, ...) with the
   ±1s jitter.

### §4.4 — Client FSM (INIT-REBOOT, RENEWING, REBINDING)

**No test surface — gap not yet closed.** Each state
needs its own integration scenario:

- INIT-REBOOT: bring up the stack twice with a cached
  prior lease; assert the second boot sends REQUEST
  with the prior IP, not DISCOVER.
- RENEWING: advance the FakeTimer past T1; assert
  unicast REQUEST to the lease's server-id.
- REBINDING: advance past T2; assert broadcast
  REQUEST with `ciaddr` set.

### §4.4.5 — Lease expiry

**No test surface — gap not yet closed.** Test would
advance the FakeTimer past the lease expiry and
assert IPv4 host removal + INIT-state restart.

### Test coverage summary

| Aspect                                              | Coverage                                                    |
|-----------------------------------------------------|-------------------------------------------------------------|
| Wire-format (header, options, magic cookie, sizes)  | locked in (~3 700 lines of unit tests)                      |
| Linear DISCOVER → REQUEST happy path                | locked in (`test__lib__dhcp4_client.py`)                    |
| Client Identifier in REQUEST                        | locked in (Phase 0 — `TestDhcp4ClientFetchClientIdInRequest`) |
| DHCPNAK handling (bounded restart)                  | locked in (Phase 0 — `TestDhcp4ClientFetchNakRestart`)      |
| ARP conflict → DHCPDECLINE                          | not tested — gap (Phase 2)                                  |
| Retransmission backoff                              | not tested — gap (Phase 1)                                  |
| FSM states (INIT-REBOOT/RENEWING/REBINDING/BOUND)   | not tested — gap (Phase 4)                                  |
| Lease expiry / T1 / T2                              | not tested — gap (Phase 4)                                  |
| DHCPRELEASE on shutdown                             | not tested — gap (Phase 4)                                  |
| DHCPINFORM                                          | not tested — gap                                            |
| xid validation on inbound                           | locked in (Phase 0 — `TestDhcp4ClientFetchXidMismatch`)     |
| Lease Time surfaced on Dhcp4Lease                   | locked in (Phase 0 — `TestDhcp4ClientFetchLeaseReturn`)     |

---

## Overall assessment

| Aspect                                                  | Status                       |
|---------------------------------------------------------|------------------------------|
| Wire format (header fields, magic cookie, flags)        | met                          |
| BROADCAST flag emission                                 | met (always set)             |
| DHCP message-type option present                        | met (DISCOVER, REQUEST)      |
| Client Identifier emission (RFC 2131 legacy form)       | met (DISCOVER + REQUEST)     |
| Server Identifier echo in REQUEST                       | met                          |
| Requested IP Address in SELECTING-state REQUEST         | met                          |
| Param Request List forwarded DISCOVER → REQUEST         | met                          |
| Magic cookie + `end` option                             | met                          |
| Single DISCOVER → OFFER → REQUEST → ACK linear path     | met                          |
| Multiple-OFFER collection + selection                   | not met (first OFFER wins)   |
| ARP probe on ACK + DHCPDECLINE on conflict              | partial (RFC 5227 DAD only)  |
| Retransmission with exponential backoff                 | not met (single recv)        |
| Initial random delay (1–10 s)                           | not met                      |
| FSM (INIT-REBOOT / BOUND / RENEWING / REBINDING)        | not implemented              |
| T1 / T2 / lease-expiry handling                         | not implemented              |
| DHCPRELEASE on shutdown                                 | not implemented              |
| DHCPDECLINE on detected address conflict                | not implemented              |
| DHCPNAK handling (bounded restart from DISCOVER)        | met (Phase 0)                |
| DHCPINFORM                                              | not implemented              |
| xid match validation on inbound messages                | met (Phase 0)                |
| Lease Time surfaced + ACK-without-Lease-Time rejected   | met (Phase 0)                |
| INIT-REBOOT (cached prior lease)                        | not implemented              |
| Unicast-to-known-server optimisation                    | not implemented              |
| 'Maximum DHCP message size' option (57)                 | not implemented              |
| 'Option overload' option (52)                           | not implemented              |
| Lease-time interpretation (T1/T2 scheduling)            | Phase 4 (Dhcp4Lifecycle)     |

**Principal compliance gap.** The PyTCP DHCP client is
a boot-time one-shot — it gets a lease then forgets
about it. Phase 0 (commit covering this audit refresh)
closed the five quick-win MUSTs: CID in REQUEST, xid
validation, CID echo (RFC 6842), NAK-triggered restart,
and Lease-Time surfacing on the returned `Dhcp4Lease`.
The remaining dominant gaps are (in rough priority for
Phase 1 host parity):

1. **Retransmission backoff (§4.1)** — a single recv
   timeout means a missed OFFER or ACK fails the boot,
   even though the next attempt would succeed. A 60-s
   four-try backoff would lift PyTCP onto the same
   resilience tier as Linux dhcpcd. Fix sketch: replace
   `_recv_offer` / `_recv_ack` with a loop that
   retransmits the prior TX every
   `4 * 2**n + uniform(-1, 1)` seconds up to `n=4`,
   `tries=5`. (Phase 1.)

2. **Lease lifecycle (§4.4.5)** — T1/T2 timers + the
   RENEWING/REBINDING states. Phase 1 host parity with
   Linux dhcpcd requires this for lease longevity past
   the initial grant period. (Phase 4.)

3. **DHCPDECLINE + restart on ARP conflict
   (§3.1 step 5)** — currently the conflict response is
   "drop the address, disable IPv4". Linux dhcpcd
   sends DECLINE and re-DISCOVERs. The hook point is
   inside `_create_stack_ip4_addressing` when the
   probe-conflict registry signals. (Phase 2.)

4. **Initial 1–10s random delay (§4.4.1)** — fleet
   boots desynchronisation; PyTCP currently kicks off
   DISCOVER immediately. (Phase 2.)

The wire-format library is comprehensive and
well-tested; the remaining gaps are all on the
client-FSM / client-policy side.
