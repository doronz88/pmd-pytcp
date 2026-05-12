# RFC 5227 — IPv4 Address Conflict Detection

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 5227                                                   |
| Title       | IPv4 Address Conflict Detection                        |
| Category    | Standards Track                                        |
| Date        | July 2008                                              |
| Updates     | RFC 826 (does not modify, but extends)                 |
| Source text | [`rfc5227.txt`](rfc5227.txt)                           |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 5227
(IPv4 ACD — ARP probe / announce / ongoing detection /
defense). The audit was performed by reading the RFC text fresh
and inspecting the codebase under
`pytcp/stack/packet_handler/packet_handler__arp__{rx,tx}.py`
and `pytcp/stack/packet_handler/__init__.py` directly.

The ACD machinery is exposed to consumers (DHCPv4 client, the
static-host claim path, future RFC 3927 link-local autoconfig)
via the sanctioned `Ip4AddressApi` surface in
`pytcp/lib/address_api.py`:

- `probe(*, address)` — runs the §2.1.1 probe sequence and
  returns success / conflict + peer info.
- `announce(*, address)` — emits the §2.3 ANNOUNCE_NUM burst.
- `claim_with_acd(*, ip4_host)` — composite probe + announce +
  install for simple consumers.
- `send_gratuitous_arp(*, address)` — single defensive ARP
  for §2.4(b).
- `subscribe_conflicts(*, address, on_conflict)` /
  `unsubscribe_conflicts(*, handle)` — post-claim ARP-conflict
  notification surface; the underlying `_fire_conflict_event`
  is dispatched from the ARP RX path.

Consumers MUST NOT reach into the `_arp_dad_*` /
`_send_gratuitous_arp` helpers on `PacketHandler` directly —
those are private implementation detail of the API as of the
RFC 3927 Phase 0.5 commit. The file:line references below
describe the underlying helpers, which still exist and still
implement the wire protocol; the public surface is the API.

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**.

Sections without normative content — Abstract, §1
(Introduction motivation), §1.2 (Relationship to RFC 826
narrative), §1.3 (Applicability narrative), §3 (rationale for
using Request not Reply for Announcements), §4 (Historical
Note), §5 (Security Considerations), §6 (Acknowledgments),
§7 (References) — are summarised inline only where they
inform a normative §2 requirement, and otherwise omitted.

---

## §2.1 — Probing an Address (mandatory probe before use)

> "Before beginning to use an IPv4 address (whether received
> from manual configuration, DHCP, or some other means), a
> host implementing this specification MUST test to see if
> the address is already in use, by broadcasting ARP Probe
> packets."

**Adherence:** **met**. PyTCP's
`_create_stack_ip4_addressing` runs ARP Probe packets via
`_send_arp_probe` for every candidate IPv4 address before
admitting it to `self._ip4_host` and using it on the wire
(`pytcp/stack/packet_handler/__init__.py:649-695`,
`pytcp/stack/packet_handler/packet_handler__arp__tx.py:171-195`).
The `_send_arp_probe` helper sets `arp__sha = our MAC`,
`arp__spa = Ip4Address()` (= `0.0.0.0`),
`arp__tha = MacAddress()` (unspecified),
`arp__tpa = ip4_unicast` (the candidate), matching the
§1.1 / §2.1.1 definition of an ARP Probe. The frame is
broadcast (`ethernet__dst = 0xFFFFFFFFFFFF`).

> "A host MUST NOT perform this check periodically as a
> matter of course."

**Adherence:** **met**. PyTCP runs probes only inside
`_create_stack_ip4_addressing`, which is invoked once during
stack startup; there is no scheduled re-probe path.

---

## §2.1.1 — Probe Details (wire format)

> "A host probes ... by broadcasting an ARP Request for the
> desired address. The client MUST fill in the 'sender
> hardware address' field of the ARP Request with the
> hardware address of the interface through which it is
> sending the packet. The 'sender IP address' field MUST be
> set to all zeroes ... The 'target hardware address' field
> is ignored and SHOULD be set to all zeroes. The 'target
> IP address' field MUST be set to the address being
> probed."

**Adherence:** **met**. `_send_arp_probe`
(`pytcp/stack/packet_handler/packet_handler__arp__tx.py:171-195`)
sets every field exactly as required:
- `arp__oper = ArpOperation.REQUEST`
- `arp__sha = self._mac_unicast`
- `arp__spa = Ip4Address()` — all-zeroes per RFC
- `arp__tha = MacAddress()` — all-zeroes per RFC SHOULD
- `arp__tpa = ip4_unicast` (the candidate)
- `ethernet__dst = MacAddress(0xFFFFFFFFFFFF)` — broadcast

> "When ready to begin probing, the host should then wait
> for a random time interval selected uniformly in the
> range zero to PROBE_WAIT seconds, and should then send
> PROBE_NUM probe packets, each of these probe packets
> spaced randomly and uniformly, PROBE_MIN to PROBE_MAX
> seconds apart."

**Adherence:** **partial**. PyTCP sends `PROBE_NUM = 3`
probes per candidate (`for _ in range(3)` at
`pytcp/stack/packet_handler/__init__.py:663-667`) with
inter-probe spacing of `time.sleep(random.uniform(1, 2))`
(`:668`), matching `PROBE_MIN = 1` and `PROBE_MAX = 2`
seconds.

The **initial random delay** (`PROBE_WAIT = 1` second
uniform from 0–1) is **not implemented**; PyTCP launches
the first probe immediately. This SHOULD-strength
deviation reduces resilience to "many hosts power on
simultaneously" but does not break correctness for a single
host.

> "If during this period, from the beginning of the probing
> process until ANNOUNCE_WAIT seconds after the last probe
> packet is sent, the host receives any ARP packet (Request
> *or* Reply) on the interface where the probe is being
> performed, where the packet's 'sender IP address' is the
> address being probed for, then the host MUST treat this
> address as being in use by some other host, and should
> indicate to the configuring agent ... that the proposed
> address is not acceptable."

**Adherence:** **partial — known disconnect bug**. The RX
handler does detect this scenario in three places:
- inbound Request with `spa` matching a candidate and
  `tha` being our own MAC
  (`pytcp/stack/packet_handler/packet_handler__arp__rx.py:200-204`);
- inbound Reply with `spa` matching a candidate, unicast to
  us, and `tpa` unspecified
  (`pytcp/stack/packet_handler/packet_handler__arp__rx.py:280-294`);
- inbound gratuitous Reply with `spa` matching a candidate
  (`pytcp/stack/packet_handler/packet_handler__arp__rx.py:318-322`).

In all three places the RX handler writes the conflicting
IP into a **module-level** set —
`stack.arp_probe_unicast_conflict.add(packet_rx.arp.spa)`
(`pytcp/stack/__init__.py:198`).

However, the DAD claim flow in
`_create_stack_ip4_addressing` reads a **per-instance** set
named `self._arp_probe__unicast_conflict`
(`pytcp/stack/packet_handler/__init__.py:521,665,670,680`).
The two sets are never reconciled. As a result, conflicts
detected during the probe window are recorded, but the
claim flow does not see them and proceeds to admit the
candidate anyway. **This is a real RFC 5227 §2.1.1
violation**; the test
`pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__probe`
confirms the RX side updates `stack.arp_probe_unicast_conflict`
but does not verify the integrated end-to-end behaviour
(probe → claim abort).

The "indicate to the configuring agent" requirement is
loosely met by the warning log
`<WARN>Unable to claim IPv4 address {ip4_unicast}` at
`pytcp/stack/packet_handler/__init__.py:670-674` — which
only fires if the per-instance set has entries (so today,
never on RX-detected conflict).

> "In addition, if during this period the host receives any
> ARP Probe where the packet's 'target IP address' is the
> address being probed for, and the packet's 'sender
> hardware address' is not the hardware address of any of
> the host's interfaces, then the host SHOULD similarly
> treat this as an address conflict ..."

**Adherence:** **met**. Three RX paths cover the
probe-conflict shapes:

- The gratuitous-probe case (peer's SPA = our candidate,
  broadcast L2 dst, `arp.spa == arp.tpa`, `arp.tha`
  unspecified) at `packet_handler__arp__rx.py:218-223`
  registers the conflict on the per-instance
  `_arp_probe__unicast_conflict` set the DAD flow reads.
- The "two hosts simultaneously probing the same address"
  case (peer's SPA = `0.0.0.0`, `tpa = our candidate`,
  foreign SHA) is detected explicitly at
  `packet_handler__arp__rx.py:204-217`. The earlier
  loop-drop check filters our own SHA before this branch
  fires, so it only triggers for genuine foreign probes.
  Counted in `arp__op_request__simultaneous_probe`.
- The probe-Reply case (`arp.spa = candidate`, `arp.tpa`
  unspecified, L2 dst = our MAC) at
  `packet_handler__arp__rx.py:299-313` covers a peer that
  already owns the address replying to our probe.

All three branches feed the same per-instance set the
DAD claim flow reads, so the disconnect-bug is closed
end-to-end. Test coverage at
`pytcp/tests/integration/protocols/arp/test__arp__dad.py`
covers each shape with a `_drive_dad(on_sleep=...)` test.

> "NOTE: The check that the packet's 'sender hardware
> address' is not the hardware address of any of the host's
> interfaces is important. ... a host is not confused when
> it sees its own ARP packets echoed back."

**Adherence:** **met (loop guards present)**. PyTCP's RX
handler explicitly drops looped packets at
`packet_handler__arp__rx.py:162-171` (Request) and
`:257-264` (Reply): when `arp.spa in self._ip4_unicast` (or
`is_unspecified`) **and** `arp.sha == self._mac_unicast`,
the frame is treated as a loopback and dropped before any
conflict path runs. The same anti-self-confusion logic is
present in `__phrx_arp__request` for the candidate-probe
branch via the `arp.tha == self._mac_unicast` check at
`:282`.

> "A host implementing this specification MUST take
> precautions to limit the rate at which it probes for new
> candidate addresses: if the host experiences MAX_CONFLICTS
> or more address conflicts on a given interface, then the
> host MUST limit the rate at which it probes for new
> addresses on this interface to no more than one attempted
> new address per RATE_LIMIT_INTERVAL."

**Adherence:** **not implemented**. There is no
`MAX_CONFLICTS = 10` counter and no
`RATE_LIMIT_INTERVAL = 60` seconds gate anywhere in the
ARP / packet-handler subsystems. PyTCP probes as fast as
the synchronous `_create_stack_ip4_addressing` loop will
let it for the candidates handed to it; the rate-limiting
clause has no effect because PyTCP also has no automatic
candidate-rotation path (a conflict simply fails the
claim; there is no "try a different IP" loop to slow
down). The MUST is dormant in PyTCP's current static-
configuration model but would become live the moment any
auto-claim mechanism (RFC 3927 link-local, DHCP fallback)
is added.

> "If, by ANNOUNCE_WAIT seconds after the transmission of
> the last ARP Probe no conflicting ARP Reply or ARP Probe
> has been received, then the host has successfully
> determined that the desired address may be used safely."

**Adherence:** **not met**. PyTCP launches the
ARP Announcement immediately after the last probe loop
iteration finishes
(`pytcp/stack/packet_handler/__init__.py:678-686`). There
is no `ANNOUNCE_WAIT = 2` second post-probe quiet period
during which late conflicts can still be honoured. A late
Reply arriving 0.5 s after the last Probe (well within the
ANNOUNCE_WAIT window) would be lost: the RX handler still
records it into `stack.arp_probe_unicast_conflict`, but the
claim has already moved on (and even if the per-instance
set were correctly populated, the loop has already
finished iterating).

---

## §2.2 — Shorter timeouts on appropriate network technologies

> "Network technologies may emerge for which shorter delays
> are appropriate ... If the situation arises where
> different hosts on a link are using different timing
> parameters, this does not cause any problems."

**Adherence:** **met (no deviation; tunable)**. PyTCP uses
the default constants from
`pytcp/protocols/arp/arp__constants.py`. Each timing
constant (PROBE_WAIT, PROBE_NUM, PROBE_MIN, PROBE_MAX,
ANNOUNCE_NUM, ANNOUNCE_INTERVAL, ANNOUNCE_WAIT,
DEFEND_INTERVAL) is registered with the `pytcp.lib.sysctl`
registry, so an operator on a fast network technology can
shorten any of them via
`stack.init(sysctls={"arp.probe_wait": 0, ...})` at boot or
`pytcp.stack.sysctl["arp.probe_min"] = 0` at runtime. There
is no per-link override mechanism (deferred to Phase 2
multi-interface), but RFC 5227 itself acknowledges that
mixed timing parameters are non-disruptive.

---

## §2.3 — Announcing an Address

> "Having probed to determine that a desired address may be
> used safely, a host implementing this specification MUST
> then announce that it is commencing to use this address
> by broadcasting ANNOUNCE_NUM ARP Announcements, spaced
> ANNOUNCE_INTERVAL seconds apart."

**Adherence:** **partial**.
`_create_stack_ip4_addressing` calls
`_send_arp_announcement(ip4_unicast=ip4_host.address)`
exactly once per claimed address
(`pytcp/stack/packet_handler/__init__.py:678-685`). RFC
5227 mandates `ANNOUNCE_NUM = 2` Announcements spaced
`ANNOUNCE_INTERVAL = 2` seconds apart. PyTCP sends only
one Announcement and proceeds without the second. The IP is
usable from the first Announcement (which the RFC also
allows: "The host may begin legitimately using the IP
address immediately after sending the first of the two ARP
Announcements"), but the second-announcement insurance
against ARP-cache staleness on peers is absent.

> "An ARP Announcement is identical to the ARP Probe
> described above, except that now the sender and target IP
> addresses are both set to the host's newly selected IPv4
> address."

**Adherence:** **met**. `_send_arp_announcement`
(`pytcp/stack/packet_handler/packet_handler__arp__tx.py:119-143`)
emits a Request with `arp__sha = self._mac_unicast`,
`arp__spa = ip4_unicast`, `arp__tha = MacAddress()`,
`arp__tpa = ip4_unicast`, `ethernet__dst =
0xFFFFFFFFFFFF` — which is exactly the §2.3 wire form.

---

## §2.4 — Ongoing Address Conflict Detection and Address Defense

> "At any time, if a host receives an ARP packet (Request
> *or* Reply) where the 'sender IP address' is (one of) the
> host's own IP address(es) configured on that interface,
> but the 'sender hardware address' does not match any of
> the host's own interface addresses, then this is a
> conflicting ARP packet ..."

**Adherence:** **met (detection)**. Both
`__phrx_arp__request`
(`pytcp/stack/packet_handler/packet_handler__arp__rx.py:175-183`)
and `__phrx_arp__reply`
(`pytcp/stack/packet_handler/packet_handler__arp__rx.py:268-276`)
test exactly this predicate: `arp.spa in self._ip4_unicast
and arp.sha != self._mac_unicast`. Conflict-defend stats
(`arp__op_request__conflict__defend`,
`arp__op_reply__conflict__defend`) are bumped and a
gratuitous ARP is emitted.

> "(a) Upon receiving a conflicting ARP packet, a host MAY
> elect to immediately cease using the address ..."

**Adherence:** **not implemented (option not chosen)**.
PyTCP elects (b)/(c) defense, not (a) abandon.

> "(b) If a host currently has active TCP connections or
> other reasons to prefer to keep the same IPv4 address,
> and it has not seen any other conflicting ARP packets
> within the last DEFEND_INTERVAL seconds, then it MAY
> elect to attempt to defend its address by recording the
> time that the conflicting ARP packet was received, and
> then broadcasting one single ARP Announcement ..."

**Adherence:** **partial**. PyTCP defends by emitting
`_send_gratuitous_arp(ip4_unicast=packet_rx.arp.spa)` on
every conflicting packet
(`pytcp/stack/packet_handler/packet_handler__arp__rx.py:182,275`).
The §2.4(b) **DEFEND_INTERVAL = 10 second** rate-limit /
loop-breaker is **not implemented**: PyTCP will defend
against a flood of conflicts as fast as it sees them,
which is exactly the "endless loop" failure mode RFC 5227
warns against. The "record the time" state is not kept.

> "However, if this is not the first conflicting ARP packet
> the host has seen, and the time recorded for the
> previous conflicting ARP packet is recent, within
> DEFEND_INTERVAL seconds, then the host MUST immediately
> cease using this address and signal an error to the
> configuring agent ..."

**Adherence:** **not implemented**. The MUST clause is
absent; PyTCP has no abandon path and no "record previous
conflict time" state. This is the most consequential RFC
5227 §2.4 gap: under sustained conflict (e.g. a misconfigured
peer permanently claiming our address) PyTCP will defend
forever.

> "(c) If a host has been configured such that it should
> not give up its address under any circumstances ... then
> it MAY elect to defend its address indefinitely. ... if
> this is not the first conflicting ARP packet the host
> has seen, and the time recorded for the previous
> conflicting ARP packet is within DEFEND_INTERVAL seconds,
> then the host MUST NOT send another defensive ARP
> Announcement."

**Adherence:** **not met**. PyTCP's behaviour today is
*close* to (c) ("defend indefinitely") but **violates the
rate-limit MUST NOT** at the bottom of (c) — it will send a
defensive Announcement on every conflicting packet, no
matter how recent the previous one. RFC 5227 explicitly
calls this the "endless loop flooding the network with
broadcast traffic" failure mode.

> "Before abandoning an address due to a conflict, hosts
> SHOULD actively attempt to reset any existing connections
> using that address."

**Adherence:** **vacuous (no abandon path)**. Since PyTCP
has no abandon path, the SHOULD is never reached. Once an
abandon path is added (RFC 3927 link-local, DHCP fallback,
or a future `ip addr del` API), this SHOULD becomes live —
PyTCP would need to ABORT all `TcpSession`s bound to the
address, which the existing `pytcp/socket/` layer can do
via `tcp_session.tcp_fsm(syscall=SysCall.ABORT)` but the
ARP layer has no plumbing to call it.

---

## §2.5 — Continuing Operation

> "From the time a host sends its first ARP Announcement,
> until the time it ceases using that IP address, the host
> MUST answer ARP Requests in the usual way required by
> the ARP specification [RFC826]."

**Adherence:** **met**. The Reply path runs unconditionally
once the candidate has graduated to `self._ip4_unicast`:
`packet_handler__arp__rx.py:235-242` emits an ARP Reply for
any Request whose TPA matches our IP, broadcast or unicast.

> "This applies equally for both standard ARP Requests with
> non-zero sender IP addresses and Probe Requests with
> all-zero sender IP addresses."

**Adherence:** **met**. The Probe-Request branch at
`packet_handler__arp__rx.py:215-242` distinguishes
`arp.spa.is_unspecified` (probe) from `arp.spa.is_unicast`
(regular) but takes the same Reply path for both.

---

## §2.6 — Broadcast ARP Replies

> "If quicker conflict detection is desired, this may be
> achieved by having hosts send ARP Replies using
> link-level broadcast, instead of sending only ARP
> Requests via broadcast, and Replies via unicast. This is
> NOT RECOMMENDED for general use ..."

**Adherence:** **met (NOT-RECOMMENDED form not selected)**.
PyTCP unicasts ARP Replies to the requester
(`packet_handler__arp__tx.py:209-218` sets
`ethernet__dst = arp__tha`). RFC 5227 §2.6 says broadcast
Replies SHOULD NOT be used universally; PyTCP follows the
default. RFC 3927 §2.6 mandates broadcast ARP Replies for
link-local addresses, but PyTCP doesn't implement RFC 3927;
see [`../rfc3927__ipv4_lla/adherence.md`](../rfc3927__ipv4_lla/adherence.md).

---

## §1.2.1 — Broadcast ARP Replies (handling them on RX)

> "The Packet Reception rules in RFC 826 specify that the
> content of the 'ar$spa' field should be processed *before*
> examining the 'ar$op' field, so any host that correctly
> implements the Packet Reception algorithm specified in
> RFC 826 will correctly handle ARP Replies delivered via
> link-layer broadcast."

**Adherence:** **met**. PyTCP's `__phrx_arp__reply`
explicitly distinguishes broadcast-destined Replies from
unicast Replies
(`packet_handler__arp__rx.py:297-322`); the broadcast
form (gratuitous Reply) is parsed, logged as
`arp__op_reply__gratuitous`, optionally flags candidate
conflicts (§2.4 / probe), and then runs the cache learn.

---

## Test coverage audit

### §2.1 / §2.1.1 — ARP Probe wire format

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers`
  — `_send_arp_probe` case asserts the exact 28-byte ARP
  Probe wire form (`spa = 0.0.0.0`, `tha = unspecified`,
  `tpa = candidate IP`, broadcast L2).
- **Unit:**
  `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers::test__stack__packet_handler__arp__tx__probe_uses_unspecified_spa`
  — pins `arp__spa = Ip4Address()` on probes.

**Status:** **locked in**.

### §2.1 / §2.1.1 — Probe count and inter-probe spacing

- The `for _ in range(3): ... time.sleep(random.uniform(1,
  2))` loop at
  `pytcp/stack/packet_handler/__init__.py:663-668` has no
  dedicated test; the fixed PROBE_NUM = 3 is captured only
  in the integer literal.

**Status:** **locked in indirectly** (any change to the
loop count would break integration tests that expect
exactly 3 probes per candidate, but no test asserts the
count directly). When closing the timing gaps below, add a
dedicated test that asserts exactly 3 probes and that
inter-probe sleep falls in `[1, 2]` seconds.

### §2.1.1 — Initial PROBE_WAIT random delay (0–1 s)

**No test surface — gap not yet closed.** When the gap is
closed, the natural test is one that:

1. patches `time.sleep`, `random.uniform` to capture the
   first sleep call's bound;
2. asserts the first sleep call is `random.uniform(0, 1)`
   before any probe is sent.

### §2.1.1 — RX-side conflict detection (probe window)

- **Unit:**
  `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__gratuitous_probe_conflict_candidate`
  — asserts a gratuitous Request with our candidate's SPA
  registers in `stack.arp_probe_unicast_conflict`.
- **Unit:**
  `..::TestPacketHandlerArpRxReply::test__stack__packet_handler__arp__rx__reply_probe_conflict`
  — asserts a unicast Reply with our candidate's SPA and
  TPA = unspecified registers the conflict.
- **Unit:**
  `..::TestPacketHandlerArpRxReply::test__stack__packet_handler__arp__rx__reply_gratuitous_probe_conflict`
  — asserts a gratuitous Reply with our candidate's SPA
  registers the conflict.

**Status:** **locked in (RX side only)**. Crucially these
tests assert only that `stack.arp_probe_unicast_conflict`
is populated — they do **not** verify the end-to-end
probe → claim-abort behaviour, which is silently broken
by the disconnect described in §2.1.1 above.

**Gap-not-closed test sketch.** When the disconnect is
fixed (either by changing the RX writer to use
`self._arp_probe__unicast_conflict` or by changing the DAD
reader to use the module-level set), add an integration
test that:

1. constructs a `PacketHandler` with a candidate IP;
2. drives an inbound conflicting ARP through the RX
   handler synchronously *during* the probe loop;
3. asserts `_create_stack_ip4_addressing` does **not**
   admit the conflicted candidate to `self._ip4_host` and
   does emit the warning log.

### §2.1.1 — Two-hosts-simultaneously-probing detection

**No test surface — gap not yet closed.** When the gap
is closed, the natural test is one that drives an inbound
ARP Probe (SPA = `0.0.0.0`, TPA = our candidate, SHA = a
foreign MAC) and asserts the conflict is recorded.

### §2.1.1 — MAX_CONFLICTS rate-limit

**No test surface — gap not yet closed.** When closed,
test that 10 consecutive conflicts on different candidates
trigger the RATE_LIMIT_INTERVAL gate before the 11th probe.

### §2.1.1 — ANNOUNCE_WAIT post-probe quiet period

**No test surface — gap not yet closed.** When closed,
test that an inbound conflicting ARP arriving *after* the
last probe but *before* `ANNOUNCE_WAIT` seconds elapses
still aborts the claim.

### §2.3 — Announcement wire format

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers`
  — `_send_arp_announcement` case asserts the exact wire
  bytes (REQUEST opcode, `spa = tpa = our IP`, broadcast
  L2).
- **Unit:**
  `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers::test__stack__packet_handler__arp__tx__announcement_uses_request_with_spa_tpa_self`
  — pins the field semantics.

**Status:** **locked in (single-shot; ANNOUNCE_NUM = 2 not
yet implemented)**.

### §2.3 — ANNOUNCE_NUM = 2 with ANNOUNCE_INTERVAL spacing

**No test surface — gap not yet closed.** When closed,
test that two Announcements are sent 2 seconds apart.

### §2.4 — Conflict detection (Request and Reply)

- **Unit:**
  `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__conflict_defend`
  — asserts a Request with SPA = our IP and SHA != our MAC
  triggers the gratuitous-ARP defense path.
- **Unit:**
  `..::TestPacketHandlerArpRxReply::test__stack__packet_handler__arp__rx__reply_conflict_defend`
  — same for a Reply.
- **Integration:**
  `pytcp/tests/integration/test__packet_handler__arp__rx.py`
  — "request with SPA == our IP -> send gratuitous ARP as
  defense" case.

**Status:** **locked in (defense fires)**.

### §2.4 — DEFEND_INTERVAL rate-limit

**No test surface — gap not yet closed.** When closed,
test that a second conflicting ARP within 10 seconds does
**not** trigger a second defensive Announcement (current
code does — that is a regression that needs a failing test
written first under the tests-first rule).

### §2.4 — Abandon after second conflict in DEFEND_INTERVAL

**No test surface — gap not yet closed.** When closed,
test that two conflicting ARPs within 10 seconds cause the
host to mark the address as failed and ABORT all bound
sockets.

### §2.5 — Continuing operation (Reply to Request)

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__arp__rx.py`
  — "request for stack MAC, broadcasted" and "request for
  stack MAC, unicasted" both verify a Reply is emitted
  with the correct field swap.
- **Integration:**
  `..` "request probe (SPA=0.0.0.0) for stack IP" — also
  verifies §2.5's "applies equally for ... Probe Requests
  with all-zero sender IP addresses".

**Status:** **locked in**.

### §2.6 — Broadcast Replies (NOT-RECOMMENDED form not used)

**Status:** **n/a (deliberate non-implementation)**. The
existing `_send_arp_reply` always unicasts; no test is
needed to pin the absence of broadcast Replies. RFC 3927
would require this if implemented; see that audit.

### Test coverage summary

| §       | Aspect                                                           | Coverage                                        |
|---------|------------------------------------------------------------------|-------------------------------------------------|
| §2.1.1  | Probe wire format                                                | locked in                                       |
| §2.1.1  | PROBE_NUM = 3 + PROBE_MIN/MAX spacing                            | locked in indirectly                            |
| §2.1.1  | Initial PROBE_WAIT (0–1 s)                                       | n/a (gap not closed; add test with fix)         |
| §2.1.1  | RX-side conflict detection (probe window)                        | locked in (RX only; end-to-end has a bug)       |
| §2.1.1  | RX-detected conflict aborts claim                                | n/a (gap not closed; disconnect-bug fix needed) |
| §2.1.1  | Simultaneous-probe detection (SPA = 0)                           | locked in (integration: test__arp__dad.py)      |
| §2.1.1  | MAX_CONFLICTS / RATE_LIMIT_INTERVAL                              | n/a (gap not closed; add test with fix)         |
| §2.1.1  | ANNOUNCE_WAIT post-probe quiet period                            | n/a (gap not closed; add test with fix)         |
| §2.3    | Announcement wire format                                         | locked in                                       |
| §2.3    | ANNOUNCE_NUM = 2 + ANNOUNCE_INTERVAL                             | n/a (gap not closed; add test with fix)         |
| §2.4    | Conflict detection (Request and Reply)                           | locked in                                       |
| §2.4    | DEFEND_INTERVAL rate-limit                                       | n/a (gap not closed; add test with fix)         |
| §2.4    | Abandon after second conflict                                    | locked in (unit: TestPacketHandlerArpRxDefendInterval abandon tests) |
| §2.4    | Reset connections before abandoning                              | n/a (no abandon path)                           |
| §2.5    | Continuing operation (Reply to Request)                          | locked in                                       |
| §2.6    | Broadcast Replies (NOT-RECOMMENDED)                              | n/a (deliberately not selected)                 |

---

## Overall assessment

| §           | Aspect                                       | Status                                                 |
|-------------|----------------------------------------------|--------------------------------------------------------|
| §2.1        | MUST probe before use                        | met                                                    |
| §2.1        | MUST NOT probe periodically                  | met                                                    |
| §2.1.1      | Probe wire format (`spa=0`, etc.)            | met                                                    |
| §2.1.1      | PROBE_NUM = 3                                | met                                                    |
| §2.1.1      | PROBE_MIN..PROBE_MAX inter-probe spacing     | met                                                    |
| §2.1.1      | PROBE_WAIT initial 0–1 s random delay        | not implemented                                        |
| §2.1.1      | RX-side conflict registration                | met (writes to module-level set)                       |
| §2.1.1      | Conflict aborts claim                        | **broken** — disconnect between RX writer / DAD reader |
| §2.1.1      | Simultaneous-probe (SPA = 0) detection       | met                                                    |
| §2.1.1      | Self-loopback ignore (NOTE)                  | met                                                    |
| §2.1.1      | MAX_CONFLICTS / RATE_LIMIT_INTERVAL          | not implemented (dormant in static-config model)       |
| §2.1.1      | ANNOUNCE_WAIT post-probe quiet               | not implemented                                        |
| §2.3        | MUST announce after probe                    | met (single Announcement; ANNOUNCE_NUM = 2 partial)    |
| §2.3        | Announcement wire format                     | met                                                    |
| §2.3        | ANNOUNCE_NUM = 2, ANNOUNCE_INTERVAL = 2 s    | not implemented                                        |
| §2.4        | Ongoing conflict detection                   | met                                                    |
| §2.4 (a)    | Abandon-on-conflict path                     | not implemented (option not chosen — that's allowed)   |
| §2.4 (b)    | Defense via single gratuitous Announcement   | met (mechanism); fires per-packet, not rate-limited    |
| §2.4 (b)    | DEFEND_INTERVAL rate-limit (MAY but pinned)  | not implemented                                        |
| §2.4 (b)    | Abandon after second conflict in DEFEND_INTERVAL | met                                                |
| §2.4 (c)    | Indefinite-defend rate-limit (MUST NOT)      | **violated** — defends every packet, no rate-limit     |
| §2.4 final  | Reset connections before abandon (SHOULD)    | vacuous (no abandon path)                              |
| §2.5        | Reply to Requests during use                 | met                                                    |
| §2.5        | Reply to Probe Requests (SPA = 0)            | met                                                    |
| §2.6        | Broadcast Replies (NOT-RECOMMENDED)          | met (not selected)                                     |
| §1.2.1      | Handle inbound broadcast Replies             | met                                                    |

### Principal compliance gaps

1. **The RX-vs-DAD set disconnect** is the most consequential
   correctness bug. The fix is one of two one-line edits:
   either change the three RX call sites
   (`packet_handler__arp__rx.py:202,292,320`) to call
   `self._arp_probe__unicast_conflict.add(...)`, or change
   the DAD-reader sites
   (`packet_handler/__init__.py:521,665,670,680`) to read
   `stack.arp_probe_unicast_conflict`. Either edit closes
   the gap; the per-instance side is preferred because the
   set is naturally per-PacketHandler and the module-level
   global is awkward for multi-stack future. Tests-first:
   the integration test sketched in the §2.1.1 audit above
   should be written first and verified to fail under the
   current code.

2. **§2.4(c) DEFEND_INTERVAL violation**: PyTCP defends
   every conflicting packet. The fix needs a per-IP "last
   defended at" timestamp and a 10-second guard around the
   `_send_gratuitous_arp` call. The data structure can
   live on `PacketHandler` as a `dict[Ip4Address, float]`.

3. **§2.4(b) abandon-after-second-conflict (MUST)** —
   needs an abandon path that ABORTs all `TcpSession`s
   bound to the address and removes the address from
   `self._ip4_host`. Substantial change; touches the
   socket layer.

4. **§2.3 ANNOUNCE_NUM = 2** — single-line change to add
   a second `_send_arp_announcement` call after a 2-second
   delay. Cheap and worth doing.

5. **§2.1.1 ANNOUNCE_WAIT** — wait 2 seconds after the
   last probe before the first Announcement; lets late
   conflicts still abort the claim.

The remaining gaps (PROBE_WAIT initial random delay,
MAX_CONFLICTS rate-limit, simultaneous-probe detection)
are smaller / dormant and can be sequenced after the
above three.
