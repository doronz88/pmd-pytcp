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
defense). The audit was refreshed on 2026-05-12 after the
RFC 3927 link-local autoconfig track closed (Phases 0-5,
commits `a845d5a1` → `8f09846b`), which shipped the
underlying ACD machinery this RFC pins. Prior audit text
described a pre-RFC-3927-track state with multiple "gap not
closed" entries; the bulk of those gaps are now closed —
this refresh re-derives every adherence verdict from the
current code state without re-using prior content.

The ACD machinery is exposed to consumers (DHCPv4 client,
RFC 3927 link-local autoconfig client, future operator-config
tools) via the sanctioned `Ip4AddressApi` surface in
`pytcp/stack/address.py`:

- `probe(*, address)` — runs the §2.1.1 probe sequence and
  returns success / conflict + peer info.
- `announce(*, address)` — emits the §2.3 ANNOUNCE_NUM burst.
- `claim_with_acd(*, ip4_ifaddr)` — composite probe + announce
  + install for simple consumers.
- `send_gratuitous_arp(*, address)` — single defensive ARP
  for §2.4(b).
- `subscribe_conflicts(*, address, on_conflict)` /
  `unsubscribe_conflicts(*, handle)` — post-claim conflict
  notification surface; the underlying `_fire_conflict_event`
  is dispatched from the ARP RX path. Used by RFC 3927
  link-local for the §2.5 defend / abandon decision tree.
- `abort_bound_tcp_sessions(*, address)` — RFC 5227 §2.4-final
  SHOULD primitive that ABORTs every `TcpSession` bound to
  the yielded address.

Consumers MUST NOT reach into the `_arp_dad_*` /
`_send_gratuitous_arp` helpers on `PacketHandler` directly —
those are private implementation detail of the API as of the
RFC 3927 Phase 0.5 commit (`6970c042`). The file:line
references below describe the underlying helpers, which still
exist and still implement the wire protocol; the public
surface is the API.

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**.

Sections without normative content — Abstract, §1
(Introduction motivation), §1.2 (Relationship to RFC 826
narrative), §1.3 (Applicability narrative), §3 (rationale
for using Request not Reply for Announcements), §4 (Historical
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

**Adherence:** **met**. PyTCP's claim path —
`Ip4AddressApi.claim_with_acd`
(`pytcp/stack/address.py:290-313`) — runs the §2.1.1 probe
sequence via `_arp_dad_probe_address` before admitting a
candidate address to `self._ip4_ifaddr`. Same primitive backs
the DHCPv4 DAD path
(`pytcp/protocols/dhcp4/dhcp4__client.py` via the
`arp_dad_verifier` callback wired in
`pytcp/stack/__init__.py:476`) and the RFC 3927 link-local
candidate-probe loop
(`pytcp/protocols/ip4/link_local/link_local__client.py`).

> "A host MUST NOT perform this check periodically as a
> matter of course."

**Adherence:** **met**. Probes are emitted only on explicit
claim (DHCP discover, RFC 3927 candidate-rotation, manual
static-host configure). There is no scheduled re-probe path.

---

## §2.1.1 — Probe Details (wire format + timing)

> "A host probes ... by broadcasting an ARP Request for the
> desired address. The client MUST fill in the 'sender
> hardware address' field of the ARP Request with the
> hardware address of the interface ... The 'sender IP
> address' field MUST be set to all zeroes ... The 'target
> hardware address' field is ignored and SHOULD be set to
> all zeroes. The 'target IP address' field MUST be set to
> the address being probed."

**Adherence:** **met**. `_send_arp_probe`
(`pytcp/runtime/packet_handler/packet_handler__arp__tx.py:194-218`)
sets every field exactly as required:
- `arp__oper = ArpOperation.REQUEST`
- `arp__sha = self._mac_unicast`
- `arp__spa = Ip4Address()` — all-zeroes per MUST
- `arp__tha = MacAddress()` — all-zeroes per SHOULD
- `arp__tpa = ip4_unicast` (the candidate)
- `ethernet__dst = MacAddress(0xFFFFFFFFFFFF)` — broadcast

> "When ready to begin probing, the host should then wait
> for a random time interval selected uniformly in the
> range zero to PROBE_WAIT seconds, and should then send
> PROBE_NUM probe packets, each of these probe packets
> spaced randomly and uniformly, PROBE_MIN to PROBE_MAX
> seconds apart."

**Adherence:** **met**. `_arp_dad_probe_address`
(`pytcp/runtime/packet_handler/__init__.py:1796-1833`)
implements the full sequence:

1. `time.sleep(random.uniform(0, ARP__PROBE_WAIT))` at
   `:1817` — initial 0..PROBE_WAIT random delay.
2. `for _ in range(ARP__PROBE_NUM): _send_arp_probe(...)` at
   `:1821-1825` — exactly PROBE_NUM probes.
3. `time.sleep(random.uniform(ARP__PROBE_MIN, ARP__PROBE_MAX))`
   at `:1825` — uniform inter-probe spacing.

Default constants from `pytcp/protocols/arp/arp__constants.py`:
`ARP__PROBE_WAIT = 1`, `ARP__PROBE_NUM = 3`, `ARP__PROBE_MIN
= 1`, `ARP__PROBE_MAX = 2`. All four are sysctl-registered at
`arp__constants.py:154-194` so operators can tune them at
boot or runtime.

> "If during this period, from the beginning of the probing
> process until ANNOUNCE_WAIT seconds after the last probe
> packet is sent, the host receives any ARP packet (Request
> *or* Reply) on the interface where the probe is being
> performed, where the packet's 'sender IP address' is the
> address being probed for, then the host MUST treat this
> address as being in use by some other host ..."

**Adherence:** **met**. The probe-window conflict surface
runs through a per-candidate `DadSlotRegistry` slot
(`pytcp/lib/dad_slot_registry.py:102-198`): the claim path
installs a slot before the first probe, the RX path signals
conflicts atomically via `try_signal_conflict`, and the
post-probe check at
`pytcp/runtime/packet_handler/__init__.py:1833` returns False
if any conflict was signalled during the probe + ANNOUNCE_WAIT
window. The historical RX-vs-DAD "two unrelated sets" bug
that prior audit text described is closed by the registry
abstraction.

Three RX paths feed the registry:

- `__phrx_arp__request` SPA=candidate detection at
  `packet_handler__arp__rx.py:266` — gratuitous Request
  claiming our candidate.
- `__phrx_arp__request` simultaneous-probe (SPA=0,
  TPA=candidate, foreign SHA) detection at
  `packet_handler__arp__rx.py:269-289`.
- `__phrx_arp__reply` direct Reply to our probe
  (`spa=candidate`, `tpa=0`, L2-unicast to us) at
  `packet_handler__arp__rx.py:419,424-442`.

> "In addition, if during this period the host receives any
> ARP Probe where the packet's 'target IP address' is the
> address being probed for, and the packet's 'sender
> hardware address' is not the hardware address of any of
> the host's interfaces, then the host SHOULD similarly
> treat this as an address conflict ..."

**Adherence:** **met (§1.2.4 simultaneous-probe case)**. The
explicit simultaneous-probe detector at
`packet_handler__arp__rx.py:269-289` triggers when an inbound
Probe carries SPA=0 + TPA=our-candidate + foreign SHA. The
preceding self-loopback guard (foreign SHA check) at
`:259-264` prevents our own echoed Probes from being
mis-flagged. The `arp__op_request__simultaneous_probe`
counter is bumped on detection.

> "NOTE: The check that the packet's 'sender hardware
> address' is not the hardware address of any of the host's
> interfaces is important. ... a host is not confused when
> it sees its own ARP packets echoed back."

**Adherence:** **met (loop guards present)**. PyTCP drops
looped Probes at `packet_handler__arp__rx.py:259-264` and
looped Replies at `:413-418`: when `arp.sha ==
self._mac_unicast`, the frame is treated as a loopback and
dropped before any conflict path runs. The
`arp__op_request__looped__drop` / `arp__op_reply__looped__drop`
counters are bumped on each drop.

> "A host implementing this specification MUST take
> precautions to limit the rate at which it probes for new
> candidate addresses: if the host experiences MAX_CONFLICTS
> or more address conflicts on a given interface, then the
> host MUST limit the rate at which it probes for new
> addresses on this interface to no more than one attempted
> new address per RATE_LIMIT_INTERVAL."

**Adherence:** **met (in the RFC 3927 link-local
subsystem)**. The MAX_CONFLICTS / RATE_LIMIT_INTERVAL gate
is enforced in the link-local candidate-rotation loop
(`pytcp/protocols/ip4/link_local/link_local__client.py:242-249`):
after `MAX_CONFLICTS` conflicts within a tracking window,
the subsystem inserts a `RATE_LIMIT_INTERVAL` sleep before
the next probe attempt. The constants live in
`pytcp/protocols/ip4/link_local/link_local__constants.py:45,51`
and are sysctl-registered at `:75-90`
(`ip4_link_local.max_conflicts` default 10;
`ip4_link_local.rate_limit_interval_s` default 60).

DHCP-driven claims do not rotate candidates (one DHCP server
hands out one address), so the rate-limit MUST is dormant
in the DHCP path — but it would activate naturally if a
DHCPDECLINE-on-conflict retry loop is added (deferred to
DHCPv4 Phase 9 backlog).

> "If, by ANNOUNCE_WAIT seconds after the transmission of
> the last ARP Probe no conflicting ARP Reply or ARP Probe
> has been received, then the host has successfully
> determined that the desired address may be used safely."

**Adherence:** **met**. `_arp_dad_probe_address` sleeps
`ARP__ANNOUNCE_WAIT` seconds after the last Probe at
`pytcp/runtime/packet_handler/__init__.py:1831` before
returning the success / conflict verdict. Late conflicting
ARPs arriving within this window still feed the registry
slot via the RX paths above; only after the quiet period
does `has_signal(...)` at `:1833` decide the outcome.
`ARP__ANNOUNCE_WAIT = 2` default; sysctl-tunable.

---

## §2.2 — Shorter timeouts on appropriate network technologies

> "Network technologies may emerge for which shorter delays
> are appropriate ... If the situation arises where
> different hosts on a link are using different timing
> parameters, this does not cause any problems."

**Adherence:** **met (no deviation; all timing tunable)**.
PyTCP uses RFC-default constants from
`pytcp/protocols/arp/arp__constants.py`. Every timing
constant (PROBE_WAIT, PROBE_NUM, PROBE_MIN, PROBE_MAX,
ANNOUNCE_NUM, ANNOUNCE_INTERVAL, ANNOUNCE_WAIT,
DEFEND_INTERVAL) is registered with `pytcp.stack.sysctl` so
an operator on a fast network can shorten any of them via
`stack.init(sysctls={"arp.probe_wait": 0, ...})` at boot or
`pytcp.stack.sysctl["arp.probe_min"] = 0` at runtime. No
per-link override mechanism yet (deferred to Phase 2
multi-interface), but RFC 5227 itself acknowledges mixed
timing parameters across hosts are non-disruptive.

---

## §2.3 — Announcing an Address

> "Having probed to determine that a desired address may be
> used safely, a host implementing this specification MUST
> then announce that it is commencing to use this address
> by broadcasting ANNOUNCE_NUM ARP Announcements, spaced
> ANNOUNCE_INTERVAL seconds apart."

**Adherence:** **met**. `_arp_dad_announce_address`
(`pytcp/runtime/packet_handler/__init__.py:1835-1847`) loops
`ARP__ANNOUNCE_NUM` times with `time.sleep(ARP__ANNOUNCE_INTERVAL)`
between successive sends:

```
for announce_idx in range(ARP__ANNOUNCE_NUM):
    if announce_idx > 0:
        time.sleep(ARP__ANNOUNCE_INTERVAL)
    self._send_arp_announcement(ip4_unicast=ip4_unicast)
```

Defaults: `ARP__ANNOUNCE_NUM = 2`, `ARP__ANNOUNCE_INTERVAL =
2` per `arp__constants.py:63-64`; both sysctl-registered at
`arp__constants.py:195-217`.

> "An ARP Announcement is identical to the ARP Probe
> described above, except that now the sender and target IP
> addresses are both set to the host's newly selected IPv4
> address."

**Adherence:** **met**. `_send_arp_announcement`
(`packet_handler__arp__tx.py:142-166`) emits a Request with
`arp__sha = self._mac_unicast`, `arp__spa = ip4_unicast`,
`arp__tha = MacAddress()`, `arp__tpa = ip4_unicast`,
`ethernet__dst = 0xFFFFFFFFFFFF` — exactly the §2.3 wire
form.

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
(`packet_handler__arp__rx.py:259-267`) and
`__phrx_arp__reply` (`:413-422`) test exactly this
predicate: `arp.spa in self._ip4_unicast` AND `arp.sha !=
self._mac_unicast`. Both feed the shared
`_handle_arp_conflict` helper at `:95-131`.

> "(a) Upon receiving a conflicting ARP packet, a host MAY
> elect to immediately cease using the address ..."

**Adherence:** **partial — option not chosen by default**.
PyTCP defaults to (b)/(c) defense. The (a) immediate-abandon
behaviour is available to consumers via the conflict-
subscription surface: a subscriber to
`Ip4AddressApi.subscribe_conflicts(address=..., on_conflict=
abandon_callback)` can call
`Ip4AddressApi.remove_ifaddr(ip4_address=..., abort_bound_sessions=True)`
on first conflict for the (a) semantics. The RFC 3927
link-local client uses this surface for its §2.5 defend /
abandon decision tree.

> "(b) If a host currently has active TCP connections or
> other reasons to prefer to keep the same IPv4 address,
> and it has not seen any other conflicting ARP packets
> within the last DEFEND_INTERVAL seconds, then it MAY
> elect to attempt to defend its address by recording the
> time that the conflicting ARP packet was received, and
> then broadcasting one single ARP Announcement ..."

**Adherence:** **met**. `_handle_arp_conflict`
(`packet_handler__arp__rx.py:95-131`) keeps a per-IP
"last defense at" timestamp in
`self._arp_defend__last_emitted: dict[Ip4Address, float]`
and a per-IP "last conflict at" timestamp tracking the
previous conflict's timestamp. On a first conflict (no prior
within `ARP__DEFEND_INTERVAL`), the handler:

1. Records the conflict timestamp.
2. Records the defense-emit timestamp.
3. Calls `_send_gratuitous_arp(ip4_unicast=...)` once.

`ARP__DEFEND_INTERVAL = 10` per `arp__constants.py:77`,
sysctl-registered.

> "However, if this is not the first conflicting ARP packet
> the host has seen, and the time recorded for the
> previous conflicting ARP packet is recent, within
> DEFEND_INTERVAL seconds, then the host MUST immediately
> cease using this address and signal an error to the
> configuring agent ..."

**Adherence:** **met**. The second-conflict-within-window
branch at `packet_handler__arp__rx.py:119-123` calls
`_abandon_ipv4_address(ip4_unicast=...)` which:

1. ABORTs every `TcpSession` bound to the address (RFC 9293
   §3.10.7.4 SysCall.ABORT path; emits RST).
2. Removes the address from `self._ip4_ifaddr`.
3. Fires the conflict-subscription callback (carries the
   abandoned-address signal to the consumer).

Implementation at `packet_handler__arp__rx.py:132-165`.

> "(c) If a host has been configured such that it should
> not give up its address under any circumstances ... then
> it MAY elect to defend its address indefinitely. ... if
> this is not the first conflicting ARP packet the host
> has seen, and the time recorded for the previous
> conflicting ARP packet is within DEFEND_INTERVAL seconds,
> then the host MUST NOT send another defensive ARP
> Announcement."

**Adherence:** **met (DEFEND_INTERVAL rate-limit pinned at
the (b) ceiling)**. PyTCP's defense path falls under (b) +
abandon-after-second-conflict, not (c) indefinite-defend.
The DEFEND_INTERVAL-MUST-NOT clause from (c) is honoured
trivially because the (b) path abandons after the second
conflict rather than defending again. A future (c)-mode
hook (configurable "this address is too important to yield")
would re-enter the rate-limit guard at `:127-130` which
already short-circuits defense within `ARP__DEFEND_INTERVAL`
of the previous defense.

> "Before abandoning an address due to a conflict, hosts
> SHOULD actively attempt to reset any existing connections
> using that address."

**Adherence:** **met**. `_abandon_ipv4_address` at
`packet_handler__arp__rx.py:132-165` invokes
`SysCall.ABORT` on every `TcpSession` whose local address
equals the abandoned IP — the RFC 9293 ABORT primitive
emits RST and tears the session down. The public surface
`Ip4AddressApi.abort_bound_tcp_sessions(address=...)` at
`pytcp/stack/address.py:329-339` exposes the same
primitive to consumers running their own abandon logic
(e.g. DHCPDECLINE flows when they land).

---

## §2.5 — Continuing Operation

> "From the time a host sends its first ARP Announcement,
> until the time it ceases using that IP address, the host
> MUST answer ARP Requests in the usual way required by
> the ARP specification [RFC826]."

**Adherence:** **met**. The Reply path runs unconditionally
once the candidate has been admitted to `self._ip4_ifaddr`:
`packet_handler__arp__rx.py:378-386` calls
`_send_arp_reply(...)` for any Request whose TPA matches our
IP.

> "This applies equally for both standard ARP Requests with
> non-zero sender IP addresses and Probe Requests with
> all-zero sender IP addresses."

**Adherence:** **met**. The Probe-Request branch and the
unicast-Request branch share the same Reply path; the only
differentiation is in conflict-detection logic upstream.

---

## §2.6 — Broadcast ARP Replies

> "If quicker conflict detection is desired, this may be
> achieved by having hosts send ARP Replies using
> link-level broadcast, instead of sending only ARP
> Requests via broadcast, and Replies via unicast. This is
> NOT RECOMMENDED for general use ..."

**Adherence:** **met (NOT-RECOMMENDED form not selected)**.
PyTCP unicasts ARP Replies to the requester
(`packet_handler__arp__tx.py:209-218` sets `ethernet__dst =
arp__tha`). RFC 5227 §2.6 says broadcast Replies SHOULD NOT
be used universally; PyTCP follows the default. RFC 3927
link-local does not flip this — see
[`../../ip4/rfc3927__ip4_link_local/adherence.md`](../../ip4/rfc3927__ip4_link_local/adherence.md).

---

## §1.2.1 — Broadcast ARP Replies (handling them on RX)

> "The Packet Reception rules in RFC 826 specify that the
> content of the 'ar$spa' field should be processed *before*
> examining the 'ar$op' field, so any host that correctly
> implements the Packet Reception algorithm specified in
> RFC 826 will correctly handle ARP Replies delivered via
> link-layer broadcast."

**Adherence:** **met**. `__phrx_arp__reply` explicitly
handles broadcast-destined Replies at
`packet_handler__arp__rx.py:453-476`; the gratuitous-Reply
form (broadcast L2 dst, `arp.spa == arp.tpa`) is parsed,
logged as `arp__op_reply__gratuitous`, flagged into the
DAD registry if it conflicts with a candidate, and then
runs the cache learn.

---

## Test coverage audit

### §2.1 / §2.1.1 — ARP Probe wire format

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers`
  — `_send_arp_probe` case asserts the exact 28-byte ARP
  Probe wire form (`spa=0.0.0.0`, `tha=unspecified`,
  `tpa=candidate IP`, broadcast L2).

**Status:** locked in.

### §2.1.1 — Probe count, PROBE_WAIT initial delay, inter-probe spacing

- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDadProbeSequence`
  (cases at `:394-427`) — asserts the initial PROBE_WAIT
  random delay, the PROBE_NUM count, and the
  PROBE_MIN..PROBE_MAX inter-probe spacing.

**Status:** locked in.

### §2.1.1 — RX-side conflict detection (probe window)

- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__dad.py`
  (cases at `:109-312`) — drives an inbound conflicting ARP
  during the probe window and asserts the claim aborts.
  Covers all four conflict shapes:
  - gratuitous Request with SPA=candidate
  - simultaneous-probe (SPA=0, TPA=candidate, foreign SHA)
  - direct Reply to our probe (`spa=candidate`, `tpa=0`)
  - gratuitous Reply (broadcast Reply with SPA=candidate)
- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDad__ConflictDuringAnnounceWait`
  — drives a conflict in the post-probe ANNOUNCE_WAIT window
  and asserts the claim still aborts.

**Status:** locked in.

### §2.1.1 — MAX_CONFLICTS / RATE_LIMIT_INTERVAL

- **Unit:**
  `pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__claiming.py::test__ip4_link_local__claiming_max_conflicts_rate_limits`
  — drives `MAX_CONFLICTS` conflicts in succession, asserts
  the next probe is gated by a `RATE_LIMIT_INTERVAL` sleep.

**Status:** locked in (RFC 3927 link-local subsystem; DHCP
path has no candidate-rotation today so the gate is dormant
there).

### §2.3 — Announcement wire format

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__tx.py::TestPacketHandlerArpTxConvenienceHelpers`
  — `_send_arp_announcement` case asserts the wire bytes
  (REQUEST opcode, `spa=tpa=our IP`, broadcast L2).

**Status:** locked in.

### §2.3 — ANNOUNCE_NUM=2 + ANNOUNCE_INTERVAL spacing

- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDadAnnounceSequence`
  (cases at `:313-388`) — asserts two Announcements are
  emitted, separated by `ARP__ANNOUNCE_INTERVAL`.

**Status:** locked in.

### §2.4 — Conflict detection (Request and Reply)

- **Unit:**
  `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__conflict_defend`
  — asserts a Request with SPA = our IP and SHA != our MAC
  triggers the defense path.
- **Unit:**
  `..::TestPacketHandlerArpRxReply::test__stack__packet_handler__arp__rx__reply_conflict_defend`
  — same for Reply.

**Status:** locked in.

### §2.4(b) — DEFEND_INTERVAL rate-limit + first-defense behaviour

- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__defend_interval.py::TestArpDefendInterval__FirstConflict`
  (cases at `:122-232`) — asserts first conflict triggers
  exactly one gratuitous Announcement.
- **Integration:**
  `..::TestArpDefendInterval__PerIpIndependence` — asserts
  per-IP timestamps don't cross-contaminate defenses.

**Status:** locked in.

### §2.4(b) — Abandon after second conflict in DEFEND_INTERVAL

- **Integration:**
  `pytcp/tests/integration/protocols/arp/test__arp__defend_interval.py::TestArpDefendInterval__SecondConflictAbandons`
  — asserts the second conflict within `DEFEND_INTERVAL`
  drops the address from `_ip4_ifaddr` and ABORTs bound
  sessions.

**Status:** locked in.

### §2.4-final — Reset connections before abandoning (SHOULD)

- **Unit:**
  `pytcp/tests/unit/lib/test__lib__address_api.py::TestIp4AddressApi__RemoveHost`
  (cases at `:188-225`) — asserts `remove_ifaddr` issues
  `SysCall.ABORT` to every `TcpSession` bound to the
  removed address.
- **Unit:**
  `pytcp/tests/unit/lib/test__lib__address_api.py::TestIp4AddressApi__AbortBoundTcpSessions`
  (cases at `:394-469`) — asserts the standalone primitive
  is consumer-callable for RFC 3927 §2.5(a) abandon paths.

**Status:** locked in.

### §2.5 — Continuing operation (Reply to Request)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
  — "request for stack MAC, broadcasted" and "request for
  stack MAC, unicasted" both verify a Reply is emitted
  with the correct field swap.
- **Integration:** `..` "request probe (SPA=0.0.0.0) for
  stack IP" — verifies §2.5's "applies equally for ... Probe
  Requests with all-zero sender IP addresses".

**Status:** locked in.

### §2.6 — Broadcast Replies (NOT-RECOMMENDED form not used)

**Status:** n/a (deliberate non-implementation). PyTCP's
`_send_arp_reply` unicasts; no test pins the absence of
broadcast Replies. RFC 3927 link-local does not opt into
the §2.6 broadcast form either.

### §1.2.1 — Broadcast Reply handling

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
  — gratuitous-Reply (broadcast L2, SPA=SPA=peer-IP) case
  asserts the cache-learn path runs.

**Status:** locked in.

### Test coverage summary

| §           | Aspect                                                       | Coverage                       |
|-------------|--------------------------------------------------------------|--------------------------------|
| §2.1.1      | Probe wire format                                            | locked in                      |
| §2.1.1      | PROBE_WAIT initial random delay                              | locked in                      |
| §2.1.1      | PROBE_NUM + PROBE_MIN/MAX spacing                            | locked in                      |
| §2.1.1      | RX-side conflict detection (all four shapes)                 | locked in                      |
| §2.1.1      | Conflict aborts claim (end-to-end via DAD registry)          | locked in                      |
| §2.1.1      | Simultaneous-probe detection (SPA=0, foreign SHA)            | locked in                      |
| §2.1.1      | MAX_CONFLICTS / RATE_LIMIT_INTERVAL                          | locked in (link-local subsystem) |
| §2.1.1      | ANNOUNCE_WAIT post-probe quiet period                        | locked in                      |
| §2.3        | Announcement wire format                                     | locked in                      |
| §2.3        | ANNOUNCE_NUM = 2 + ANNOUNCE_INTERVAL spacing                 | locked in                      |
| §2.4        | Conflict detection (Request and Reply)                       | locked in                      |
| §2.4(b)     | DEFEND_INTERVAL rate-limit + first-defense                   | locked in                      |
| §2.4(b)     | Abandon after second conflict in DEFEND_INTERVAL             | locked in                      |
| §2.4-final  | Reset connections before abandoning (SHOULD)                 | locked in                      |
| §2.5        | Continuing operation (Reply to Request)                      | locked in                      |
| §2.6        | Broadcast Replies (NOT-RECOMMENDED, not used)                | n/a (deliberate)               |
| §1.2.1      | Broadcast Reply handling on RX                               | locked in                      |

---

## Overall assessment

| §           | Aspect                                       | Status                                      |
|-------------|----------------------------------------------|---------------------------------------------|
| §2.1        | MUST probe before use                        | met                                         |
| §2.1        | MUST NOT probe periodically                  | met                                         |
| §2.1.1      | Probe wire format (`spa=0`, etc.)            | met                                         |
| §2.1.1      | PROBE_WAIT initial 0..PROBE_WAIT random delay | met                                        |
| §2.1.1      | PROBE_NUM = 3                                | met                                         |
| §2.1.1      | PROBE_MIN..PROBE_MAX inter-probe spacing     | met                                         |
| §2.1.1      | RX-side conflict registration                | met (via `DadSlotRegistry`)                 |
| §2.1.1      | Conflict aborts claim end-to-end             | met                                         |
| §2.1.1      | Simultaneous-probe (SPA = 0) detection       | met                                         |
| §2.1.1      | Self-loopback ignore (NOTE)                  | met                                         |
| §2.1.1      | MAX_CONFLICTS / RATE_LIMIT_INTERVAL          | met (RFC 3927 link-local subsystem)         |
| §2.1.1      | ANNOUNCE_WAIT post-probe quiet               | met                                         |
| §2.3        | MUST announce after probe                    | met                                         |
| §2.3        | Announcement wire format                     | met                                         |
| §2.3        | ANNOUNCE_NUM = 2, ANNOUNCE_INTERVAL = 2 s    | met                                         |
| §2.4        | Ongoing conflict detection                   | met                                         |
| §2.4 (a)    | Immediate-abandon path (consumer-controlled) | partial (default declines (a); subscribe_conflicts exposes it) |
| §2.4 (b)    | Defense via single gratuitous Announcement   | met (DEFEND_INTERVAL rate-limited)          |
| §2.4 (b)    | DEFEND_INTERVAL rate-limit                   | met                                         |
| §2.4 (b)    | Abandon after second conflict                | met                                         |
| §2.4 (c)    | Indefinite-defend mode                       | n/a (not configured; (b) abandon supersedes) |
| §2.4 final  | Reset connections before abandon (SHOULD)    | met                                         |
| §2.5        | Reply to Requests during use                 | met                                         |
| §2.5        | Reply to Probe Requests (SPA = 0)            | met                                         |
| §2.6        | Broadcast Replies (NOT-RECOMMENDED)          | met (not selected)                          |
| §1.2.1      | Handle inbound broadcast Replies             | met                                         |

PyTCP fully implements RFC 5227 for IPv4 ACD. Every Phase-1
normative requirement is met; the only "partial" entry is
§2.4(a) immediate-abandon, which the RFC explicitly lists as
a MAY option not chosen by the default policy — and consumers
who want (a)-mode semantics can wire it via the
conflict-subscription surface (`subscribe_conflicts` →
`remove_ifaddr(abort_bound_sessions=True)`).

The ACD machinery has clean Phase-3 boundaries: all consumer
access flows through `pytcp.stack.address` (`Ip4AddressApi`);
the underlying `_arp_dad_*` and `_send_gratuitous_arp`
helpers on `PacketHandler` are implementation detail. DHCPv4
and RFC 3927 link-local both consume the public API, not
the internals.

### History

- Initial audit (commit `03c0b678`) described the
  pre-implementation state.
- ARP NUD framework (commit `586a693e`) registered timing
  constants as sysctls.
- Simultaneous-probe detection (commit `3f051584`) closed
  §1.2.4 / §2.1.1 SHOULD.
- Abandon-after-second-conflict (commit `67e60e39`) closed
  §2.4(b) MUST.
- ACD API extraction (commit `6970c042`, RFC 3927 Phase 0.5)
  consolidated the public surface on `Ip4AddressApi`.
- RFC 3927 link-local track (commits `b48d7fc3` → `8f09846b`)
  closed MAX_CONFLICTS / RATE_LIMIT_INTERVAL via the
  candidate-rotation loop.
- Audit refresh (this commit) re-derived every adherence
  verdict from the current code state.
