# DHCPv6 Client (RFC 8415) — implementation plan

| Field | Value |
|-------|-------|
| Status | PLANNED |
| Target RFC | RFC 8415 (DHCPv6, consolidates 3315/3633/…), with RFC 3646 (DNS options) |
| North Star | Phase 1 (host-stack parity). The missing IPv6 autoconfig leg. |
| Template | the shipped DHCPv4 client: `packages/net_proto/net_proto/protocols/dhcp4/` (wire codec) + `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` (FSM/subsystem) + `dhcp4__uid.py` (client identity). Mirror its structure throughout. |

## 0. The gap (surveyed this session)

PyTCP covers two of the three IPv6/IPv4 autoconfig legs — SLAAC ✓
(RFC 4862) and DHCPv4 ✓ — but **DHCPv6 is entirely absent**
(`find -iname "*dhcp6*"` → nothing; only `dhcp4/` exists). The RA
**Managed (M)** and **Other-config (O)** flags are *parsed* into
`Icmp6NdMessageRouterAdvertisement.flag_m` / `flag_o`
(`.../icmp6/message/nd/icmp6__nd__message__router_advertisement.py:101-102,
292-293`) but the RA RX handler **does nothing with them** — they are
read and discarded. On a default Linux host these flags trigger a
DHCPv6 client: M=1 → stateful (address assignment), O=1 → stateless
(other config — DNS/NTP). This plan closes that leg.

## 1. DHCPv6 essentials (RFC 8415)

- **Transport:** UDP. Client port **546**, server **547**. Client sends
  to the link-scoped multicast `ff02::1:2`
  (All_DHCP_Relay_Agents_and_Servers); source is the client's
  link-local address. Hop limit per §7.6.
- **Identity:** **DUID** (DHCP Unique Identifier) — DUID-LLT (type 1,
  link-layer + time) or DUID-LL (type 3). Persist/derive once per
  stack from the interface MAC (mirror `dhcp4__uid.py`).
- **Stateful (M flag) — 4-message:** SOLICIT → ADVERTISE → REQUEST →
  REPLY, carrying an **IA_NA** (Identity Association for Non-temporary
  Addresses, option 3) holding **IA_Address** (option 5) with
  preferred/valid lifetimes. **Rapid-commit (option 14):** SOLICIT(RC)
  → REPLY (2-message). Renewal via **RENEW** (T1) / **REBIND** (T2).
- **Stateless (O flag):** **INFORMATION-REQUEST** → REPLY (no IA; just
  Option Request for DNS etc.). Simpler; good first milestone.
- **Message types:** SOLICIT 1, ADVERTISE 2, REQUEST 3, CONFIRM 4,
  RENEW 5, REBIND 6, REPLY 7, RELEASE 8, DECLINE 9, RECONFIGURE 10,
  INFORMATION-REQUEST 11, RELAY-FORW/REPL 12/13 (relay — out of scope).
- **Header:** 1-byte msg-type + 3-byte transaction-id, then TLV options
  (2-byte option-code + 2-byte option-len + value). Relay messages
  have a different header — host client never builds them.
- **Key options:** Client Identifier 1, Server Identifier 2, IA_NA 3,
  IA_Address 5, Option Request (ORO) 6, Elapsed Time 8, Status Code 13,
  Rapid Commit 14, IA_PD 25 / IA_Prefix 26 (prefix delegation — out of
  host scope, Phase-2 router), DNS Recursive Name Servers 23 (RFC 3646),
  Domain Search List 24.

## 2. Phasing (each phase = its own tests-first commit(s))

### Phase 1 — net_proto DHCPv6 wire codec
New `packages/net_proto/net_proto/protocols/dhcp6/` mirroring `dhcp4/`:
- `dhcp6__header.py` — the 4-byte client/server message header
  (msg-type + 3-byte transaction-id) + `Dhcp6MessageType` enum + the
  RFC ASCII diagram.
- `dhcp6__base.py` / `dhcp6__parser.py` / `dhcp6__assembler.py` /
  `dhcp6__errors.py` — the six-file pattern (`net_proto.md` §1).
- `dhcp6/options/` — TLV base (`dhcp6__option.py`, 4-byte
  code+len prefix + envelope diagram, mirror the `dhcp4__option.py`
  diagram convention) + one file per option: client-id, server-id,
  ia_na, ia_address, oro, elapsed_time, status_code, rapid_commit,
  dns_servers, plus `dhcp6__option__unknown.py` (opaque) +
  `dhcp6__options.py` container. The DUID is a sub-structure inside
  client-id/server-id.
- Wire into `IpProto`/UDP dispatch? DHCPv6 is UDP payload (ports
  546/547), so it is parsed by the **client**, not the IP/UDP
  dispatch — like DHCPv4 (the client socket recv's raw UDP and parses).
  Confirm how dhcp4 parses inbound (via the client socket, not a
  packet-handler) and mirror.
- Full net_proto test matrix per message/option (asserts / parser
  integrity+sanity+operation / assembler operation).

### Phase 2 — DUID + stateless client (O flag), the smaller first cut
- `packages/pytcp/pytcp/protocols/dhcp6/dhcp6__uid.py` — DUID
  derivation (DUID-LL from the interface MAC; mirror `dhcp4__uid.py`).
- `dhcp6__client.py` — a `Subsystem` (or socket-driven client mirroring
  `dhcp4__client.py`): bind a UDP socket on `[::]:546`, send
  INFORMATION-REQUEST to `ff02::1:2`, parse the REPLY, surface the
  other-config (DNS) — Information-Request is the minimal, IA-free
  path and validates the whole transport + codec + DUID stack before
  the stateful FSM.
- `dhcp6__constants.py` — timers (SOL_TIMEOUT/SOL_MAX_RT, INF_TIMEOUT,
  T1/T2 defaults), retransmit (RFC 8415 §15 RT algorithm with
  randomized exponential backoff), ports, multicast addr. Classify
  policy knobs for later sysctl migration (`pytcp.md` §2).

### Phase 3 — stateful client (M flag): SOLICIT/REQUEST/REPLY + IA_NA
- The 4-message FSM (SOLICIT → ADVERTISE-select → REQUEST → REPLY),
  rapid-commit handling, IA_NA/IA_Address parse, Status Code handling.
- On a successful REPLY, assign the address via the **Address API**
  (`pytcp.stack.address` / the IPv6 address-config path) — NOT a direct
  `_ip6_ifaddr.append` (Phase-3 boundary). The address carries the
  preferred/valid lifetimes.
- RFC 8415 §15 retransmission (RT, IRT, MRT, MRC, MRD per message
  type) — mirror the dhcp4 retransmit/backoff.

### Phase 4 — RA M/O trigger wiring
- In the RA RX handler (`packet_handler__icmp6__rx.py`
  `__phrx_icmp6__nd_router_advertisement`): on `flag_m` → kick the
  stateful client; on `flag_o` (and not M) → kick the stateless client.
  Debounce/idempotent (don't re-solicit on every RA). This is the
  consumer that makes the M/O flags load-bearing — wire it last so the
  client exists before the trigger.
- Stack lifecycle: the DHCPv6 client is a stack-wide subsystem started
  via `stack.start()` / stopped via `stack.stop()` (the §6.1 boundary);
  harness snapshot/restore if it adds `stack`-module state.

### Phase 5 — RENEW/REBIND/RELEASE + adherence
- T1/T2-driven RENEW (5) / REBIND (6); RELEASE (8) on
  address-drop / `stack.stop()` (mirror the IGMP graceful-leave R7).
- DECLINE (9) on DAD failure of a DHCPv6-assigned address.
- New `docs/rfc/icmp6/...` or `docs/rfc/dhcp6/rfc8415__dhcpv6/adherence.md`
  (create a `dhcp6` group under `docs/rfc/` mirroring `dhcp4`).

## 3. Tests
- **net_proto unit** — full matrix per message + option (Phase 1).
- **Integration** (`IcmpTestCase`/a DHCPv6 harness mirroring the
  DHCPv4 mock-server `dhcp4_mock_server.py`): drive a canned
  ADVERTISE/REPLY into the client socket; assert SOLICIT/REQUEST on the
  wire, the assigned address (via the introspection API), the
  stateless DNS surface, and the RA-M/O → client-kick wiring.
- A `dhcp6_mock_server` test double mirroring `dhcp4_mock_server.py`.

## 4. Scope boundaries
- **In scope (host):** stateful + stateless client, IA_NA, DUID,
  RENEW/REBIND/RELEASE/DECLINE, DNS options, the RA-M/O trigger.
- **Out of scope:** server role, relay agent (RELAY-FORW/REPL),
  RECONFIGURE (server-initiated), **IA_PD prefix delegation** (a router
  feature — Phase 2), authentication (RFC 8415 §20, rarely used),
  Secure DHCPv6.

## 5. Effort / risk
- **Large** — multi-day, comparable to the DHCPv4 client build. Phase 1
  (codec) and Phase 3 (stateful FSM) are the bulk. Phase 2 (stateless)
  is the de-risking first cut that exercises the full transport + codec
  + DUID before the FSM.
- **Risk:** the RFC 8415 §15 retransmission state machine and the
  IA_NA/lifetime → Address-API assignment. The DHCPv4 client is a
  close template for both. Land phase by phase; never half-wire the
  RA-M/O trigger before the client exists (unconsumed-knob anti-pattern).

## 6. Resume prompt (paste verbatim in a fresh session after compacting)

```
Read docs/refactor/dhcp6_client.md end to end — the phased plan for a
DHCPv6 client (RFC 8415), the missing IPv6 autoconfig leg on
PyTCP_3_0_6. Then read CLAUDE.md and the rules in .claude/rules/
(net_proto.md, pytcp.md, feature_implementation.md, typing.md).

Context: PyTCP has SLAAC + DHCPv4 but NO DHCPv6; the RA Managed/Other
flags are parsed (flag_m/flag_o) but unconsumed. The shipped DHCPv4
client is the template: net_proto/protocols/dhcp4/ (wire codec, the
six-file + options pattern) + pytcp/protocols/dhcp4/dhcp4__client.py
(FSM/subsystem) + dhcp4__uid.py (identity) + the dhcp4_mock_server.py
test double. Before coding Phase 1, survey those dhcp4 files to mirror
their exact structure, and confirm how the dhcp4 client parses inbound
(via its own socket, not a packet-handler) so DHCPv6 mirrors it.

Start with Phase 1 (net_proto DHCPv6 wire codec: dhcp6/ package —
header + Dhcp6MessageType + the TLV options client-id/server-id/IA_NA/
IA_Address/ORO/elapsed-time/status-code/rapid-commit/DNS + unknown +
container, with RFC 8415 ASCII diagrams), tests-first, full net_proto
test matrix per message/option. Then Phase 2 (DUID + stateless
Information-Request client) as the de-risking first cut, before the
Phase-3 stateful SOLICIT/REQUEST/REPLY FSM.

Standing discipline: tests-first (failing test before each fix), one
logical unit per commit, make lint + full make test + the §7.2
docstring audit clean before each commit, modernise legacy forms on
touch, RFC/Linux-ground behavioural claims, assign DHCPv6 addresses
through the Address API (never _ip6_ifaddr.append — Phase-3 boundary),
commit trailer "Co-Authored-By: Claude Opus 4.8 (1M context)
<noreply@anthropic.com>", push only when I explicitly say so. New
adherence record under docs/rfc/dhcp6/ when behaviour lands.
```
