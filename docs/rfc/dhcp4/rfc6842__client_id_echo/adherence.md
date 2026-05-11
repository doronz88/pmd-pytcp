# RFC 6842 — Client Identifier Option in DHCP Server Replies

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 6842                                                 |
| Title       | Client Identifier Option in DHCP Server Replies      |
| Category    | Standards Track                                      |
| Date        | January 2013                                         |
| Updates     | RFC 2131                                             |
| Source text | [`rfc6842.txt`](rfc6842.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6842. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/` and `net_proto/` directly.

RFC 6842 overrides the RFC 2131 §4.3.1 prohibition on
servers echoing the Client Identifier option back in
DHCPOFFER/DHCPACK/DHCPNAK. Under RFC 6842, **servers
MUST echo the option** and **clients MUST validate the
echoed value matches what they sent** (silently
discarding any mismatching reply).

PyTCP's compliance status:

- **Server-side requirement (MUST echo):** N/A — PyTCP
  is a DHCP client only.
- **Client-side requirement (MUST validate echo):**
  not implemented. PyTCP's client reads only
  `message_type`, `xid` (implicitly via socket flow),
  `yiaddr`, `subnet_mask`, and `router` from the ACK
  (`pytcp/lib/dhcp4_client.py:111-125`).
  It never compares the inbound `client_id` against
  the value it sent.

Sections without normative content (§1 Introduction,
§2 Conventions, §4 Security Considerations, §5
Acknowledgments, §6 Normative References, Authors'
Addresses) are omitted.

---

## §3 Modification to RFC 2131

> "If the 'client identifier' option is present in a
>  message received from a client, the server MUST
>  return the 'client identifier' option, unaltered,
>  in its response message."

**Adherence:** N/A. PyTCP has no DHCP server.

> "Option   DHCPOFFER  DHCPACK    DHCPNAK
>  Client identifier (if sent by client)  MUST MUST MUST
>  Client identifier (if not sent by client)  MUST NOT MUST NOT MUST NOT"

**Adherence:** N/A (server-side).

> "When a client receives a DHCP message containing a
>  'client identifier' option, the client MUST compare
>  that client identifier to the one it is configured
>  to send. If the two client identifiers do not match,
>  the client MUST silently discard the message."

**Adherence:** not met. **MUST gap.** The PyTCP client
at `pytcp/lib/dhcp4_client.py:155-174`
(`_recv_offer`) and `:210-229` (`_recv_ack`) does not
extract `client_id` from the inbound message and does
not compare it. A server that (correctly) echoes the
Client Identifier per RFC 6842 would have the option
silently ignored. A misdirected reply with someone
else's Client Identifier would be accepted by PyTCP
(provided `message_type` and the socket-level UDP
filter agree).

Note: the `Dhcp4OptionClientId` codec at
`net_proto/protocols/dhcp4/options/dhcp4__option__client_id.py`
is bidirectional — the inbound option WOULD parse
correctly if read. The gap is in the consumer.

---

## Test coverage audit

### §3 — Client-side echo validation

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test plan:

1. Construct an ACK frame whose Client Identifier
   option contains a different value than the one the
   client sent in REQUEST.
2. Drive the frame into `_recv_ack`.
3. Assert the client returns None (silently discards)
   without applying the lease.

A second test should cover the happy path: matching
Client Identifier echo → lease applied.

### Test coverage summary

| Aspect                                  | Coverage                          |
|-----------------------------------------|-----------------------------------|
| Server-side echo (MUST)                 | n/a (PyTCP is client only)        |
| Client-side echo validation (MUST)      | not implemented; no test          |
| Mismatching-echo silent discard         | not implemented; no test          |

---

## Overall assessment

| Aspect                                                   | Status                              |
|----------------------------------------------------------|-------------------------------------|
| §3 Server MUST echo Client Identifier                    | n/a (PyTCP is client only)          |
| §3 Client MUST compare echoed CID to configured CID      | not met                             |
| §3 Client MUST silently discard mismatching messages     | not met                             |
| `Dhcp4OptionClientId` codec on RX                        | available (in `Dhcp4Options`)       |

**Principal compliance note.** This is a defence-in-depth
MUST: in practice, the UDP socket flow filter and the
`xid` field already prevent cross-client confusion in
nearly all real deployments. The MUST exists to
handle pathological cases (multiple clients sharing
`chaddr` on one host, or `chaddr=0` clients on a
relay).

Fix is mechanical (~5 lines):

```python
# In _recv_offer and _recv_ack, after the message_type check:
if (echoed := offer.client_id) is not None:
    expected = b"\x01" + bytes(self._mac_address)
    if echoed != expected:
        __debug__ and log("dhcp4", "<WARN>CID echo mismatch; discarding")
        return None
```

Requires that the `Dhcp4Options` container expose a
`client_id` accessor — currently
`net_proto/protocols/dhcp4/options/dhcp4__options.py`
does not have one (Subnet Mask, Router, Server ID,
Param Req List, Req IP, Lease Time, Host Name, and
Message Type are exposed; Client Identifier is parsed
but not surfaced as a property). Add the accessor
alongside the others.

Worth bundling with the RFC 4361 DUID work (which
fundamentally rewrites the CID emission path) — both
audits identify the same area, and the right test
asserts both:

1. The emitted CID matches the configured DUID/IAID
   (RFC 4361).
2. The CID echoed in the reply matches the emitted
   one (RFC 6842).
