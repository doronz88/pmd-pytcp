# RFC 5925 — The TCP Authentication Option (TCP-AO)

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 5925                                   |
| Title       | The TCP Authentication Option (TCP-AO) |
| Category    | Standards Track                        |
| Date        | June 2010                              |
| Obsoletes   | RFC 2385 (TCP MD5 Signature Option)    |
| Source text | [`rfc5925.txt`](rfc5925.txt)           |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 5925.

---

## Top-line adherence

PyTCP has **zero TCP-AO support**. A grep across
`pytcp/`, `net_proto/`, and `net_addr/` returns no
references to TCP-AO, TCP_AO, MD5 signature, MAC
algorithm, Master Key Tuple (MKT), traffic key, or
any RFC 5925 wire-format identifier.

This audit is therefore a comprehensive gap report
rather than a paragraph-by-paragraph evaluation.

---

## §3 The TCP Authentication Option Format — Gaps

### §3.1 Option fields (Kind=29)

> "The TCP-AO option occupies space at TCP options
> length. It has Kind = 29, Length, KeyID,
> RNextKeyID, and a MAC field of length determined
> by the MAC algorithm."

**Adherence:** not implemented. PyTCP's
`net_proto/protocols/tcp/options/` does not include a
`tcp__option__ao.py`. The TCP option parser would
treat any inbound Kind=29 option as unknown and
ignore it.

### §3.2 Option processing per segment

**Adherence:** not implemented.

---

## §4 Master Key Tuples (MKTs) and Traffic Keys

> "TCP-AO uses Master Key Tuples (MKTs) per
> connection... Traffic keys are derived from MKT
> via key derivation function (KDF)."

**Adherence:** not implemented.

---

## §5 Crypto algorithms (delegated to RFC 5926)

> "MAC computation: HMAC-SHA-1-96 or AES-128-CMAC-96,
> depending on negotiated algorithm."

**Adherence:** not implemented. PyTCP has no
HMAC or AES-CMAC implementations in its tree.

---

## §6-§8 Connection state, key rollover, ICMP handling

**Adherence:** not implemented.

---

## §9 Interactions

> "TCP-AO interacts with NAT, with PAWS, with SACK,
> with timestamps, etc."

**Adherence:** n/a (TCP-AO not implemented).

---

## Test coverage audit

No TCP-AO tests exist.

### Test coverage summary

| Aspect                                    | Coverage  |
|-------------------------------------------|-----------|
| §3 TCP-AO option Kind=29 wire format      | n/a (gap) |
| §3 KeyID / RNextKeyID                     | n/a (gap) |
| §3 MAC field                              | n/a (gap) |
| §4 MKT / traffic key derivation           | n/a (gap) |
| §5 HMAC-SHA1-96 / AES-CMAC-96             | n/a (gap) |
| §6-§8 connection state / rollover / ICMP  | n/a (gap) |
| §9 interactions with other features       | n/a (gap) |

---

## Overall assessment

| Aspect              | Status          |
|---------------------|-----------------|
| All TCP-AO normative | not implemented |

PyTCP does not implement TCP-AO. RFC 2385 (the
obsoleted MD5 signature option) is also not
implemented. Implementing TCP-AO would require:

- TCP option parser/assembler for Kind=29.
- Master Key Tuple (MKT) configuration and storage.
- Key Derivation Function (KDF) per RFC 5926.
- HMAC-SHA-1-96 or AES-128-CMAC-96 MAC computation.
- Per-segment authentication on TX (sign before
  serialization) and RX (verify before parsing).
- Key rollover support via KeyID / RNextKeyID
  signaling.
- ICMP handling (refuse to honor unauthenticated
  ICMP destination-unreachable / soft-error
  injections).
- Coexistence rules with PAWS, SACK, timestamps.

Estimated effort: ~25+ commits, multiple weeks. This
is a major addition that would also require a
crypto dependency (PyTCP currently has zero runtime
deps outside stdlib; HMAC-SHA1 is in stdlib's
`hashlib` / `hmac` modules but AES-CMAC is not, so
choosing the AES-CMAC variant would force an
external dep).

The simpler TCP-MD5 (RFC 2385) is also not
implemented and is officially deprecated in favor
of TCP-AO.
