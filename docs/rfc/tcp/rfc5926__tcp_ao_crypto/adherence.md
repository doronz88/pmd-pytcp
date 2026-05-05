# RFC 5926 — Cryptographic Algorithms for the TCP Authentication Option (TCP-AO)

| Field       | Value                                                          |
|-------------|----------------------------------------------------------------|
| RFC number  | 5926                                                           |
| Title       | Cryptographic Algorithms for the TCP Authentication Option (TCP-AO) |
| Category    | Standards Track                                                |
| Date        | June 2010                                                      |
| Source text | [`rfc5926.txt`](rfc5926.txt)                                   |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 5926. RFC 5926 specifies the MAC
and KDF cryptographic algorithms used by TCP-AO
(RFC 5925).

---

## Top-line adherence

PyTCP has **zero TCP-AO support** and therefore has
no implementation of either the MAC or KDF
algorithms specified in RFC 5926. See also the
companion adherence record for RFC 5925.

---

## §3 KDF Algorithms — Gaps

### §3.1 KDF_HMAC_SHA1

> "KDF_HMAC_SHA1: HMAC-SHA1 used as a Key Derivation
> Function. Output truncated to 96 bits where
> required."

**Adherence:** not implemented. PyTCP has no HMAC-
SHA1-based KDF.

### §3.2 KDF_AES_128_CMAC

> "KDF_AES_128_CMAC: AES-128 in CMAC mode used as a
> Key Derivation Function."

**Adherence:** not implemented. PyTCP has no AES
implementation and no CMAC mode.

---

## §4 MAC Algorithms — Gaps

### §4.1 HMAC-SHA-1-96

> "HMAC-SHA-1, output truncated to 96 bits, used as
> the MAC algorithm. Mandatory-to-implement."

**Adherence:** not implemented.

### §4.2 AES-128-CMAC-96

> "AES-128-CMAC, output truncated to 96 bits, used
> as an alternative MAC algorithm."

**Adherence:** not implemented.

---

## §5 Test Vectors

> "Implementations SHOULD verify against the test
> vectors provided in §5."

**Adherence:** n/a.

---

## Test coverage audit

No TCP-AO crypto tests exist.

### Test coverage summary

| Aspect                          | Coverage  |
|---------------------------------|-----------|
| §3.1 KDF_HMAC_SHA1              | n/a (gap) |
| §3.2 KDF_AES_128_CMAC           | n/a (gap) |
| §4.1 HMAC-SHA-1-96 MAC          | n/a (gap) |
| §4.2 AES-128-CMAC-96 MAC        | n/a (gap) |
| §5 test-vector verification     | n/a (gap) |

---

## Overall assessment

| Aspect                            | Status          |
|-----------------------------------|-----------------|
| §3.1 KDF_HMAC_SHA1                | not implemented |
| §3.2 KDF_AES_128_CMAC             | not implemented |
| §4.1 HMAC-SHA-1-96                | not implemented |
| §4.2 AES-128-CMAC-96              | not implemented |

RFC 5926 is moot until RFC 5925 (TCP-AO) is
implemented. HMAC-SHA1 is available in Python's
stdlib `hashlib` / `hmac` modules, so the §3.1 / §4.1
mandatory-to-implement algorithms could be supplied
without external dependencies. AES-128-CMAC is NOT
in stdlib and would require an external crypto
library (cryptography, pycryptodome, or similar) —
this conflicts with PyTCP's zero-runtime-deps
principle.

A future TCP-AO implementation in PyTCP could
reasonably ship only the HMAC-SHA1-based MAC and
KDF, omitting the AES-CMAC variant to preserve the
stdlib-only constraint. Most operational TCP-AO
deployments use the HMAC-SHA1 algorithm; this would
be a defensible scope cut.
