# RFC 6528 — Defending against Sequence Number Attacks

| Field       | Value                                       |
|-------------|---------------------------------------------|
| RFC number  | 6528                                        |
| Title       | Defending against Sequence Number Attacks   |
| Category    | Standards Track                             |
| Date        | February 2012                               |
| Obsoletes   | RFC 1948                                    |
| Updates     | RFC 793                                     |
| Source text | [`rfc6528.txt`](rfc6528.txt)                |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6528. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` and `pytcp/stack/`
directly; no prior memory or rule-file content was
reused. Sections that contain no normative content
(Abstract, Introduction narrative, §2 motivation /
discussion, Acknowledgements, References, Appendix A
historical context, Appendix B RFC 1948 diff) are
omitted.

---

## §3. Proposed Initial Sequence Number Generation Algorithm

### Core formula

> "TCP SHOULD generate its Initial Sequence Numbers with
> the expression:
>
>     ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
>
> where M is the 4 microsecond timer, and F() is a
> pseudorandom function (PRF) of the connection-id."

**Adherence:** met. The implementation lives at
`pytcp/protocols/tcp/tcp__iss.py:89-131` and computes
exactly the §3 expression:

```python
digest = hashlib.sha256(
    secret
    + bytes(local_address)
    + local_port.to_bytes(2, "big")
    + bytes(remote_address)
    + remote_port.to_bytes(2, "big")
).digest()
f = int.from_bytes(digest[:4], "big")
m = (clock_us // ISS_CLOCK_RATE_US) & 0xFFFF_FFFF
return (m + f) & 0xFFFF_FFFF
```

with `ISS_CLOCK_RATE_US = 4` (line 86) matching the
RFC's "4 microsecond timer". `M` advances at the
canonical RFC 6528 cadence, and `F` is keyed by all
four address/port components plus the secret. The
function is invoked from
`pytcp/protocols/tcp/tcp__session.py:621` (active
session construction) and `:1900` (session re-init for
RFC 6191 4-tuple reuse).

### F() must not be externally computable

> "F() MUST NOT be computable from the outside, or an
> attacker could still guess at sequence numbers from
> the ISN used for some other connection."

**Adherence:** met. `F` is keyed by `secret`
(`pytcp/stack/__init__.py:82`), a 16-byte (128-bit)
value generated at module-import time via
`secrets.token_bytes(16)`. The secret never leaves the
process and is fresh on every PyTCP startup. Without
the secret, an external attacker cannot compute any
host's ISN even with full knowledge of the algorithm.
The SHA-256 PRF is preimage-resistant under standard
cryptographic assumptions, so the secret cannot be
recovered from observed ISNs.

### Hash function suggestion: MD5

> "The PRF could be implemented as a cryptographic hash
> of the concatenation of the connection-id and some
> secret data; MD5 [RFC1321] would be a good choice for
> the hash function."

**Adherence:** exceeded. The RFC suggests MD5 ("would
be a good choice"); PyTCP uses SHA-256 (Python's
`hashlib.sha256`). SHA-256 has stronger collision and
preimage resistance than MD5 and is the modern default.
The §3 closing paragraph explicitly anticipates this:
"implementations should consider the trade-offs
involved in using functions with stronger security
properties, and employ them if it is deemed
appropriate". PyTCP's choice meets this guidance.

### Secret-key length

> "Key lengths of 128 bits should be adequate."

**Adherence:** met. `secrets.token_bytes(16)` produces
16 bytes = 128 bits, exactly matching the RFC's
recommended length.

### Secret-key source

> "The secret key can either be a true random number
> [RFC4086] or some per-host secret."

**Adherence:** met. Python's `secrets.token_bytes`
uses the OS entropy source (`/dev/urandom` on Linux),
which qualifies as a "true random number" under
RFC 4086 §5.2's CSPRNG requirements. The secret is
also per-process (= per-host-instance), satisfying
both alternatives the RFC permits.

### Secret-key rotation

> "A possible mechanism for protecting the secret key
> would be to change it on occasion. For example, the
> secret key could be changed whenever one of the
> following events occur:
>
>   - The system is being bootstrapped (e.g., the
>     secret key could be a combination of some secret
>     and the boot time of the machine).
>
>   - Some predefined/random time has expired.
>
>   - The secret key has been used sufficiently often
>     that it should be regarded as insecure at that
>     point."

**Adherence:** partially met. PyTCP regenerates the
secret on every process restart (matching the
"bootstrap" example), but does not rotate within a
running process. The "predefined/random time" and
"used sufficiently often" rotation triggers are not
implemented. The RFC's wording is permissive ("A
possible mechanism") rather than normative — the bullet
list describes "could change" not "MUST change". For a
research / educational stack with relatively short
process lifetimes, the omission is acceptable.

### 4.4BSD heuristic preservation

> "Note that changing the secret would change the ISN
> space used for reincarnated connections, and thus
> could cause the 4.4BSD heuristics to fail; to
> maintain safety, either dead connection state could
> be kept or a quiet time observed for two maximum
> segment lifetimes before such a change."

**Adherence:** vacuously satisfied. With no in-process
secret rotation (see above), the post-rotation safety
clause has no triggering event. The MAY-skip Quiet
Time at startup is exercised consistently with this:
the inline docstring at `tcp__iss.py:53-70` cites
RFC 9293 §3.4.3 and explains that the hash form's
4-tuple binding plus the M clock together provide the
collision-resistance guarantee Quiet Time was meant to
deliver, so no startup wait is needed.

---

## §4. Security Considerations

### Random secret + RFC 4086

> "If random numbers are used as the sole source of the
> secret, they MUST be chosen in accordance with the
> recommendations given in [RFC4086]."

**Adherence:** met. `secrets.token_bytes` is Python's
documented CSPRNG entry point and reads from the OS's
secure random source (`os.urandom` → `/dev/urandom` /
`getrandom(2)` on Linux). RFC 4086 §5.2 recommends
"any standard cryptographic random number generator,
or any other strong source"; CSPRNGs backed by
`getrandom(2)` clearly qualify.

### NAT system count side-channel

> "An attacker might be able to count the number of
> systems behind a NAT by establishing a number of TCP
> connections (using the public address of the NAT)
> and identifying the number of different sequence
> number 'spaces'."

**Adherence:** descriptive, not normative — the RFC
notes this as a side-effect of the algorithm rather
than imposing a requirement. The mitigation
([Gont2009]) is out of scope for the host-side stack.

### Eavesdropper observability

> "An eavesdropper who can observe the initial messages
> for a connection can determine its sequence number
> state, and may still be able to launch sequence
> number guessing attacks by impersonating that
> connection."

**Adherence:** descriptive, not normative — the RFC
acknowledges the algorithm does not protect against
on-path attackers. PyTCP correctly does not claim such
protection; the docstring at `tcp__iss.py:43-51`
explicitly frames the threat model as "blind off-path
attacker".

---

## Test coverage audit

### §3 Core formula

- **Unit:**
  `pytcp/tests/unit/protocols/tcp/test__tcp__iss.py::TestComputeIss`
  contains 12 dedicated tests covering every input
  parameter of `compute_iss`:
  - `test__compute_iss__same_args_same_iss` —
    determinism over identical (4-tuple, secret,
    clock).
  - `test__compute_iss__different_local_address__different_iss`
  - `test__compute_iss__different_remote_address__different_iss`
  - `test__compute_iss__different_local_port__different_iss`
  - `test__compute_iss__different_remote_port__different_iss`
  - `test__compute_iss__different_secret__different_iss`
    — pin that any single-input change yields a
    different ISN, satisfying the "different
    connection-ids must have unrelated ISN spaces"
    intent of §3.
  - `test__compute_iss__output_is_uint32` — pins
    `0 <= ISN < 2**32`.
  - `test__compute_iss__monotonic_in_clock_us` —
    pins the M-component time advance.
  - `test__compute_iss__different_4tuple_at_same_clock_yields_different_iss`
    — explicit "F binds to 4-tuple" assertion.
  - `test__compute_iss__ip6_addresses_supported`
  - `test__compute_iss__ip4_and_ip6_for_same_logical_4tuple_differ`
  - `test__compute_iss__same_4tuple_post_msl_yields_different_iss`
    — pin that same-4-tuple ISNs at clocks one MSL
    apart differ enough to make Quiet Time skipping
    safe.

**Status:** locked in (12 dedicated unit tests).

### §3 F() externally non-computable

The non-computability is a property of the SHA-256
PRF + secret keying, not a directly testable code
path. The
`test__compute_iss__different_secret__different_iss`
test ensures the secret influences the output, which
locks in the keying invariant. The cryptographic
preimage resistance of SHA-256 is taken as given (not
reproducible in PyTCP's test surface).

**Status:** locked in for the keying contract; the
PRF strength is an axiom of the chosen hash function.

### §3 Secret length = 128 bits

- **Indirect:** the secret is constructed at
  `pytcp/stack/__init__.py:82` via
  `secrets.token_bytes(16)`. There is no test that
  asserts `len(TCP__ISS_SECRET) == 16`, but the
  module-level construction makes any deviation
  immediately visible.

**Status:** locked in by construction; no dedicated
regression test, though one would be a one-liner
addition.

### §3 Secret source = CSPRNG (RFC 4086 satisfied)

The `secrets.token_bytes` call documents Python's
binding to the OS CSPRNG. No test surface is needed
because any deviation would replace the construction
site with a non-CSPRNG source — caught by code review
rather than runtime assertion.

**Status:** locked in by source-level construction.

### §3 Secret rotation

Not implemented (per the partial-met audit above); no
test surface.

### §4 RFC 4086 secret choice

Same as §3 secret source — covered by the
`secrets.token_bytes` source-level construction.

**Status:** locked in by construction.

### Test coverage summary

| Aspect                                       | Coverage                                              |
|----------------------------------------------|-------------------------------------------------------|
| §3 Core formula (M + F)                      | locked in (12 dedicated unit tests)                   |
| §3 4-tuple binding                           | locked in (5 input-variance tests)                    |
| §3 M monotonicity                            | locked in (clock-advance test)                        |
| §3 Same-4-tuple-post-MSL differs             | locked in (Quiet-Time-skip-safety test)               |
| §3 IPv6 support                              | locked in                                             |
| §3 F externally non-computable               | locked in (keying-invariant test + crypto axiom)      |
| §3 Secret length = 128 bits                  | locked in by construction (no dedicated test)         |
| §3 Secret source = CSPRNG                    | locked in by construction (no dedicated test)         |
| §3 Secret rotation                           | n/a (not implemented)                                 |
| §4 RFC 4086 secret choice                    | locked in by construction                             |

---

## Overall assessment

| Aspect                                  | Status                            |
|-----------------------------------------|-----------------------------------|
| §3 Core ISN formula (M + F)             | met                               |
| §3 F externally non-computable          | met (SHA-256 + secret)            |
| §3 Hash function suggestion (MD5)       | exceeded (SHA-256)                |
| §3 Secret length 128 bits               | met                               |
| §3 Secret source (random / per-host)    | met (CSPRNG, per-process)         |
| §3 Secret rotation                      | partial (process-restart only)    |
| §3 4.4BSD heuristic preservation        | vacuous (no in-process rotation)  |
| §4 RFC 4086 secret choice               | met (CSPRNG)                      |
| Quiet Time MAY-skip alternative         | met (cited, justified)            |

PyTCP's RFC 6528 implementation is well-aligned with
the standard's intent. The choice of SHA-256 over MD5
exceeds the RFC's hash-function suggestion. The single
gap is in-process secret rotation: the RFC's bullet
list ("predefined/random time", "used sufficiently
often") describes possible rotation triggers but does
not normatively require them, so the omission is
permissible. For long-running PyTCP deployments this
gap could become relevant; for the current research /
educational use cases, process-restart-rotation is
adequate.
