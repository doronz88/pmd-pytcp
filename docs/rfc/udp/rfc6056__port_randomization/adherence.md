# RFC 6056 — Port Randomization (BCP 156)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6056                                           |
| Title       | Recommendations for Transport-Protocol Port Randomization |
| Authors     | M. Larsen, F. Gont                             |
| Category    | Best Current Practice (BCP 156)                |
| Date        | January 2011                                   |
| Source text | [`rfc6056.txt`](rfc6056.txt)                   |

RFC 6056 applies to **both TCP and UDP** ephemeral
source-port selection. In PyTCP the implementation is
shared: a single helper `pick_local_port` at
`pytcp/lib/ip_helper.py:140-152` services both
`pytcp/socket/udp__socket.py` and
`pytcp/socket/tcp__socket.py`. This audit lives under
`docs/rfc/udp/` because the UDP audit campaign surfaced
the gap, but the findings apply equally to TCP — see
cross-references at the bottom.

This audit walks each algorithm RFC 6056 §3.3 describes,
classifies PyTCP's current implementation against that
catalogue, and proposes the minimal fix that brings it
into conformance.

Sections without normative content (§1 Introduction, §2
Ephemeral Ports — background, §5 Security boilerplate,
§6 Acknowledgements, §7 References) are omitted.

---

## Top-line summary

| §        | Topic                                          | PyTCP status |
|----------|------------------------------------------------|--------------|
| §3.1     | Characteristics of a Good Algorithm            | partial — `pick_local_port` is non-deterministic but not cryptographic |
| §3.2     | Ephemeral Port Number Range                    | **not met** — `range(32168, 60700, 2)`: narrow, even-only, range size ~7k vs Linux's 28k |
| §3.3.1   | Algorithm 1 — Simple Port Randomization        | closest match to PyTCP's behaviour (effectively) |
| §3.3.2   | Algorithm 2 — Random Re-selection on Collision | not used |
| §3.3.3   | Algorithm 3 — Hash-Based (per RFC 6528 ISS)    | not implemented |
| §3.3.4   | Algorithm 4 — Double-Hash with Increment Table | not implemented |
| §3.3.5   | Algorithm 5 — Random Increments                | not implemented |
| §3.5     | Choosing an Algorithm                          | n/a (no choice; whatever set-pop happens to be) |
| §4       | Interaction with NAPT                          | N/A — PyTCP is not a NAPT |

---

## §3.1 Characteristics of a Good Algorithm

> "Ephemeral port selection algorithms SHOULD obfuscate
>  the selection of their ephemeral ports, since this
>  helps to mitigate a number of attacks that depend on
>  the attacker's ability to guess or know the five-tuple
>  that identifies the transport-protocol instance to be
>  attacked."

**Adherence:** partial. PyTCP's `pick_local_port` at
`pytcp/lib/ip_helper.py:140-152`:

```python
def pick_local_port() -> int:
    """
    Pick an ephemeral local port, ensuring no socket is already using it.
    """

    available_ephemeral_ports = set(stack.EPHEMERAL_PORT_RANGE) - {
        socket.local_port for socket in stack.sockets.values()
    }

    if available_ephemeral_ports:
        return available_ephemeral_ports.pop()

    raise OSError("[Errno 98] Address already in use - [Unable to find free local ephemeral port]")
```

`set.pop()` on a Python `set` returns an arbitrary
element. The Python 3.x runtime applies hash
randomization to string and bytes hashing (since 3.3,
under `PYTHONHASHSEED=random` which is the default), but
**integer hashing is identity** — `hash(N) == N` for
small ints. The iteration order over `set(range(...))`
is therefore deterministic on a given build / interpreter
version: it's a function of the integer hash collisions
into the set's hash table buckets.

In practice this means an attacker who knows what build
of CPython the target is running and what set of ports
are currently in use can **predict the next port
`pick_local_port` will return** — not "easily" the way
RFC 6056's pre-randomization sequential scheme is
predictable, but the algorithm provides *no
cryptographic guarantee of unpredictability*.

The §3.1 obfuscation SHOULD is therefore weakly met. The
selection is non-deterministic from an attacker's
operational point of view (they would need to enumerate
many possibilities), but it does NOT use
`secrets.randbelow` or `random.SystemRandom` and an
internal observer (e.g. a privileged process on the same
host) could in principle reconstruct the choice.

---

## §3.2 Ephemeral Port Number Range

> "[T]he dynamic ports consist of the range 49152-65535.
>  However, ephemeral port selection algorithms should
>  use the whole range 1024-65535."

> "Ephemeral port selection algorithms SHOULD use the
>  largest possible port range, since this reduces the
>  chances of an off-path attacker of guessing the
>  selected port numbers."

**Adherence:** **not met.** `stack.EPHEMERAL_PORT_RANGE`
at `pytcp/stack/__init__.py:175`:

```python
EPHEMERAL_PORT_RANGE = range(32168, 60700, 2)
```

Three concerns:

1. **The range is narrow.** 32168-60700 is a 28,532-port
   window, but with `step=2` the actual pool is **14,266
   ports** (only even-numbered ports). Linux's default
   `ip_local_port_range = 32768 60999` is 28,232 ports —
   roughly 2× larger. The IANA "dynamic" range
   `49152-65535` (the most conservative reading of RFC
   6056 §3.2) is 16,384 ports.
2. **Even-only is bizarre.** No RFC requires step=2; no
   Linux setting recommends it; no commit message in
   PyTCP's history justifies it. It halves the effective
   range entropy for no apparent gain.
3. **The lower bound dips into IANA Registered Ports.**
   The range starts at 32168, but 32768 is a more
   commonly-used lower bound (Linux), and 49152 is the
   IANA-recommended ephemeral lower bound. Ports
   32168-49151 might collide with services the operator
   expects to bind on (anything in the 32k-49k range).

**Fix sketch:** change to
`EPHEMERAL_PORT_RANGE = range(32768, 61000)` (Linux
parity) — drop step=2 and align the lower bound. The
upper bound `60999` rather than `65535` mirrors Linux's
default (which keeps `61000-65535` available for static
allocation if the operator wants it).

---

## §3.3.1 Algorithm 1 — Simple Port Randomization

> "do { port = min_ephemeral + (random() % num_ephemeral);
>      if (check_suitable_port(port)) return port;
>      next_ephemeral++; ... } while (count > 0);"

Algorithm 1 picks a random starting port, then
**sequentially scans** the range looking for an unused
slot. The first call's pick is random; subsequent picks
within the same scan are predictable.

**Closest match to PyTCP's behaviour.** `set.pop()`
returns an arbitrary element from the available pool,
which is functionally similar to "random pick from
available" — except that PyTCP's "random" is set-hash
order rather than `random()`. The collision check is
done **upfront** (set difference) rather than as a scan,
so PyTCP doesn't actually do the linear walk Algorithm 1
describes — it picks from a pre-filtered set of unused
ports.

**Deviation from Algorithm 1:** PyTCP's pick is closer
to "random sample of a set" than "random offset into a
range." This is actually *better* than Algorithm 1 in
one sense — there's no linear-scan bias toward "first
available after an unavailable run." But it's *worse*
in another — the entropy source is set-hash-order rather
than `random()`.

---

## §3.3.2 Algorithm 2 — Random Re-selection on Collision

Like Algorithm 1 but on collision, picks ANOTHER random
port rather than sequentially scanning.

**Adherence:** not used (PyTCP doesn't loop on
collision — it computes the available set once).

---

## §3.3.3 Algorithm 3 — Hash-Based (per RFC 6528 ISS)

```c
/* offset = F(local_IP, remote_IP, remote_port, secret_key)
 * port   = min_ephemeral + ((offset + next_ephemeral) mod num_ephemeral)
 */
```

The keyed hash provides isolation between
flows-to-different-destinations: each destination tuple
gets its own port subspace, so an attacker who guesses
the port for one connection learns nothing about ports
for connections to other destinations.

**Adherence:** not implemented. PyTCP's
`pick_local_port` ignores the destination tuple entirely
— it picks from a single global pool regardless of
remote address. An attacker who can observe one
connection's source port learns information about the
likely source ports of other connections.

This is the **algorithm Linux uses for TCP** (see
`__inet_hash_connect` in `net/ipv4/inet_hashtables.c`).
For UDP, Linux currently uses Algorithm 2.

---

## §3.3.4 Algorithm 4 — Double-Hash with Increment Table

Refinement of Algorithm 3 — adds a per-destination
increment table to lower port-reuse frequency.

**Adherence:** not implemented (same as Algorithm 3).

---

## §3.3.5 Algorithm 5 — Random Increments

```c
/* next_ephemeral += (random() % N) + 1; */
```

Picks a random small increment from the previous port
rather than a fresh random pick. Lower port-reuse
frequency than Algorithm 1/2 at the cost of weaker
unpredictability.

**Adherence:** not implemented.

---

## §3.4 Secret-Key Considerations for Hash-Based Algorithms

**N/A** — PyTCP doesn't implement a hash-based algorithm.
When it eventually does (Algorithm 3 is the natural
target), the key would follow the `IP6__FLOW_SECRET` /
`TCP__ISS_SECRET` / `TCP__FASTOPEN_SECRET` pattern at
`pytcp/stack/__init__.py` — `secrets.token_bytes(16)` at
process start, never persisted.

---

## §3.5 Choosing an Ephemeral Port Selection Algorithm

RFC 6056 §3.5 recommends Algorithm 3 or 4 for TCP and
notes Algorithm 1/2 may be appropriate for "the
scenarios that may not warrant the additional complexity
of Algorithms 3 and 4," which includes most UDP
applications.

**Adherence:** **PyTCP is closest to Algorithm 1 with a
non-cryptographic randomness source.** A Phase-1 fix
would move to Algorithm 1 properly (use `secrets.choice`
on the unused-port set, or
`secrets.randbelow(len(pool))` on a sorted list). A
Phase-2 hardening could move TCP to Algorithm 3.

---

## §4 Interaction with NAPT

**N/A** — PyTCP is not a NAPT. The recommendations on
NAPT-side port mapping (preserve randomness, avoid
sequential allocation) do not apply.

---

## Fix sketch

**Phase 1 (minimal fix, addresses §3.1 and §3.2):**

1. **Widen the range to Linux defaults:**

   ```python
   # pytcp/stack/__init__.py
   EPHEMERAL_PORT_RANGE = range(32768, 61000)  # was: range(32168, 60700, 2)
   ```

2. **Make the pick cryptographically random:**

   ```python
   # pytcp/lib/ip_helper.py
   import secrets

   def pick_local_port() -> int:
       used = {socket.local_port for socket in stack.sockets.values()}
       available = [port for port in stack.EPHEMERAL_PORT_RANGE if port not in used]
       if not available:
           raise OSError("[Errno 98] Address already in use - ...")
       return secrets.choice(available)
   ```

   `secrets.choice` is backed by `os.urandom` so the
   §3.1 unpredictability SHOULD is properly met.

**Phase 2 (Algorithm 3 for TCP):**

When the source-isolation property of Algorithm 3 is
desired (TCP especially), add a keyed-hash variant —
the secret key plumbing already exists for ISS
(`TCP__ISS_SECRET`). Out of scope for the Phase-1 fix.

---

## Test coverage audit

### §3.1 Obfuscation of port selection

**Status:** locked in **for non-determinism**, not
locked in for **cryptographic unpredictability**.
Existing tests verify the picker returns *a* port in
the configured range and avoids ports already in use,
but not that the selection is uniformly distributed
nor that it resists prediction.

When the Phase-1 fix above lands, the natural tests are:

1. Pick 1000 ports from an empty pool; assert the
   result set's distribution over `EPHEMERAL_PORT_RANGE`
   is approximately uniform (chi-square at the 95%
   level).
2. Mock `secrets.choice` to a deterministic stub; verify
   the picker calls it with the correct available-port
   list.

### §3.2 Port range

**Status:** locked in (the existing
`pick_local_port` tests verify the range bound), but
the range itself is **incorrect** — the test pins the
deviation. When the fix flips the range to
`range(32768, 61000)`, the test's range-bound assertion
needs the same flip.

### §3.3 Algorithm classification

**N/A** — no dedicated test surface. The audit's value
is documentary.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Picker returns a port in range                        | locked in |
| Picker avoids already-bound ports                     | locked in |
| Picker uses cryptographic randomness (§3.1)           | n/a (gap not closed; add test with fix) |
| Picker range matches Linux default (§3.2)             | **locked in BAD** (test pins the wrong range) |
| Algorithm 3 hash-based isolation (TCP)                | n/a (Phase-2 hardening) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Obfuscation of port selection                    | partial (non-deterministic but not cryptographic) |
| §3.2 Ephemeral range — use 49152-65535 or wider       | **not met** (range too narrow + step=2 + low lower bound) |
| §3.3.1 Algorithm 1 implementation                     | closest match (with set-pop entropy instead of `random()`) |
| §3.3.3 Algorithm 3 (TCP isolation per-destination)    | not implemented (Phase-2 hardening) |
| §3.4 Secret-key handling                              | N/A (no hash-based algorithm) |
| §3.5 Algorithm choice documented                      | N/A (no formal choice) |
| §4 NAPT interaction                                   | N/A (not a NAPT) |

**Principal gaps:**

1. **Ephemeral range is wrong.** `range(32168, 60700, 2)`
   should be `range(32768, 61000)` (Linux default) at
   minimum. The step=2 is unexplained and reduces
   entropy.
2. **Randomness source is set-hash order**, not
   cryptographic. `secrets.choice` is the one-line
   improvement.

Both fixes are mechanical; both unlock the §3.1 and §3.2
SHOULDs without adding complexity. Algorithm 3 for TCP
is a separate Phase-2 hardening track and would build on
the existing `TCP__ISS_SECRET` keyed-hash infrastructure.

---

## Cross-references

- **TCP audit family applies equally** — `pick_local_port`
  is shared between `tcp__socket.py` and `udp__socket.py`.
  When this gap closes, the
  [RFC 9293 audit](../../tcp/rfc9293__tcp/adherence.md)
  (§3.1 / §3.4.1) and the
  [RFC 6528 audit](../../tcp/rfc6528__iss_hash/adherence.md)
  (which already covers the ISS-secret keyed-hash
  pattern) should both cross-reference the fix.
- UDP usage guidelines: [`../rfc8085__udp_usage_guidelines/adherence.md`](../rfc8085__udp_usage_guidelines/adherence.md) §5.1 references this audit
- UDP base spec: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md) (the sport=0 RX-reject deviation interacts — the picker assigns the source port, so sport=0 should never reach the wire from a socket-using app)
- ISS hash secret pattern (template for Algorithm 3 secret_key): [`../../tcp/rfc6528__iss_hash/adherence.md`](../../tcp/rfc6528__iss_hash/adherence.md)
- Socket-API parity: `docs/refactor/socket_linux_parity_audit.md`
