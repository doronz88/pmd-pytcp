# RFC 4429 — Optimistic Duplicate Address Detection (DAD) for IPv6

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| RFC number  | 4429                                                      |
| Title       | Optimistic Duplicate Address Detection (DAD) for IPv6     |
| Category    | Standards Track                                           |
| Date        | April 2006                                                |
| Source text | [`rfc4429.txt`](rfc4429.txt)                              |

## Status: SHIPPED (opt-in via `icmp6.optimistic_dad`)

PyTCP supports RFC 4429 Optimistic DAD on the address-claim
path. The behaviour is gated by the
`icmp6.optimistic_dad` sysctl (mirroring Linux
`net.ipv6.conf.<iface>.optimistic_dad`), default `0` to
match the Linux host default. When the sysctl is set to
`1` the host installs the candidate address into its
`_ip6_host` list as `OPTIMISTIC` *before* the DAD probe
sequence begins; the address is usable as outbound source
for the duration of the probe loop. Neighbor
Advertisements emitted while the address is `OPTIMISTIC`
clear the Override (O) flag per §3.3 step 5 so peers do
not overwrite an existing cache entry on the basis of an
unverified address. On DAD success the per-address state
transitions to `VALID` and the Override-flag suppression
no longer applies; on collision the address is removed
from `_ip6_host` and the per-address state cleared.

When `icmp6.optimistic_dad = 0` (the default) PyTCP
retains the strict RFC 4862 §5.4 lifecycle: the address
stays out of `_ip6_host` until DAD passes, and only then
is the state recorded as `VALID`.

Per-RFC mechanism inventory:

| §   | Mechanism                                                | Status     | Where                                                                                           |
|-----|----------------------------------------------------------|------------|-------------------------------------------------------------------------------------------------|
| §1  | Optimistic DAD overview                                  | met        | enabled via `icmp6.optimistic_dad = 1`                                                          |
| §3.1| Optimistic Tentative Address state model                 | met        | `Icmp6DadState` enum (`pytcp/protocols/icmp6/nd/nd__router_state.py`); per-address state map    |
| §3.2| DAD probe TX uses `src=::` regardless of OPTIMISTIC      | met        | unchanged from RFC 4862 strict path; `_send_icmp6_nd_dad_message` always uses unspecified src   |
| §3.3| NA Override flag cleared while OPTIMISTIC                | met        | `send_icmp6_neighbor_advertisement` consults `_icmp6_dad__states`                               |
| §3.3| OPTIMISTIC → VALID promotion before gratuitous NA        | met        | `_perform_ip6_nd_dad` promotes state, then emits gratuitous NA (RFC 9131 §3) with Override=1    |
| §3.4| OPTIMISTIC removal on DAD failure                        | met        | `_claim_ip6_address_optimistic` rolls back via `_remove_ip6_host`                               |
| §4  | Behaviour when peer sends NS for our OPTIMISTIC address  | met        | NA reply suppresses Override flag; conflict NS still aborts DAD via existing §5.4.3 path        |

Phase-2 forwarding parity: the per-address state map is a
host-local model; a router-grade build will need to
extend it per-interface and per-prefix. Tracked under the
broader `# Phase 2: per-interface` work item in
`pytcp/lib/sysctl.py` rather than RFC 4429-specific.

## Test coverage

- `pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__optimistic_dad.py`
  - `TestIcmp6Nd__OptimisticDad__SysctlRegistration` — §3.1
    sysctl plumbing (registration + validator)
  - `TestIcmp6Nd__OptimisticDad__StateAccessorUnknown` —
    `get_icmp6_dad_state` returns `None` for unknown
    addresses
  - `TestIcmp6Nd__OptimisticDad__SyncDad__StateLifecycle` —
    state transitions (`TENTATIVE → VALID` on success,
    cleared on conflict) when sysctl is off
  - `TestIcmp6Nd__OptimisticDad__OptimisticPath__PreClaim` —
    §3.3 pre-claim: address is in `_ip6_host` and
    `OPTIMISTIC` during the wait, transitions to `VALID`
    on success, removed on collision
  - `TestIcmp6Nd__OptimisticDad__NaOverrideFlag` — §3.3
    Override-flag clearing for `OPTIMISTIC` source,
    preserved for `VALID` source
  - `TestIcmp6Nd__OptimisticDad__SysctlOff__NoPreClaim` —
    strict RFC 4862 §5.4 path is preserved when sysctl is
    off

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (optional / MAY); RFC 4429 is
  opt-in
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC / DAD record (strict-DAD path is
  unchanged)
- `docs/rfc/icmp6/rfc7527__enhanced_dad/adherence.md` —
  Enhanced-DAD nonce mechanism; Optimistic DAD does not
  alter probe TX so the two features compose
- `docs/refactor/nd_linux_parity.md` §20 — implementation
  phase
