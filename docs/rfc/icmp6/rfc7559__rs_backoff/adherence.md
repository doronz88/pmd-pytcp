# RFC 7559 — Packet-Loss Resiliency for Router Solicitations

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7559                                              |
| Title       | Packet-Loss Resiliency for Router Solicitations   |
| Category    | Standards Track (Updates RFC 4861)                |
| Date        | May 2015                                          |
| Source text | [`rfc7559.txt`](rfc7559.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when RS retransmission backoff is implemented.

## Status: deferred (MUST per RFC 8504 §5.4)

PyTCP sends a single Router Solicitation at boot, waits
1 second on a `Semaphore`, and proceeds to consume any RA
that arrived (`PacketHandler._create_stack_ip6_addressing`).
On a lossy link the RS or the RA can be dropped and the
host falls back to no IPv6 address.

RFC 7559 §2 mandates an exponential-backoff retransmission
schedule for RS:

- Initial RTR_SOLICITATION_INTERVAL = 4 seconds.
- After each RS, multiply the interval by 2 (random jitter
  ±10%) up to MAX_RTR_SOLICITATION_INTERVAL = 3600
  seconds (1 hour).
- A successful RA causes the schedule to reset.

The implementation needs:

- A retransmission timer wired to the RS-emit path.
- A "received first RA" event that cancels the timer.
- Jitter generator (use `random.uniform`).

This is a Phase-1 polish item — the RFC explicitly marks
the algorithm a MUST, but the absence of backoff is only
a problem on lossy links, which is not the typical PyTCP
deployment.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (MUST)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
