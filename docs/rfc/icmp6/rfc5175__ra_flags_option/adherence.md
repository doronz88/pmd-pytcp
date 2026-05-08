# RFC 5175 — IPv6 Router Advertisement Flags Option

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 5175                                              |
| Title       | IPv6 Router Advertisement Flags Option            |
| Category    | Standards Track                                   |
| Date        | March 2008                                        |
| Source text | [`rfc5175.txt`](rfc5175.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when an RA flag-extension consumer lands in
PyTCP.

## Status: deferred (MAY per RFC 8504 §5.6; no consumer)

The base Router Advertisement message carries an 8-bit
flags field; six bits are assigned (M, O, H, plus the 2-bit
Prf preference field defined by RFC 4191), two remain
available for future assignment. RFC 5175 defines a 48-bit
extension via a separate ND option, allowing future RA
flags to be advertised without exhausting the 8-bit field.

PyTCP does not parse RA Flags Option today. RFC 8504 §5.6
explicitly notes "no flags have been defined that make use
of the new option" — implementations MAY parse it for
forward-compatibility but no current standard requires
consumption.

This is an inert deferral: nothing to implement until a
real consumer flag is defined and PyTCP needs to react to
it.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.6
  — parent classification (MAY)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
