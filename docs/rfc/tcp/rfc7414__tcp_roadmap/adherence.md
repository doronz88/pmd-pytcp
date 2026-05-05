# RFC 7414 — A Roadmap for TCP Specification Documents

| Field       | Value                                    |
|-------------|------------------------------------------|
| RFC number  | 7414                                     |
| Title       | A Roadmap for TCP Specification Documents |
| Category    | Informational                            |
| Date        | February 2015                            |
| Obsoletes   | RFC 4614                                 |
| Source text | [`rfc7414.txt`](rfc7414.txt)             |

This document records the relationship between the
PyTCP codebase and RFC 7414. The audit was performed by
reading the RFC text fresh; no prior memory or
rule-file content was reused.

---

## Audit summary

RFC 7414 is purely informational. It contains no
normative requirements: every section is a descriptive
roadmap of other TCP-related RFCs (the core spec, the
"strongly encouraged" enhancements, the "experimental"
extensions, the historic-but-not-recommended extensions,
etc.). The §1.1 Terminology section even omits the
RFC 2119 "MUST"/"SHOULD"/"MAY" boilerplate found in
normative RFCs — the document explicitly does not use
those keywords.

There is therefore nothing for an implementation to
"adhere to" in RFC 7414 directly. The RFC's purpose is
to catalogue other RFCs that an implementation should
consult; PyTCP's adherence to TCP as a whole is
reflected in the per-RFC adherence records under
`docs/rfc/tcp/`.

---

## Cross-reference: RFCs catalogued by RFC 7414 that PyTCP has dedicated adherence records for

| Section heading in RFC 7414         | RFC referenced  | PyTCP adherence record                                                |
|-------------------------------------|-----------------|-----------------------------------------------------------------------|
| Core functionality                  | RFC 793 / 9293  | `rfc9293__tcp/adherence.md` (consolidates RFC 793)                    |
| Core functionality                  | RFC 1122        | `rfc1122__host_requirements/adherence.md` (TCP §4.2)                  |
| Strongly encouraged enhancements    | RFC 2018        | `rfc2018__sack/adherence.md`                                          |
| Strongly encouraged enhancements    | RFC 5681        | `rfc5681__reno_cwnd/adherence.md`                                     |
| Strongly encouraged enhancements    | RFC 6298        | `rfc6298__rto_computation/adherence.md`                               |
| Strongly encouraged enhancements    | RFC 6691        | `rfc6691__tcp_options_and_mss/adherence.md`                           |
| Strongly encouraged enhancements    | RFC 7323        | `rfc7323__timestamps_wscale_paws/adherence.md`                        |
| Strongly encouraged enhancements    | RFC 5961        | `rfc5961__blind_attack_hardening/adherence.md`                        |
| Strongly encouraged enhancements    | RFC 6528        | `rfc6528__iss_hash/adherence.md`                                      |
| Strongly encouraged enhancements    | RFC 6582        | `rfc6582__newreno/adherence.md`                                       |
| Strongly encouraged enhancements    | RFC 6675        | `rfc6675__sack_loss_recovery/adherence.md`                            |
| Strongly encouraged enhancements    | RFC 3168        | `rfc3168__ecn/adherence.md`                                           |
| Strongly encouraged enhancements    | RFC 5562        | `rfc5562__ecn_syn/adherence.md`                                       |
| Strongly encouraged enhancements    | RFC 6928        | `rfc6928__initial_window_of_10/adherence.md`                          |
| Strongly encouraged enhancements    | RFC 6937        | `rfc6937__prr/adherence.md`                                           |
| Strongly encouraged enhancements    | RFC 1337        | `rfc1337__time_wait_assassination/adherence.md`                       |
| Strongly encouraged enhancements    | RFC 2883        | `rfc2883__dsack/adherence.md`                                         |
| Strongly encouraged enhancements    | RFC 6191        | `rfc6191__time_wait_4tuple_reuse/adherence.md`                        |
| Strongly encouraged enhancements    | RFC 3042        | `rfc3042__limited_transmit/adherence.md`                              |
| Experimental extensions             | RFC 7413        | `rfc7413__tfo/adherence.md`                                           |
| Experimental extensions             | RFC 8985        | `rfc8985__rack_tlp/adherence.md`                                      |
| Experimental extensions             | RFC 9438        | `rfc9438__cubic/adherence.md`                                         |
| Best Current Practice               | RFC 8961        | `rfc8961__rto_requirements/adherence.md`                              |
| Historic / not recommended          | RFC 6093 (URG)  | `rfc6093__urgent_mechanism/adherence.md`                              |

PyTCP does not implement (and has no adherence record
for) every RFC catalogued by RFC 7414. The omitted
categories include:

- TCP Authentication Option (RFC 5925, RFC 5926).
- Multipath TCP (RFC 8684).
- TCP Cookie Transactions (RFC 6013).
- TCP Quick-Start (RFC 4782, experimental).
- IPsec / TCP-MD5 (RFC 2385, obsoleted by TCP-AO).
- L4S / Accurate ECN extensions (RFC 9330+).

These are explicitly out of scope for PyTCP's current
implementation. The omissions are noted here for
completeness; absence does not violate RFC 7414, which
imposes no adherence requirement of its own.

---

## Test coverage audit

RFC 7414 contains no normative requirements, so there
is no test surface for this RFC specifically. Each
catalogued RFC's tests are audited under that RFC's
own adherence record.

---

## Overall assessment

| Aspect                                              | Status                                       |
|-----------------------------------------------------|----------------------------------------------|
| Normative requirements                              | none (informational only)                    |
| Catalogue of TCP RFCs                               | n/a (descriptive)                            |
| PyTCP adherence to catalogued RFCs                  | see per-RFC adherence records                |

RFC 7414 is a catalog/roadmap, not a specification.
PyTCP's adherence to TCP as a whole is the union of
the per-RFC adherence records listed in the cross-
reference table above. This document exists to make
that mapping explicit and to serve as the entry point
for readers who arrive at the project via the RFC 7414
roadmap.
