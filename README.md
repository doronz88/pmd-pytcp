# PyTCP
**The TCP/IP stack written in Python**
<br>

[![GitHub release](https://img.shields.io/github/v/release/ccie18643/PyTCP)](https://github.com/ccie18643/PyTCP/releases)
[![OS](https://img.shields.io/badge/os-Linux-blue)](https://kernel.org)
[![Supported Versions](https://img.shields.io/pypi/pyversions/PyTCP.svg)](https://pypi.org/project/PyTCP)
[![GitHub License](https://img.shields.io/badge/license-GPL--3.0-yellowgreen)](https://github.com/ccie18643/PyTCP/blob/master/LICENSE)
[![CI](https://github.com/ccie18643/PyTCP/actions/workflows/ci.yml/badge.svg)](https://github.com/ccie18643/PyTCP/actions/workflows/ci.yml)

[![GitHub watchers](https://img.shields.io/github/watchers/ccie18643/PyTCP.svg?style=social&label=Watch&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/watchers/)
[![GitHub forks](https://img.shields.io/github/forks/ccie18643/PyTCP.svg?style=social&label=Fork&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/network/)
[![GitHub stars](https://img.shields.io/github/stars/ccie18643/PyTCP.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/stargazers/)

<br>

**PyTCP is a TCP/IP stack written in pure Python.** It runs in user space, attached to a Linux TAP/TUN interface, and implements the protocol layers itself rather than calling the host stack.

The stack covers Ethernet II and IEEE 802.3 framing, ARP, IPv4 and IPv6 (extension headers and fragmentation), ICMPv4 and ICMPv6, IPv6 Neighbor Discovery and SLAAC, a DHCPv4 client, UDP, and RFC 9293 TCP. The TCP implementation includes the full finite state machine, congestion control (CUBIC, NewReno, PRR, HyStart++), SACK and RACK-TLP loss recovery, and RFC 5961 hardening. It exchanges traffic with other hosts on the local segment and over the Internet.

The project's goal is a pure-Python stack that is feature-equivalent to the Linux kernel network stack. RFC text is the primary authority; where a spec is silent or offers a choice, PyTCP follows Linux. Host-stack parity is the current scope; router-grade forwarding is planned.

Behaviour is covered by roughly 11,000 unit and integration tests and tracked against more than 100 per-RFC adherence audits kept in the repository under `docs/rfc/`.

The stack has zero runtime dependencies (standard library only), is organised as three packages (`net_addr`, `net_proto`, `pytcp`), and exposes a Berkeley-sockets-style API so it can be used in place of the standard socket layer.

Contributions are welcome.

---


### Features

#### Stack & sockets (engineering, non-RFC)

 - Zero-copy packet parser and assembler (buffer-protocol / memoryview based).
 - `net_addr` value-type libraries for MAC / IPv4 / IPv6 addresses, networks, hosts and masks - no Python standard-library dependency.
 - Importable as a zero-runtime-dependency library (stdlib only), split into three independent packages: `net_addr`, `net_proto`, `pytcp`.
 - Event-driven millisecond-resolution timer (heap-based deadline scheduler, no polling tick).
 - Runtime-tunable sysctl registry mirroring the Linux `/proc/sys/net/` surface (boot-time and live overrides).
 - Link control API (ip-link-style): per-interface MAC / MTU / state / counters.
 - Per-protocol packet-flow stat counters; TX-path feedback so send failures reach sockets.
 - Homegrown high-performance logger (no third-party logging dependency).
 - Berkeley-sockets-style API for TCP / UDP / RAW: `fileno()`/eventfd + `selectors` integration, blocking & non-blocking modes, errno-mapped `OSError`, `getaddrinfo` family, common `setsockopt` options, `IP_RECVERR`/`MSG_ERRQUEUE` error queue.
 - Native `unittest` suite (~11,000 unit + integration tests); per-RFC adherence audits in `docs/rfc/`.

#### Ethernet

 - Ethernet II framing with EtherType demux, broadcast and multicast mapping (RFC 894)
 - Inbound IEEE 802.3 / LLC + SNAP support (RFC 1042)

#### ARP

 - ARP resolution with a neighbor cache, replies and queries (RFC 826, RFC 1122)
 - IPv4 Address Conflict Detection — probe, announce, defend (RFC 5227)
 - IANA-correct ARP codepoint handling (RFC 5494)

#### IPv4

 - IPv4 with options parsing, inbound reassembly and outbound fragmentation (RFC 791, RFC 815)
 - Multiple host addresses; private, special-purpose and broadcast address handling (RFC 1918, RFC 6890, RFC 919, RFC 922)
 - ECN, DSCP and Router Alert support (RFC 3168, RFC 2474, RFC 6398)
 - IPv4 link-local autoconfiguration (RFC 3927)
 - Host-side IP multicasting (RFC 1112)

#### ICMPv4

 - Echo, Destination Unreachable, Time Exceeded and Parameter Problem, with RFC-correct generation gating and rate-limiting (RFC 792, RFC 1122)
 - Obsolete message types correctly omitted (RFC 6633, RFC 6918)

#### IPv6

 - IPv6 with the full extension-header chain and TLV options (RFC 8200)
 - Inbound reassembly and outbound fragmentation, with fragmentation hardening (RFC 5722, RFC 6946, RFC 7739)
 - Unique-local and special-purpose addressing (RFC 4193, RFC 8190)
 - Flow-label generation (RFC 6437)
 - Default source-address selection (RFC 6724); Path MTU Discovery (RFC 8201); node requirements (RFC 8504)

#### ICMPv6 / Neighbor Discovery

 - Full ICMPv6 message set including Packet Too Big (RFC 4443)
 - Stateless Address Autoconfiguration: link-local, DAD, RA prefixes and lifetimes (RFC 4862)
 - Stable opaque and temporary (privacy) addresses (RFC 7217, RFC 8981)
 - Optimistic DAD, Enhanced DAD and Gratuitous NA (RFC 4429, RFC 7527, RFC 9131)
 - Neighbor Discovery with a NUD cache and Router Solicitation backoff (RFC 4861, RFC 7559)
 - MLDv2 listener (RFC 3810)

#### UDP

 - UDP with full host-requirements conformance (RFC 768, RFC 1122)
 - Zero-checksum UDP over IPv6 (RFC 6935)
 - Ephemeral-port randomisation (RFC 6056)
 - Echo / Discard / Daytime example services

#### TCP

 - Complete TCP: full finite state machine and reliable bulk transfer (RFC 9293, RFC 1122)
 - Modern congestion control — CUBIC, NewReno, PRR, HyStart++, ABE, IW10 (RFC 9438, RFC 6582, RFC 6937, RFC 9406, RFC 8511, RFC 6928)
 - Advanced loss recovery — SACK, D-SACK, RACK-TLP, F-RTO, limited transmit (RFC 2018, RFC 2883, RFC 8985, RFC 5682, RFC 3042)
 - RFC-correct RTO with Karn's algorithm and backoff (RFC 6298, RFC 8961)
 - Window Scale, Timestamps, PAWS, MSS and TCP Fast Open (RFC 7323, RFC 6691, RFC 7413)
 - ECN and Accurate ECN (RFC 3168, RFC 9768)
 - Blind-attack and ICMP-attack hardening, randomised ISS and ports, robust TIME-WAIT (RFC 5961, RFC 5927, RFC 6528, RFC 1337, RFC 6191)
 - Keep-alive, zero-window probing, silly-window-syndrome avoidance, Nagle

#### DHCPv4 client

 - Full DHCPv4 client: lease acquisition, RENEW / REBIND / DECLINE (RFC 2131, RFC 1542)
 - Detecting Network Attachment and client-ID handling (RFC 4436, RFC 6842, RFC 4361)

---


### Principle of operation and the test setup

The PyTCP stack depends on a Linux TAP/TUN interface. The TAP interface is a virtual interface that,
on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux
bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by
programmatically sending and receiving packets to/from it.

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network
setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the
PyTCP stack to your local network at the same time.

```console
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux TCP/IP stack]
                                            |
                                            |--(tap7) <---> [PyTCP TCP/IP stack]
```

After the example program (either client or service) starts the stack, it can communicate with it
via simplified BSD Sockets like API interface. There is also the possibility of sending packets
directly by calling one of the internal ```_phtx_*()``` methods on the ```PacketHandler```.

---


### Cloning PyTCP from the GitHub repository

In most cases, PyTCP should be cloned directly from the [GitHub repository](https://github.com/ccie18643/PyTCP),
as this type of installation provides full development and testing environment.

```shell
git clone https://github.com/ccie18643/PyTCP
```

After cloning, we can run one of the included examples:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the ```sudo make bridge``` command to create the 'br0' bridge if needed.
 - Run the ```sudo make tap7``` command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the ```make venv``` command to create the virtual environment for development and testing.
 - Run ```. venv/bin/activate``` command to activate the virtual environment.
 - Execute any example, e.g., ```python -m examples.stack``` (see the ```examples/``` directory; pass ```--help``` for options).
 - Hit Ctrl-C to stop it.

Stack parameters are configured per run via the ```stack.init(...)``` keyword arguments and the runtime sysctl registry (see ```pytcp/stack/```), not a static config file.

---


### Installing PyTCP from the PyPi repository

PyTCP can also be installed as a regular module from the [PyPi repository](https://pypi.org/project/PyTCP/).

```console
python -m pip install PyTCP
```

After installation, please ensure the TAP interface is operational and added to the bridge.

```console
sudo ip tuntap add name tap7 mode tap
sudo ip link set dev tap7 up
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up
sudo ip link set dev tap7 master br0
```

PyTCP is consumed as a library through the ```pytcp.stack``` lifecycle API
(```stack.init(...)``` → ```stack.start()``` → ```stack.stop()```) and the
```pytcp.socket``` Berkeley-sockets-style API. The subsystems run in their own
threads; after ```start()``` control returns to your code.

For a complete, runnable reference — opening the TAP/TUN file descriptor,
calling ```stack.init(...)```, and driving the stack — see
[```examples/stack.py```](examples/stack.py) and the other programs in the
[```examples/```](examples/) directory.

---


### Examples

All output below is captured from a live stack on a Linux `tap7`
interface bridged to a LAN — PyTCP's own log plus a `tshark` wire
capture. RFC back-off delays (RFC 5227 ACD, RFC 4862 DAD) are
visible in the timestamps.

Every wire block uses the same columns:

```text
time(s)   PROTO   src → dst   summary
```

`—` in the `src → dst` column marks frames with no IPv4/IPv6 layer
(ARP), or IPv6 ND/MLD frames whose source/destination are
link-local/multicast and are named in the summary instead.

#### Stack startup — IPv6 SLAAC + DAD, MLDv2, IPv4 ACD

On start the stack autoconfigures itself: it derives an IPv6
link-local address and runs Duplicate Address Detection, reports its
multicast groups via MLDv2, solicits routers, builds a global
address from the Router Advertisement and DADs that too, then runs
RFC 5227 conflict detection for its IPv4 address.

Stack log:

```text
0000.05 | STACK | ICMPv6 ND DAD - Starting process for fe80::d559:3d07:bd31:f1d1
0001.44 | STACK | ICMPv6 ND DAD - No duplicate address detected for fe80::d559:3d07:bd31:f1d1
0001.45 | STACK | Successfully claimed IPv6 address fe80::d559:3d07:bd31:f1d1/64
0001.45 | STACK | Sent out ICMPv6 ND Router Solicitation
0001.45 | STACK | ICMPv6 ND DAD - Starting process for 2603:808c:2800:4301:d9fd:d546:1fd:4484
0003.08 | STACK | Successfully claimed IPv6 address 2603:808c:2800:4301:d9fd:d546:1fd:4484/64
0007.13 | STACK | Sent out ARP Announcement for 192.168.1.77
0009.13 | STACK | Successfully claimed IPv4 address 192.168.1.77
```

Wire capture (`tshark -i tap7`):

```text
0.39   ICMPv6  —   Neighbor Solicitation for fe80::d559:3d07:bd31:f1d1   (link-local DAD)
0.62   ARP     —   Who has 192.168.1.77?   (ARP Probe)
1.39   ICMPv6  —   Multicast Listener Report Message v2
1.39   ICMPv6  —   Router Solicitation from 02:00:00:77:77:77
2.03   ICMPv6  —   Neighbor Solicitation for 2603:808c:2800:4301:d9fd:d546:1fd:4484   (SLAAC GUA DAD)
6.39   ICMPv6  —   Neighbor Advertisement fe80::d559:3d07:bd31:f1d1 (sol) is at 02:00:00:77:77:77
7.08   ARP     —   ARP Announcement for 192.168.1.77
9.08   ARP     —   ARP Announcement for 192.168.1.77
```

#### ARP Probe / Announcement (RFC 5227 Address Conflict Detection)

The stack defends each configured IPv4 address: it sends three ARP
**Probes** (sender `0.0.0.0`), and if no host objects, claims the
address with two ARP **Announcements** (sender = target).

Wire capture (`tshark -i tap7 -f arp`):

```text
0.00   ARP   —   ARP Probe — Who has 192.168.1.77?   (sender 0.0.0.0)
1.47   ARP   —   ARP Probe — Who has 192.168.1.77?   (sender 0.0.0.0)
3.37   ARP   —   ARP Probe — Who has 192.168.1.77?   (sender 0.0.0.0)
6.63   ARP   —   ARP Announcement for 192.168.1.77   (sender = target)
8.63   ARP   —   ARP Announcement for 192.168.1.77   (sender = target)
```

Probe vs. Announcement, decoded (`tshark -V`):

```text
ARP Probe         Opcode: request   Sender IP: 0.0.0.0        Target IP: 192.168.1.77
ARP Announcement  Opcode: request   Sender IP: 192.168.1.77   Target IP: 192.168.1.77
```

#### ARP resolution and ICMP Echo

A host on the segment pings the stack. Having learned the stack's MAC
from its ARP Announcement, the host sends the Echo Request directly;
the stack then resolves the *host's* MAC via ARP before replying:

Wire capture (`tshark -i tap7`, rebased to the first Echo Request):

```text
0.000  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626c, seq=1, ttl=64
0.001  ARP   —                             Who has 192.168.1.10? Tell 192.168.1.77
0.001  ARP   —                             192.168.1.10 is at a2:4b:a1:00:92:56
0.001  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626c, seq=1, ttl=64
1.001  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626c, seq=2, ttl=64
1.002  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626c, seq=2, ttl=64
2.046  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626c, seq=3, ttl=64
2.047  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626c, seq=3, ttl=64
```

From the pinging host:
`3 packets transmitted, 3 received, 0% packet loss; rtt min/avg/max/mdev = 0.807/1.017/1.405/0.274 ms`.

#### Monkeys over TCP

PyTCP ships a matching TCP echo client and service
(`examples/client__tcp_echo.py` / `examples/service__tcp_echo.py`).
As a quick end-to-end check the client streams two ASCII-art
"monkeys" as the payload and the service echoes them back over the
TCP connection — the original "two monkeys delivered via TCP" demo,
now reproducible as plain text. Connecting to the service returns
its banner, then the monkeys make the full round trip through the
stack's TCP path intact:

```text
$ nc 192.168.1.77 7
***CLIENT OPEN / SERVICE OPEN***
                                       ______AAAA_______________AAAA______
                                             VVVV               VVVV
                                             (__)               (__)
                                              \ \               / /
               .="=.                           \ \              / /
             _/.-.-.\_    _                     > \   .="=.   / <
            ( ( o o ) )   ))                     > \ /     \ / <
             |/  "  \|   //                       > \\_o_o_// <
              \'---'/   //                         > ( (_) ) <
              /`---`\  ((                           >|     |<
             / /_,_\ \  \\                         / |\___/| \
             \_\_'__/ \  ))                        / \_____/ \
             /`  /`~\  |//                         /         \
            /   /    \  /                           /   o   \
        ,--`,--'\/\    /                             ) ___ (
         '-- "--'  '--'                             / /   \ \
                                                   ( /     \ )
                                                   ><       ><
                                                  ///\     /\\\
                                                  '''       '''
```

On the wire (`tshark -i tap7`) — the full RFC 9293 exchange:

```text
44.934  TCP  192.168.1.10 → 192.168.1.77   [SYN]       MSS=1460 SACK_PERM WS=1024 TSopt
44.937  ARP  —                             Who has 192.168.1.10? Tell 192.168.1.77
44.937  ARP  —                             192.168.1.10 is at a2:4b:a1:00:92:56
44.937  TCP  192.168.1.77 → 192.168.1.10   [SYN,ACK]   MSS=1460 SACK_PERM WS=128 TSopt
44.937  TCP  192.168.1.10 → 192.168.1.77   [ACK]
44.937  TCP  192.168.1.10 → 192.168.1.77   [PSH,ACK]   len 11     "malpi\nquit\n"  (request)
44.941  TCP  192.168.1.77 → 192.168.1.10   [ACK]       len 1448   monkeys, segment 1 (full MSS)
44.941  TCP  192.168.1.10 → 192.168.1.77   [ACK]       ack 1449
44.943  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]   len 146    monkeys, segment 2
44.943  TCP  192.168.1.10 → 192.168.1.77   [ACK]       ack 1595
49.948  TCP  192.168.1.10 → 192.168.1.77   [FIN,ACK]              peer closes (nc idle timeout)
49.951  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]   len 37     service "CLOSING" banner
49.951  TCP  192.168.1.10 → 192.168.1.77   [RST]                  peer already gone
```

The stack negotiates MSS / SACK-permitted / window-scale /
timestamps on the handshake, resolves the peer's MAC via ARP
mid-handshake, segments the echoed monkeys to the MSS, and tracks
the peer's cumulative ACKs — a complete TCP connection driven
entirely by pure-Python code.

#### Monkeys over UDP — IPv4 fragmentation

The same ASCII monkeys, echoed over the UDP service. The reply
(~1.5 KB) exceeds the 1500-byte link MTU, so the stack
IPv4-fragments it — the classic "IP fragmentation" demo, captured
for real.

```text
$ printf 'malpi\n' | nc -u 192.168.1.77 7
                                       ______AAAA_______________AAAA______
                                             VVVV               VVVV
                                             (__)               (__)
                                              \ \               / /
               .="=.                           \ \              / /
             _/.-.-.\_    _                     > \   .="=.   / <
            ( ( o o ) )   ))                     > \ /     \ / <
             |/  "  \|   //                       > \\_o_o_// <
              \'---'/   //                         > ( (_) ) <
              /`---`\  ((                           >|     |<
             / /_,_\ \  \\                         / |\___/| \
             \_\_'__/ \  ))                        / \_____/ \
             /`  /`~\  |//                         /         \
            /   /    \  /                           /   o   \
        ,--`,--'\/\    /                             ) ___ (
         '-- "--'  '--'                             / /   \ \
                                                   ( /     \ )
                                                   ><       ><
                                                  ///\     /\\\
                                                  '''       '''
```

On the wire (`tshark -i tap7`; the summary carries the IPv4
fragmentation fields — IP-id, MF, frag-offset):

```text
38.987  UDP  192.168.1.10 → 192.168.1.77   id=0x2361 MF=0 off=0     UDP "malpi\n" request (14 B)
38.988  ARP  —                             Who has 192.168.1.10? Tell 192.168.1.77
38.988  ARP  —                             192.168.1.10 is at a2:4b:a1:00:92:56
38.988  UDP  192.168.1.77 → 192.168.1.10   id=0x0001 MF=1 off=0     fragment 1 — UDP header + first 1480 B
38.988  UDP  192.168.1.77 → 192.168.1.10   id=0x0001 MF=0 off=185   fragment 2 — final 89 B (offset 185×8 = 1480)
```

The oversized UDP datagram is split into two IPv4 fragments sharing
one IP id; the peer's kernel reassembles them and `nc -u` prints
the monkeys. The first datagram is held in the per-neighbour queue
until the ARP reply resolves the peer's MAC (RFC 1122 §2.3.2.2),
then both fragments are flushed in order — a fragmented datagram
delivered to a cold neighbour, lost by neither the DF bit nor a
single-slot queue.
