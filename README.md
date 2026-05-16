# PyTCP
### The TCP/IP stack written in Python
<br>

[![GitHub release](http://img.shields.io/github/v/release/ccie18643/PyTCP)](http://github.com/ccie18643/PyTCP/releases)
[![OS](http://img.shields.io/badge/os-Linux-blue)](http://kernel.org)
[![Supported Versions](http://img.shields.io/pypi/pyversions/PyTCP.svg)](http://pypi.org/project/PyTCP)
[![GitHub License](http://img.shields.io/badge/license-GPL--3.0-yellowgreen)](http://pytcp.io/LICENSE)
[![CI](http://github.com/ccie18643/PyTCP/actions/workflows/ci.yml/badge.svg)](http://github.com/ccie18643/PyTCP/actions/workflows/ci.yml)

[![GitHub watchers](http://img.shields.io/github/watchers/ccie18643/PyTCP.svg?style=social&label=Watch&maxAge=2592000)](http://GitHub.com/ccie18643/PyTCP/watchers/)
[![GitHub forks](http://img.shields.io/github/forks/ccie18643/PyTCP.svg?style=social&label=Fork&maxAge=2592000)](http://GitHub.com/ccie18643/PyTCP/network/)
[![GitHub stars](http://img.shields.io/github/stars/ccie18643/PyTCP.svg?style=social&label=Star&maxAge=2592000)](http://GitHub.com/ccie18643/PyTCP/stargazers/)

<br>

**PyTCP is a TCP/IP stack written in pure Python.** It runs in user space, attached to a Linux TAP/TUN interface, and implements the protocol layers itself rather than calling the host stack.

The stack covers Ethernet II and IEEE 802.3 framing, ARP, IPv4 and IPv6 (extension headers and fragmentation), ICMPv4 and ICMPv6, IPv6 Neighbor Discovery and SLAAC, a DHCPv4 client, UDP, and RFC 9293 TCP. The TCP implementation includes the full finite state machine, congestion control (CUBIC, NewReno, PRR, HyStart++), SACK and RACK-TLP loss recovery, and RFC 5961 hardening. It exchanges traffic with other hosts on the local segment and over the Internet.

The project's goal is a pure-Python stack that is feature-equivalent to the Linux kernel network stack. RFC text is the primary authority; where a spec is silent or offers a choice, PyTCP follows Linux. Host-stack parity is the current scope; router-grade forwarding is planned.

Behaviour is covered by roughly 11,000 unit and integration tests and tracked against more than 100 per-RFC adherence audits kept in the repository under `docs/rfc/`.

The stack has zero runtime dependencies (standard library only), is organised as three packages (`net_addr`, `net_proto`, `pytcp`), and exposes a Berkeley-sockets-style API so it can be used in place of the standard socket layer.

Contributions are welcome.

---


### Features

Highlights per protocol, with the governing RFC(s) in parentheses.
Conformance is tracked through per-RFC adherence audits under
`docs/rfc/`; some areas are still in progress.

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

The PyTCP stack depends on the Linux TAP interface. The TAP interface is a virtual interface that,
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
directly by calling one of the ```_*_phtx()``` methods from ```PacketHandler``` class.

---


### Clonning PyTCP from the GitHub repository

In most cases, PyTCP should be cloned directly from the [GitHub repository](http://github.com/ccie18643/PyTCP),
as this type of installation provides full development and testing environment.

```shell
git clone http://github.com/ccie18643/PyTCP
```

After cloning, we can run one of the included examples:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the ```sudo make bridge``` command to create the 'br0' bridge if needed.
 - Run the ```sudo make tap``` command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the ```make``` command to create the proper virtual environment for development and testing.
 - Run ```. venv/bin/activate``` command to activate the virtual environment.
 - Execute any example, e.g., ```example/run_stack.py```.
 - Hit Ctrl-C to stop it.

To fine-tune various stack operational parameters, please edit the ```pytcp/config.py``` file accordingly.

---


### Installing PyTCP from the PyPi repository

PyTCP can also be installed as a regular module from the [PyPi repository](http://pypi.org/project/PyTCP/).

```console
python -m pip install PyTCP
```

After installation, please ensure the TAP interface is operational and added to the bridge.

```console
sudo ip tuntap add name tap7 mode tap
sudo ip link set dev tap7 up
sudo brctl addbr br0
sudo brctl addif br0 tap7
```

The PyTCP stack can be imported and started using the following code. It starts the stack
subsystems and autoconfigures both the IPv4 and IPv6 protocol addresses using DHCPv4 and IPv6 SLAAC,
respectively.

```python
from pytcp import TcpIpStack
stack = TcpIpStack(interface="tap7")
stack.start()
```

The stack subsystems run in their own threads. After starting, the stack gives control back to
the user code and can be stopped using the following call.

```python
stack.stop()
```

---


### Examples

#### Several ping packets and two monkeys were delivered via TCP over the IPv6 protocol.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_00.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_08.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_09.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_10.png)

<br>

#### IPv6 Neighbor Discovery / Duplicate Address Detection / Address Auto Configuration.
 - Stack tries to auto-configure its link-local address. It generates it as a EUI64 address. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for its generated address.
 - Stack doesn't receive any Neighbor Advertisement for the address it generated, so it assigns it to its interface.
 - Stack tries to assign a preconfigured static address. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for the static address.
 - Another host with the same address already assigned replies with a Neighbor Advertisement message. This tells the stack that another host has already assigned the address it is trying to assign, so the stack cannot use it.
 - Stack sends a Router Solicitation message to check if there are any global prefixes it should use.
 - Router responds with Router Advertisement containing additional prefix.
 - Stack tries to assign an address generated based on the received prefix and EUI64 host portion. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for the static address.
 - Stack doesn't receive any Neighbor Advertisement for the address it generated, so it assigns it to its interface.
 - After all the addresses are assigned, stack sends out one more Multicast Listener report listing all the multicast addresses it wants to listen to.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_05.png)

<br>

#### TCP Fast Retransmit in action after lost TX packet.
 - Outgoing packet is 'lost' due to simulated packet loss mechanism.
 - Peer notices the inconsistency in packet SEQ numbers and sends out a 'fast retransmit request'.
 - Stack receives the request and retransmits the lost packet.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_04.png)

<br>

#### Out-of-order queue in action during RX packet loss event
 - Incoming packet is 'lost' due to simulated packet loss mechanism.
 - Stack notices an inconsistency in the inbound packet's SEQ number and sends a 'fast retransmit' request.
 - Before the peer receives the request, it sends multiple packets with higher SEQ than the stack expects. Stack queues all those packets.
 - Peer retransmits the lost packet.
 - Stack receives the lost packet, pulls all the packets stored in the out-of-order queue, and processes them.
 - Stacks sends out ACK packet to acknowledge the latest packets pulled from the queue.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_06.png)

<br>

#### TCP Finite State Machine - stack is running TCP Echo service.
 - Peer opens the connection.
 - Peer sends data.
 - Stack echoes the data back.
 - Peer closes the connection.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_04.png)

<br>

#### TCP Finite State Machine - stack is running TCP Echo client.
 - Stack opens the connection.
 - Stack sends data.
 - Peer echoes the data back.
 - Stack closes the connection.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_04.png)

<br>

#### Pre-parse packet sanity checks in action.
 - The first screenshot shows the stack with the sanity check turned off. A malformed ICMPv6 packet can crash it.
 - The second screenshot shows the stack with the sanity check turned on. A malformed ICMPv6 packet is discarded before being passed to the ICMPv6 protocol parser.
 - The third screenshot shows the malformed packet. The number of MA records field has been set to 777 even though the packet contains only one record.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_03.png)

<br>

#### ARP Probe/Announcement mechanism.
 - Stack uses ARP Probes to find any possible conflicts for every IP address configured.
 - One of the IP addresses (192.168.9.102) is already taken, so the stack gets notified about it and skips it.
 - The rest of the IP addresses are free, so stack claims them by sending ARP Announcement for each of them.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_04.png)

<br>

#### ARP resolution and handling ping packets.
 - Host 192.168.9.20 tries to ping the stack. To be able to do it, it first sends an ARP Request packet to find out the stack's MAC address.
 - Stack responds by sending an ARP Reply packet (stack doesn't need to send out its request since it already made a note of the host's MAC from the host's request).
 - Host sends ping packets, and stack responds to them.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/arp_ping_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/arp_ping_02.png)

<br>

#### IP fragmentation.
 - Host sends 4Kb UDP datagram using three fragmented IP packets (three fragments).
 - Stack receives packets and assembles them into a single piece, then passes it (via UDP protocol handler and UDP Socket) to UDO Echo service.
 - UDP Echo service picks data up and puts it back into UDP Socket.
 - UDP datagram is passed to the IP protocol handler, which creates an IP packet, and after checking that it exceeds the link, MTU fragments it into three separate IP packets.
 - IP packets are encapsulated in Ethernet frames and put on a TX ring.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_03.png)

