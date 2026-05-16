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

PyTCP is a fully functional TCP/IP stack written in Python. It supports TCP stream-based transport with reliable packet delivery based on a sliding window mechanism and basic congestion control. It also supports IPv6/ICMPv6 protocols with SLAAC address configuration. It operates as a user space program attached to the Linux TAP interface. It has implemented simple routing and can send and receive traffic over a local network and the Internet. 

Version 2.7, unlike its predecessors, contains the PyTCP stack code in the form of a library so that it can be easily imported and used by external code. This should make the user experience smoother and eventually provide the full ability to replace the standard Linux stack calls (e.g., socket library) with the PyTCP calls in any 3rd party application.

This project initially started as a purely educational effort aimed at improving my Python skills and refreshing my network knowledge as part of the preparation for the Network Engineer role at Facebook. Since then, it has become more like a 'pet project' which
I dedicate some of my time on a somewhat irregular basis. However, a couple of updates are usually added to it every month or two.

I welcome any contributions and help from anyone interested in network programming. Any input is appreciated. Also, remember that some stack features may be implemented only partially (as needed for stack operation). They may be implemented in a sub-optimal fashion or not 100% RFC-compliant way (due to lack of time), or they may contain bug(s) that
I still need to fix.

Please feel free to check my two other related projects:
 - [RusTCP](http://github.com/ccie18643/RusTCP) - Attempt to rewrite some of PyTCP functionality in Rust and use it to create IPv6/SRv6 lab router.
 - [SeaTCP](http://github.com/ccie18643/SeaTCP) - Attempt to create low latency stack using C and Assembly languages.

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


### Features

PyTCP tracks RFC conformance through per-RFC adherence audits under
`docs/rfc/`. The list below summarises those audits per protocol.
**Full** = substantially implemented and conformant for a host stack;
**Partial** = implemented with documented gaps; items still on the
roadmap (host-stack gaps, or Phase-2 router-grade scope) are noted at
the end of each protocol.

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

 - **RFC 894** IP over Ethernet (Ethernet II) - *Full* - framing, EtherType demux, ARP, broadcast/multicast mapping.
 - **RFC 1042** IP over IEEE 802 (LLC + SNAP) - *Partial* - inbound 802.3/LLC/SNAP demux; outbound is Ethernet II only.

#### ARP

 - **RFC 826** Address Resolution Protocol - *Partial* - resolution + cache faithful; drop-on-miss packet not saved.
 - **RFC 1122** Host Requirements (ARP) - *Partial* - core met; flood-prevention / packet-save not implemented.
 - **RFC 5227** IPv4 Address Conflict Detection - *Full* - ARP Probe / Announcement / defence.
 - **RFC 5494** ARP IANA considerations - *Full* - reserved/experimental codepoints rejected.
 - *Roadmap:* RFC 1027 Proxy ARP (Phase-2 router).

#### IPv4

 - **RFC 791** Internet Protocol v4 - *Partial* - host wire format / options met; forwarding (TTL-decrement, source-route) is Phase-2.
 - **RFC 815** Datagram reassembly - *Full* - sorted-offset reassembly, overlap rejection, lazy reaper.
 - **RFC 3168** ECN - *Full*. **RFC 3927** IPv4 link-local autoconfiguration - *Full*. **RFC 6814** deprecated IPv4 options (never originated) - *Full*.
 - **RFC 919 / 922** broadcasting - *Partial* (host-side). **RFC 1112** IP multicasting - *Partial* (send/receive; no IGMP). **RFC 1122** Host Requirements (IPv4) - *Partial*.
 - **RFC 1918** private addresses, **RFC 2474** DSCP, **RFC 6398** Router Alert, **RFC 6864** IPv4 ID field, **RFC 6890** special-purpose registries, **RFC 7126** IP-option filtering - *Partial* (host-side; QoS/forwarding scope deferred).
 - Multiple stack IPv4 addresses supported; outbound fragmentation.
 - *Roadmap:* RFC 1191 IPv4 Path MTU Discovery (not implemented); RFC 1812 router requirements (Phase-2).

#### ICMPv4

 - **RFC 792** ICMPv4 - *Partial* - echo / unreachable / time-exceeded / parameter-problem with RFC 1122 generation gates + rate-limiting; Redirect (type 5) not implemented.
 - **RFC 1122** Host Requirements (ICMP) - *Partial* - inbound Redirect processing not implemented.
 - **RFC 6633** deprecate Source Quench - *Full*. **RFC 6918** deprecate obsolete ICMP types - *Full* (compliant by structural absence).
 - *Roadmap:* RFC 1812 router ICMP, RFC 4884 extended multi-part ICMP.

#### IPv6

 - **RFC 8200** IPv6 + extension headers - *Full* - all §4 extension headers, TLV options, chain ordering.
 - **RFC 4193** unique local addresses, **RFC 8190** special-purpose registries - *Full*.
 - **RFC 5095** RH0 deprecation, **RFC 5722** overlapping-fragment handling, **RFC 6946** atomic fragments, **RFC 7739** fragment-ID randomisation - *Full*.
 - **RFC 6437** flow label (keyed-hash, sysctl-toggle) - *Full*.
 - **RFC 6724** default address selection - *Partial* - source-selection rules shipped; destination-address selection deferred.
 - **RFC 8201** Path MTU Discovery for IPv6 - *Partial* - PTB demuxed & cached; no MTU aging / probe walk-back.
 - **RFC 8504** IPv6 node requirements - *Partial* - core host requirements met.
 - Inbound defragmentation + outbound fragmentation; Solicited-Node multicast & IPv6 multicast-MAC auto-assignment.

#### ICMPv6 / Neighbor Discovery

 - **RFC 4443** ICMPv6 - *Full* - echo + destination-unreachable / time-exceeded / parameter-problem / packet-too-big.
 - **RFC 4862** Stateless Address Autoconfiguration - *Full* - link-local, DAD, RA prefix, 2-hour rule, lifetime sweep.
 - **RFC 7217** stable opaque IIDs (default-on), **RFC 4429** Optimistic DAD, **RFC 7527** Enhanced DAD, **RFC 9131** Gratuitous NA, **RFC 6980** ND-no-fragmentation - *Full*.
 - **RFC 7559** RS retransmission backoff, **RFC 4311** host-to-router load sharing - *Full*.
 - **RFC 4861** Neighbor Discovery - *Partial* - host NS/NA/RS/RA + NUD cache + inbound Redirect processing; Redirect generation (router) is Phase-2.
 - **RFC 3810** MLDv2 - *Partial* - listener role (responds to queries with a scheduled Report); querier role is Phase-2.
 - **RFC 8981** temporary (privacy) addresses - *Partial* - random IID + per-prefix claim; regeneration cadence deferred.
 - *Roadmap:* RFC 4191 default-router preferences / more-specific routes, RFC 8028 multihomed first-hop selection, RFC 8106 RA DNS options. (RFC 4941 superseded by 7217/8981; RFC 5175 RA-flags option has no consumer.)

#### UDP

 - **RFC 768** UDP - *Full*. **RFC 1122** Host Requirements (UDP) - *Full*.
 - **RFC 6935** UDP zero-checksum over IPv6 - *Full*.
 - **RFC 6056** transport-port randomisation - *Partial* - Algorithms 1 & 2.
 - **RFC 8085** UDP usage guidelines - *Partial* - UDP-path PLPMTUD not implemented.
 - UDP Echo / Discard / Daytime example services.

#### TCP

 - **RFC 9293** TCP - *Full* - complete wire format + Finite State Machine; bulk data transfer.
 - **RFC 1122** Host Requirements (TCP), **RFC 6093** urgent mechanism - *Full*.
 - *Congestion control:* **RFC 5681** Reno, **RFC 6582** NewReno, **RFC 9438** CUBIC, **RFC 9406** HyStart++, **RFC 8511** ABE, **RFC 6928** IW10 - *Full*.
 - *Loss recovery:* **RFC 2018** SACK, **RFC 2883** D-SACK, **RFC 3042** Limited Transmit, **RFC 6675** SACK-based recovery, **RFC 6937** PRR, **RFC 8985** RACK-TLP, **RFC 5682** F-RTO - *Full*.
 - *Timers:* **RFC 6298** RTO computation (Karn + backoff), **RFC 8961** time-based loss-detection requirements - *Full*.
 - *Options:* **RFC 7323** Timestamps / Window Scale / PAWS, **RFC 6691** MSS, **RFC 7413** TCP Fast Open - *Full*.
 - *ECN:* **RFC 3168** ECN, **RFC 9768** AccECN - *Full*; **RFC 8311** ECN relaxation - *Partial*.
 - *Hardening:* **RFC 5961** blind in-window attacks, **RFC 5927** ICMP-against-TCP, **RFC 6056** port randomisation, **RFC 6528** hash-based ISS, **RFC 1337** / **RFC 6191** TIME-WAIT - *Full*.
 - Keep-alive, zero-window probing / persist timer, SWS avoidance, Nagle.
 - *Partial:* RFC 3522 Eifel detection, RFC 4821 PLPMTUD, RFC 8899 DPLPMTUD.
 - *Roadmap:* RFC 4015 Eifel response, RFC 5562 ECN-setup SYN, RFC 5827 Early Retransmit, RFC 5925/5926 TCP-AO, RFC 7661 CWV, RFC 8257 DCTCP, RFC 8684 MPTCP, RFC 9331 L4S.

#### DHCPv4 (client)

 - **RFC 2131** DHCP - *Full* - client FSM, lease, RENEW / REBIND / DECLINE (no DHCPINFORM).
 - **RFC 1542** BOOTP clarifications - *Full*. **RFC 4436** DNAv4 detect-network-attachment - *Full*. **RFC 6842** client-ID echo - *Full*.
 - **RFC 951** BOOTP, **RFC 2132** DHCP options, **RFC 4361** node-specific client-ID/DUID - *Partial*.
 - *Roadmap:* RFC 3203 FORCERENEW, RFC 3442 classless static route (opt 121), RFC 4702 client FQDN (opt 81), RFC 8910 captive-portal (opt 114).

#### General roadmap (non-RFC / cross-cutting)

 - [ ] Stack debugging console (`show icmpv6 nd cache`, `show ipv6 route`, interactive ping / echo clients).
 - [ ] QUIC protocol - research and lab environment.
 - [ ] IPv4 defragmentation - store whole packets in the flow DB instead of header/data copies.
 - [ ] TCP CLOSE - set FIN on the last data segment instead of a separate segment.
 - [ ] IPv6 RA PI option - full A/L flag handling and non-/64 advertised prefixes.
 - [ ] Refactor integrity/sanity error messages for more consistent detail.
 - [ ] Phase-2 router grade: IPv4/IPv6 forwarding plane, route tables, router role.

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

