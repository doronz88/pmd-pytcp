################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the peer-side TCP segment builder used by the
TCP session integration tests to synthesize ingress frames.

pytcp/tests/lib/tcp_segment_factory.py

ver 3.0.4
"""

from collections.abc import Iterable

from net_addr import Ip4Address, Ip6Address, MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.tcp.options.tcp__option__mss import TcpOptionMss
from net_proto.protocols.tcp.options.tcp__option__nop import TcpOptionNop
from net_proto.protocols.tcp.options.tcp__option__sackperm import TcpOptionSackperm
from net_proto.protocols.tcp.options.tcp__option__wscale import TcpOptionWscale
from net_proto.protocols.tcp.options.tcp__options import TcpOption, TcpOptions
from net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

TCP_FLAGS__VALID: frozenset[str] = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "NS"})


def _build_tcp_assembler(
    *,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: Iterable[str],
    win: int,
    mss: int | None,
    wscale: int | None,
    sackperm: bool,
    payload: Buffer,
    paws_ts: object,
    sack_block: object,
) -> TcpAssembler:
    """
    Build the inner 'TcpAssembler' carrying the requested header
    fields, options, and payload. Validates the 'flags' set against
    the supported names and raises 'NotImplementedError' for the
    PAWS / SACK option slots reserved for future tests.
    """

    if paws_ts is not None:
        raise NotImplementedError(
            "PAWS timestamps are not supported by 'tcp_segment_factory' yet; "
            "the TCP assembler does not emit the option."
        )

    if sack_block is not None:
        raise NotImplementedError(
            "SACK blocks are not supported by 'tcp_segment_factory' yet; "
            "TCP session SACK behaviour is out of scope per the integration "
            "test plan."
        )

    flag_set = frozenset(flags)
    unknown = flag_set - TCP_FLAGS__VALID
    assert not unknown, f"Unknown TCP flag name(s) {sorted(unknown)!r}; supported: {sorted(TCP_FLAGS__VALID)!r}"

    options = _build_options(mss=mss, wscale=wscale, sackperm=sackperm)

    return TcpAssembler(
        tcp__sport=sport,
        tcp__dport=dport,
        tcp__seq=seq,
        tcp__ack=ack,
        tcp__flag_syn="SYN" in flag_set,
        tcp__flag_ack="ACK" in flag_set,
        tcp__flag_fin="FIN" in flag_set,
        tcp__flag_rst="RST" in flag_set,
        tcp__flag_psh="PSH" in flag_set,
        tcp__flag_urg="URG" in flag_set,
        tcp__flag_ece="ECE" in flag_set,
        tcp__flag_cwr="CWR" in flag_set,
        tcp__flag_ns="NS" in flag_set,
        tcp__win=win,
        tcp__options=options,
        tcp__payload=payload,
    )


def _build_options(*, mss: int | None, wscale: int | None, sackperm: bool) -> TcpOptions:
    """
    Build a 'TcpOptions' container holding the requested MSS,
    WSCALE, and SACK-permitted options, padding with NOPs so the
    total option block length is a multiple of 4 bytes (TCP
    requires 4-byte alignment of the data offset).
    """

    options: list[TcpOption] = []

    if mss is not None:
        options.append(TcpOptionMss(mss=mss))

    if wscale is not None:
        options.append(TcpOptionWscale(wscale=wscale))

    if sackperm:
        options.append(TcpOptionSackperm())

    pad_count = (-sum(len(opt) for opt in options)) % 4
    options.extend(TcpOptionNop() for _ in range(pad_count))

    return TcpOptions(*options)


def build_tcp4(
    *,
    src_mac: MacAddress = HOST_A__MAC_ADDRESS,
    dst_mac: MacAddress = STACK__MAC_ADDRESS,
    src_ip: Ip4Address = HOST_A__IP4_ADDRESS,
    dst_ip: Ip4Address = STACK__IP4_HOST.address,
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: Iterable[str] = (),
    win: int = 65535,
    mss: int | None = None,
    wscale: int | None = None,
    sackperm: bool = False,
    payload: Buffer = b"",
    paws_ts: object = None,
    sack_block: object = None,
) -> bytes:
    """
    Build an Ethernet/IPv4/TCP frame with the supplied TCP fields and
    options and return it as raw bytes ready to feed into
    'PacketHandler._phrx_ethernet'.
    """

    tcp = _build_tcp_assembler(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        mss=mss,
        wscale=wscale,
        sackperm=sackperm,
        payload=payload,
        paws_ts=paws_ts,
        sack_block=sack_block,
    )

    ip4 = Ip4Assembler(
        ip4__src=src_ip,
        ip4__dst=dst_ip,
        ip4__payload=tcp,
    )

    ethernet = EthernetAssembler(
        ethernet__src=src_mac,
        ethernet__dst=dst_mac,
        ethernet__payload=ip4,
    )

    buffers: list[Buffer] = []
    ethernet.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


def build_tcp6(
    *,
    src_mac: MacAddress = HOST_A__MAC_ADDRESS,
    dst_mac: MacAddress = STACK__MAC_ADDRESS,
    src_ip: Ip6Address = HOST_A__IP6_ADDRESS,
    dst_ip: Ip6Address = STACK__IP6_HOST.address,
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: Iterable[str] = (),
    win: int = 65535,
    mss: int | None = None,
    wscale: int | None = None,
    sackperm: bool = False,
    payload: Buffer = b"",
    paws_ts: object = None,
    sack_block: object = None,
) -> bytes:
    """
    Build an Ethernet/IPv6/TCP frame with the supplied TCP fields and
    options and return it as raw bytes ready to feed into
    'PacketHandler._phrx_ethernet'.
    """

    tcp = _build_tcp_assembler(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        mss=mss,
        wscale=wscale,
        sackperm=sackperm,
        payload=payload,
        paws_ts=paws_ts,
        sack_block=sack_block,
    )

    ip6 = Ip6Assembler(
        ip6__src=src_ip,
        ip6__dst=dst_ip,
        ip6__payload=tcp,
    )

    ethernet = EthernetAssembler(
        ethernet__src=src_mac,
        ethernet__dst=dst_mac,
        ethernet__payload=ip6,
    )

    buffers: list[Buffer] = []
    ethernet.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)
