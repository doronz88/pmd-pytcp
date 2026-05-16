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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the ICMP PMTUD → TCP demux path added in
Phase 6 of the ICMP demux + PMTUD refactor. Drives an ICMPv4
Frag-Needed (Type 3 Code 4) into a SYN_SENT-state TCP session and
verifies pmtu_cache update + snd_mss recompute.

pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__pmtu.py

ver 3.0.5
"""

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Ip4Assembler,
    TcpAssembler,
)
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000
NEXT_HOP_MTU: int = 1400


def _build_icmp4_frag_needed_frame(*, mtu: int, embedded_seq: int) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Type 3 Code 4 (Frag-Needed) frame
    whose embedded data is an IPv4+TCP SYN segment for the
    (PEER → STACK : PEER__PORT → STACK__PORT) flow with seq=embedded_seq.
    """

    embedded_tcp = bytes(
        Ip4Assembler(
            ip4__src=STACK__IP,
            ip4__dst=PEER__IP,
            ip4__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )
    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageDestinationUnreachable(
            code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
            mtu=mtu,
            data=embedded_tcp,
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP,
            ip4__dst=STACK__IP,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


class TestTcpOnPmtu(TcpSessionTestCase):
    """
    Integration tests for the ICMPv4 Frag-Needed → TCP PMTUD path.
    """

    def _make_syn_sent_session(self) -> TcpSession:
        """
        Build a SYN_SENT-state session.
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        assert session.state is FsmState.SYN_SENT
        return session

    def test__icmp4__frag_needed__updates_pmtu_cache(self) -> None:
        """
        Ensure an ICMPv4 Frag-Needed for a 4-tuple matching a TCP
        session updates 'stack.pmtu_cache' with the advertised
        next-hop MTU keyed by the remote address.

        Reference: RFC 1191 §3 (Path MTU Discovery on the host).
        """

        self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_frag_needed_frame(mtu=NEXT_HOP_MTU, embedded_seq=LOCAL__ISS),
        )

        self.assertEqual(
            stack.pmtu_cache.get(PEER__IP),
            NEXT_HOP_MTU,
            msg="ICMPv4 Frag-Needed must update stack.pmtu_cache for the remote address.",
        )

    def test__icmp4__frag_needed__shrinks_snd_mss(self) -> None:
        """
        Ensure the Frag-Needed callback shrinks the session's
        snd_mss to fit the new path MTU minus IPv4(20) + TCP(20) =
        40 bytes of fixed overhead.

        Reference: RFC 9293 §3.7.5 (MSS option update on path-MTU change).
        """

        session = self._make_syn_sent_session()
        # Force a comfortably-large initial MSS so the shrink is observable.
        session._win.snd_mss = 1460

        self._drive_rx(
            frame=_build_icmp4_frag_needed_frame(mtu=NEXT_HOP_MTU, embedded_seq=LOCAL__ISS),
        )

        self.assertEqual(
            session._win.snd_mss,
            NEXT_HOP_MTU - 40,
            msg="snd_mss must drop to next_hop_mtu - 40 (IPv4 + TCP overhead).",
        )

    def test__icmp4__frag_needed__never_grows_snd_mss(self) -> None:
        """
        Ensure a Frag-Needed advertising a MTU larger than the
        current snd_mss + overhead does NOT grow snd_mss — RFC 1191
        is shrink-only on the immediate signal.

        Reference: RFC 1191 §6.4 (PMTU only shrinks on a Frag-Needed).
        """

        session = self._make_syn_sent_session()
        session._win.snd_mss = 500  # smaller than NEXT_HOP_MTU - 40 = 1360

        self._drive_rx(
            frame=_build_icmp4_frag_needed_frame(mtu=NEXT_HOP_MTU, embedded_seq=LOCAL__ISS),
        )

        self.assertEqual(
            session._win.snd_mss,
            500,
            msg="snd_mss must not grow on a Frag-Needed signaling a larger path MTU.",
        )

    def test__icmp4__frag_needed__seq_out_of_window__drops(self) -> None:
        """
        Ensure a Frag-Needed whose embedded TCP seq fails the
        sequence-in-window guard does not update the cache and does
        not change snd_mss.

        Reference: RFC 5927 §4 (sequence-in-window check).
        """

        session = self._make_syn_sent_session()
        session._win.snd_mss = 1460
        before = self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__seq_out_of_window__drop

        self._drive_rx(
            frame=_build_icmp4_frag_needed_frame(
                mtu=NEXT_HOP_MTU,
                embedded_seq=LOCAL__ISS + 0x4000_0000,
            ),
        )

        self.assertEqual(
            session._win.snd_mss,
            1460,
            msg="Out-of-window Frag-Needed must NOT shrink snd_mss.",
        )
        self.assertNotIn(
            PEER__IP,
            stack.pmtu_cache,
            msg="Out-of-window Frag-Needed must NOT update pmtu_cache.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__seq_out_of_window__drop,
            before + 1,
            msg="Out-of-window Frag-Needed must bump the seq-out-of-window drop counter.",
        )

    def test__icmp4__frag_needed__bumps_notify_pmtu_counter(self) -> None:
        """
        Ensure a successful Frag-Needed → TCP demux bumps the
        'icmp4__destination_unreachable__fragmentation_needed__notify_pmtu'
        counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._make_syn_sent_session()
        before = self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu

        self._drive_rx(
            frame=_build_icmp4_frag_needed_frame(mtu=NEXT_HOP_MTU, embedded_seq=LOCAL__ISS),
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu,
            before + 1,
            msg="Successful Frag-Needed → TCP demux must bump the notify-pmtu counter.",
        )
