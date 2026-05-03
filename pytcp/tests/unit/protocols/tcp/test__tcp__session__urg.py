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
This module contains unit tests for the RFC 1122 §4.2.2.4 urgent-
pointer receive-side handling in 'TcpSession._update_urg_state'.

RFC 1122 §4.2.2.4:

    "A TCP MUST inform the application layer asynchronously
     whenever it receives an Urgent pointer and there was
     previously no pending urgent data, or whenever the Urgent
     pointer advances in the data stream."

The 'urgent endpoint' for an inbound segment is
'add32(SEG.SEQ, urg_ptr)' (RFC 1122 §4.2.2.4 corrects RFC 793's
LAST+1 to LAST). The receive-side state PyTCP exposes via
'TcpSession._rcv_urg_seq' (highest endpoint ever seen, modular
max) and '_rcv_urg_pending' (the application-observable
"asynchronous notification" the MUST clause requires).

The tests in this file are tests-first: they assert the planned
behaviour against the '_update_urg_state' stub. The stub is a no-
op; the fix commit replaces its body with the real per-segment
URG processing, flipping these tests green.

Reference RFCs:
    RFC 1122 §4.2.2.4   The Urgent Pointer
    RFC 9293 §3.7       Urgent pointer (carried-forward semantics)
    RFC 6093            Reasons applications should not USE urgent
                        (does not affect receiver-side MUST-inform)

pytcp/tests/unit/protocols/tcp/test__tcp__session__urg.py

ver 3.0.4
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, IpVersion
from pytcp.protocols.tcp.tcp__session import TcpSession
from pytcp.socket.tcp__metadata import TcpMetadata


def _make_metadata(
    *,
    seq: int,
    flag_urg: bool = False,
    urg: int = 0,
    flag_ack: bool = True,
) -> TcpMetadata:
    """
    Build a minimal 'TcpMetadata' fixture for URG-handling tests.
    Only the fields the URG state machine reads are pinned;
    everything else takes safe defaults.
    """

    return TcpMetadata(
        ip__ver=IpVersion.IP4,
        ip__local_address=Ip4Address("10.0.0.1"),
        ip__remote_address=Ip4Address("10.0.0.2"),
        tcp__local_port=8080,
        tcp__remote_port=44444,
        tcp__flag_syn=False,
        tcp__flag_ack=flag_ack,
        tcp__flag_fin=False,
        tcp__flag_rst=False,
        tcp__seq=seq,
        tcp__ack=0,
        tcp__win=65535,
        tcp__wscale=0,
        tcp__mss=1460,
        tcp__sackperm=False,
        tcp__sack_blocks=(),
        tcp__data=memoryview(b""),
        tcp__flag_urg=flag_urg,
        tcp__urg=urg,
    )


class _TcpSessionUrgFixture(TestCase):
    """
    Shared fixture that patches the stack singletons so a
    'TcpSession' can be constructed without spinning a real FSM.
    """

    def setUp(self) -> None:
        """
        Install the per-test patches.
        """

        self._timer = SimpleNamespace(
            register_method=lambda **_: None,
            register_timer=lambda **_: None,
            is_expired=lambda _: False,
            unregister_timers_with_prefix=lambda _: None,
            unregister_method=lambda _: None,
        )
        self._timer_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.timer",
            self._timer,
        )
        self._timer_patch.start()

        self._mtu_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.interface_mtu",
            1500,
            create=True,
        )
        self._mtu_patch.start()

    def tearDown(self) -> None:
        """
        Tear down the per-test patches.
        """

        self._timer_patch.stop()
        self._mtu_patch.stop()

    def _make_session(self) -> TcpSession:
        """
        Build a canonical IPv4 'TcpSession' against a mocked socket.
        """

        return TcpSession(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_ip_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
            socket=MagicMock(),
        )


class TestTcpSessionUrgState(_TcpSessionUrgFixture):
    """
    The 'TcpSession._update_urg_state' RFC 1122 §4.2.2.4 receive-
    side urgent-pointer tests.
    """

    def test__urg__default_state_is_no_urgent_pending(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSession' has no urgent-
        data state set: '_rcv_urg_seq is None' (no URG ever seen),
        '_rcv_urg_pending is False'. Regression guard for the
        default-state invariant.
        """

        session = self._make_session()

        self.assertIsNone(
            session._rcv_urg_seq,
            msg="Fresh session must have '_rcv_urg_seq = None' (no URG ever received).",
        )
        self.assertFalse(
            session._rcv_urg_pending,
            msg="Fresh session must have '_rcv_urg_pending = False'.",
        )

    def test__urg__non_urg_segment_does_not_change_state(self) -> None:
        """
        Ensure a segment without 'flag_urg' set leaves the URG state
        unchanged. The MUST-inform clause only fires on URG arrival.
        Regression guard.
        """

        session = self._make_session()

        metadata = _make_metadata(seq=1000, flag_urg=False, urg=0)
        session._update_urg_state(metadata)

        self.assertIsNone(
            session._rcv_urg_seq,
            msg="Non-URG segment must not set '_rcv_urg_seq'.",
        )
        self.assertFalse(
            session._rcv_urg_pending,
            msg="Non-URG segment must not set '_rcv_urg_pending'.",
        )

    def test__urg__urg_segment_sets_pending_and_endpoint(self) -> None:
        """
        [FLAGS BUG]

        Ensure that a segment with 'flag_urg=True' and 'urg=N'
        sets '_rcv_urg_seq = SEG.SEQ + N' (modularly) and
        '_rcv_urg_pending = True'. RFC 1122 §4.2.2.4 mandates the
        application be informed; the pending flag is the
        observable signal.
        """

        session = self._make_session()

        metadata = _make_metadata(seq=1000, flag_urg=True, urg=10)
        session._update_urg_state(metadata)

        self.assertEqual(
            session._rcv_urg_seq,
            1010,
            msg=(
                "RFC 1122 §4.2.2.4: an URG segment with SEG.SEQ=1000, "
                "urg_ptr=10 must set '_rcv_urg_seq' to the urgent endpoint "
                "1000+10=1010."
            ),
        )
        self.assertTrue(
            session._rcv_urg_pending,
            msg=("RFC 1122 §4.2.2.4: an URG segment must set " "'_rcv_urg_pending = True' to inform the application."),
        )

    def test__urg__advancing_pointer_updates_endpoint(self) -> None:
        """
        [FLAGS BUG]

        Ensure that two consecutive URG segments with an advancing
        urgent endpoint update '_rcv_urg_seq' to the higher value.
        RFC 1122 §4.2.2.4 requires the application be informed
        "whenever the Urgent pointer advances in the data stream",
        which implies the recorded endpoint must track the latest.
        """

        session = self._make_session()

        first = _make_metadata(seq=1000, flag_urg=True, urg=10)
        session._update_urg_state(first)

        second = _make_metadata(seq=1500, flag_urg=True, urg=50)  # endpoint = 1550
        session._update_urg_state(second)

        self.assertEqual(
            session._rcv_urg_seq,
            1550,
            msg=(
                "RFC 1122 §4.2.2.4: an advancing URG pointer must update "
                "'_rcv_urg_seq' to the new (higher) endpoint."
            ),
        )

    def test__urg__retreating_pointer_does_not_move_endpoint_back(self) -> None:
        """
        [FLAGS BUG]

        Ensure that a stale-arrival URG segment carrying an endpoint
        BELOW the currently-recorded one does not move the endpoint
        backward. The state must be monotonic (modular max) so that
        a delayed retransmit doesn't roll back the application's
        urgent-data context.
        """

        session = self._make_session()

        # Establish a high endpoint first.
        first = _make_metadata(seq=2000, flag_urg=True, urg=100)  # endpoint = 2100
        session._update_urg_state(first)

        # Now feed a stale URG segment with a lower endpoint.
        stale = _make_metadata(seq=1500, flag_urg=True, urg=10)  # endpoint = 1510
        session._update_urg_state(stale)

        self.assertEqual(
            session._rcv_urg_seq,
            2100,
            msg=(
                "URG state must not move backward when a stale URG segment "
                "arrives - the recorded endpoint must stay at the highest "
                "value ever seen (modular max)."
            ),
        )

    def test__urg__zero_urg_pointer_still_updates(self) -> None:
        """
        [FLAGS BUG]

        Ensure that 'urg_ptr=0' (single-byte urgent data at SEG.SEQ
        exactly, since RFC 1122 §4.2.2.4 corrects the urgent pointer
        to point at the LAST octet) still triggers the URG state
        update. The endpoint is 'SEG.SEQ + 0 = SEG.SEQ'.
        """

        session = self._make_session()

        metadata = _make_metadata(seq=5000, flag_urg=True, urg=0)
        session._update_urg_state(metadata)

        self.assertEqual(
            session._rcv_urg_seq,
            5000,
            msg=(
                "RFC 1122 §4.2.2.4: 'urg_ptr=0' must set the endpoint to "
                "SEG.SEQ exactly (single-byte urgent at SEG.SEQ)."
            ),
        )
        self.assertTrue(
            session._rcv_urg_pending,
            msg="'urg_ptr=0' is still a valid URG arrival - must inform.",
        )

    def test__urg__endpoint_advances_across_32bit_wrap(self) -> None:
        """
        [FLAGS BUG]

        Ensure that the URG endpoint update uses RFC 9293 §3.4
        modular comparison so an endpoint crossing the 32-bit
        wrap is correctly recognised as "advancing", not "stale".
        Sequence number 0xFFFF_FF00 + urg_ptr 0x200 = 0x100 modulo
        2**32 - this is one byte ahead of any pre-wrap endpoint
        but NUMERICALLY less than 0xFFFF_FFFF.
        """

        session = self._make_session()

        # Pre-wrap URG sets endpoint near the 32-bit ceiling.
        pre_wrap = _make_metadata(seq=0xFFFF_FF00, flag_urg=True, urg=0x10)
        session._update_urg_state(pre_wrap)
        self.assertEqual(
            session._rcv_urg_seq,
            0xFFFF_FF10,
            msg="Setup precondition: pre-wrap endpoint must record correctly.",
        )

        # Post-wrap URG advances by 0x100 sequence positions but the
        # numerical sequence number is small (256). Modular max must
        # recognise this as an advance, not a retreat.
        post_wrap = _make_metadata(seq=0xFFFF_FFE0, flag_urg=True, urg=0x140)
        # endpoint = (0xFFFF_FFE0 + 0x140) & 0xFFFF_FFFF = 0x120
        session._update_urg_state(post_wrap)

        self.assertEqual(
            session._rcv_urg_seq,
            0x120,
            msg=(
                "URG endpoint must advance modularly across the 32-bit "
                "sequence wrap. Pre-wrap endpoint 0xFFFF_FF10, post-wrap "
                "endpoint 0x120 - the latter is 'ahead' by 528 sequence "
                "positions modulo 2**32, so the recorded endpoint must be 0x120."
            ),
        )
