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
Integration tests for the per-address DAD slot lock and the
atomic '_icmp6_nd_dad__try_signal_conflict' helper —
nd_linux_parity §20.1 lock-discipline addendum.

The per-address DAD slot dicts ('_icmp6_nd_dad__events',
'_icmp6_nd_dad__nonces', '_icmp6_nd_dad__tllas') are
mutated by both the DAD worker thread (slot install at
probe start, nonce-set mutation during probe send, slot
tear-down after the wait returns) and the RX subsystem
thread (NS / NA arrival signals the slot for the right
target). The '_icmp6_nd_dad__lock' guards every
cross-thread access so:

- The RX path cannot KeyError on a slot the worker tore
  down between the membership check and the
  '_tllas[]='/'event.set()' lines.
- The worker's nonce-set mutation cannot interleave with
  an RX nonce-membership read.

The atomic '_icmp6_nd_dad__try_signal_conflict' helper is
the single check + nonce-test + tlla-write + event-signal
entry point used by both the RX NS and RX NA handlers.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__dad_slot_lock.py

ver 3.0.4
"""

import threading
from typing import override

from net_addr import Ip6Address, MacAddress
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6NdDadSignalResult
from pytcp.tests.lib.nd_testcase import NdTestCase

_CANDIDATE = Ip6Address("2001:db8:0:1::5")
_CANDIDATE_OTHER = Ip6Address("2001:db8:0:1::6")
_PEER_TLLA = MacAddress("02:00:00:00:00:91")


class TestIcmp6Nd__DadSlotLock__Attribute(NdTestCase):
    """
    The packet handler exposes a threading.Lock guarding the
    DAD slot dicts.
    """

    def test__icmp6__nd__dad_slot_lock__exists_and_is_acquirable(self) -> None:
        """
        Ensure '_icmp6_nd_dad__lock' is a context-manager-capable
        threading primitive so the worker and RX paths can take
        it with the canonical 'with self._icmp6_nd_dad__lock:'
        form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lock = self._packet_handler._icmp6_nd_dad__lock
        self.assertTrue(
            hasattr(lock, "acquire") and hasattr(lock, "release"),
            msg="DAD slot lock must expose acquire / release methods.",
        )
        with lock:
            pass


class TestIcmp6Nd__DadSlotLock__TrySignalHelper(NdTestCase):
    """
    The atomic '_icmp6_nd_dad__try_signal_conflict' helper
    is the single entry point the RX NS / NA handlers use to
    check + signal a conflict on the per-address DAD slot.
    """

    @override
    def setUp(self) -> None:
        """
        Pre-populate a DAD slot for '_CANDIDATE' so the helper
        sees a target to signal on.
        """

        super().setUp()
        self._packet_handler._icmp6_nd_dad__events[_CANDIDATE] = threading.Event()
        self._packet_handler._icmp6_nd_dad__nonces[_CANDIDATE] = set()
        self._packet_handler._icmp6_nd_dad__tllas[_CANDIDATE] = None

    def test__icmp6__nd__dad_slot_lock__not_dad_when_target_unknown(self) -> None:
        """
        Ensure the helper returns NOT_DAD when no slot exists
        for the inbound target — the RX caller falls through to
        the normal NS / NA processing path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._packet_handler._icmp6_nd_dad__try_signal_conflict(
            target_address=_CANDIDATE_OTHER,
            tlla=None,
            inbound_nonce=None,
        )

        self.assertIs(
            result,
            Icmp6NdDadSignalResult.NOT_DAD,
            msg="Unknown target must return NOT_DAD.",
        )

    def test__icmp6__nd__dad_slot_lock__loop_hairpin_when_nonce_matches(self) -> None:
        """
        Ensure the helper returns LOOP_HAIRPIN when the inbound
        NS carries a Nonce option matching one we emitted for
        the same target — the slot Event must NOT be signalled
        and '_tllas' must remain untouched.

        Reference: RFC 7527 §4.2 (Enhanced DAD loop-hairpin drop).
        """

        nonce = b"\x01\x02\x03\x04\x05\x06"
        self._packet_handler._icmp6_nd_dad__nonces[_CANDIDATE].add(nonce)

        result = self._packet_handler._icmp6_nd_dad__try_signal_conflict(
            target_address=_CANDIDATE,
            tlla=None,
            inbound_nonce=nonce,
        )

        self.assertIs(
            result,
            Icmp6NdDadSignalResult.LOOP_HAIRPIN,
            msg="Nonce match must return LOOP_HAIRPIN.",
        )
        self.assertFalse(
            self._packet_handler._icmp6_nd_dad__events[_CANDIDATE].is_set(),
            msg="Loop-hairpin must NOT signal the slot Event.",
        )
        self.assertIsNone(
            self._packet_handler._icmp6_nd_dad__tllas[_CANDIDATE],
            msg="Loop-hairpin must NOT write to '_tllas'.",
        )

    def test__icmp6__nd__dad_slot_lock__signaled_when_nonce_unknown(self) -> None:
        """
        Ensure the helper returns SIGNALED, writes the supplied
        TLLA into '_tllas', and sets the slot Event when the
        inbound carries no Nonce or a Nonce not registered for
        this candidate (genuine peer conflict).

        Reference: RFC 4862 §5.4.3 case (b) (peer-conflict signal).
        """

        result = self._packet_handler._icmp6_nd_dad__try_signal_conflict(
            target_address=_CANDIDATE,
            tlla=_PEER_TLLA,
            inbound_nonce=b"\xff\xff\xff\xff\xff\xff",
        )

        self.assertIs(
            result,
            Icmp6NdDadSignalResult.SIGNALED,
            msg="Unknown nonce must signal conflict.",
        )
        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__events[_CANDIDATE].is_set(),
            msg="Conflict signal must set the slot Event.",
        )
        self.assertEqual(
            self._packet_handler._icmp6_nd_dad__tllas[_CANDIDATE],
            _PEER_TLLA,
            msg="Conflict signal must write the inbound TLLA into '_tllas'.",
        )

    def test__icmp6__nd__dad_slot_lock__signaled_when_no_inbound_nonce(self) -> None:
        """
        Ensure the helper returns SIGNALED when the inbound
        carries no Nonce option at all — the NA path always
        supplies 'inbound_nonce=None' (NA messages do not carry
        the Nonce option) and an NS without a Nonce option from
        Enhanced-DAD-incapable peers is still a peer conflict.

        Reference: RFC 4861 §4.4 (NA carries no Nonce option).
        """

        result = self._packet_handler._icmp6_nd_dad__try_signal_conflict(
            target_address=_CANDIDATE,
            tlla=_PEER_TLLA,
            inbound_nonce=None,
        )

        self.assertIs(
            result,
            Icmp6NdDadSignalResult.SIGNALED,
            msg="Inbound without nonce must signal conflict.",
        )
        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__events[_CANDIDATE].is_set(),
            msg="Conflict signal must set the slot Event.",
        )


class TestIcmp6Nd__DadSlotLock__Concurrency(NdTestCase):
    """
    A worker thread rapidly installing and tearing down DAD
    slots in parallel with an RX thread firing
    '_icmp6_nd_dad__try_signal_conflict' calls must never
    raise — the lock makes the check + signal atomic.
    """

    def test__icmp6__nd__dad_slot_lock__install_teardown_vs_rx_signal__no_keyerror(
        self,
    ) -> None:
        """
        Ensure 500 iterations of worker install / tear-down
        racing against an RX-thread signal loop produce no
        KeyError (today, without the lock, the RX path can
        observe the slot present during the membership check
        and absent during the '_tllas[]=' / '.set()' lines).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        iterations = 500
        errors: list[BaseException] = []
        stop = threading.Event()
        handler = self._packet_handler

        def _worker_loop() -> None:
            try:
                for _ in range(iterations):
                    with handler._icmp6_nd_dad__lock:
                        handler._icmp6_nd_dad__events[_CANDIDATE] = threading.Event()
                        handler._icmp6_nd_dad__nonces[_CANDIDATE] = set()
                        handler._icmp6_nd_dad__tllas[_CANDIDATE] = None
                    with handler._icmp6_nd_dad__lock:
                        handler._icmp6_nd_dad__events.pop(_CANDIDATE, None)
                        handler._icmp6_nd_dad__nonces.pop(_CANDIDATE, None)
                        handler._icmp6_nd_dad__tllas.pop(_CANDIDATE, None)
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)
            finally:
                stop.set()

        def _rx_loop() -> None:
            try:
                while not stop.is_set():
                    handler._icmp6_nd_dad__try_signal_conflict(
                        target_address=_CANDIDATE,
                        tlla=_PEER_TLLA,
                        inbound_nonce=None,
                    )
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t_worker = threading.Thread(target=_worker_loop, name="DAD-stress-worker")
        t_rx = threading.Thread(target=_rx_loop, name="DAD-stress-rx")
        t_worker.start()
        t_rx.start()
        t_worker.join(timeout=10.0)
        t_rx.join(timeout=10.0)

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent install / tear-down vs RX signal must not raise. Got: {errors!r}",
        )

    def test__icmp6__nd__dad_slot_lock__nonce_set_mutation_vs_rx_read__no_exception(
        self,
    ) -> None:
        """
        Ensure 500 iterations of worker thread mutating the
        per-candidate nonce set ('nonce_set.add(...)') in
        parallel with an RX thread reading the same set via
        '_icmp6_nd_dad__try_signal_conflict' produce no
        exception — the lock serialises set mutation against
        nonce-membership lookup.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        iterations = 500
        errors: list[BaseException] = []
        stop = threading.Event()
        handler = self._packet_handler

        # Install the slot once; both threads share it for the
        # duration of the test.
        with handler._icmp6_nd_dad__lock:
            handler._icmp6_nd_dad__events[_CANDIDATE] = threading.Event()
            handler._icmp6_nd_dad__nonces[_CANDIDATE] = set()
            handler._icmp6_nd_dad__tllas[_CANDIDATE] = None

        def _worker_loop() -> None:
            try:
                for i in range(iterations):
                    new_nonce = i.to_bytes(6, "big")
                    with handler._icmp6_nd_dad__lock:
                        handler._icmp6_nd_dad__nonces[_CANDIDATE].add(new_nonce)
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)
            finally:
                stop.set()

        def _rx_loop() -> None:
            try:
                probe_nonce = b"\xfe\xfe\xfe\xfe\xfe\xfe"
                while not stop.is_set():
                    handler._icmp6_nd_dad__try_signal_conflict(
                        target_address=_CANDIDATE,
                        tlla=_PEER_TLLA,
                        inbound_nonce=probe_nonce,
                    )
                    # Re-arm the slot Event so the next iteration
                    # can re-test the signalling path.
                    handler._icmp6_nd_dad__events[_CANDIDATE].clear()
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t_worker = threading.Thread(target=_worker_loop, name="DAD-nonce-worker")
        t_rx = threading.Thread(target=_rx_loop, name="DAD-nonce-rx")
        t_worker.start()
        t_rx.start()
        t_worker.join(timeout=10.0)
        t_rx.join(timeout=10.0)

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent nonce mutation vs RX read must not raise. Got: {errors!r}",
        )
