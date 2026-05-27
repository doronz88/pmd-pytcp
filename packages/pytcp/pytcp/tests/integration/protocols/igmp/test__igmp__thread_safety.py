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
This module contains the IGMP / IPv4-multicast thread-safety tests —
pinning that the per-interface multicast reception state is mutated only
while holding the interface multicast lock, so concurrent application-
thread membership changes cannot corrupt it on a free-threaded build.

packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__thread_safety.py

ver 3.0.6
"""

import threading
from typing import override

from net_addr import Ip4Address
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.stack import sysctl
from pytcp.stack.membership import MembershipApi
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip4Address("239.7.7.7")
_SOURCE = Ip4Address("10.0.0.5")


class _TrackingRLock:
    """
    A reentrant lock that exposes its current hold depth so a test can
    assert a critical section was entered around a given operation.
    """

    def __init__(self) -> None:
        """
        Wrap a real reentrant lock and start at zero hold depth.
        """

        self._lock = threading.RLock()
        self.depth = 0

    def __enter__(self) -> "_TrackingRLock":
        """
        Acquire the underlying lock and record the deeper hold.
        """

        self._lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


class _LockAssertingDict[K, V](dict[K, V]):
    """
    A dict that records, on every structural mutation, whether the
    tracking lock was held at the moment of the write.
    """

    def __init__(self, lock: _TrackingRLock, observed: list[bool], source: dict[K, V], /) -> None:
        """
        Seed from 'source' and remember where to record observations.
        """

        super().__init__(source)
        self._lock = lock
        self._observed = observed

    @override
    def __setitem__(self, key: K, value: V) -> None:
        """
        Record the lock-held state, then insert / replace the key.
        """

        self._observed.append(self._lock.depth > 0)
        super().__setitem__(key, value)

    @override
    def __delitem__(self, key: K) -> None:
        """
        Record the lock-held state, then delete the key.
        """

        self._observed.append(self._lock.depth > 0)
        super().__delitem__(key)


class TestIgmpMulticastReceptionStateLocking(IcmpTestCase):
    """
    The IPv4 multicast reception-state lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and pin robustness to 1 so a membership change
        emits a single report without a lingering retransmit train.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 1))

    def test__igmp__reception_state_mutations_hold_the_multicast_lock(self) -> None:
        """
        Ensure every structural mutation of the IPv4 multicast reception
        state — the joined-group filter map and the per-group contributor
        registry — happens while the interface multicast lock is held, so
        concurrent application-thread join / leave / source-filter changes
        cannot corrupt the reference-counted state on a free-threaded
        build.

        Reference: RFC 3376 §3.2 (interface reception state is the merge of per-socket filters).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        observed: list[bool] = []

        # Install the depth-tracking lock in place of the real multicast
        # lock and wrap the two reception-state dicts so each set / del
        # records whether the lock was held. 'setattr' keeps mypy strict
        # clean without re-typing the production attributes.
        setattr(handler, "_lock__multicast", tracking)
        setattr(
            handler,
            "_ip4_multicast_filters",
            _LockAssertingDict(tracking, observed, handler._ip4_multicast_filters),
        )
        setattr(
            handler,
            "_ip4_multicast_refs",
            _LockAssertingDict(tracking, observed, handler._ip4_multicast_refs),
        )

        membership = MembershipApi(packet_handler=handler)

        # Drive every reception-state mutator: an operator join (filter
        # map insert), a per-socket source-filter change (merge update),
        # and a leave (filter map + contributor registry delete).
        membership.join(group=_GROUP)
        membership.set_socket_filter(
            group=_GROUP,
            token=1,
            source_filter=Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_SOURCE})),
        )
        membership.clear_socket_filter(group=_GROUP, token=1)
        membership.leave(group=_GROUP)

        self.assertTrue(
            observed,
            msg="The membership changes must mutate the reception-state dicts.",
        )
        self.assertTrue(
            all(observed),
            msg="Every reception-state mutation must occur while the interface multicast lock is held.",
        )
