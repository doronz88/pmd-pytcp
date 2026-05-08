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
This module contains the classes used in the IPv4/IPv6 packet fragmentation and reassembly processes.

pytcp/protocols/ip/ip_frag.py

ver 3.0.4
"""

import time
from dataclasses import dataclass, field

from net_addr import Ip4Address, Ip6Address
from net_proto import IpProto


@dataclass(frozen=True, kw_only=True, slots=True)
class IpFragFlowId:
    """
    The IPv4/IPv6 packet fragmentation flow ID.

    For IPv4 the reassembly key is (src, dst, ID, proto) per RFC
    791 §3.2. For IPv6 the key is (src, dst, ID) per RFC 8200
    §4.5; the 'proto' slot stays None.
    """

    src: Ip6Address | Ip4Address
    dst: Ip6Address | Ip4Address
    id: int
    proto: IpProto | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class IpFragData:
    """
    The IPv4/IPv6 packet fragmentation data.
    """

    timestamp: float = field(repr=False, init=False, default_factory=time.time)
    header: bytes
    last: bool = field(repr=False, init=False, default=False)
    payload: dict[int, bytes]
    discarded: bool = field(repr=False, init=False, default=False)

    def received_last_frag(self) -> None:
        """
        Set the last fragment flag.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "last", True)

    def mark_discarded(self) -> None:
        """
        Mark the flow as discarded and free its stored fragments.

        The discarded flag tells subsequent fragment arrivals
        for the same flow to be silently dropped without
        admission, per RFC 5722 §3 ("the entire datagram (and
        any constituent fragments, including those not yet
        received) MUST be silently discarded"). The flow itself
        is not deleted from the table — it is reaped by the
        normal expiry sweep once its timestamp goes stale.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "discarded", True)
        self.payload.clear()
