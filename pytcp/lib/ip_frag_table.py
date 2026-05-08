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
This module contains the shared IPv4/IPv6 fragment-reassembly flow table.

pytcp/lib/ip_frag_table.py

ver 3.0.4
"""

import struct
from dataclasses import dataclass
from enum import Enum
from time import time

from net_proto.lib.buffer import Buffer
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId


class IpFragAddOutcome(Enum):
    """
    Tag for the outcome of an 'IpFragTable.add_fragment' call.
    """

    PENDING = "pending"
    COMPLETE = "complete"


@dataclass(frozen=True, kw_only=True, slots=True)
class IpFragAddResult:
    """
    Tagged result of an 'IpFragTable.add_fragment' call.

    'header' / 'payload' carry the joined datagram bytes when
    'outcome is IpFragAddOutcome.COMPLETE'. Otherwise both are
    empty 'bytes()' sentinels and callers must not consume them.
    """

    outcome: IpFragAddOutcome
    header: bytes = b""
    payload: bytes = b""


class IpFragTable:
    """
    Shared IPv4/IPv6 fragment-reassembly flow table.

    Mirrors the Linux 'net/ipv4/inet_fragment.c' shape: a flow
    table keyed by the family-specific 'IpFragFlowId' carrying a
    per-offset fragment store, with a lazy expiry sweep on every
    admission. Family differences (key shape, header rewrite,
    atomic-fragment fast-path) live in the calling handler — this
    table only owns the common machinery.
    """

    _flows: dict[IpFragFlowId, IpFragData]
    _timeout: float

    def __init__(self, *, timeout: float) -> None:
        """
        Initialize the flow table with the given expiry timeout.
        """

        self._flows = {}
        self._timeout = timeout

    @property
    def flows(self) -> dict[IpFragFlowId, IpFragData]:
        """
        Get a live view of the flow store. Mutation by callers is
        permitted and used by tests that backdate a flow's
        timestamp to drive the expiry path.
        """

        return self._flows

    def add_fragment(
        self,
        *,
        flow_id: IpFragFlowId,
        offset: int,
        payload: Buffer,
        flag_mf: bool,
        header: Buffer,
    ) -> IpFragAddResult:
        """
        Admit one fragment into the flow store.

        Returns an 'IpFragAddResult' tagged by 'IpFragAddOutcome':

          - PENDING:  the fragment is stored and more are
                      expected (or the offset chain is not yet
                      contiguous).
          - COMPLETE: the fragment that just arrived completes
                      the datagram; 'header' / 'payload' carry
                      the joined bytes.

        The expiry sweep ('time() - timestamp >= timeout' purges
        the flow) runs at the head of every admission, matching
        Linux's lazy-reap model.
        """

        # Lazy expiry sweep.
        now = time()
        self._flows = {
            flow: self._flows[flow] for flow in self._flows if now - self._flows[flow].timestamp < self._timeout
        }

        # Insert / update per-offset entry.
        if flow_id in self._flows:
            self._flows[flow_id].payload[offset] = payload
        else:
            self._flows[flow_id] = IpFragData(
                header=header,
                payload={offset: payload},
            )
        if not flag_mf:
            self._flows[flow_id].received_last_frag()

        # Completeness check: last-fragment seen + every byte
        # covered by a contiguous offset chain starting at zero.
        if not self._flows[flow_id].last:
            return IpFragAddResult(outcome=IpFragAddOutcome.PENDING)
        payload_len = 0
        for entry_offset in sorted(self._flows[flow_id].payload):
            if entry_offset > payload_len:
                return IpFragAddResult(outcome=IpFragAddOutcome.PENDING)
            payload_len = entry_offset + len(self._flows[flow_id].payload[entry_offset])

        # Build the joined payload buffer in offset order.
        joined = bytearray(payload_len)
        for entry_offset in sorted(self._flows[flow_id].payload):
            chunk = self._flows[flow_id].payload[entry_offset]
            struct.pack_into(f"{len(chunk)}s", joined, entry_offset, bytes(chunk))

        header_bytes = bytes(self._flows[flow_id].header)
        del self._flows[flow_id]

        return IpFragAddResult(
            outcome=IpFragAddOutcome.COMPLETE,
            header=header_bytes,
            payload=bytes(joined),
        )
