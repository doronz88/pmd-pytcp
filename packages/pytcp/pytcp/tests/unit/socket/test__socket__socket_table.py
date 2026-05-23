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
This module contains unit tests for the 'SocketTable' registry.

pytcp/tests/unit/socket/test__socket__socket_table.py

ver 3.0.6
"""

import threading
from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock

from pytcp.socket import socket
from pytcp.socket.socket_id import SocketId
from pytcp.socket.socket_table import SocketTable


def _make_socket_id(token: str) -> SocketId:
    """
    Build a distinct opaque 'SocketId' fixture for the table tests.
    """

    return cast(SocketId, token)


def _make_socket() -> socket:
    """
    Build a spec'd stand-in socket for table-storage tests.
    """

    return cast(socket, MagicMock(spec=socket))


class TestSocketTableBasic(TestCase):
    """
    The 'SocketTable' dict-compatible operation tests.
    """

    def test__socket_table__register_and_get_roundtrip(self) -> None:
        """
        Ensure a registered socket is returned by 'get' under its id.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()

        table[sid] = sock

        self.assertIs(
            table.get(sid),
            sock,
            msg="get must return the socket registered under the id.",
        )

    def test__socket_table__get_missing_returns_default(self) -> None:
        """
        Ensure 'get' on an unknown id returns the supplied default
        ('None' when omitted), never raising.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()

        self.assertIsNone(
            table.get(_make_socket_id("missing")),
            msg="get on an unknown id must return None by default.",
        )

    def test__socket_table__pop_removes_and_returns(self) -> None:
        """
        Ensure 'pop' removes the entry and returns it; a second pop
        returns the default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()
        table[sid] = sock

        self.assertIs(
            table.pop(sid, None),
            sock,
            msg="pop must return the removed socket.",
        )
        self.assertIsNone(
            table.pop(sid, None),
            msg="a second pop must return the default (entry gone).",
        )

    def test__socket_table__contains_and_len(self) -> None:
        """
        Ensure '__contains__' and '__len__' reflect the registered set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        table[sid] = _make_socket()

        self.assertIn(sid, table, msg="a registered id must be 'in' the table.")
        self.assertEqual(len(table), 1, msg="len must count registered sockets.")

    def test__socket_table__values_returns_snapshot_safe_under_mutation(self) -> None:
        """
        Ensure 'values' returns a snapshot list so iterating it while
        the table is concurrently mutated cannot raise
        'RuntimeError: dictionary changed size during iteration'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        for i in range(8):
            table[_make_socket_id(str(i))] = _make_socket()

        # Mutating the table while iterating the returned snapshot
        # must not raise — the snapshot is detached from the live dict.
        for index, _ in enumerate(table.values()):
            if index == 0:
                table[_make_socket_id("added-during-iteration")] = _make_socket()

    def test__socket_table__dict_roundtrip(self) -> None:
        """
        Ensure the table supports the 'dict(table)' Mapping protocol
        (keys + __getitem__) used by the test harness to snapshot and
        restore the registry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()
        table[sid] = sock

        snapshot = dict(table)

        self.assertEqual(
            snapshot,
            {sid: sock},
            msg="dict(table) must reproduce the registered mapping.",
        )

    def test__socket_table__clear_and_update(self) -> None:
        """
        Ensure 'clear' empties the table and 'update' bulk-installs a
        mapping (the harness snapshot/restore primitives).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        table[_make_socket_id("a")] = _make_socket()

        table.clear()
        self.assertEqual(len(table), 0, msg="clear must empty the table.")

        restored = {_make_socket_id("b"): _make_socket()}
        table.update(restored)
        self.assertEqual(len(table), 1, msg="update must bulk-install the mapping.")


class TestSocketTableConcurrency(TestCase):
    """
    The 'SocketTable' thread-safety tests — concurrent register /
    unregister / lookup must neither raise nor corrupt the registry.
    """

    def test__socket_table__concurrent_register_unregister_consistent(self) -> None:
        """
        Ensure concurrent register / unregister / get from many
        threads never raises and leaves the table in a consistent
        state (every id either present-with-its-socket or absent).
        The bare 'dict' is GIL-atomic per-op but the wrapper makes
        the registry safe under free-threaded builds where compound
        access is not.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        ids = [_make_socket_id(str(i)) for i in range(64)]
        socks = {sid: _make_socket() for sid in ids}
        errors: list[BaseException] = []

        def churn(sid: SocketId) -> None:
            try:
                for _ in range(200):
                    table[sid] = socks[sid]
                    table.get(sid)
                    _ = list(table.values())
                    table.pop(sid, None)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=churn, args=(sid,)) for sid in ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent table access must not raise; got: {errors!r}",
        )
        # Every surviving entry must map an id to its own socket.
        for sid, sock in table.items():
            self.assertIs(
                sock,
                socks[sid],
                msg="A surviving entry must map its id to the registered socket.",
            )
