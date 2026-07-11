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
Unit tests for the cross-platform interface-fd I/O in
'pmd_pytcp/lib/io_backend.py' — specifically the 'writev()'
fallthrough taken when the fd is NOT in the socket-I/O
registry.

On POSIX that fallthrough is 'os.writev' and a torn-down fd
surfaces as OSError, which the TX Ring drop-handling absorbs.
On Windows 'os.writev' does not exist, so the same
unregister-then-transmit teardown race (stop()'s socket-abort
RSTs racing 'unregister_interface_fd()') used to surface as an
AttributeError that killed the TX Ring worker thread
(doronz88/pymobiledevice3#1756). These tests pin the contract:
the no-'os.writev' fallthrough raises OSError (EBADF), never
AttributeError, and registered fds route through the socket on
the way in AND stop doing so once unregistered.

pmd_pytcp/tests/unit/lib/test__lib__io_backend.py

ver 3.0.7
"""

from __future__ import annotations

import errno
import os
import socket
from contextlib import AbstractContextManager, nullcontext
from unittest import TestCase
from unittest.mock import patch

from pmd_pytcp.lib import io_backend


def _without_os_writev() -> AbstractContextManager:
    """
    Make 'os.writev' unavailable inside the context — patched to
    None where it exists (io_backend treats a None lookup as
    absent), a no-op on Windows where it is genuinely missing.
    """

    return patch.object(os, "writev", None) if hasattr(os, "writev") else nullcontext()


class TestIoBackendWritevFallthrough(TestCase):
    """
    The 'writev()' branch taken when the fd has no registered
    socket — the teardown-race path.
    """

    def test__writev__unregistered_fd__no_os_writev__raises_oserror(self) -> None:
        """
        With 'os.writev' unavailable (Windows), 'writev()' on an
        unregistered fd must raise OSError (EBADF) — the error the
        TX Ring's OSError drop-handling absorbs — and not the
        AttributeError that used to kill the worker thread.
        """

        with _without_os_writev():
            with self.assertRaises(OSError) as ctx:
                io_backend.writev(999_999, [b"\x00"])

        self.assertNotIsInstance(ctx.exception, AttributeError)
        self.assertEqual(ctx.exception.errno, errno.EBADF)

    def test__writev__unregister_then_write__no_os_writev__raises_oserror(self) -> None:
        """
        The exact doronz88/pymobiledevice3#1756 sequence: a
        registered interface fd is unregistered (interface
        teardown) and a straggler transmit then hits 'writev()' —
        must raise OSError, not AttributeError.
        """

        with patch.dict(os.environ, {"PYTCP_FORCE_SOCK_IO": "1"}):
            sock_a, sock_b = socket.socketpair()
            try:
                io_backend.register_interface_fd(sock_a)
                io_backend.unregister_interface_fd(sock_a)
                with _without_os_writev():
                    with self.assertRaises(OSError) as ctx:
                        io_backend.writev(sock_a.fileno(), [b"\x00"])
                self.assertEqual(ctx.exception.errno, errno.EBADF)
            finally:
                sock_a.close()
                sock_b.close()


class TestIoBackendRegisteredSocketIo(TestCase):
    """
    The registered-fd path: 'read()' / 'writev()' route through
    the socket itself.
    """

    def setUp(self) -> None:
        self._env_patcher = patch.dict(os.environ, {"PYTCP_FORCE_SOCK_IO": "1"})
        self._env_patcher.start()
        self.sock_a, self.sock_b = socket.socketpair()
        io_backend.register_interface_fd(self.sock_a)

    def tearDown(self) -> None:
        io_backend.unregister_interface_fd(self.sock_a)
        self.sock_a.close()
        self.sock_b.close()
        self._env_patcher.stop()

    def test__writev__registered_fd__routes_through_socket(self) -> None:
        """
        'writev()' on a registered fd coalesces the buffers into the
        socket and reports the byte count — 'os.writev' is not
        involved, so this is the path that must work on Windows.
        """

        sent = io_backend.writev(self.sock_a.fileno(), [b"abc", b"def"])

        self.assertEqual(sent, 6)
        self.assertEqual(self.sock_b.recv(64), b"abcdef")

    def test__read__registered_fd__routes_through_socket(self) -> None:
        """
        'read()' on a registered fd receives via the socket —
        'os.read' cannot touch a socket handle on Windows.
        """

        self.sock_b.send(b"payload")

        self.assertEqual(io_backend.read(self.sock_a.fileno(), 64), b"payload")
