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
Unit tests for the hot-path logging gate — 'log.enabled' and
'refresh_log_enabled' in pmd_pytcp/lib/logger.py. The gate
replaces the historical '__debug__ and log(...)' pattern whose
guard was compile-time True in any normal interpreter run, so
every call site formatted its message string and threw it away.

pmd_pytcp/tests/unit/lib/test__lib__logger__enabled_gate.py

ver 3.0.7
"""

from __future__ import annotations

import logging
from unittest import TestCase

from pmd_pytcp.lib.logger import log, refresh_log_enabled

_LOGGER = logging.getLogger("pmd_pytcp")


class TestLoggerEnabledGate(TestCase):
    """
    'refresh_log_enabled' against the live logging configuration.
    """

    def setUp(self) -> None:
        """
        Snapshot and restore the 'pmd_pytcp' logger level and the
        gate value around each test.
        """

        self._saved_level = _LOGGER.level
        self._saved_enabled = log.enabled
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        _LOGGER.setLevel(self._saved_level)
        log.enabled = self._saved_enabled

    def test__logger__gate_off_when_debug_disabled(self) -> None:
        """
        Ensure the gate resolves False when the host has not
        enabled DEBUG for the 'pmd_pytcp' logger — the embedded-
        library default, where the hot path must skip message
        formatting entirely.
        """

        _LOGGER.setLevel(logging.WARNING)

        self.assertFalse(
            refresh_log_enabled(),
            msg="refresh_log_enabled MUST resolve False with DEBUG disabled.",
        )
        self.assertFalse(
            log.enabled,
            msg="The gate attribute MUST mirror the resolved value.",
        )

    def test__logger__gate_on_when_debug_enabled(self) -> None:
        """
        Ensure the gate resolves True when DEBUG is enabled for
        the 'pmd_pytcp' logger (and the default LOG__CHANNEL set
        is non-empty) — hot-path sites then evaluate their
        messages exactly as before the gate existed.
        """

        _LOGGER.setLevel(logging.DEBUG)

        self.assertTrue(
            refresh_log_enabled(),
            msg="refresh_log_enabled MUST resolve True with DEBUG enabled.",
        )
        self.assertTrue(
            log.enabled,
            msg="The gate attribute MUST mirror the resolved value.",
        )

    def test__logger__gated_call_still_logs_when_enabled(self) -> None:
        """
        Ensure the call-site idiom 'log.enabled and log(...)'
        still emits when the gate is armed — the gate must only
        short-circuit, never suppress genuine logging.
        """

        _LOGGER.setLevel(logging.DEBUG)
        refresh_log_enabled()

        with self.assertLogs("pmd_pytcp", level=logging.DEBUG):
            emitted = log.enabled and log("stack", "gate test message")

        self.assertTrue(
            emitted,
            msg="An armed gate MUST let log() emit through the standard logger.",
        )
