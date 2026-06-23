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
pytest configuration and cross-version test shims for the PyTCP suites.

conftest.py

ver 3.0.7
"""

from __future__ import annotations

import sys
import unittest
if not hasattr(unittest.TestCase, "enterContext"):

    def _enter_context(self: unittest.TestCase, cm: object) -> object:
        manager = type(cm)
        result = manager.__enter__(cm)  # type: ignore[attr-defined]
        self.addCleanup(manager.__exit__, cm, None, None, None)  # type: ignore[attr-defined]
        return result

    unittest.TestCase.enterContext = _enter_context  # type: ignore[attr-defined]


def pytest_runtest_teardown(item: object, nextitem: object) -> None:
    """
    Restore 'pmd_pytcp.stack' submodule attributes after every test.

    Stack tests assign module-level globals (e.g. 'stack.address' /
    'stack.neighbor' via 'init()' / 'mock__init()') that shadow the
    same-named submodules. On Python 3.9 / 3.10 'unittest.mock.patch'
    resolves a dotted target getattr-first, so a leaked global makes
    'patch("pmd_pytcp.stack.address.log")' resolve the instance (no 'log')
    and fail; Python 3.11+ resolves via 'pkgutil.resolve_name'
    (import-first) and is immune. Re-pointing the attributes at the
    submodules after each test makes the suite behave identically on every
    supported interpreter. A no-op until the stack package is imported.
    """

    stack = sys.modules.get("pmd_pytcp.stack")
    if stack is None:
        return
    prefix = "pmd_pytcp.stack."
    for name, module in list(sys.modules.items()):
        if name.startswith(prefix) and "." not in name[len(prefix) :]:
            setattr(stack, name[len(prefix) :], module)

