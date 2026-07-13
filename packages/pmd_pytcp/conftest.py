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

import asyncio
import sys
import unittest


def pytest_runtest_setup(item: object) -> None:
    """
    Guarantee a current event loop before each test on Python < 3.10.

    The pure-asyncio stack ('docs/refactor/pure_asyncio.md') constructs
    'asyncio.Event' / 'asyncio.Semaphore' in subsystem / socket / handler
    '__init__'. On Python < 3.10 those bind the *current* event loop at
    construction, and 'IsolatedAsyncioTestCase' sets the current loop to
    None when its async runner tears down — so a sync test that
    constructs a stack object after an async test in the same process
    raises 'RuntimeError: There is no current event loop'. Installing a
    fresh loop here restores the pre-3.10 default. Python 3.10+ defers
    loop binding to first await, so this is a no-op there.
    """

    if sys.version_info < (3, 10):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())


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

