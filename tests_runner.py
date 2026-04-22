#!/usr/bin/env python3

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
Testslide-style 'unittest' runner for the PyTCP test suites. Emits the
two-line "<dotted-class-path>\\n  <method>: PASS" format per test that
the project standardised on while testslide was the runner.

tests_runner.py

ver 3.0.4
"""


import os
import sys
import unittest
from typing import Any

# ANSI SGR escape sequences for colorising the per-test status word.
# Honours NO_COLOR (https://no-color.org/) and falls back to no-op
# strings when the output stream is not a TTY.
_ANSI__RESET = "\033[0m"
_ANSI__BOLD_GREEN = "\033[1;32m"
_ANSI__BOLD_RED = "\033[1;31m"
_ANSI__BOLD_YELLOW = "\033[1;33m"
_ANSI__BOLD_MAGENTA = "\033[1;35m"

_STATUS_COLORS: dict[str, str] = {
    "PASS": _ANSI__BOLD_GREEN,
    "FAIL": _ANSI__BOLD_RED,
    "ERROR": _ANSI__BOLD_RED,
    "SKIP": _ANSI__BOLD_YELLOW,
    "XFAIL": _ANSI__BOLD_YELLOW,
    "XPASS": _ANSI__BOLD_MAGENTA,
}


class TestslideStyleResult(unittest.TextTestResult):
    """
    'unittest.TextTestResult' subclass that prints a two-line summary
    per test: full dotted class path on the first line, indented
    "<method_name>: <STATUS>" on the second. The status word is
    colorised when the output stream is an interactive TTY.
    """

    _color: bool

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Detect whether the output stream supports ANSI colour and
        cache the result for use by '_emit'.
        """

        super().__init__(*args, **kwargs)
        self._color = "NO_COLOR" not in os.environ and hasattr(self.stream, "isatty") and bool(self.stream.isatty())

    def _paint(self, status: str) -> str:
        """
        Wrap a status word in ANSI colour codes when colour is active.
        """

        if not self._color:
            return status

        color = _STATUS_COLORS.get(status, "")
        if not color:
            return status

        return f"{color}{status}{_ANSI__RESET}"

    def _emit(self, test: unittest.TestCase, status: str, suffix: str = "") -> None:
        """
        Write one test's two-line summary to the runner's stream.
        """

        full_id = test.id()
        class_path, _, method = full_id.rpartition(".")

        self.stream.writeln(class_path)
        self.stream.writeln(f"  {method}: {self._paint(status)}{suffix}")
        self.stream.flush()

    def startTest(self, test: unittest.TestCase) -> None:
        """
        Skip the base class's "<method> ... " prefix print; the full
        line is emitted by the per-status hooks below.
        """

        unittest.TestResult.startTest(self, test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        """
        Record a passing test and emit "PASS".
        """

        unittest.TestResult.addSuccess(self, test)
        self._emit(test, "PASS")

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record a failing test and emit "FAIL".
        """

        unittest.TestResult.addFailure(self, test, err)
        self._emit(test, "FAIL")

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an unexpected-exception test and emit "ERROR".
        """

        unittest.TestResult.addError(self, test, err)
        self._emit(test, "ERROR")

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        """
        Record a skipped test and emit "SKIP (<reason>)".
        """

        unittest.TestResult.addSkip(self, test, reason)
        self._emit(test, "SKIP", suffix=f" ({reason})")

    def addExpectedFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an expected-failure test and emit "XFAIL".
        """

        unittest.TestResult.addExpectedFailure(self, test, err)
        self._emit(test, "XFAIL")

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        """
        Record an unexpected-success test and emit "XPASS".
        """

        unittest.TestResult.addUnexpectedSuccess(self, test)
        self._emit(test, "XPASS")


class TestslideStyleRunner(unittest.TextTestRunner):
    """
    'unittest.TextTestRunner' wired to 'TestslideStyleResult'. Always
    runs at verbosity 2 so the per-test output is emitted regardless
    of the caller's '--verbose' flag.
    """

    resultclass = TestslideStyleResult

    def __init__(self, *args: object, **kwargs: object) -> None:
        """
        Force verbosity=2 so the per-test summary is always emitted.
        """

        kwargs["verbosity"] = 2
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]


def main() -> None:
    """
    Run 'unittest.TestProgram' with the testslide-style runner.
    Forwards 'sys.argv' so caller-supplied test paths and discovery
    options work exactly as with 'python -m unittest'.
    """

    unittest.TestProgram(
        module=None,
        argv=sys.argv,
        testRunner=TestslideStyleRunner,
        exit=True,
    )


if __name__ == "__main__":
    main()
