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
Testslide-style 'unittest' runner for the PyTCP test suites. Mirrors
the on-screen layout testslide used while it was the project's
runner: bold class path, colour-coded indented method names (no
"PASS"/"FAIL" word — colour is the indicator), and a summary block
listing successful / failed / skipped counts.

tests_runner.py

ver 3.0.4
"""


import os
import sys
import time
import unittest
from typing import Any

# ANSI SGR escape sequences for colorising output. Honours NO_COLOR
# (https://no-color.org/) and degrades to no-op strings when the
# output stream is not a TTY (decided once in TestslideStyleResult).
_ANSI__RESET = "\033[0m"
_ANSI__BOLD = "\033[1m"
_ANSI__DIM = "\033[2m"
_ANSI__RED = "\033[31m"
_ANSI__GREEN = "\033[32m"
_ANSI__YELLOW = "\033[33m"
_ANSI__MAGENTA = "\033[35m"

# Map outcome -> ANSI colour for the indented method-name line.
_OUTCOME_COLORS: dict[str, str] = {
    "pass": _ANSI__GREEN,
    "fail": _ANSI__RED,
    "error": _ANSI__RED,
    "skip": _ANSI__YELLOW,
    "xfail": _ANSI__YELLOW,
    "xpass": _ANSI__MAGENTA,
}


class TestslideStyleResult(unittest.TextTestResult):
    """
    'unittest.TextTestResult' that prints testslide-style two-line
    output per test (bold class path, colour-coded method name) and
    a testslide-style summary block at the end of the run.
    """

    _color: bool
    _current_class_path: str | None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Detect whether the output stream supports ANSI colour and
        seed the per-class deduplication state.
        """

        super().__init__(*args, **kwargs)
        self._color = "NO_COLOR" not in os.environ and hasattr(self.stream, "isatty") and bool(self.stream.isatty())
        self._current_class_path = None

    def _wrap(self, text: str, *codes: str) -> str:
        """
        Wrap 'text' in the given ANSI codes when colour is active.
        Always emits a leading reset so partial state from the prior
        line cannot bleed into this one (matches testslide).
        """

        if not self._color or not codes:
            return text

        return f"{_ANSI__RESET}{''.join(codes)}{text}{_ANSI__RESET}"

    def _emit(self, test: unittest.TestCase, outcome: str, suffix: str = "") -> None:
        """
        Print one test in the testslide two-line layout: a bold class
        path on a class transition, followed by an indented coloured
        method name (with optional trailing ': <error>' for failures).
        """

        full_id = test.id()
        class_path, _, method = full_id.rpartition(".")

        if class_path != self._current_class_path:
            self.stream.writeln(self._wrap(class_path, _ANSI__BOLD))
            self._current_class_path = class_path

        color = _OUTCOME_COLORS[outcome]
        self.stream.writeln(self._wrap(f"  {method}{suffix}", color))
        self.stream.flush()

    @staticmethod
    def _format_exception_short(err: Any) -> str:
        """
        Render an exc_info triple as "<ExceptionType>: <message>" for
        the trailing fragment on a failed-test line.
        """

        exc_type, exc_value, _ = err
        return f"{exc_type.__name__}: {exc_value}"

    def startTest(self, test: unittest.TestCase) -> None:
        """
        Bypass the base class's "<method> ... " prefix print; the
        per-status hooks below are responsible for all output.
        """

        unittest.TestResult.startTest(self, test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        """
        Record a passing test and emit a green method-name line.
        """

        unittest.TestResult.addSuccess(self, test)
        self._emit(test, "pass")

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record a failing test and emit a red method-name line with
        the trailing exception summary.
        """

        unittest.TestResult.addFailure(self, test, err)
        self._emit(test, "fail", suffix=f": {self._format_exception_short(err)}")

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an unexpected-exception test and emit a red
        method-name line with the trailing exception summary.
        """

        unittest.TestResult.addError(self, test, err)
        self._emit(test, "error", suffix=f": {self._format_exception_short(err)}")

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        """
        Record a skipped test and emit a yellow method-name line.
        """

        unittest.TestResult.addSkip(self, test, reason)
        self._emit(test, "skip")

    def addExpectedFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an expected-failure test and emit a yellow
        method-name line.
        """

        unittest.TestResult.addExpectedFailure(self, test, err)
        self._emit(test, "xfail")

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        """
        Record an unexpected-success test and emit a magenta
        method-name line.
        """

        unittest.TestResult.addUnexpectedSuccess(self, test)
        self._emit(test, "xpass")

    def printErrors(self) -> None:
        """
        Print a testslide-style 'Failures:' block listing every
        failure / error with its exception summary and traceback.
        Replaces the default unittest dashed-section format.
        """

        if not (self.failures or self.errors):
            return

        self.stream.writeln()
        self.stream.writeln(self._wrap("Failures:", _ANSI__RED))
        self.stream.writeln()

        index = 0
        for test, formatted_tb in self.failures + self.errors:
            index += 1
            class_path, _, method = test.id().rpartition(".")
            self.stream.writeln(self._wrap(f"  {index}) {class_path}: {method}", _ANSI__BOLD))
            # Pull the final exception line from the formatted traceback;
            # the rest is the traceback context, which we re-print verbatim.
            tb_lines = formatted_tb.rstrip("\n").splitlines()
            exception_line = tb_lines[-1] if tb_lines else ""
            self.stream.writeln(self._wrap(f"    {index}) {exception_line}", _ANSI__RED))
            # Drop the boilerplate 'Traceback (most recent call last):'
            # header — testslide prints just the frame lines.
            frame_lines = tb_lines[:-1]
            if frame_lines and frame_lines[0].startswith("Traceback"):
                frame_lines = frame_lines[1:]
            for line in frame_lines:
                self.stream.writeln(line)
            self.stream.writeln()

        self.stream.flush()


class TestslideStyleRunner(unittest.TextTestRunner):
    """
    'unittest.TextTestRunner' wired to 'TestslideStyleResult' and a
    testslide-style summary printer. Always runs at verbosity 2 so
    the per-test output is emitted regardless of the caller's flags.
    """

    resultclass = TestslideStyleResult

    def __init__(self, *args: object, **kwargs: object) -> None:
        """
        Force verbosity=2 so the per-test summary is always emitted.
        """

        kwargs["verbosity"] = 2
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def run(self, test: Any) -> Any:
        """
        Run the test suite, then print the testslide-style summary
        block in place of the default 'OK' / 'FAILED (...)' line.
        """

        result = self.resultclass(self.stream, self.descriptions, 2)
        unittest.signals.registerResult(result)
        result.failfast = self.failfast
        result.buffer = self.buffer
        result.tb_locals = self.tb_locals

        start = time.perf_counter()
        try:
            test(result)
        finally:
            elapsed = time.perf_counter() - start

        if isinstance(result, TestslideStyleResult):
            result.printErrors()
            self._print_summary(result, elapsed)

        return result

    def _print_summary(self, result: TestslideStyleResult, elapsed: float) -> None:
        """
        Emit the testslide-style summary block.
        """

        successful = (
            result.testsRun
            - len(result.failures)
            - len(result.errors)
            - len(result.skipped)
            - len(result.expectedFailures)
            - len(result.unexpectedSuccesses)
        )
        failed = len(result.failures) + len(result.errors)
        skipped = len(result.skipped) + len(result.expectedFailures)
        unexpected = len(result.unexpectedSuccesses)

        def _line(label: str, count: int, color: str) -> str:
            text = f"  {label}: {count}"
            return result._wrap(text, color if count else _ANSI__DIM)

        self.stream.writeln()
        self.stream.writeln(
            result._wrap(
                f"Executed {result.testsRun} examples in {elapsed:.1f}s:",
                _ANSI__BOLD,
            )
        )
        self.stream.writeln(_line("Successful", successful, _ANSI__GREEN))
        self.stream.writeln(_line("Failed", failed, _ANSI__RED))
        self.stream.writeln(_line("Skipped", skipped, _ANSI__YELLOW))
        self.stream.writeln(_line("Not executed", 0, _ANSI__DIM))
        if unexpected:
            self.stream.writeln(_line("Unexpected pass", unexpected, _ANSI__MAGENTA))
        self.stream.flush()


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
