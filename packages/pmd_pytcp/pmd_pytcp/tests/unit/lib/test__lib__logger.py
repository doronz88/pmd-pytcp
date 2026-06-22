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
This module contains tests for the 'log' function.

pmd_pytcp/tests/unit/lib/test__lib__logger.py

ver 3.0.7
"""

import io
import logging
import time
from contextlib import contextmanager
from typing import Iterator
from unittest import TestCase
from unittest.mock import patch

from pmd_pytcp.lib.logger import LOG__START_TIME, log


@contextmanager
def _capture_log(*, channels: set[str] = frozenset({"stack"}), debug: bool = False) -> Iterator[io.StringIO]:
    """Capture 'log()' output.

    The stack emits every channel through the 'pmd_pytcp' logger at DEBUG (via the standard
    logging module), so a test attaches a StreamHandler at DEBUG and reads the formatted
    record back. 'LOG__CHANNEL' / 'LOG__DEBUG' still gate eligibility and the caller segment.
    """

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("pmd_pytcp")
    saved_level, saved_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        with (
            patch("pmd_pytcp.stack.LOG__CHANNEL", set(channels)),
            patch("pmd_pytcp.stack.LOG__DEBUG", debug),
        ):
            yield stream
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved_level)
        logger.propagate = saved_propagate


class TestLoggerStartTime(TestCase):
    """
    The 'logger.LOG__START_TIME' module constant tests.
    """

    def test__logger__start_time_is_float(self) -> None:
        """
        Ensure 'LOG__START_TIME' was captured as a float at import time,
        so timestamp deltas computed inside 'log()' stay numeric.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            LOG__START_TIME,
            float,
            msg="logger.LOG__START_TIME must be a float captured at module import.",
        )

    def test__logger__start_time_not_in_future(self) -> None:
        """
        Ensure 'LOG__START_TIME' is not set in the future relative to
        the current wall-clock reading — guards against a typo that
        would swap 'time.time()' for some other arithmetic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertLessEqual(
            LOG__START_TIME,
            time.time(),
            msg="logger.LOG__START_TIME must be <= the current wall-clock time.",
        )


class TestLoggerChannelGate(TestCase):
    """
    The 'log()' channel-gating tests.
    """

    def test__logger__channel_not_in_log_channel__returns_false(self) -> None:
        """
        Ensure 'log()' returns False and writes nothing when the channel
        is not in 'LOG__CHANNEL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            result = log("disabled-channel", "irrelevant message")

        self.assertFalse(
            result,
            msg="log() must return False when the channel is disabled.",
        )
        self.assertEqual(
            stream.getvalue(),
            "",
            msg="log() must not emit anything when the channel is disabled.",
        )

    def test__logger__channel_in_log_channel__returns_true(self) -> None:
        """
        Ensure 'log()' returns True and emits a non-empty line when the
        channel is enabled and the logger is at DEBUG.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            result = log("stack", "hello")

        self.assertTrue(
            result,
            msg="log() must return True when the channel is enabled and DEBUG is on.",
        )
        self.assertNotEqual(
            stream.getvalue(),
            "",
            msg="log() must emit a record when the channel is enabled.",
        )

    def test__logger__channel_enabled_but_logger_below_debug__returns_false(self) -> None:
        """
        Ensure 'log()' is a cheap no-op when the host has not enabled DEBUG
        for the 'pmd_pytcp' logger, even if the channel is in 'LOG__CHANNEL'.
        This is what lets the stack stay silent by default without a host shim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        logger = logging.getLogger("pmd_pytcp")
        saved_level = logger.level
        logger.setLevel(logging.WARNING)
        try:
            with (
                patch("pmd_pytcp.stack.LOG__CHANNEL", {"stack"}),
                patch("pmd_pytcp.stack.LOG__DEBUG", False),
            ):
                result = log("stack", "hello")
        finally:
            logger.setLevel(saved_level)

        self.assertFalse(
            result,
            msg="log() must return False (and not format) when 'pmd_pytcp' is below DEBUG.",
        )


class TestLoggerPlainOutput(TestCase):
    """
    The 'log()' non-debug output-formatting tests.
    """

    def test__logger__plain_message_ends_with_newline(self) -> None:
        """
        Ensure each emitted record is a single line — the logging
        StreamHandler terminates the formatted record with a newline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "hello")

        self.assertTrue(
            stream.getvalue().endswith("\n"),
            msg="log() output must end with a newline (one record per line).",
        )

    def test__logger__plain_message_contains_channel_upper(self) -> None:
        """
        Ensure the channel name is rendered upper-cased and padded to
        seven characters — the canonical '<b>{channel.upper():7}</>'
        format in the source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "hello")

        self.assertIn(
            "STACK  ",
            stream.getvalue(),
            msg="log() must render the channel name upper-cased and padded to width 7.",
        )

    def test__logger__plain_message_contains_message(self) -> None:
        """
        Ensure the caller-supplied message text appears verbatim in the
        emitted line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "hello world sentinel")

        self.assertIn(
            "hello world sentinel",
            stream.getvalue(),
            msg="log() must render the caller-supplied message verbatim.",
        )

    def test__logger__plain_message_replaces_style_tokens(self) -> None:
        """
        Ensure all style tokens (e.g. '<g>', '</>') are replaced by their
        ANSI escape sequences before output.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "styled")

        output = stream.getvalue()

        self.assertNotIn(
            "<g>",
            output,
            msg="log() must substitute the '<g>' style token before output.",
        )
        self.assertNotIn(
            "</>",
            output,
            msg="log() must substitute the '</>' style token before output.",
        )
        self.assertIn(
            "\33[32m",
            output,
            msg="log() must emit the ANSI green escape for the '<g>' style token.",
        )
        self.assertIn(
            "\33[0m",
            output,
            msg="log() must emit the ANSI reset escape for the '</>' style token.",
        )

    def test__logger__plain_message_substitutes_caller_message_styles(self) -> None:
        """
        Ensure style tokens embedded in the caller's message are also
        substituted (the replacement loop covers the whole line, not just
        the header).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "<WARN>pay attention</>")

        output = stream.getvalue()

        self.assertNotIn(
            "<WARN>",
            output,
            msg="log() must substitute in-message style tokens before output.",
        )
        self.assertIn(
            "\33[1m\33[93m",
            output,
            msg="log() must emit the ANSI escape for an in-message '<WARN>' token.",
        )

    def test__logger__plain_message_omits_caller_info(self) -> None:
        """
        Ensure the non-debug path does not include the 'ClassName.method'
        caller segment that the debug path would add.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log() as stream:
            log("stack", "payload")

        self.assertNotIn(
            "TestLoggerPlainOutput.",
            stream.getvalue(),
            msg="Non-debug log() output must not include a 'ClassName.method' caller segment.",
        )


class TestLoggerDebugOutput(TestCase):
    """
    The 'log()' debug-mode output-formatting tests.
    """

    def test__logger__debug_includes_caller_class_and_method(self) -> None:
        """
        Ensure the debug path formats a 'ClassName.methodName' segment
        using 'inspect.stack()' — the caller must be an instance method
        so the inspected frame has 'self' in its locals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with _capture_log(debug=True) as stream:
            log("stack", "debug-payload")

        output = stream.getvalue()

        self.assertIn(
            "TestLoggerDebugOutput.test__logger__debug_includes_caller_class_and_method",
            output,
            msg="Debug-mode log() must include the caller 'ClassName.methodName' segment.",
        )
        self.assertIn(
            "debug-payload",
            output,
            msg="Debug-mode log() must still render the caller-supplied message.",
        )

    def test__logger__debug_inspect_depth_can_be_tuned(self) -> None:
        """
        Ensure the 'inspect_depth' keyword lets a wrapper push the frame
        lookup one level deeper. The canonical use case is a thin helper
        that still wants the real caller's class/method in the log line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _wrapper() -> None:
            """
            Forward to 'log()' with depth+1 so the inspected frame points
            at this test method, not the wrapper itself.
            """

            log("stack", "depth-payload", inspect_depth=2)

        with _capture_log(debug=True) as stream:
            _wrapper()

        output = stream.getvalue()

        self.assertIn(
            "TestLoggerDebugOutput.test__logger__debug_inspect_depth_can_be_tuned",
            output,
            msg="inspect_depth=2 must make 'log()' look past its immediate caller.",
        )


class TestLoggerSignature(TestCase):
    """
    The 'log()' public signature tests.
    """

    def test__logger__channel_and_message_are_positional_only(self) -> None:
        """
        Ensure 'channel' and 'message' are positional-only (they appear
        before the '/' in the signature). Passing them as keywords must
        raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            log(channel="stack", message="bad")  # type: ignore[call-arg]

    def test__logger__inspect_depth_is_keyword_only(self) -> None:
        """
        Ensure 'inspect_depth' is keyword-only (after the '*'). Passing
        it positionally must raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            log("stack", "msg", 1)  # type: ignore[misc]
