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
This module contains the methods supporting the stack logging.

pmd_pytcp/lib/logger.py

ver 3.0.7
"""

from __future__ import annotations

import inspect
import logging
import time

LOG__START_TIME = time.time()

#: All stack log channels emit through this logger at DEBUG. The host application controls
#: visibility via the standard logging module (quiet unless it enables DEBUG for 'pmd_pytcp'),
#: so the stack never writes to stderr on its own. 'LOG__CHANNEL' still gates which channels
#: are eligible to emit.
_LOGGER = logging.getLogger("pmd_pytcp")


def _apply_styles(s: str, /) -> str:
    """
    Substitute every supported style token in 's' with its ANSI escape.

    Hardcoded chain of 'str.replace' calls. Faster than iterating a
    {token: escape} dict because each '.replace' is a single C call.
    """

    return (
        s.replace("</>", "\33[0m")
        .replace("<WARN>", "\33[1m\33[93m")
        .replace("<CRIT>", "\33[41m")
        .replace("<INFO>", "\33[1m")
        .replace("<B>", "\33[1m")
        .replace("<I>", "\33[3m")
        .replace("<U>", "\33[4m")
        .replace("<r>", "\33[31m")
        .replace("<lr>", "\33[91m")
        .replace("<g>", "\33[32m")
        .replace("<lg>", "\33[92m")
        .replace("<y>", "\33[33m")
        .replace("<ly>", "\33[93m")
        .replace("<b>", "\33[34m")
        .replace("<lb>", "\33[94m")
        .replace("<c>", "\33[36m")
        .replace("<lc>", "\33[96m")
        .replace("<v>", "\33[35m")
        .replace("<lv>", "\33[95m")
    )


def log(
    channel: str,
    message: str,
    /,
    *,
    inspect_depth: int = 1,
) -> bool:
    """
    Log a message if the channel matches one of the configured channels.
    """

    from pmd_pytcp.stack import LOG__CHANNEL, LOG__DEBUG

    if channel not in LOG__CHANNEL:
        return False

    # Cheap exit before any formatting (incl. the LOG__DEBUG inspect.stack() walk) when the
    # host hasn't enabled DEBUG for the 'pmd_pytcp' logger.
    if not _LOGGER.isEnabledFor(logging.DEBUG):
        return False

    prefix = f" <g>{(time.time() - LOG__START_TIME):07.02f}</> | <b>{channel.upper():7}</>"

    if LOG__DEBUG:
        frame_info = inspect.stack()[inspect_depth]
        caller_self = frame_info.frame.f_locals.get("self")
        if caller_self is not None:
            caller_info = f"{caller_self.__class__.__name__}.{frame_info.function}"
        else:
            caller_info = frame_info.function
        output = f"{prefix} | <c>{caller_info}</> | {message}"
    else:
        output = f"{prefix} | {message}"

    _LOGGER.debug(_apply_styles(output))

    return True


def refresh_log_enabled() -> bool:
    """
    Recompute the fast hot-path gate 'log.enabled'.

    Every hot-path call site is written as 'log.enabled and log(...)':
    the guard is one attribute load on the (already-bound) 'log'
    function, so when logging is off the f-string argument is never
    even built. This replaces the historical 'log.enabled and log(...)'
    pattern, whose guard was compile-time-constant True in any normal
    interpreter run — the message strings for ~500 call sites (many
    per packet) were fully formatted and then thrown away unless the
    process ran under 'python -O' (measured at 30-55% of bulk-transfer
    CPU through the userspace-tunnel stack).

    Called by 'stack.init()' after logging/sysctl configuration is in
    place. A host that flips the 'pmd_pytcp' logger's level (or edits
    'stack.LOG__CHANNEL') at runtime AFTER init must call this again
    to re-arm the gate — the per-call fallback gates inside 'log()'
    still apply either way, so a stale True only costs performance,
    never spurious output.
    """

    from pmd_pytcp.stack import LOG__CHANNEL

    log.enabled = bool(LOG__CHANNEL) and _LOGGER.isEnabledFor(logging.DEBUG)
    return log.enabled


#: Fast hot-path gate (see 'refresh_log_enabled'). Starts True so any
#: pre-'stack.init()' logging behaves exactly as before; the first
#: 'stack.init()' resolves it against the live logging configuration.
log.enabled = True  # type: ignore[attr-defined]
