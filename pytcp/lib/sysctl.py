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
This module contains the runtime-tunable sysctl knob registry
— PyTCP's equivalent of the Linux net.* sysctl namespace.
Policy constants in protocol packages register themselves at
import time; operators read and write live values through
'pytcp.stack.sysctl["<dotted.key>"]' or via 'stack.init()'
kwargs at boot.

Design + classification rules: docs/refactor/sysctl_framework.md
Workflow for adding a knob: .claude/skills/sysctl_knob/SKILL.md

pytcp/lib/sysctl.py

ver 3.0.4
"""

import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Generator, Iterator


@dataclass(slots=True)
class _Knob:
    """
    Single registry entry. Tracks the dotted-name canonical
    key, the backing module + attribute that holds the live
    value, the registration-time default (for restore), and an
    optional per-knob validator.
    """

    key: str
    module_name: str
    attr: str
    default: Any
    validator: Callable[[Any], None] | None
    description: str


_registry: dict[str, _Knob] = {}
_finalize_validators: list[Callable[[], None]] = []


def register(
    *,
    key: str,
    module_name: str,
    attr: str,
    default: Any,
    validator: Callable[[Any], None] | None = None,
    description: str = "",
) -> None:
    """
    Register a runtime-tunable knob. Called from inside a
    protocol package's '*__constants.py' module at import
    time, once per knob. The 'module_name' is the calling
    module's '__name__'; the registry resolves it via
    'sys.modules' on each access so the binding survives
    re-imports.
    """

    _registry[key] = _Knob(
        key=key,
        module_name=module_name,
        attr=attr,
        default=default,
        validator=validator,
        description=description,
    )


def register_finalize_validator(callback: Callable[[], None], /) -> None:
    """
    Register a cross-knob constraint callback. The callback is
    invoked from 'finalize_validators()' (called at the end of
    'stack.init()' and on every individual 'set()'). It must
    raise 'ValueError' on rejection — the registry re-raises
    the first failure verbatim.
    """

    _finalize_validators.append(callback)


def _resolve(key: str) -> _Knob:
    """
    Look up the registry entry for a key, raising 'KeyError'
    with a self-explanatory message on miss.
    """

    knob = _registry.get(key)
    if knob is None:
        raise KeyError(f"unknown sysctl: {key!r}")
    return knob


def get(key: str) -> Any:
    """
    Return the live value of the named sysctl by reading the
    backing module attribute through 'getattr'. Raises
    'KeyError' with the offending key in the message when no
    such knob is registered.
    """

    knob = _resolve(key)
    return getattr(sys.modules[knob.module_name], knob.attr)


def set(key: str, value: Any) -> None:
    """
    Set the live value of the named sysctl. Runs the per-knob
    validator (if any) before the write so a rejected value
    never leaks through to the backing attribute. Raises
    'KeyError' on unknown keys, 'ValueError' on validator
    rejection (with both the offending key and the value in
    the message).
    """

    knob = _resolve(key)
    if knob.validator is not None:
        knob.validator(value)
    setattr(sys.modules[knob.module_name], knob.attr, value)


def list_keys() -> list[str]:
    """
    Return the list of registered keys in registration order.
    Drives operator-facing discovery ('sysctl --list'-style).
    """

    return list(_registry.keys())


def describe(key: str) -> str:
    """
    Return the human-readable description string registered
    with the knob. Empty string when no description was given.
    """

    return _resolve(key).description


def snapshot() -> dict[str, Any]:
    """
    Return a snapshot of every registered key's current live
    value. Used for debug dumps and as a save-point for
    'reset_to_defaults'-style restoration.
    """

    return {key: get(key) for key in _registry}


def reset_to_defaults() -> None:
    """
    Restore every registered knob's backing attribute to the
    value passed at registration time. Used by 'stack.stop()'
    and test teardown to guarantee per-run mutation does not
    leak across runs.
    """

    for knob in _registry.values():
        setattr(sys.modules[knob.module_name], knob.attr, knob.default)


def finalize_validators() -> None:
    """
    Run every registered cross-knob constraint. Called at the
    end of 'stack.init()' after all kwargs have been applied,
    and on every individual 'set()' so runtime mutation that
    breaks a cross-knob constraint also fails fast. Each
    constraint is a callable that raises 'ValueError' on
    rejection — the registry re-raises the first failure
    verbatim.
    """

    for validator in _finalize_validators:
        validator()


@contextmanager
def override(key: str, value: Any) -> Generator[None, None, None]:
    """
    Context manager that mutates a sysctl on enter and
    restores the prior value on exit. Restoration runs even
    when the wrapped block raises.
    """

    prior = get(key)
    set(key, value)
    try:
        yield
    finally:
        set(key, prior)


class _SysctlRegistry:
    """
    Dict-like facade over the registry, exposed as the
    'pytcp.lib.sysctl.sysctl' singleton. Forwards subscript
    access to the module-level 'get' / 'set' functions.
    """

    def __getitem__(self, key: str) -> Any:
        """
        Return the live value of the named sysctl.
        """

        return get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Set the live value of the named sysctl.
        """

        set(key, value)

    def __contains__(self, key: object) -> bool:
        """
        Test whether the registry contains the named sysctl.
        """

        return isinstance(key, str) and key in _registry

    def __iter__(self) -> Iterator[str]:
        """
        Iterate over the registered keys in registration order.
        """

        return iter(_registry)

    def __len__(self) -> int:
        """
        Return the number of registered keys.
        """

        return len(_registry)


sysctl = _SysctlRegistry()


def is_positive_int(name: str) -> Callable[[Any], None]:
    """
    Build a validator that requires a positive (> 0) integer.
    The 'name' is closed over so the rejection message
    surfaces the offending key.
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a positive int.
        """

        # 'isinstance(True, int)' is True in Python so booleans
        # would otherwise pass — reject them explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"sysctl {name!r} must be a positive int; got {value!r}")

    return validator
