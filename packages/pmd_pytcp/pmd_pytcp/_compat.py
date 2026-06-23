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
Backwards-compatibility helpers for Python 3.9+.

pmd_pytcp/_compat.py

ver 3.0.7
"""

from __future__ import annotations

import sys
from typing import TypeVar

_T = TypeVar("_T")

if sys.version_info >= (3, 10):
    # Python 3.10+ has native `slots=` and `kw_only=` on `dataclasses.dataclass`,
    # so the project's decorators work unchanged. Type checkers (run on a modern
    # interpreter) only ever see this branch, keeping full dataclass fidelity.
    from dataclasses import dataclass as dataclass
else:  # pragma: no cover - exercised only on the Python 3.9 back-compat path
    import dataclasses as _dc

    _MISSING = _dc.MISSING

    def dataclass(cls=None, /, **kwargs):  # type: ignore[no-untyped-def]
        """
        Shim for `dataclasses.dataclass` on Python 3.9, which lacks the
        `slots` and `kw_only` keywords (added in 3.10).

        `slots` is dropped (the class keeps `__dict__`; a memory-only
        optimisation). `kw_only=True` is emulated: the class is built with
        `init=False` (so a required field may follow a defaulted one without
        the positional 'non-default argument follows default' error), then a
        keyword-only `__init__` is synthesised from the resolved field list
        (inherited fields included), honouring defaults, default factories,
        `frozen`, and `__post_init__`.
        """

        kwargs.pop("slots", None)
        kw_only = kwargs.pop("kw_only", False)

        def wrap(klass):
            if not kw_only:
                return _dc.dataclass(klass, **kwargs)
            frozen = kwargs.get("frozen", False)
            klass = _dc.dataclass(klass, init=False, **kwargs)
            fields = _dc.fields(klass)

            def __init__(self, **values):
                for field in fields:
                    if field.init and field.name in values:
                        value = values.pop(field.name)
                    elif field.default is not _MISSING:
                        value = field.default
                    elif field.default_factory is not _MISSING:
                        value = field.default_factory()
                    elif field.init:
                        raise TypeError(
                            "__init__() missing required keyword-only "
                            "argument: " + repr(field.name)
                        )
                    else:
                        continue
                    if frozen:
                        object.__setattr__(self, field.name, value)
                    else:
                        setattr(self, field.name, value)
                if values:
                    raise TypeError(
                        "__init__() got unexpected keyword arguments "
                        + repr(list(values))
                    )
                post_init = getattr(self, "__post_init__", None)
                if post_init is not None:
                    post_init()

            __init__.__qualname__ = klass.__qualname__ + ".__init__"
            klass.__init__ = __init__
            return klass

        return wrap if cls is None else wrap(cls)


if sys.version_info >= (3, 12):
    # PEP 688: objects implementing `__buffer__` are first-class buffers, so
    # `bytes()`/`bytearray()`/`memoryview()` accept them directly. No-op here.
    def as_buffer(obj: _T) -> _T:
        return obj
else:  # pragma: no cover - exercised only on the Python 3.9 back-compat path

    def as_buffer(obj):  # type: ignore[no-untyped-def]
        """
        Coerce a `__buffer__`-only object (PEP 688, 3.12+) to `bytes` so it
        can be fed to `bytearray()`/`memoryview()`/`+=` on Python < 3.12.
        Real byte buffers and ints are returned unchanged.
        """

        return bytes(obj) if hasattr(type(obj), "__bytes__") else obj


__all__ = ["dataclass", "as_buffer"]
