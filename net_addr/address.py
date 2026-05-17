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
This module contains network address base class.

net_addr/address.py

ver 3.0.5
"""

from abc import ABC, abstractmethod
from typing import Self, override

from net_addr.base import Base


class Address(Base, ABC):
    """
    Network address support base class.
    """

    __slots__ = ("_address",)

    _address: int

    @abstractmethod
    def __init__(
        self,
        address: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the network address object. Concrete
        subclasses bind the accepted input forms.
        """

        raise NotImplementedError

    def __int__(self) -> int:
        """
        Get the network address as integer.
        """

        return self._address

    def _format_alt(self, format_spec: str, /) -> str | None:
        """
        Render a type-specific textual format code, or None if
        the code is not recognised by this address type. The
        base type recognises none.
        """

        return None

    def __format__(self, format_spec: str, /) -> str:
        """
        Format the address. An empty spec or one ending in 's'
        yields the text form (str-style width / alignment
        applied); a type-specific text code ('ex' for the
        expanded IP form, 'hy' / 'ci' for MAC notations) is
        rendered by '_format_alt'; otherwise the value is a
        fixed-width integer — 'b' / 'x' / 'X' zero-padded to
        the address-family bit width, 'n' mapping to 'b' for
        32-bit families and 'x' otherwise, with the '#' (radix
        prefix) and '_' (4-digit grouping) modifiers.
        """

        if not format_spec or format_spec[-1] == "s":
            return format(str(self), format_spec)

        alt = self._format_alt(format_spec)
        if alt is not None:
            return alt

        code = format_spec[-1]
        flags = format_spec[:-1]

        if set(flags) - {"#", "_"} or code not in {"b", "x", "X", "n"}:
            raise ValueError(f"Unknown format code {format_spec!r} for object of type {type(self).__name__!r}")

        bits = len(memoryview(self)) * 8

        if code == "n":
            code = "b" if bits == 32 else "x"

        digit_width = bits if code == "b" else bits // 4
        digits = format(self._address, f"0{digit_width}{code}")

        if "_" in flags:
            digits = "_".join(digits[i : i + 4] for i in range(0, len(digits), 4))

        if "#" in flags:
            digits = ("0b" if code == "b" else "0x") + digits

        return digits

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the network address as a memoryview.
        """

        raise NotImplementedError

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the network address with another object.
        """

        return other is self or (isinstance(other, type(self)) and self._address == other._address)

    @override
    def __hash__(self) -> int:
        """
        Get the network address hash value.
        """

        return hash((type(self), self._address))

    def __lt__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address < other._address

    def __le__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address <= other._address

    def __gt__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address > other._address

    def __ge__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address >= other._address

    def __add__(self, other: object, /) -> Self:
        """
        Get the network address advanced by an integer offset.
        An out-of-range result raises the address-type format
        error (delegated to the constructor).
        """

        if not isinstance(other, int):
            return NotImplemented

        return type(self)(self._address + other)

    def __sub__(self, other: object, /) -> Self:
        """
        Get the network address retreated by an integer offset.
        An out-of-range result raises the address-type format
        error (delegated to the constructor).
        """

        if not isinstance(other, int):
            return NotImplemented

        return type(self)(self._address - other)

    @property
    def unspecified(self) -> Self:
        """
        Get the unspecified network address.
        """

        return type(self)()

    @property
    def is_unspecified(self) -> bool:
        """
        Check if the network address is unspecified.
        """

        return self._address == 0
