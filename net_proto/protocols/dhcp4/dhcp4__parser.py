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
This module contains the DHCPv4 packet parser class.

net_proto/protocols/dhcp4/dhcp4__parser.py

ver 3.0.4
"""

from typing import override

from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.dhcp4.dhcp4__base import Dhcp4
from net_proto.protocols.dhcp4.dhcp4__errors import (
    Dhcp4IntegrityError,
)
from net_proto.protocols.dhcp4.dhcp4__header import (
    DHCP4__HEADER__LEN,
    Dhcp4Header,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options


class Dhcp4Parser(Dhcp4, ProtoParser):
    """
    The DHCPv4 packet parser.
    """

    def __init__(self, data_rx: memoryview) -> None:
        """
        Initialize the DHCPv4 packet parser.
        """

        self._frame = data_rx

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the DHCPv4 packet before parsing it.
        """

        if len(self._frame) < DHCP4__HEADER__LEN:
            raise Dhcp4IntegrityError(
                "The minimum packet length must be " f"{DHCP4__HEADER__LEN} bytes, got {len(self._frame)} bytes."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the DHCPv4 packet.
        """

        self._header = Dhcp4Header.from_buffer(self._frame)
        self._options = Dhcp4Options.from_buffer(self._frame[len(self._header) :])

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the DHCPv4 packet after parsing it.
        """
