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
This module contains the TCP session enums and exception classes.

pytcp/protocols/tcp/tcp__enums.py

ver 3.0.4
"""

from enum import auto

from pytcp.lib.name_enum import NameEnum


class TcpSessionError(Exception):
    """
    Critical errors.
    """


class SysCall(NameEnum):
    """
    System call identifier.
    """

    LISTEN = auto()
    CONNECT = auto()
    CLOSE = auto()


class FsmState(NameEnum):
    """
    TCP Finite State Machine state identifier.
    """

    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RCVD = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSING = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


class ConnError(NameEnum):
    """
    Connection fail reasons.
    """

    NONE = auto()
    REFUSED = auto()
    TIMEOUT = auto()
    CANCELED = auto()
