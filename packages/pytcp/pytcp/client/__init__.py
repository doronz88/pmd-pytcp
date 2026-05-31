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
This package contains the PyTCP client — the userspace half of the
kernel/userspace boundary.

A client process talks to a running PyTCP daemon over the AF_UNIX IPC
control channel through a surface that mirrors the in-process
'pytcp.stack' control APIs. 'connect()' opens a connection and returns a
'ClientStack' whose '.sysctl' / '.route' / '.link' / '.address' /
'.neighbor' / '.membership' attributes carry the same method signatures
as the daemon-side singletons, marshalling each call across the boundary.

'ClientStack.socket()' opens a socket on the daemon and returns a
'ClientTcpSocket' (STREAM) or 'ClientUdpSocket' (DGRAM) whose data path is
a real, selectable descriptor.

This is an encapsulated subpackage (source_files.md §2.4.1): the only
public symbols are 'connect', 'ClientStack', 'ClientTcpSocket', and
'ClientUdpSocket'; every other module here ('client__*') is private
implementation. The per-API proxy objects are reached through
'ClientStack' attributes, and a socket shim through 'ClientStack.socket()',
never imported directly.

pytcp/client/__init__.py

ver 3.0.7
"""

from pytcp.client.client__tcp_socket import ClientTcpSocket
from pytcp.client.client__udp_socket import ClientUdpSocket
from pytcp.client.client_stack import ClientStack, connect

__all__ = ["ClientStack", "ClientTcpSocket", "ClientUdpSocket", "connect"]
