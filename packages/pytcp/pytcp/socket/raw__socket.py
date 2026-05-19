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
This module contains the BSD-like Raw socket interface for the stack.

pytcp/socket/raw__socket.py

ver 3.0.6
"""

from __future__ import annotations

import errno
import os
import threading
from typing import TYPE_CHECKING, cast, override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from net_proto.lib.enums import IpProto
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.socket import (
    IPPROTO_IP,
    IPPROTO_IPV6,
    SOL_SOCKET,
    AddressFamily,
    SocketType,
    gaierror,
    socket,
)
from pytcp.socket.socket__bind_helpers import pick_local_ip_address

if TYPE_CHECKING:
    from pytcp.socket.raw__metadata import RawMetadata


class RawSocket(socket):
    """
    The IPv6/IPv4 Raw socket.
    """

    _socket_type = SocketType.RAW

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily,
        type: SocketType = SocketType.RAW,
        protocol: IpProto | None = None,
    ) -> None:
        """
        Initialize the IPv6/IPv4 Raw socket.
        """

        assert type is SocketType.RAW

        # Raw sockets need an explicit IANA next-header value; there
        # is no meaningful default. Mirror Linux 'sys_socket' which
        # returns 'EPROTONOSUPPORT' for 'socket(AF_INET, SOCK_RAW, 0)'.
        if protocol is None:
            raise OSError(errno.EPROTONOSUPPORT, os.strerror(errno.EPROTONOSUPPORT))

        super().__init__()

        self._ip_proto = protocol
        self._address_family = family
        self._packet_rx_md: list[RawMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)

        match self._address_family:
            case AddressFamily.INET6:
                self._local_ip_address = Ip6Address()
                self._remote_ip_address = Ip6Address()
            case AddressFamily.INET4:
                self._local_ip_address = Ip4Address()
                self._remote_ip_address = Ip4Address()

        self._local_port = int(self._ip_proto)
        self._remote_port = 0

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address, Ip6Address] | tuple[Ip4Address, Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._address_family is AddressFamily.INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]") from error

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address=remote_ip_address)
            if local_ip_address.is_unspecified:
                raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]")
        else:
            local_ip_address = self._local_ip_address

        return local_ip_address, remote_ip_address  # type: ignore[return-value]

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option per the BSD 'setsockopt' API. RAW
        sockets honor SOL_SOCKET / IPPROTO_IP / IPPROTO_IPV6
        options through the base-class helpers. 'value' is 'int'
        for scalar options and 'bytes' for IP_OPTIONS.
        """

        if isinstance(value, int) and level == SOL_SOCKET and self._sol_socket_setsockopt(optname, value):
            return
        if level == IPPROTO_IP and self._ipproto_ip_setsockopt(optname, value):
            return
        if isinstance(value, int) and level == IPPROTO_IPV6 and self._ipproto_ipv6_setsockopt(optname, value):
            return
        raise OSError(
            errno.ENOPROTOOPT,
            f"setsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option per the BSD 'getsockopt' API.
        Symmetric to 'setsockopt': 'int' for scalar options,
        'bytes' for IP_OPTIONS.
        """

        value: int | bytes | None
        if level == SOL_SOCKET and (value := self._sol_socket_getsockopt(optname)) is not None:
            return value
        if level == IPPROTO_IP and (value := self._ipproto_ip_getsockopt(optname)) is not None:
            return value
        if level == IPPROTO_IPV6 and (value := self._ipproto_ipv6_getsockopt(optname)) is not None:
            return value
        raise OSError(
            errno.ENOPROTOOPT,
            f"getsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    @override
    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address.

        local_ip_address: Ip6Address | Ip4Address

        match self._address_family:
            case AddressFamily.INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(stack.packet_handler.ip6_unicast) | {
                        Ip6Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

            case AddressFamily.INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(stack.packet_handler.ip4_unicast) | {
                        Ip4Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip4AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        stack.sockets[self.socket_id] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    @override
    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local IP address (will
        # rebind if necessary) and specific remote IP address.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("connect(): port must be 0-65535. - [Port out of range]")

        # Set local and remote ip addresses appropriately
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[self.socket_id] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Connected socket")

    @override
    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.
        if self._remote_ip_address.is_unspecified:
            raise OSError(
                errno.EDESTADDRREQ,
                "Destination address required - [Socket has no destination address set]",
            )

        match self._address_family:
            case AddressFamily.INET6:
                tx_status = stack.packet_handler.send_ip6_packet(
                    ip6__local_address=cast(Ip6Address, self._local_ip_address),
                    ip6__remote_address=cast(Ip6Address, self._remote_ip_address),
                    ip6__next=self._ip_proto,
                    ip6__payload=data,
                    ip6__hop=self._effective_ip_ttl(),
                    ip6__ecn=self._effective_ip_ecn(),
                )
            case AddressFamily.INET4:
                tx_status = stack.packet_handler.send_ip4_packet(
                    ip4__local_address=cast(Ip4Address, self._local_ip_address),
                    ip4__remote_address=cast(Ip4Address, self._remote_ip_address),
                    ip4__proto=self._ip_proto,
                    ip4__payload=data,
                    ip4__ttl=self._effective_ip_ttl(),
                    ip4__ecn=self._effective_ip_ecn(),
                )

        sent_data_len = len(data) if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING else 0

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    @override
    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send the data to remote host.
        """

        # Set local and remote ip addresses appropriately
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        match self._address_family:
            case AddressFamily.INET6:
                tx_status = stack.packet_handler.send_ip6_packet(
                    ip6__local_address=cast(Ip6Address, local_ip_address),
                    ip6__remote_address=cast(Ip6Address, remote_ip_address),
                    ip6__next=self._ip_proto,
                    ip6__payload=data,
                    ip6__hop=self._effective_ip_ttl(),
                    ip6__ecn=self._effective_ip_ecn(),
                )
            case AddressFamily.INET4:
                tx_status = stack.packet_handler.send_ip4_packet(
                    ip4__local_address=cast(Ip4Address, local_ip_address),
                    ip4__remote_address=cast(Ip4Address, remote_ip_address),
                    ip4__proto=self._ip_proto,
                    ip4__payload=data,
                    ip4__ttl=self._effective_ip_ttl(),
                    ip4__ecn=self._effective_ip_ecn(),
                )

        sent_data_len = len(data) if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING else 0

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    @override
    def recv(self, bufsize: int | None = None, timeout: float | None = None) -> bytes:
        """
        Read data from socket.
        """

        # SO_RCVTIMEO supplies the default if no per-call timeout.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if acquired:
            data_rx = self._packet_rx_md.pop(0).raw__data
            # POSIX recv(2) on SOCK_RAW truncates the packet to
            # 'bufsize' bytes and silently discards the remainder.
            if bufsize is not None:
                data_rx = data_rx[:bufsize]
            if not self._packet_rx_md:
                self._drain_readable()
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - Received {len(data_rx)} bytes of data",
            )
            return bytes(data_rx)  # Note: Conversion: memoryview -> bytes

        if effective_timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("RAW Socket - Receive operation timed out.")

    @override
    def recvfrom(self, bufsize: int | None = None, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        """
        Read data from socket.
        """

        # SO_RCVTIMEO supplies the default if no per-call timeout.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if acquired:
            packet_rx_md = self._packet_rx_md.pop(0)
            data_rx = packet_rx_md.raw__data
            if bufsize is not None:
                data_rx = data_rx[:bufsize]
            if not self._packet_rx_md:
                self._drain_readable()
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - Received {len(data_rx)} bytes of data",
            )
            return (
                bytes(data_rx),  # Note: Conversion: memoryview -> bytes
                (
                    str(packet_rx_md.ip__remote_address),
                    0,
                ),
            )

        if effective_timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("RAW Socket - Receive operation timed out.")

    @override
    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.pop(self.socket_id, None)
        self._close_io_runtime()

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_raw_packet(self, packet_rx_md: RawMetadata) -> None:
        """
        Process incoming packet's metadata.
        """

        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()
        self._signal_readable()
