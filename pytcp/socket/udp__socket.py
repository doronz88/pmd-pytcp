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
This module contains the BSD-like UDP socket interface for the stack.

pytcp/socket/udp__socket.py

ver 3.0.4
"""

from __future__ import annotations

import errno
import os
import threading
from typing import TYPE_CHECKING, override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp import stack
from pytcp.lib.ip_helper import (
    is_address_in_use,
    pick_local_ip_address,
    pick_local_port,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.socket import (
    AddressFamily,
    IpProto,
    SocketType,
    gaierror,
    socket,
)

if TYPE_CHECKING:
    from pytcp.socket.udp__metadata import UdpMetadata


class UdpSocket(socket):
    """
    The IPv6/IPv4 UDP socket.
    """

    _socket_type = SocketType.DGRAM
    _ip_proto = IpProto.UDP

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.DGRAM,
        protocol: IpProto | int | None = IpProto.UDP,
    ) -> None:
        """
        Initialize the IPv6/IPv4 UDP socket.
        """

        assert type is SocketType.DGRAM
        # Accept the BSD 'IPPROTO_IP' (= 0) default-protocol sentinel
        # as equivalent to 'IpProto.UDP' for DGRAM sockets.
        if protocol is None or (protocol.__class__ is int and protocol == 0):
            protocol = IpProto.UDP
        assert protocol is IpProto.UDP

        super().__init__()

        self._address_family = family
        self._local_port = 0
        self._remote_port = 0
        self._packet_rx_md: list[UdpMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)
        self._unreachable = False

        match self._address_family:
            case AddressFamily.INET6:
                self._local_ip_address = Ip6Address()
                self._remote_ip_address = Ip6Address()
            case AddressFamily.INET4:
                self._local_ip_address = Ip4Address()
                self._remote_ip_address = Ip4Address()

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

        if remote_ip_address.is_unspecified:
            self._unreachable = True

        local_ip_address = self._local_ip_address

        if local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address=remote_ip_address)

            if local_ip_address.is_unspecified and not (
                (
                    self._address_family == AddressFamily.INET4 and self._local_port == 68 and remote_address[1] == 67
                )  # The DHCPv4 client operation.
                or (
                    self._address_family == AddressFamily.INET6 and self._local_port == 546 and remote_address[1] == 547
                )  # The DHCPv6 client operation.
            ):
                raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]")

        return (local_ip_address, remote_ip_address)  # type: ignore[return-value]

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

    @override
    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address and specific local port in case provided port equals zero
        # port value will be picked automatically.

        # Check if "bound" already.
        if self._local_port in range(1, 65536):
            raise OSError("[Errno 22] Invalid argument - [Socket bound to specific port already]")

        local_ip_address: Ip4Address | Ip6Address

        match self._address_family:
            case AddressFamily.INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(stack.packet_handler.ip6_unicast) | {
                        Ip6Address()
                    }:
                        raise OSError(
                            "[Errno 99] Cannot assign requested address - [Local IP address not owned by stack]"
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

            case AddressFamily.INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(stack.packet_handler.ip4_unicast) | {
                        Ip4Address()
                    }:
                        raise OSError(
                            "[Errno 99] Cannot assign requested address - [Local IP address not owned by stack]"
                        )
                except Ip4AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

        # Sanity check on local port number.
        if address[1] not in range(0, 65536):
            raise OverflowError("bind(): port must be 0-65535. - [Port out of range]")

        # Confirm or pick local port number.
        if (local_port := address[1]) > 0:
            if is_address_in_use(
                local_ip_address=local_ip_address,
                local_port=local_port,
                address_family=self._address_family,
                socket_type=self._socket_type,
            ):
                raise OSError("[Errno 98] Address already in use - [Local address already in use]")
        else:
            local_port = pick_local_port()

        # Assigning local port makes socket "bound".
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets[self.socket_id] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    @override
    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local IP address (will
        # rebind if necessary), specific local port, specific remote IP address
        # and specific remote port.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("connect(): port must be 0-65535. - [Port out of range]")

        # Assigning local port makes socket "bound" if not "bound" already.
        if (local_port := self._local_port) not in range(1, 65536):
            local_port = pick_local_port()

        # Set local and remote ip addresses appropriately.
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id.
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
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
        if self._remote_ip_address.is_unspecified or self._remote_port == 0:
            raise OSError("[Errno 89] Destination address required - [Socket has no destination address set]")

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError("[Errno 111] Connection refused - [Remote host sent ICMP Unreachable]")

        tx_status = stack.packet_handler.send_udp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=self._remote_port,
            udp__payload=data,
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

        # The 'sendto' call will bind socket to specific local port,
        # will leave local ip address intact.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("sendto(): port must be 0-65535. - [Port out of range]")

        # Assigning local port makes socket "bound" if not "bound" already.
        if self._local_port not in range(1, 65536):
            stack.sockets.pop(self.socket_id, None)
            self._local_port = pick_local_port()
            stack.sockets[self.socket_id] = self

        # Set local and remote ip addresses appropriately.
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        tx_status = stack.packet_handler.send_udp_packet(
            ip__local_address=local_ip_address,
            ip__remote_address=remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=remote_port,
            udp__payload=data,
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

        return bytes(self.recv__mv(bufsize=bufsize, timeout=timeout))

    @override
    def recv__mv(self, bufsize: int | None = None, timeout: float | None = None) -> memoryview:
        """
        Read data from socket as a memoryview.
        """

        # TODO - Implement support for bufsize.

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError("[Errno 111] Connection refused - [Remote host sent ICMP Unreachable]")

        # Per-call 'timeout' takes precedence over 'setblocking()';
        # otherwise non-blocking mode equates to a non-blocking
        # acquire that surfaces as 'BlockingIOError(EAGAIN)'.
        if timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=timeout)

        if acquired:
            data_rx = self._packet_rx_md.pop(0).udp__data
            if not self._packet_rx_md:
                self._drain_readable()
                # Producer race: a packet handler may have appended
                # between the empty-check and the drain; re-check
                # under the GIL and re-signal so the selector wakes.
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - Received {len(data_rx)} bytes of data",
            )
            return data_rx

        if timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("UDP Socket - Receive operation timed out.")

    @override
    def recvfrom(self, bufsize: int | None = None, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        """
        Read data from socket.
        """

        _bytes, (remote_ip, remote_port) = self.recvfrom__mv(bufsize=bufsize, timeout=timeout)

        return bytes(_bytes), (remote_ip, remote_port)

    @override
    def recvfrom__mv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> tuple[memoryview, tuple[str, int]]:
        """
        Read data from socket as a memoryview.
        """

        # TODO - Implement support for bufsize.

        if timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=timeout)

        if acquired:
            packet_rx_md = self._packet_rx_md.pop(0)
            if not self._packet_rx_md:
                self._drain_readable()
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - <lg>Received</> {len(packet_rx_md.udp__data)} bytes of data",
            )
            return (
                packet_rx_md.udp__data,
                (
                    str(packet_rx_md.ip__remote_address),
                    packet_rx_md.udp__remote_port,
                ),
            )

        if timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("UDP Socket - Receive operation timed out.")

    @override
    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.pop(self.socket_id, None)
        self._close_io_runtime()

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_udp_packet(self, packet_rx_md: UdpMetadata) -> None:
        """
        Process incoming packet's metadata.
        """

        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()
        self._signal_readable()

    def notify_unreachable(self) -> None:
        """
        Set the unreachable notification.
        """

        self._unreachable = True

    def notify_time_exceeded(self, *, icmp_type: int, icmp_code: int) -> None:
        """
        Pass an inbound ICMP Time Exceeded notification that the RX
        handler has matched against this socket. RFC 1122 §3.2.2.4
        mandates the transport layer be informed; current behaviour
        is purely a hook (counter bumps in the packet handler) so a
        future MSG_ERRQUEUE / IP_RECVERR feature can deliver this to
        the application without a separate plumbing pass.
        """

        # Accept arguments to keep the future MSG_ERRQUEUE handler's
        # signature stable; the body is intentionally minimal today.
        del icmp_type, icmp_code

    def notify_parameter_problem(self, *, icmp_type: int, icmp_code: int) -> None:
        """
        Pass an inbound ICMP Parameter Problem notification that the
        RX handler has matched against this socket. Same hook shape
        as notify_time_exceeded — RFC 1122 §3.2.2.5 mandates pass-to-
        transport.
        """

        del icmp_type, icmp_code

    def notify_pmtu(self, *, next_hop_mtu: int) -> None:
        """
        Receive a Path-MTU update for this socket's remote peer. The
        per-destination MTU is recorded in 'stack.pmtu_cache' so the
        next 'sendto' call can fragment-or-fail-or-shrink against it.
        Currently a thin shim: the callback's behaviour is just to
        update the cache; the policy for what to do with the smaller
        MTU is deferred to a future feature commit (RFC 4821 / 8899
        active probing).
        """

        stack.pmtu_cache[self._remote_ip_address] = next_hop_mtu
