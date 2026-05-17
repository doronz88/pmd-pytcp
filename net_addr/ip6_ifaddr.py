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
This module contains IPv6 interface address support class.

net_addr/ip6_ifaddr.py

ver 3.0.5
"""

import hashlib
import secrets
from typing import Self, override

from net_addr.errors import (
    Ip6AddressFormatError,
    Ip6IfAddrFormatError,
    Ip6IfAddrGatewayError,
    Ip6IfAddrSanityError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
)
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MacAddress

# RFC 5453 / RFC 2526 §3 reserved IID range. The Subnet-Router
# Anycast (RFC 4291 §2.6.1) is IID == 0; the Reserved Subnet
# Anycast IIDs are 0xfdff_ffff_ffff_ff80..0xfdff_ffff_ffff_ffff.
# RFC 7217 §5 step 2 and RFC 8981 §3.3.2 both require generators
# to compare against this range and regenerate on a hit.
_RESERVED_SUBNET_ANYCAST_LO = 0xFDFF_FFFF_FFFF_FF80
_RESERVED_SUBNET_ANYCAST_HI = 0xFDFF_FFFF_FFFF_FFFF

# Practical upper bound on retry attempts when the random IID
# happens to land in a reserved range. With 64-bit randomness the
# expected hit rate is ~129 / 2^64 ≈ 7e-18, so any hit beyond a
# handful of retries indicates a broken random source.
_RFC8981__MAX_RETRIES = 10


def _is_reserved_iid(iid: int) -> bool:
    """
    Return True if 'iid' falls in the RFC 5453 / RFC 2526 §3
    reserved range — Subnet-Router Anycast (all-zero) or
    Reserved Subnet Anycast (0xfdff_ffff_ffff_ff80..ffff).
    """

    if iid == 0:
        return True
    return _RESERVED_SUBNET_ANYCAST_LO <= iid <= _RESERVED_SUBNET_ANYCAST_HI


class Ip6IfAddr(IfAddr[Ip6Address, Ip6Network]):
    """
    IPv6 interface address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6
    _gateway: Ip6Address | None

    def __init__(
        self,
        host: Self | tuple[Ip6Address, Ip6Network] | tuple[Ip6Address, Ip6Mask] | str,
        /,
        *,
        gateway: Ip6Address | None = None,
    ) -> None:
        """
        Initialize the IPv6 interface address object.
        """

        if isinstance(host, Ip6IfAddr):
            assert gateway is None, f"Gateway cannot be set when copying an interface address. Got: {gateway!r}"
            self._address = host.address
            self._network = host.network
            self._gateway = host.gateway
            return

        self._gateway = gateway

        if isinstance(host, tuple):
            tuple_address, network_or_mask = host
            self._address = tuple_address
            if isinstance(network_or_mask, Ip6Network):
                self._network = network_or_mask
            elif isinstance(network_or_mask, Ip6Mask):
                self._network = Ip6Network((tuple_address, network_or_mask))
            else:
                raise Ip6IfAddrFormatError(host)
            if self._address not in self._network:
                raise Ip6IfAddrSanityError(host)
            self._validate_gateway(gateway)
            return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip6Address(address)
                self._network = Ip6Network(host)
                self._validate_gateway(gateway)
                return
            except ValueError, Ip6AddressFormatError, Ip6MaskFormatError, Ip6NetworkFormatError:
                pass

        raise Ip6IfAddrFormatError(host)

    @override
    def _validate_gateway(self, address: Ip6Address | None, /) -> None:
        """
        Validate the IPv6 interface address gateway.
        """

        if address is not None and (
            not address.is_global
            and not address.is_link_local
            or address == self._network.address
            or address == self._address
        ):
            raise Ip6IfAddrGatewayError(address)

    @classmethod
    def from_eui64(cls, *, mac_address: MacAddress, ip6_network: Ip6Network) -> Self:
        """
        Create IPv6 EUI64 interface address.
        """

        assert len(ip6_network.mask) == 64, f"The IPv6 EUI64 network address mask must be /64. Got: {ip6_network.mask}"

        interface_id = (
            ((int(mac_address) & 0xFFFFFF000000) << 16) | int(mac_address) & 0xFFFFFF | 0xFFFE000000
        ) ^ 0x0200000000000000

        return cls(
            (
                Ip6Address(int(ip6_network.address) | interface_id),
                Ip6Mask("/64"),
            )
        )

    @classmethod
    def from_rfc8981_temp(cls, *, ip6_network: Ip6Network) -> Self:
        """
        Create an IPv6 interface address with a random Interface
        Identifier per RFC 8981 §3.3.2 (temporary addresses).

        The IID is a fresh 64-bit random draw, regenerated if
        it lands in the RFC 5453 reserved range. Unlike
        'from_rfc7217' (which is deterministic per
        {prefix, mac, secret}), each call returns a different
        IID — the regeneration cycle that gives temporary
        addresses their privacy property.

        Phase 2: callers will pair this generator with the
        per-prefix temp-address state machine and the RFC 6724
        source-address-selection consumer; nd_linux_parity §18b/c.

        Reference: RFC 8981 §3.3.2 (random IID generation).
        Reference: RFC 5453 (reserved IIDs).
        """

        assert (
            len(ip6_network.mask) == 64
        ), f"The IPv6 RFC 8981 temp network address mask must be /64. Got: {ip6_network.mask}"

        for _ in range(_RFC8981__MAX_RETRIES):
            iid = int.from_bytes(secrets.token_bytes(8), byteorder="big")
            if not _is_reserved_iid(iid):
                return cls(
                    (
                        Ip6Address((int(ip6_network.address) & ((1 << 128) - (1 << 64))) | iid),
                        Ip6Mask("/64"),
                    )
                )

        raise RuntimeError(
            f"RFC 8981 temp-IID generator failed to produce a non-reserved IID after "
            f"{_RFC8981__MAX_RETRIES} retries — random source may be broken."
        )

    @classmethod
    def from_rfc7217(
        cls,
        *,
        ip6_network: Ip6Network,
        mac_address: MacAddress,
        secret_key: bytes,
        dad_counter: int = 0,
        network_id: bytes = b"",
    ) -> Self:
        """
        Create an IPv6 interface address with a stable opaque
        Interface Identifier per RFC 7217 §5:

            RID = SHA-256(Prefix || Net_Iface || Network_ID || DAD_Counter || secret_key)
            IID = least-significant 64 bits of RID

        The result is stable per (prefix, mac, secret_key,
        dad_counter, network_id) tuple but unlinkable across
        prefixes — a host at two different networks will look
        like two unrelated hosts to passive observers, which
        the EUI-64 form does not satisfy because it embeds the
        permanent MAC in every IID.

        Per RFC 7217 §5 'secret_key' MUST be at least 128 bits
        (16 bytes); shorter keys are rejected. PyTCP regenerates
        the secret per process at stack init; persistent
        per-machine keys (Linux's 'stable_secret') are out of
        scope for a libray-style stack.

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        assert (
            len(ip6_network.mask) == 64
        ), f"The IPv6 RFC 7217 network address mask must be /64. Got: {ip6_network.mask}"

        assert (
            len(secret_key) >= 16
        ), f"RFC 7217 §5 mandates secret_key length ≥ 128 bits (16 bytes). Got: {len(secret_key)} bytes"

        # Concatenate the PRF inputs in the order specified by
        # RFC 7217 §5. Net_Iface = MAC bytes; DAD_Counter =
        # 1-byte counter (sufficient for any plausible run of
        # consecutive conflicts on a host).
        prf_input = (
            bytes(ip6_network.address)
            + int(mac_address).to_bytes(6, byteorder="big")
            + network_id
            + dad_counter.to_bytes(1, byteorder="big")
            + secret_key
        )
        rid = hashlib.sha256(prf_input).digest()
        # Take the least-significant 64 bits of the SHA-256
        # output as the IID (per RFC 7217 §5).
        iid = int.from_bytes(rid[-8:], byteorder="big")

        return cls(
            (
                Ip6Address((int(ip6_network.address) & ((1 << 128) - (1 << 64))) | iid),
                Ip6Mask("/64"),
            )
        )
