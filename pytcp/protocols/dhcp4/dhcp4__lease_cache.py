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
This module contains the DHCPv4 lease cache — a small JSON
file PyTCP uses to remember a prior lease across reboots so
the RFC 2131 §4.4.2 INIT-REBOOT fast-path can ask the
leasing server to re-confirm the cached IP instead of
running a full DISCOVER/OFFER/REQUEST/ACK exchange.

The cache file format is a single JSON object with the
shape:

    {
        "version": 1,
        "address": "192.168.1.145",
        "mask": "255.255.255.0",
        "gateway": "192.168.1.1" | null,
        "server_id": "192.168.1.1",
        "lease_time__sec": 3600,
        "acquired_at_wall": 1701234567.89
    }

'acquired_at_wall' is 'time.time()' at the moment the lease
was acquired — a wall-clock timestamp so freshness can be
evaluated across reboots. The reader rejects a cache file
whose wall-clock-age exceeds 'lease_time__sec'.

Writes go through 'tempfile.mkstemp' + 'os.replace' for
atomic file replacement — a half-written cache from a
crash never reaches the reader. Reads are defensive: any
structural / type / value error returns 'None' so a
corrupted cache cannot crash the lifecycle.

pytcp/protocols/dhcp4/dhcp4__lease_cache.py

ver 3.0.4
"""

import json
import os
import tempfile
import time
from typing import TYPE_CHECKING, Any

from net_addr import Ip4Address, Ip4Host, Ip4Mask
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Lease

# Bump on incompatible format changes; reader rejects unknown
# versions so an older PyTCP binary will not try to consume
# a cache written by a newer one.
_DHCP4__LEASE_CACHE__VERSION: int = 1


def write_cached_lease(path: str, lease: "Dhcp4Lease", /) -> None:
    """
    Atomically write 'lease' to the JSON file at 'path'. Best-
    effort — any OSError is logged as a WARNING and swallowed so
    a read-only cache directory cannot prevent the DHCPv4
    lifecycle from completing.

    The wall-clock-time-of-acquisition is computed at call time
    via 'time.time()'; the lease's 'acquired_at_monotonic' is
    not portable across reboots and would be useless to a
    future reader.
    """

    if not path:
        return

    payload: dict[str, Any] = {
        "version": _DHCP4__LEASE_CACHE__VERSION,
        "address": str(lease.ip4_host.address),
        "mask": str(lease.ip4_host.network.mask),
        "gateway": (str(lease.ip4_host.gateway) if lease.ip4_host.gateway is not None else None),
        "server_id": str(lease.server_id),
        "lease_time__sec": lease.lease_time__sec,
        "acquired_at_wall": time.time(),
    }

    try:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        # Atomic write: tempfile in the same directory + os.replace.
        # A crash mid-write leaves the prior cache intact.
        fd, tmp_path = tempfile.mkstemp(prefix=".dhcp4_lease.", dir=directory)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, path)
        except BaseException:
            # Cleanup the half-written tempfile on any failure.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Failed to write DHCPv4 lease cache to {path!r}: {error}</>",
        )


def read_cached_lease(path: str, /) -> "Dhcp4Lease | None":
    """
    Return the cached lease at 'path' if the file exists, parses
    cleanly, has a known 'version', and the lease has not yet
    expired by wall-clock time. Return 'None' on any failure —
    missing file, malformed JSON, unknown version, expired
    lease, structural errors. Callers should treat 'None' as
    "no usable cache; proceed with INIT".

    Imports 'Dhcp4Lease' lazily to break the
    'dhcp4__client → dhcp4__lease_cache → dhcp4__client'
    circular import chain.
    """

    from pytcp.protocols.dhcp4.dhcp4__client import (  # noqa: PLC0415 — local for cycle break
        Dhcp4Lease,
    )

    if not path:
        return None

    try:
        with open(path, "r") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Cannot read DHCPv4 lease cache at {path!r}: {error}</>",
        )
        return None

    if not isinstance(payload, dict):
        return None
    if payload.get("version") != _DHCP4__LEASE_CACHE__VERSION:
        return None

    try:
        address = Ip4Address(payload["address"])
        mask = Ip4Mask(payload["mask"])
        gateway_str = payload.get("gateway")
        gateway: Ip4Address | None = Ip4Address(gateway_str) if gateway_str is not None else None
        server_id = Ip4Address(payload["server_id"])
        lease_time__sec = int(payload["lease_time__sec"])
        acquired_at_wall = float(payload["acquired_at_wall"])
    except (KeyError, ValueError, TypeError) as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Malformed DHCPv4 lease cache at {path!r}: {error}</>",
        )
        return None

    # Drop expired leases — RFC 2131 §4.4.2 INIT-REBOOT applies
    # only to a "previously allocated network address" that is
    # still within its lease duration.
    age_s = time.time() - acquired_at_wall
    if age_s < 0 or age_s >= lease_time__sec:
        __debug__ and log(
            "dhcp4",
            f"DHCPv4 lease cache at {path!r} is expired "
            f"(age={age_s:.0f}s, lease_time={lease_time__sec}s); dropping",
        )
        return None

    ip4_host = Ip4Host((address, mask))
    if gateway is not None:
        ip4_host.gateway = gateway

    # The monotonic clock did not exist before this process
    # started, so we cannot reconstruct the original
    # 'acquired_at_monotonic'. Anchor it so the FSM's T1/T2/
    # expiry deadlines (which subtract from this value) line
    # up with the wall-clock age: 'now_mono - age_s' is the
    # monotonic instant that corresponds to the wall-clock
    # acquisition time within the current process.
    acquired_at_monotonic = time.monotonic() - age_s

    return Dhcp4Lease(
        ip4_host=ip4_host,
        lease_time__sec=lease_time__sec,
        server_id=server_id,
        acquired_at_monotonic=acquired_at_monotonic,
    )


def delete_cached_lease(path: str, /) -> None:
    """
    Remove the cache file if it exists. Best-effort — a missing
    file is not an error; an OSError on an existing file is
    logged as a WARNING and swallowed so the DHCPv4 lifecycle
    is never blocked on cache cleanup.
    """

    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Failed to delete DHCPv4 lease cache at {path!r}: {error}</>",
        )
