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
This module contains the client-side mirror of the sysctl control API.

'ClientSysctl' marshals each sysctl operation across the IPC control
channel to the daemon's 'pytcp.stack.sysctl' registry, mirroring the
in-process module functions ('get' / 'set' / 'list_keys' / 'describe' /
'snapshot' / 'reset_to_defaults') with the same signatures.

pytcp/client/client__sysctl.py

ver 3.0.7
"""

from typing import Any, cast

from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__rpc import control_call

_API_NAME: str = "sysctl"


class ClientSysctl:
    """
    The client-side mirror of the sysctl control API.
    """

    def __init__(self, client: IpcClient, /) -> None:
        """
        Bind the sysctl mirror to an IPC client connection.
        """

        self._client = client

    def get(self, key: str) -> Any:
        """
        Get the current value of the sysctl knob 'key'.
        """

        return control_call(self._client, api=_API_NAME, method="get", ifindex=None, args={"key": key})

    def set(self, key: str, value: Any) -> None:
        """
        Set the sysctl knob 'key' to 'value'.
        """

        control_call(self._client, api=_API_NAME, method="set", ifindex=None, args={"key": key, "value": value})

    def list_keys(self) -> list[str]:
        """
        List every registered sysctl key.
        """

        return cast(
            list[str],
            control_call(self._client, api=_API_NAME, method="list_keys", ifindex=None, args={}),
        )

    def describe(self, key: str) -> str:
        """
        Describe the sysctl knob 'key'.
        """

        return cast(
            str,
            control_call(self._client, api=_API_NAME, method="describe", ifindex=None, args={"key": key}),
        )

    def snapshot(self) -> dict[str, Any]:
        """
        Return a snapshot of every sysctl key and its current value.
        """

        return cast(
            dict[str, Any],
            control_call(self._client, api=_API_NAME, method="snapshot", ifindex=None, args={}),
        )

    def reset_to_defaults(self) -> None:
        """
        Reset every sysctl knob to its registered default.
        """

        control_call(self._client, api=_API_NAME, method="reset_to_defaults", ifindex=None, args={})
