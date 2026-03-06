# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

"""Wrapper for C ``network_config_t``."""

from .._ffi import ffi, lib

# Re-export Python Network for full API compatibility
from ..._python.network.network import Network  # noqa: F401


# Port constants from network.h
COMM_PORT = 27787
PING_RCV_PORT = COMM_PORT + 2
PING_SND_PORT = PING_RCV_PORT + 1
NTP_PORT = COMM_PORT + 4


def _set_char_field(field, value: str, max_len: int):
    """Copy a Python string into a CFFI char[] field with NUL termination."""
    encoded = value.encode('ascii')
    n = min(len(encoded), max_len)
    ffi.memmove(field, encoded, n)
    field[n] = b'\0'


class NetworkConfig:
    """Read/write wrapper around C ``network_config_t``."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, *, _ptr=None, _owned=False):
        if _ptr is None:
            _ptr = ffi.new('network_config_t *')
            _owned = False  # ffi.new memory is CFFI-managed
        self._ptr = _ptr
        self._owned = _owned

    @property
    def port(self) -> int:
        return self._ptr.port

    @port.setter
    def port(self, value: int):
        self._ptr.port = value

    @property
    def mac_address(self) -> str:
        return ffi.string(self._ptr.mac_address).decode('ascii')

    @mac_address.setter
    def mac_address(self, value: str):
        _set_char_field(self._ptr.mac_address, value, 17)

    @property
    def ip4_cidr(self) -> str:
        return ffi.string(self._ptr.ip4_cidr).decode('ascii')

    @ip4_cidr.setter
    def ip4_cidr(self, value: str):
        _set_char_field(self._ptr.ip4_cidr, value, 19)

    @property
    def mcast4_addr(self) -> str:
        return ffi.string(self._ptr.mcast4_addr).decode('ascii')

    @mcast4_addr.setter
    def mcast4_addr(self, value: str):
        _set_char_field(self._ptr.mcast4_addr, value, 16)

    @property
    def ip6_cidr(self) -> str:
        return ffi.string(self._ptr.ip6_cidr).decode('ascii')

    @ip6_cidr.setter
    def ip6_cidr(self, value: str):
        _set_char_field(self._ptr.ip6_cidr, value, 50)

    @property
    def mcast6_addr(self) -> str:
        return ffi.string(self._ptr.mcast6_addr).decode('ascii')

    @mcast6_addr.setter
    def mcast6_addr(self, value: str):
        _set_char_field(self._ptr.mcast6_addr, value, 46)

    def __repr__(self):
        return (f'NetworkConfig(ip4={self.ip4_cidr!r}, '
                f'ip6={self.ip6_cidr!r}, port={self.port})')

    def __del__(self):
        if self._owned and self._ptr is not None:
            lib.smrt_deref(self._ptr)
            self._ptr = None
