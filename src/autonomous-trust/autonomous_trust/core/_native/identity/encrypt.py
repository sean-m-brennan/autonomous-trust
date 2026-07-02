# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Wrapper for C ``encryptor_t`` — the encryption key pair."""

from .._ffi import ffi

# Re-export Python Encryptor for full API compatibility
from ..._python.identity.encrypt import Encryptor  # noqa: F401


class NativeEncryptor:
    """Read-only view of an ``encryptor_t`` embedded in a public identity."""

    __slots__ = ('_cdata',)

    def __init__(self, *, _cdata=None):
        self._cdata = _cdata

    @property
    def public_key(self) -> bytes:
        """Raw 32-byte Curve25519 public key."""
        return bytes(ffi.buffer(self._cdata.public_key, 32))

    @property
    def public_hex(self) -> str:
        """Hex-encoded public key."""
        return bytes(ffi.buffer(self._cdata.public_hex, 64)).decode('ascii')

    def __repr__(self):
        return f'Encryptor(public_hex={self.public_hex[:16]}...)'
