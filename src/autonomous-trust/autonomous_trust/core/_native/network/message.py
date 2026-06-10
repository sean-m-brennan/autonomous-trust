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

"""Wrapper for C ``net_wire_msg_t`` — network wire messages."""

import enum

from .._ffi import ffi, lib
from ..identity import PublicIdentity

# Re-export Python Message for full API compatibility
from ..._python.network.message import Message  # noqa: F401


class RecipientType(enum.IntEnum):
    PEER = 0
    BROADCAST = 1


class NetWireMessage:
    """Wrapper around C ``net_wire_msg_t``."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, *, _ptr=None, _owned=True):
        if _ptr is None:
            _ptr = ffi.new('net_wire_msg_t *')
        self._ptr = _ptr
        self._owned = _owned

    @property
    def process(self) -> str:
        return ffi.string(self._ptr.process).decode('utf-8')

    @process.setter
    def process(self, value: str):
        encoded = value.encode('utf-8')
        n = min(len(encoded), 64)
        ffi.memmove(self._ptr.process, encoded, n)
        self._ptr.process[n] = b'\0'

    @property
    def function(self) -> str:
        if self._ptr.function == ffi.NULL:
            return ''
        return ffi.string(self._ptr.function).decode('utf-8')

    @property
    def data(self) -> bytes:
        if self._ptr.data == ffi.NULL or self._ptr.data_len == 0:
            return b''
        return bytes(ffi.buffer(self._ptr.data, self._ptr.data_len))

    @property
    def data_len(self) -> int:
        return self._ptr.data_len

    @property
    def recipient_type(self) -> RecipientType:
        return RecipientType(self._ptr.to_whom.type)

    @property
    def to_whom(self) -> PublicIdentity:
        return PublicIdentity(
            _ptr=ffi.addressof(self._ptr.to_whom.target, 'peer'),
            _owned=False)

    @property
    def from_whom(self) -> PublicIdentity:
        return PublicIdentity(
            _ptr=ffi.addressof(self._ptr, 'from_whom'),
            _owned=False)

    @property
    def encrypt(self) -> bool:
        return bool(self._ptr.encrypt)

    def to_wire(self) -> bytes:
        """Serialize to wire format bytes."""
        wire_out = ffi.new('uint8_t **')
        wire_len = ffi.new('size_t *')
        # 2nd arg is `const identity_t *signer`; NULL = serialize without
        # signing (matches the C NULL-signer path). Omitting it left the C
        # function reading a garbage pointer for the wire-out slot.
        rc = lib.net_message_to_wire(self._ptr, ffi.NULL, wire_out, wire_len)
        if rc != 0:
            raise RuntimeError(f"net_message_to_wire failed with rc={rc}")
        result = bytes(ffi.buffer(wire_out[0], wire_len[0]))
        lib.smrt_deref(wire_out[0])
        return result

    @classmethod
    def from_wire(cls, data: bytes, peer: PublicIdentity) -> 'NetWireMessage':
        """Deserialize from wire format bytes."""
        msg = ffi.new('net_wire_msg_t *')
        rc = lib.net_message_from_wire(data, len(data), peer._ptr, msg)
        if rc != 0:
            raise RuntimeError(f"net_message_from_wire failed with rc={rc}")
        return cls(_ptr=msg, _owned=True)

    def __repr__(self):
        return (f'NetWireMessage(process={self.process!r}, '
                f'function={self.function!r}, '
                f'data_len={self.data_len})')

    def __del__(self):
        if self._owned and self._ptr is not None:
            lib.net_wire_msg_free(self._ptr)
