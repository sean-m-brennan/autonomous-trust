# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

# Re-export Python Message for full API compatibility. _identity_from_wire is
# re-exported too: the native backend parses envelopes through this same
# Python Message (which calls _identity_from_wire internally), so exposing it
# here keeps `core.network.message` import-compatible across both backends.
from ..._python.network.message import Message, _identity_from_wire  # noqa: F401


class RecipientType(enum.IntEnum):
    PEER = 0
    BROADCAST = 1


#: Envelope-format names accepted by to_wire/from_wire, mapped to the C enum
#: values in network/net_wire_format.h. Spelled here rather than imported from
#: the pure-Python NetWireFormat so the native backend does not depend on it.
_WIRE_FORMATS = {'json': 0, 'proto': 1}


def _fmt_value(name: str) -> int:
    """Map an envelope-format name to its C enum value, refusing anything else.

    Refused rather than defaulted: a caller that passes an unknown name has a
    bug, and silently sending JSON would surface as a peer that cannot read us.
    """
    try:
        return _WIRE_FORMATS[name]
    except KeyError:
        raise ValueError(
            'unknown wire format %r (want one of %s)'
            % (name, '|'.join(sorted(_WIRE_FORMATS)))) from None


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

    def to_wire(self, wire_format: str = 'json') -> bytes:
        """Serialize to wire format bytes.

        `wire_format` is the ENVELOPE encoding (doc/architecture/network-wire-format.md):
        'json' (the
        default, and what every caller outside a group wants) or 'proto'. It is
        a property of the addressed group, not of this message, so the caller
        supplies it -- there is no per-peer negotiation and no detection (§2.5).
        """
        wire_out = ffi.new('uint8_t **')
        wire_len = ffi.new('size_t *')
        # 2nd arg is `const identity_t *signer`; NULL = serialize without
        # signing (matches the C NULL-signer path). Omitting it left the C
        # function reading a garbage pointer for the wire-out slot.
        rc = lib.net_message_to_wire_fmt(self._ptr, ffi.NULL,
                                         _fmt_value(wire_format),
                                         wire_out, wire_len)
        if rc != 0:
            raise RuntimeError(f"net_message_to_wire failed with rc={rc}")
        result = bytes(ffi.buffer(wire_out[0], wire_len[0]))
        lib.smrt_deref(wire_out[0])
        return result

    @classmethod
    def from_wire(cls, data: bytes, peer: PublicIdentity,
                  wire_format: str = 'json') -> 'NetWireMessage':
        """Deserialize from wire format bytes.

        The format is STATED, never inferred: a frame whose marker disagrees is
        refused by the C parser (ENET_WIRE_FORMAT) rather than being handed to
        the other decoder. See doc/architecture/network-wire-format.md.
        """
        msg = ffi.new('net_wire_msg_t *')
        rc = lib.net_message_from_wire_fmt(data, len(data), peer._ptr,
                                           _fmt_value(wire_format), msg)
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
