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

"""
Python wrappers for C ``identity_t`` (private) and ``public_identity_t``.
"""

import uuid as _uuid

from .._ffi import ffi, lib
from .sign import NativeSignature
from .encrypt import NativeEncryptor

# Re-export Python Identity for full API compatibility
from ..._python.identity.identity import (  # noqa: F401
    Identity,
    # Backend-agnostic canonical helpers (operate on the public Identity
    # interface); re-exported so `core.identity.identity` resolves them on the
    # native backend too.
    public_identity_to_canonical,
    public_identity_from_canonical,
)

# libsodium constants
_CRYPTO_SIGN_BYTES = 64
_CRYPTO_BOX_MACBYTES = 16
_CRYPTO_BOX_NONCEBYTES = 24


class PublicIdentity:
    """Wrapper around C ``public_identity_t*``."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, *, _ptr=None, _owned=True):
        self._ptr = _ptr
        self._owned = _owned

    @property
    def uuid(self) -> _uuid.UUID:
        raw = bytes(ffi.buffer(self._ptr.uuid, 16))
        return _uuid.UUID(bytes=raw)

    @property
    def address(self) -> str:
        return ffi.string(self._ptr.address).decode('ascii')

    @property
    def nickname(self) -> str:
        return ffi.string(self._ptr.nickname).decode('utf-8')

    @property
    def signature(self) -> NativeSignature:
        return NativeSignature(_cdata=ffi.addressof(self._ptr, 'signature'))

    @property
    def encryptor(self) -> NativeEncryptor:
        return NativeEncryptor(_cdata=ffi.addressof(self._ptr, 'encryptor'))

    def to_proto_bytes(self) -> bytes:
        """Serialize to protobuf binary."""
        data_ptr = ffi.new('void **')
        data_len = ffi.new('size_t *')
        rc = lib.peer_to_proto(self._ptr, data_ptr, data_len)
        if rc != 0:
            raise RuntimeError(f"peer_to_proto failed with rc={rc}")
        result = bytes(ffi.buffer(data_ptr[0], data_len[0]))
        lib.smrt_deref(data_ptr[0])
        return result

    @classmethod
    def from_proto_bytes(cls, data: bytes) -> 'PublicIdentity':
        """Deserialize from protobuf binary."""
        # Use ffi.new (CFFI-managed memory) — not owned by smrt_ptr
        ptr = ffi.new('public_identity_t *')
        rc = lib.proto_to_peer(data, len(data), ptr)
        if rc != 0:
            raise RuntimeError(f"proto_to_peer failed with rc={rc}")
        return cls(_ptr=ptr, _owned=False)

    def __repr__(self):
        return f'PublicIdentity(nickname={self.nickname!r}, address={self.address!r})'

    def __del__(self):
        if self._owned and self._ptr is not None:
            lib.smrt_deref(self._ptr)


class NativeIdentity:
    """Wrapper around C ``identity_t*`` (contains private keys).

    Provides sign, verify, encrypt, and decrypt operations.
    """

    __slots__ = ('_ptr',)

    def __init__(self, nickname: str, address: str = '',
                 uuid_val: _uuid.UUID | None = None,
                 petname: str = ''):
        """Create a new identity with generated keypairs.

        Args:
            nickname: Zooko ONLINE name for this identity (was ``fullname``);
                      the only name carried on the wire.
            address:  Network address string (up to 32 chars).
            uuid_val: Optional UUID; generated if not provided.
            petname:  Optional local-only Zooko name (NAME_LEN cap).

        petname defaults to "" because the C side accepts NULL
        (identity_init substitutes the empty string), but CFFI doesn't
        let us pass NULL for a `char *` without an extra cast — empty
        strings are simpler and match the C default.
        """
        if uuid_val is None:
            uuid_val = _uuid.uuid4()

        uuid_bytes = ffi.new('unsigned char[16]', uuid_val.bytes)
        addr_bytes = ffi.new('char[]', address.encode('utf-8'))
        name_bytes = ffi.new('char[]', nickname.encode('utf-8'))
        pet_bytes  = ffi.new('char[]', petname.encode('utf-8'))

        ident_ptr = ffi.new('identity_t **')
        ident_ptr[0] = ffi.cast('identity_t *', 0x1)  # non-NULL workaround
        rc = lib.identity_create(uuid_bytes, addr_bytes, name_bytes,
                                 pet_bytes, ident_ptr)
        if rc != 0:
            raise RuntimeError(f"identity_create failed with rc={rc}")
        self._ptr = ident_ptr[0]

    def publish(self) -> PublicIdentity:
        """Extract the public identity (safe to share)."""
        pub_ptr = ffi.new('public_identity_t **')
        pub_ptr[0] = ffi.cast('public_identity_t *', 0x1)
        rc = lib.identity_publish(self._ptr, pub_ptr)
        if rc != 0:
            raise RuntimeError(f"identity_publish failed with rc={rc}")
        return PublicIdentity(_ptr=pub_ptr[0], _owned=True)

    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning the signed message (signature + message)."""
        msg_in = ffi.new('msg_str_t *')
        msg_buf = ffi.new('unsigned char[]', message)
        msg_in.msg = msg_buf
        msg_in.len = len(message)

        msg_out = ffi.new('msg_str_t *')
        # Signed message = signature bytes + original message
        out_len = _CRYPTO_SIGN_BYTES + len(message)
        out_buf = ffi.new('unsigned char[]', out_len)
        msg_out.msg = out_buf
        msg_out.len = out_len

        rc = lib.identity_sign(self._ptr, msg_in, msg_out)
        if rc != 0:
            raise RuntimeError(f"identity_sign failed with rc={rc}")
        return bytes(ffi.buffer(msg_out.msg, msg_out.len))

    def verify(self, pub: PublicIdentity, signed_message: bytes) -> bytes:
        """Verify a signed message, returning the original message."""
        msg_in = ffi.new('msg_str_t *')
        in_buf = ffi.new('unsigned char[]', signed_message)
        msg_in.msg = in_buf
        msg_in.len = len(signed_message)

        msg_out = ffi.new('msg_str_t *')
        out_buf = ffi.new('unsigned char[]', len(signed_message))
        msg_out.msg = out_buf
        msg_out.len = len(signed_message)

        rc = lib.identity_verify(pub._ptr, msg_in, msg_out)
        if rc != 0:
            raise RuntimeError(f"identity_verify failed with rc={rc}")
        return bytes(ffi.buffer(msg_out.msg, msg_out.len))

    def encrypt(self, message: bytes, recipient: PublicIdentity,
                nonce: bytes | None = None) -> tuple[bytes, bytes]:
        """Encrypt a message for a recipient.

        Returns:
            (ciphertext, nonce) tuple.
        """
        if nonce is None:
            nonce_buf = ffi.new('unsigned char[]', _CRYPTO_BOX_NONCEBYTES)
            lib_sodium = ffi.dlopen('libsodium.so')  # noqa - for randombytes
            # Use pre-loaded libsodium
            import ctypes
            sodium = ctypes.CDLL('libsodium.so')
            sodium.randombytes_buf(ctypes.c_void_p(int(ffi.cast('uintptr_t', nonce_buf))),
                                  _CRYPTO_BOX_NONCEBYTES)
        else:
            nonce_buf = ffi.new('unsigned char[]', nonce)

        msg_in = ffi.new('msg_str_t *')
        msg_buf = ffi.new('unsigned char[]', message)
        msg_in.msg = msg_buf
        msg_in.len = len(message)

        cipher_len = len(message) + _CRYPTO_BOX_MACBYTES
        cipher_buf = ffi.new('unsigned char[]', cipher_len)

        rc = lib.identity_encrypt(self._ptr, msg_in, recipient._ptr,
                                  nonce_buf, cipher_buf)
        if rc != 0:
            raise RuntimeError(f"identity_encrypt failed with rc={rc}")
        return (bytes(ffi.buffer(cipher_buf, cipher_len)),
                bytes(ffi.buffer(nonce_buf, _CRYPTO_BOX_NONCEBYTES)))

    def decrypt(self, ciphertext: bytes, sender: PublicIdentity,
                nonce: bytes) -> bytes:
        """Decrypt a message from a sender."""
        cipher_in = ffi.new('msg_str_t *')
        cipher_buf = ffi.new('unsigned char[]', ciphertext)
        cipher_in.msg = cipher_buf
        cipher_in.len = len(ciphertext)

        nonce_buf = ffi.new('unsigned char[]', nonce)
        plain_len = len(ciphertext) - _CRYPTO_BOX_MACBYTES
        plain_buf = ffi.new('unsigned char[]', plain_len)

        rc = lib.identity_decrypt(self._ptr, cipher_in, sender._ptr,
                                  nonce_buf, plain_buf)
        if rc != 0:
            raise RuntimeError(f"identity_decrypt failed with rc={rc}")
        return bytes(ffi.buffer(plain_buf, plain_len))

    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr is not None:
            lib.identity_free(self._ptr)
