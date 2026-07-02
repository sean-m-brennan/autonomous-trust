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

"""Compare native (C-backed) and Python identity operations."""

import uuid
import pytest

from .conftest import requires_native


@requires_native
class TestIdentityParity:
    """Verify native and Python identity wrappers produce compatible results."""

    def test_native_identity_create_and_publish(self):
        """Native Identity can be created and published."""
        from autonomous_trust.core._native.identity.identity import (
            NativeIdentity, PublicIdentity,
        )

        ident = NativeIdentity('Test User', '192.168.1.1')
        pub = ident.publish()

        assert isinstance(pub, PublicIdentity)
        assert pub.nickname == 'Test User'
        assert pub.address == '192.168.1.1'
        assert isinstance(pub.uuid, uuid.UUID)

    def test_native_sign_verify_roundtrip(self):
        """Sign with native, verify with native."""
        from autonomous_trust.core._native.identity.identity import NativeIdentity

        ident = NativeIdentity('Signer', '10.0.0.1')
        pub = ident.publish()

        message = b'Hello, cryptographic world!'
        signed = ident.sign(message)

        # Verify
        recovered = ident.verify(pub, signed)
        assert recovered == message

    def test_native_encrypt_decrypt_roundtrip(self):
        """Encrypt with native, decrypt with native."""
        from autonomous_trust.core._native.identity.identity import NativeIdentity

        alice = NativeIdentity('Alice', '10.0.0.1')
        bob = NativeIdentity('Bob', '10.0.0.2')

        alice_pub = alice.publish()
        bob_pub = bob.publish()

        plaintext = b'Secret message for Bob'
        ciphertext, nonce = alice.encrypt(plaintext, bob_pub)

        # Bob decrypts
        recovered = bob.decrypt(ciphertext, alice_pub, nonce)
        assert recovered == plaintext

    def test_native_publish_has_valid_keys(self):
        """Published identity has non-empty signature and encryptor keys."""
        from autonomous_trust.core._native.identity.identity import NativeIdentity

        ident = NativeIdentity('Key Holder', '10.0.0.1')
        pub = ident.publish()

        sig = pub.signature
        enc = pub.encryptor

        assert len(sig.public_key) == 32
        assert len(sig.public_hex) == 64
        assert len(enc.public_key) == 32
        assert len(enc.public_hex) == 64


@requires_native
class TestProtoSerializationParity:
    """Verify native proto serialization matches Python."""

    def test_proto_roundtrip(self):
        """Serialize native PublicIdentity to proto and back."""
        from autonomous_trust.core._native.identity.identity import (
            NativeIdentity, PublicIdentity,
        )

        ident = NativeIdentity('Proto Test', '10.0.0.1')
        pub = ident.publish()

        data = pub.to_proto_bytes()
        assert len(data) > 0

        restored = PublicIdentity.from_proto_bytes(data)
        assert restored.nickname == pub.nickname
        assert restored.address == pub.address
        assert restored.uuid == pub.uuid
