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

import os
import uuid as uuid_mod
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers, Signature, Encryptor

from .. import TEST_DIR


def test_my_id(setup_teardown):
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    file = os.path.join(TEST_DIR, 'test_my_id')
    t1.to_file(file)
    t2 = Configuration.from_file(file)
    assert repr(t1) == repr(t2)


def test_sig(setup_teardown):
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    file = os.path.join(TEST_DIR, 'test_sig')
    t1.to_file(file)
    t2 = t1.publish()
    msg = t1.sign(b'Message')
    t2.verify(msg)


def test_peers(setup_teardown):
    t3 = Peers()
    p1 = Identity(uuid_mod.uuid4(), '123.4.5.67', 'peer1', Signature.generate(), Encryptor.generate(), 'p1')
    p2 = Identity(uuid_mod.uuid4(), '123.5.6.78', 'peer2', Signature.generate(), Encryptor.generate(), 'p2')
    p3 = Identity(uuid_mod.uuid4(), '123.6.7.89', 'peer3', Signature.generate(), Encryptor.generate(), 'p3')
    assert p1 != p2
    assert p2 != p3
    t3.promote(p1)
    t3.promote(p2)
    t3.promote(p1)
    t3.promote(p3)
    t3.promote(p2)
    t3.promote(p1)
    file = os.path.join(TEST_DIR, 'test_peers')
    t3.to_file(file)
    t4 = Configuration.from_file(file)
    assert repr(t3) == repr(t4)


def test_identity_properties(setup_teardown):
    """Test property accessors for uuid, nickname, petname (lines 86, 88, 90)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    assert t1.uuid is not None
    assert t1.nickname == 'me.myself.i'
    assert t1.petname == 'myself'


def test_verify_with_string(setup_teardown):
    """Test verify when msg is a str (line 101)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    signed = t1.sign(b'hello')
    # verify with SignedMessage (default path)
    result = pub.verify(signed)
    assert result is not None


def test_verify_with_configuration(setup_teardown):
    """Test verify when msg is a Configuration object (line 103)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    # Sign a Configuration object
    signed = t1.sign(pub)
    result = pub.verify(signed)
    assert result is not None


def test_sign_string(setup_teardown):
    """Test sign when msg is a str (line 86 in identity.py sign method)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    signed = t1.sign('hello string')
    pub = t1.publish()
    result = pub.verify(signed)
    assert result is not None


def test_encrypt_decrypt(setup_teardown):
    """Test encrypt/decrypt between two identities (lines 116-120, 130)."""
    t1 = Identity.initialize('alice', 'alice', '127.0.0.1')
    t2 = Identity.initialize('bob', 'bob', '127.0.0.2')
    pub1 = t1.publish()
    pub2 = t2.publish()
    encrypted = t1.encrypt(b'secret message', pub2)
    decrypted = t2.decrypt(encrypted, pub1)
    assert decrypted == b'secret message'


def test_encrypt_string(setup_teardown):
    """Test encrypt when msg is a str (line 118-119)."""
    t1 = Identity.initialize('alice', 'alice', '127.0.0.1')
    t2 = Identity.initialize('bob', 'bob', '127.0.0.2')
    pub2 = t2.publish()
    encrypted = t1.encrypt('string message', pub2)
    assert encrypted is not None


def test_publish(setup_teardown):
    """Test publish returns public-only identity (line 140)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    assert pub._public_only is True
    assert pub.uuid == t1.uuid
    assert pub.nickname == t1.nickname
    assert pub.petname == t1.petname


def test_signature_eq():
    """Test Signature.__eq__ (sign.py line 35)."""
    sig1 = Signature.generate()
    sig2 = Signature.generate()
    assert sig1 != sig2
    assert sig1 == sig1


def test_signature_serialize():
    """Test Signature.serialize (sign.py line 55)."""
    sig = Signature.generate()
    serialized = sig.serialize()
    assert isinstance(serialized, bytes)


def test_sign_public_only_raises(setup_teardown):
    """Test sign with public-only identity raises RuntimeError (line 90)."""
    import pytest
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    with pytest.raises(RuntimeError, match='Cannot sign'):
        pub.sign(b'message')


def test_encrypt_public_only_raises(setup_teardown):
    """Test encrypt with public-only identity raises RuntimeError (line 117)."""
    import pytest
    t1 = Identity.initialize('alice', 'alice', '127.0.0.1')
    t2 = Identity.initialize('bob', 'bob', '127.0.0.2')
    pub1 = t1.publish()
    pub2 = t2.publish()
    with pytest.raises(RuntimeError, match='Cannot encrypt'):
        pub1.encrypt(b'message', pub2)


def test_verify_with_separate_signature(setup_teardown):
    """Test verify with separate msg and signature args (line 106)."""
    from nacl.encoding import HexEncoder
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    signed = t1.sign(b'hello')
    # The separate-args path expects raw bytes, not hex-encoded
    # Decode hex first to get raw message and signature
    raw_signed = HexEncoder.decode(signed)
    sig_bytes = raw_signed[:64]
    msg_bytes = raw_signed[64:]
    result = pub.signature.public.verify(msg_bytes, sig_bytes)
    assert result is not None


def test_verify_string_msg(setup_teardown):
    """Test verify when msg is a plain string (line 101)."""
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    pub = t1.publish()
    signed = t1.sign('test string')
    result = pub.verify(signed)
    assert result is not None


def test_public_identity_canonical_roundtrip(setup_teardown):
    # DRY canonical public-identity payload (confirm + full_history peer
    # bundle): flat schema byte-shape identical to C public_identity_to_json,
    # so a C peer can parse it. Round-trip must preserve uuid + both pubkeys.
    from autonomous_trust.core.identity.identity import (
        public_identity_to_canonical, public_identity_from_canonical)
    ident = Identity.initialize('alice.a.x', 'al', '10.0.0.3')
    can = public_identity_to_canonical(ident)
    assert can['typename'] == 'identity'
    assert len(can['signature']['hex_seed']) == 64
    assert len(can['encryptor']['hex_seed']) == 64
    assert set(can) >= {'uuid', 'address', 'nickname', 'signature', 'encryptor'}
    # petname is a Zooko local name: must NOT appear in the wire form.
    assert 'petname' not in can
    back = public_identity_from_canonical(can)
    assert str(back.uuid) == str(ident.uuid)
    assert back.signature.publish() == ident.signature.publish()
    assert back.encryptor.publish() == ident.encryptor.publish()
    assert back.nickname == ident.nickname
    # malformed input → None (no crash)
    assert public_identity_from_canonical({'uuid': 'x'}) is None
    assert public_identity_from_canonical('nope') is None
