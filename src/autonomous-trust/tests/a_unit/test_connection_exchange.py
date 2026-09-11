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
"""Explicit connection request/response (Increment 5).

Pins the connection canonical + signature contract the C twin (connection.c /
connection_test.c) must match and the conformance corpus asserts cross-runtime:

  * canonical = requester[16] || accepter[16] || u8(decision) || u64le(seq).
  * a detached Ed25519 signature over it verifies against the accepter's key.
  * the decision (accept/decline) and the freshness seq are bound: a flipped
    decision or a replayed seq does not verify.
  * a bad/forged signature is rejected.

The CANONICAL + SIGNATURE vectors below are the cross-language lockstep guard:
the C connection_test.c asserts the SAME literals, so a one-byte divergence in
either runtime's canonical serialization fails both suites.
"""
from nacl.signing import SigningKey

from autonomous_trust.core import capabilities

# Fixed reference input shared with the C twin (connection_test.c):
#   requester uuid = bytes 0..15, accepter uuid = bytes 16..31,
#   decision = 1 (accept), seq = 7, accepter seed = bytes 1..32.
REQ_UUID = bytes(range(0, 16))
ACC_UUID = bytes(range(16, 32))
SEED = bytes(range(1, 33))
REF_CANON_HEX = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "010700000000000000"
)
REF_SIG_HEX = (
    "ae873deab8e825adae6299cf3721cc4caaf8610eba32825e2eef5323813efbc9"
    "0f9e07dbc83a4eee0e172bb8590f2aa9eb778b8c80794faf8fd147ee512cb505"
)


def test_canonical_matches_pinned_vector():
    assert capabilities.connection_canonical(REQ_UUID, ACC_UUID, 1, 7).hex() \
        == REF_CANON_HEX


def test_sign_matches_pinned_and_verifies():
    sk = SigningKey(SEED)
    sig = capabilities.connection_sign(sk, REQ_UUID, ACC_UUID, 1, 7)
    # Ed25519 is deterministic: the signature is byte-stable and cross-runtime.
    assert sig == REF_SIG_HEX
    assert capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                          1, 7, sig)


def test_accept_and_decline_are_bound():
    sk = SigningKey(SEED)
    accept = capabilities.connection_sign(sk, REQ_UUID, ACC_UUID, 1, 7)
    decline = capabilities.connection_sign(sk, REQ_UUID, ACC_UUID, 0, 7)
    assert accept != decline
    # A decision cannot be flipped under a valid signature.
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                              0, 7, accept)
    assert capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                          0, 7, decline)


def test_replay_seq_binding_rejected():
    sk = SigningKey(SEED)
    sig = capabilities.connection_sign(sk, REQ_UUID, ACC_UUID, 1, 7)
    # The seq is inside the signed bytes, so a replay at another seq fails.
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                              1, 6, sig)
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                              1, 8, sig)


def test_bad_signature_and_reattribution_rejected():
    sk = SigningKey(SEED)
    sig = capabilities.connection_sign(sk, REQ_UUID, ACC_UUID, 1, 7)
    # All-zero (forged) signature.
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                              1, 7, "00" * 64)
    # Re-attribution: a different accepter/requester in the canonical fails.
    other = bytes([ACC_UUID[0] ^ 0xFF]) + ACC_UUID[1:]
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, other,
                                              1, 7, sig)
    # Wrong key.
    sk2 = SigningKey(bytes([0xAA]) + SEED[1:])
    assert not capabilities.connection_verify(sk2.verify_key, REQ_UUID, ACC_UUID,
                                              1, 7, sig)
    # Malformed hex.
    assert not capabilities.connection_verify(sk.verify_key, REQ_UUID, ACC_UUID,
                                              1, 7, "not-hex")


def test_connection_verbs_not_in_unencrypted_allowlist():
    from autonomous_trust.core.identity.protocol import (IdentityProtocol,
                                                         UNENCRYPTED_VERBS)
    assert IdentityProtocol.connection_request not in UNENCRYPTED_VERBS
    assert IdentityProtocol.connection_response not in UNENCRYPTED_VERBS
