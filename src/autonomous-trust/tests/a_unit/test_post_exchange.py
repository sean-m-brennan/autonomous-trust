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
"""Feed post canonical + content-id + signature contract (Increment 7).

Pins the post canonical/content-id/signature the C twin (identity/post.c,
test/post_test.c) must match and the feed-*.yaml conformance corpus asserts
cross-runtime:

  * canonical = author[16] || u64le(seq) || f64le(ts) || u8(tier)
                || u32le(body_len) || body.
  * blake2b-256(canonical) lowercase hex is the content id (dedup/merge key).
  * a detached Ed25519 signature over the canonical verifies against the
    author's key, and binds author+seq+ts+tier+body (any flip fails).

The CANONICAL vector matches C post_test.c's REF_CANON_HEX byte-for-byte; the
content-id and signature literals are the cross-runtime lockstep guard — both
runtimes compute BLAKE2b-256 and Ed25519 over the same canonical, so a one-byte
divergence in either serialization fails these pins.
"""
import hashlib

from nacl.signing import SigningKey

from autonomous_trust.core import capabilities

# Fixed reference input shared with the C twin (post_test.c):
#   author uuid = bytes 0..15, seq = 7, ts = 0.0, tier = 2, body = "hi",
#   author seed = bytes 1..32.
AUTHOR = bytes(range(0, 16))
SEED = bytes(range(1, 33))
REF_CANON_HEX = (
    "000102030405060708090a0b0c0d0e0f"  # author uuid
    "0700000000000000"                  # seq = 7 (u64 le)
    "0000000000000000"                  # ts = 0.0 (f64 le)
    "02"                                # tier = 2
    "02000000"                          # body_len = 2 (u32 le)
    "6869"                              # "hi"
)
REF_CONTENT_ID = \
    "cea547b388f5ad97fa994ce0cbfff1bf62b679ff5a0c4eb6202b51c4c7513e7c"
REF_SIG_HEX = (
    "0c2364a3291286e9c30414be71aba15e819becb140b5039859efa02b56a2e099"
    "3c2802ed0bf1098150912752cd479fa4bd762e352ba7f20434eea77ae44b6206"
)


def test_canonical_matches_pinned_vector():
    assert capabilities.post_canonical(AUTHOR, 7, 0.0, 2, "hi").hex() \
        == REF_CANON_HEX


def test_content_id_matches_pinned_and_is_blake2b():
    cid = capabilities.post_content_id(AUTHOR, 7, 0.0, 2, "hi")
    assert cid == REF_CONTENT_ID
    assert len(cid) == capabilities.POST_ID_HEX_LEN
    # Independently confirm it is blake2b-256 over the canonical.
    assert cid == hashlib.blake2b(
        capabilities.post_canonical(AUTHOR, 7, 0.0, 2, "hi"),
        digest_size=32).hexdigest()


def test_content_id_is_field_sensitive():
    base = capabilities.post_content_id(AUTHOR, 7, 0.0, 2, "hi")
    assert capabilities.post_content_id(AUTHOR, 7, 0.0, 2, "ho") != base
    assert capabilities.post_content_id(AUTHOR, 8, 0.0, 2, "hi") != base
    assert capabilities.post_content_id(AUTHOR, 7, 0.0, 3, "hi") != base
    assert capabilities.post_content_id(AUTHOR, 7, 1.0, 2, "hi") != base


def test_sign_matches_pinned_and_verifies():
    sk = SigningKey(SEED)
    sig = capabilities.post_sign(sk, AUTHOR, 7, 0.0, 2, "hi")
    # Ed25519 is deterministic: the signature is byte-stable and cross-runtime.
    assert sig == REF_SIG_HEX
    assert capabilities.post_verify(sk.verify_key, AUTHOR, 7, 0.0, 2, "hi", sig)


def test_signature_binds_every_field():
    sk = SigningKey(SEED)
    vk = sk.verify_key
    sig = capabilities.post_sign(sk, AUTHOR, 7, 0.0, 2, "hi")
    assert not capabilities.post_verify(vk, AUTHOR, 8, 0.0, 2, "hi", sig)  # seq
    assert not capabilities.post_verify(vk, AUTHOR, 7, 1.0, 2, "hi", sig)  # ts
    assert not capabilities.post_verify(vk, AUTHOR, 7, 0.0, 3, "hi", sig)  # tier
    assert not capabilities.post_verify(vk, AUTHOR, 7, 0.0, 2, "ho", sig)  # body
    other = bytes([0xFF]) + AUTHOR[1:]
    assert not capabilities.post_verify(vk, other, 7, 0.0, 2, "hi", sig)   # author


def test_bad_signature_rejected():
    sk = SigningKey(SEED)
    vk = sk.verify_key
    assert not capabilities.post_verify(vk, AUTHOR, 7, 0.0, 2, "hi", "0" * 128)
    assert not capabilities.post_verify(vk, AUTHOR, 7, 0.0, 2, "hi", "not-hex")
    other = SigningKey(bytes([0xAA]) + bytes(range(2, 33)))
    good = capabilities.post_sign(sk, AUTHOR, 7, 0.0, 2, "hi")
    assert not capabilities.post_verify(other.verify_key, AUTHOR, 7, 0.0, 2,
                                        "hi", good)
