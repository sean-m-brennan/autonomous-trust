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
"""The credential->identity binding: who may present this credential (ISSUES §1.5).

Real CAs, real leaf keys, real ECDSA signatures over the real pre-image. The thing
under test is whether a signature made for one node verifies for that node and for
nobody else, so a stubbed verifier could not tell -- the same reason
`test_operator_binding.py` drives the real verifiers.

The case that matters most is `test_binding_does_not_verify_for_another_identity`:
that is precisely the harvested-credential replay §1.5 describes, and it is what TOFU
was standing in for.
"""
import hashlib
import os
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

pytest.importorskip("cryptography")

_ROOT = os.path.dirname(os.path.abspath(__file__))
while _ROOT != '/':
    if os.path.isfile(os.path.join(_ROOT, 'tools', 'provision_zta_certs.py')):
        break
    _ROOT = os.path.dirname(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_keypair, cert_der)

from autonomous_trust.core._python.identity.identity import Identity  # noqa: E402
from autonomous_trust.core._python.identity.sign import Signature  # noqa: E402
from autonomous_trust.core._python.identity.encrypt import Encryptor  # noqa: E402
from autonomous_trust.core._python.identity.operator_binding import (  # noqa: E402
    operator_binding_preimage)
from autonomous_trust.core._python.identity.zta_binding import (  # noqa: E402
    ZTA_BINDING_MAX, ZTA_BINDING_PREIMAGE_LEN, ZTA_BINDING_TAG,
    ZTA_SAN_URI_TEMPLATE, credential_fingerprint, identity_is_bound,
    node_signing_pubkey, operator_binding_binds_identity, san_binds_identity,
    verify_zta_binding, zta_binding_preimage)


def _identity(tag: str, seed: bytes = b'11') -> Identity:
    """A deterministic identity, so a binding made here is reproducible across runs.
    NOT `hash(tag)`: str hashing is salted per process, which would make the uuid --
    and therefore the signed pre-image -- differ run to run."""
    digest = hashlib.md5(tag.encode()).digest()   # a label, not a security claim
    return Identity(UUID(bytes=digest), '10.0.0.1', '%s.test' % tag,
                    Signature(seed * 32, public_only=False),
                    Encryptor(b'22' * 32, public_only=False))


def _sign(leaf_key, data: bytes) -> bytes:
    """Sign with the leaf's private key exactly as `_verify_signature` expects for an
    EC credential (ECDSA/SHA-256)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    return leaf_key.sign(data, ec.ECDSA(hashes.SHA256()))


@pytest.fixture
def agency():
    """One agency CA and a leaf credential with its private key -- a machine/device
    credential, the class §1.5 left exposed."""
    ca_key, ca_cert = make_ca('Agency Root')
    leaf_key, leaf_cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert)
    return ca_key, ca_cert, leaf_key, cert_der(leaf_cert)


class TestPreimage:
    def test_shape_is_pinned(self, agency):
        _, _, _, cred = agency
        me = _identity('alpha')
        pre = zta_binding_preimage(me, cred)
        assert len(pre) == ZTA_BINDING_PREIMAGE_LEN
        assert pre.startswith(ZTA_BINDING_TAG)
        # tag || uuid || node key || cred fingerprint, in that order.
        # `Identity` keeps uuid as a str, which is why _uuid_bytes normalizes it --
        # C binds the 16 raw bytes of a uuid_t and the two must agree.
        off = len(ZTA_BINDING_TAG)
        assert pre[off:off + 16] == UUID(str(me.uuid)).bytes
        assert pre[off + 16:off + 48] == node_signing_pubkey(me)
        assert pre[off + 48:] == credential_fingerprint(cred)

    def test_fingerprint_is_over_actual_bytes(self, agency):
        _, _, _, cred = agency
        assert credential_fingerprint(cred) == hashlib.sha256(cred).digest()

    def test_empty_credential_refused_loudly(self):
        # A caller that got this wrong must hear about it rather than produce a
        # binding nothing can verify.
        with pytest.raises(ValueError):
            zta_binding_preimage(_identity('alpha'), b'')

    def test_distinct_identities_yield_distinct_preimages(self, agency):
        _, _, _, cred = agency
        assert (zta_binding_preimage(_identity('alpha'), cred)
                != zta_binding_preimage(_identity('bravo'), cred))


class TestHolderAssertedBinding:
    def test_binding_verifies_for_its_own_identity(self, agency):
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        binding = _sign(leaf_key, zta_binding_preimage(me, cred))
        assert verify_zta_binding(me, cred, binding) is True

    def test_binding_does_not_verify_for_another_identity(self, agency):
        """ISSUES §1.5, in one assertion: the attacker harvests a chain-valid
        credential AND its binding from a clear-text announce, and re-presents both
        under its own identity. The pre-image names the victim, so the signature
        cannot verify -- and the attacker cannot mint a fresh one without the
        credential's private key. No roster, no first-use-wins, no TOFU."""
        _, _, leaf_key, cred = agency
        victim = _identity('alpha')
        attacker = _identity('mallory')
        harvested = _sign(leaf_key, zta_binding_preimage(victim, cred))
        assert verify_zta_binding(victim, cred, harvested) is True
        assert verify_zta_binding(attacker, cred, harvested) is False

    def test_node_key_rotation_invalidates_binding(self, agency):
        """The pre-image covers the signing key, so re-keying a node invalidates its
        binding. Re-binding is a provisioning act; the failure mode is losing
        admission until re-provisioned, which is the cost `binding_mode: require`
        accepts."""
        _, _, leaf_key, cred = agency
        me = _identity('alpha', seed=b'11')
        rekeyed = _identity('alpha', seed=b'99')
        assert me.uuid == rekeyed.uuid            # same node, new key
        binding = _sign(leaf_key, zta_binding_preimage(me, cred))
        assert verify_zta_binding(rekeyed, cred, binding) is False

    def test_binding_by_a_different_credential_refused(self, agency):
        """A signature by some other holder's key authorizes nothing, even when that
        holder is legitimate under the same CA."""
        ca_key, ca_cert, _, cred = agency
        other_key, _ = make_leaf_keypair('drone-bravo', ca_key, ca_cert)
        me = _identity('alpha')
        binding = _sign(other_key, zta_binding_preimage(me, cred))
        assert verify_zta_binding(me, cred, binding) is False

    def test_binding_for_a_different_credential_refused(self, agency):
        """Right signer, wrong credential: the fingerprint in the pre-image pins
        which credential the binding authorizes."""
        ca_key, ca_cert, leaf_key, cred = agency
        _, other_cert = make_leaf_keypair('drone-charlie', ca_key, ca_cert)
        me = _identity('alpha')
        binding = _sign(leaf_key, zta_binding_preimage(me, cert_der(other_cert)))
        assert verify_zta_binding(me, cred, binding) is False

    @pytest.mark.parametrize('binding', [b'', None])
    def test_absent_binding_is_false_not_an_error(self, agency, binding):
        _, _, _, cred = agency
        assert verify_zta_binding(_identity('alpha'), cred, binding) is False

    def test_oversized_binding_refused_before_any_crypto(self, agency):
        _, _, _, cred = agency
        assert verify_zta_binding(_identity('alpha'), cred,
                                  b'\x00' * (ZTA_BINDING_MAX + 1)) is False

    def test_empty_credential_is_false_not_an_error(self):
        assert verify_zta_binding(_identity('alpha'), b'', b'sig') is False

    def test_unparseable_credential_is_false(self):
        assert verify_zta_binding(_identity('alpha'), b'not a certificate',
                                  b'sig') is False

    def test_garbage_signature_refused(self, agency):
        _, _, _, cred = agency
        assert verify_zta_binding(_identity('alpha'), cred, b'\x30\x06garbage') is False

    def test_reads_binding_off_the_identity_when_not_passed(self, agency):
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        me.zta_credential_binding = _sign(leaf_key, zta_binding_preimage(me, cred))
        assert verify_zta_binding(me, cred) is True

    def test_domain_separated_from_the_operator_binding(self, agency):
        """An operator-key binding must never verify as a credential binding. Both are
        signatures by an X.509 holder's key over bytes naming the node; only the
        versioned tag and the trailing 32 bytes keep them apart, so this is the test
        that catches a future pre-image edit that collapses them."""
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        op_pre = operator_binding_preimage(me, bytes(range(32)))
        assert verify_zta_binding(me, cred, _sign(leaf_key, op_pre)) is False


class TestCaAssertedSan:
    @pytest.fixture
    def san_world(self):
        """A CA whose issuance AT controls, minting `at://<uuid>` the SPIFFE way."""
        ca_key, ca_cert = make_ca('AT Mission Root')
        me = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(me.uuid))
        _, cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert, san_uris=[uri])
        return ca_key, ca_cert, me, cert_der(cert)

    def test_san_naming_the_node_binds_it(self, san_world):
        _, _, me, cred = san_world
        assert san_binds_identity(cred, me) is True

    def test_san_does_not_bind_another_identity(self, san_world):
        _, _, _, cred = san_world
        assert san_binds_identity(cred, _identity('mallory')) is False

    def test_certificate_without_san_binds_nothing(self, agency):
        _, _, _, cred = agency
        assert san_binds_identity(cred, _identity('alpha')) is False

    def test_uuid_case_is_not_significant(self):
        """A CA that upper-cases a uuid has not issued a different certificate."""
        ca_key, ca_cert = make_ca('AT Mission Root')
        me = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(me.uuid).upper())
        _, cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert, san_uris=[uri])
        assert san_binds_identity(cert_der(cert), me) is True

    def test_unrelated_san_uri_does_not_bind(self):
        ca_key, ca_cert = make_ca('AT Mission Root')
        _, cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert,
                                    san_uris=['https://example.test/drone'])
        assert san_binds_identity(cert_der(cert), _identity('alpha')) is False

    def test_empty_template_disables_the_check(self, san_world):
        _, _, me, cred = san_world
        assert san_binds_identity(cred, me, template='') is False

    def test_unparseable_credential_is_false(self):
        assert san_binds_identity(b'not a certificate', _identity('alpha')) is False


class TestEitherMechanism:
    def test_holder_asserted_alone_suffices(self, agency):
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        binding = _sign(leaf_key, zta_binding_preimage(me, cred))
        assert identity_is_bound(me, cred, binding) is True

    def test_ca_asserted_alone_suffices(self):
        ca_key, ca_cert = make_ca('AT Mission Root')
        me = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(me.uuid))
        _, cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert, san_uris=[uri])
        # No binding blob at all: the issuer already said which node this is for.
        assert identity_is_bound(me, cert_der(cert), None) is True

    def test_neither_mechanism_is_unbound(self, agency):
        _, _, _, cred = agency
        assert identity_is_bound(_identity('alpha'), cred, None) is False

    def test_san_for_another_node_does_not_rescue_a_bad_binding(self):
        """Both mechanisms failing for the same reason -- the credential belongs to
        someone else -- must not add up to a pass."""
        ca_key, ca_cert = make_ca('AT Mission Root')
        victim = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(victim.uuid))
        leaf_key, cert = make_leaf_keypair('drone-alpha', ca_key, ca_cert,
                                           san_uris=[uri])
        cred = cert_der(cert)
        harvested = _sign(leaf_key, zta_binding_preimage(victim, cred))
        assert identity_is_bound(_identity('mallory'), cred, harvested) is False


class TestOperatorBindingCounts:
    """An operator-key binding is a signature by the CREDENTIAL's private key over
    bytes naming the node, so it answers this module's question too: the holder
    authorized this node to present the certificate. A node that opted in to a
    guardian key therefore needs no second signature, and no second operator session
    to produce one."""

    def test_operator_binding_satisfies_the_credential_binding(self, agency):
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        guardian = bytes(range(32))
        op_binding = _sign(leaf_key, operator_binding_preimage(me, guardian))
        assert identity_is_bound(me, cred, None, ZTA_SAN_URI_TEMPLATE,
                                 operator_pubkey=guardian,
                                 operator_key_binding=op_binding) is True

    def test_operator_binding_for_another_node_does_not_bind(self, agency):
        _, _, leaf_key, cred = agency
        victim, attacker = _identity('alpha'), _identity('mallory')
        guardian = bytes(range(32))
        harvested = _sign(leaf_key, operator_binding_preimage(victim, guardian))
        assert identity_is_bound(attacker, cred, None, ZTA_SAN_URI_TEMPLATE,
                                 operator_pubkey=guardian,
                                 operator_key_binding=harvested) is False

    def test_operator_binding_by_another_credential_does_not_bind(self, agency):
        """The signature must come from the key of the credential being presented."""
        ca_key, ca_cert, _leaf_key, cred = agency
        other_key, _ = make_leaf_keypair('someone-else', ca_key, ca_cert)
        me = _identity('alpha')
        guardian = bytes(range(32))
        op_binding = _sign(other_key, operator_binding_preimage(me, guardian))
        assert identity_is_bound(me, cred, None, ZTA_SAN_URI_TEMPLATE,
                                 operator_pubkey=guardian,
                                 operator_key_binding=op_binding) is False

    def test_binding_for_a_different_guardian_key_does_not_bind(self, agency):
        _, _, leaf_key, cred = agency
        me = _identity('alpha')
        op_binding = _sign(leaf_key, operator_binding_preimage(me, bytes(range(32))))
        assert identity_is_bound(me, cred, None, ZTA_SAN_URI_TEMPLATE,
                                 operator_pubkey=bytes(range(32, 64)),
                                 operator_key_binding=op_binding) is False

    @pytest.mark.parametrize('key,sig', [(b'', b'sig'), (bytes(range(32)), b''),
                                         (b'', b'')])
    def test_half_a_claim_binds_nothing(self, agency, key, sig):
        _, _, _, cred = agency
        assert operator_binding_binds_identity(_identity('alpha'), cred, key,
                                               sig) is False

    def test_declining_the_guardian_key_leaves_the_credential_unbound(self, agency):
        """The common case: no guardian key at all. Opting in publishes a persistent
        pseudonym across an operator's nodes, so most nodes decline and still need a
        credential binding of their own."""
        _, _, _, cred = agency
        assert identity_is_bound(_identity('alpha'), cred, None,
                                 ZTA_SAN_URI_TEMPLATE) is False


class TestTheCTwinVector:
    """One pinned pre-image, shared with `src/c/test/zta_binding_test.c`.

    Two hand-written builders in two languages are exactly what drifts unnoticed,
    and a drifted pre-image does not fail loudly: it makes every binding
    unverifiable across the runtime boundary, so a mixed fleet quietly refuses
    each other's peers with nothing in the logs but "does not verify". Pinning the
    digest on both sides turns that into one failing test.
    """

    #: uuid 00010203-…-0e0f, node signing key 32 x 0x11, credential 0x00..0x3f.
    PINNED_PREIMAGE_SHA256 = (
        '5e709bf6c00646e2914ecdb09d3127535876956fe3076fbc6c9c807ca8b2e778')
    PINNED_CRED_SHA256 = (
        'fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108')

    @staticmethod
    def _pinned():
        sig = Signature(hex_seed=(b'11' * 32))
        return SimpleNamespace(uuid=UUID(bytes=bytes(range(16))), signature=sig)

    def test_the_preimage_matches_the_c_twin(self):
        cred = bytes(range(64))
        pre = zta_binding_preimage(self._pinned(), cred)
        assert len(pre) == 97 == ZTA_BINDING_PREIMAGE_LEN   # 17 + 16 + 32 + 32
        assert hashlib.sha256(pre).hexdigest() == self.PINNED_PREIMAGE_SHA256

    def test_the_preimage_is_tag_then_node_then_fingerprint(self):
        ident = self._pinned()
        cred = bytes(range(64))
        pre = zta_binding_preimage(ident, cred)
        assert pre[:len(ZTA_BINDING_TAG)] == ZTA_BINDING_TAG
        body = pre[len(ZTA_BINDING_TAG):]
        assert body[:16] == ident.uuid.bytes
        assert body[16:48] == bytes(ident.signature.public)
        # sha256 over the bytes passed in, never the advertised hash.
        assert body[48:].hex() == self.PINNED_CRED_SHA256

    def test_the_zta_tag_is_distinct_from_the_operator_tag(self):
        """A signature over one must never verify as the other; the differing
        tags are the only thing standing between them."""
        from autonomous_trust.core._python.identity.operator_binding import (
            OPERATOR_BINDING_TAG, OPERATOR_BINDING_PREIMAGE_LEN)
        assert ZTA_BINDING_TAG != OPERATOR_BINDING_TAG
        assert ZTA_BINDING_PREIMAGE_LEN != OPERATOR_BINDING_PREIMAGE_LEN

    def test_the_san_template_placeholder_is_what_c_substitutes(self):
        """C renders this template by substituting `{uuid}` textually rather than
        via printf, because ONE policy file is read by both runtimes. If this
        default ever became a printf format, the C side would render it literally
        and silently match nothing."""
        assert ZTA_SAN_URI_TEMPLATE == 'at://{uuid}'
        assert '%s' not in ZTA_SAN_URI_TEMPLATE
        u = '00010203-0405-0607-0809-0a0b0c0d0e0f'
        assert ZTA_SAN_URI_TEMPLATE.format(uuid=u) == 'at://' + u
