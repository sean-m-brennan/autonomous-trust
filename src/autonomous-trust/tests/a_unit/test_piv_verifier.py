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
"""PIV verifier tests: chain (delegated) + PKCS#11 challenge-response.

Uses a self-minted test PKI and a `SoftwareToken` (no hardware / SoftHSM) for
the challenge-response, per PIV_MFA_OPERATOR_ACCESS_PLAN.md §7.1 stages 1-2.
"""
import datetime
import hashlib
import os
import sys

import pytest

pytest.importorskip("cryptography")

_HERE = os.path.dirname(os.path.abspath(__file__))
# Search upward for the dir holding the importable minting helpers rather than
# counting '..' levels: under the integration test container the tests live at
# /app/tests/a_unit, where a fixed four levels up clamps to '/'. Keying on the
# file also steps past src/autonomous-trust, whose own tools/ is a different
# package that does not provide provision_zta_certs.
_ROOT = _HERE
while _ROOT != os.path.dirname(_ROOT):
    if os.path.isfile(os.path.join(_ROOT, 'tools', 'provision_zta_certs.py')):
        break
    _ROOT = os.path.dirname(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)  # for the importable minting helpers in tools/

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_keypair, make_leaf_cert, ca_bundle_pem, cert_der, make_crl)

from autonomous_trust.core.identity.zta import (  # noqa: E402
    ZtaStatus, MfaChain)
from autonomous_trust.core.identity.zta.piv.piv_verifier import (  # noqa: E402
    PivVerifier, PivCredential)
from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken  # noqa: E402

_PAST_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
_PAST_AFTER = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)


def _bundle_file(tmp_path, *ca_certs) -> str:
    path = os.path.join(str(tmp_path), 'ca-bundle.pem')
    with open(path, 'wb') as fp:
        fp.write(ca_bundle_pem(*ca_certs))
    return path


def _envelope(token: SoftwareToken, nonce: bytes) -> bytes:
    return PivCredential(cert_der=token.certificate_der(),
                         nonce=nonce, signature=token.sign(nonce)).pack()


class TestPivCredentialEnvelope:
    def test_pack_unpack_roundtrip(self):
        cred = PivCredential(cert_der=b'\x30\x82cert', nonce=b'\x01' * 32,
                             signature=b'sig-bytes')
        restored = PivCredential.unpack(cred.pack())
        assert restored == cred

    def test_unpack_rejects_garbage(self):
        assert PivCredential.unpack(b'not an envelope') is None
        assert PivCredential.unpack(b'') is None

    def test_unpack_rejects_trailing_bytes(self):
        cred = PivCredential(b'a', b'b', b'c')
        assert PivCredential.unpack(cred.pack() + b'extra') is None


class TestPivVerifier:
    def setup_method(self):
        self.ca_key, self.ca_cert = make_ca("PIV Test Root")
        self.leaf_key, self.leaf_cert = make_leaf_keypair(
            "operator-alpha", self.ca_key, self.ca_cert)
        self.token = SoftwareToken(cert_der(self.leaf_cert), self.leaf_key)

    def _verifier(self, tmp_path, **kw):
        return PivVerifier(_bundle_file(tmp_path, self.ca_cert), token=self.token, **kw)

    def test_activation_happy_path(self, tmp_path):
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        r = v.verify_credential(_envelope(self.token, nonce), identity_id="op-id")
        assert r.status is ZtaStatus.VERIFIED, r.reason
        assert r.credential_hash == hashlib.sha256(cert_der(self.leaf_cert)).digest()

    def test_replay_rejected(self, tmp_path):
        # A nonce is single-use: re-presenting it fails (replay defense, §8).
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        env = _envelope(self.token, nonce)
        assert v.verify_credential(env, identity_id="op-id").status is ZtaStatus.VERIFIED
        r2 = v.verify_credential(env, identity_id="op-id")
        assert r2.status is ZtaStatus.REJECTED
        assert "already-used" in r2.reason or "unknown" in r2.reason

    def test_unknown_nonce_rejected(self, tmp_path):
        v = self._verifier(tmp_path)
        # A nonce that was never issued.
        env = _envelope(self.token, os.urandom(32))
        assert v.verify_credential(env, identity_id="op-id").status is ZtaStatus.REJECTED

    def test_identity_binding_mismatch_rejected(self, tmp_path):
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        r = v.verify_credential(_envelope(self.token, nonce), identity_id="someone-else")
        assert r.status is ZtaStatus.REJECTED
        assert "different identity" in r.reason

    def test_expired_challenge_rejected(self, tmp_path):
        v = self._verifier(tmp_path, challenge_ttl_sec=-1)  # already expired
        nonce = v.issue_challenge("op-id")
        r = v.verify_credential(_envelope(self.token, nonce), identity_id="op-id")
        assert r.status is ZtaStatus.REJECTED

    def test_tampered_signature_rejected(self, tmp_path):
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        cred = PivCredential(cert_der(self.leaf_cert), nonce,
                             self.token.sign(nonce)[:-1] + b'\x00')
        r = v.verify_credential(cred.pack(), identity_id="op-id")
        assert r.status is ZtaStatus.REJECTED
        assert "signature" in r.reason

    def test_missing_challenge_response_rejected(self, tmp_path):
        # Valid cert but no signed nonce -> rejected after the chain passes.
        v = self._verifier(tmp_path)
        cred = PivCredential(cert_der(self.leaf_cert), b'', b'')
        r = v.verify_credential(cred.pack())
        assert r.status is ZtaStatus.REJECTED
        assert "challenge response" in r.reason

    def test_rogue_cert_rejected(self, tmp_path):
        # Cert signed by a CA not in the bundle -> REJECTED (unknown issuer),
        # before any challenge check.
        rogue_key, rogue_cert = make_ca("Rogue Root", org="Rogue")
        rkey, rcert = make_leaf_keypair("operator-alpha", rogue_key, rogue_cert)
        rogue_token = SoftwareToken(cert_der(rcert), rkey)
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        r = v.verify_credential(_envelope(rogue_token, nonce), identity_id="op-id")
        assert r.status is ZtaStatus.REJECTED

    def test_expired_cert_rejected(self, tmp_path):
        exp_key, exp_cert = make_leaf_keypair(
            "operator-alpha", self.ca_key, self.ca_cert,
            not_before=_PAST_BEFORE, not_after=_PAST_AFTER)
        exp_token = SoftwareToken(cert_der(exp_cert), exp_key)
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge("op-id")
        r = v.verify_credential(_envelope(exp_token, nonce), identity_id="op-id")
        assert r.status is ZtaStatus.EXPIRED

    def test_non_envelope_falls_back_to_chain_only(self, tmp_path):
        # A bare valid cert (the form a peer presents) verifies chain-only --
        # PivVerifier is a strict superset of X509Verifier.
        v = self._verifier(tmp_path)
        r = v.verify_credential(cert_der(self.leaf_cert))
        assert r.status is ZtaStatus.VERIFIED
        assert r.credential_hash == hashlib.sha256(cert_der(self.leaf_cert)).digest()

    def test_garbage_rejected_via_chain(self, tmp_path):
        # Not an envelope and not a parseable cert -> X509 parse rejection.
        v = self._verifier(tmp_path)
        r = v.verify_credential(b'garbage-not-a-cert')
        assert r.status is ZtaStatus.REJECTED

    def test_bare_rogue_cert_rejected_chain_only(self, tmp_path):
        rogue_key, rogue_cert = make_ca("Rogue Root", org="Rogue")
        rcert = make_leaf_cert("operator-alpha", rogue_key, rogue_cert)
        v = self._verifier(tmp_path)
        assert v.verify_credential(cert_der(rcert)).status is ZtaStatus.REJECTED

    def test_no_credential_rejected(self, tmp_path):
        assert self._verifier(tmp_path).verify_credential(None).status is ZtaStatus.REJECTED

    def test_is_available_tracks_token_presence(self, tmp_path):
        v = self._verifier(tmp_path)
        assert v.is_available() is True
        self.token.remove()  # simulate card removal (§3.4)
        assert v.is_available() is False

    def test_in_mfa_chain(self, tmp_path):
        # PivVerifier as the primary factor of an MfaChain (MfaChain passes only
        # cred_data; identity binding uses the empty default both sides).
        v = self._verifier(tmp_path)
        nonce = v.issue_challenge()  # bound to '' (chain-use)
        chain = MfaChain([v])
        r = chain.verify_credential(_envelope(self.token, nonce))
        assert r.status is ZtaStatus.VERIFIED
        assert r.credential_hash == hashlib.sha256(cert_der(self.leaf_cert)).digest()


class TestCheckRevocation:
    """X509Verifier.check_revocation against a minted CRL. As of P6 the
    admission gate invokes this after a VERIFIED chain result (idprocess.
    _zta_admit / C welcoming_committee); the end-to-end admission rejection is
    covered by test_zta_admission.TestZtaAdmissionRevocation and conformance
    zta-x509-reject-revoked-credential."""

    def setup_method(self):
        from autonomous_trust.core.identity.zta import X509Verifier
        self.X509Verifier = X509Verifier
        self.ca_key, self.ca_cert = make_ca("CRL Test Root")
        self.leaf = make_leaf_cert("peer-x", self.ca_key, self.ca_cert)

    def _verifier(self, tmp_path, crl_pem: bytes):
        bundle = _bundle_file(tmp_path, self.ca_cert)
        crl_path = os.path.join(str(tmp_path), 'revoked.crl.pem')
        with open(crl_path, 'wb') as fp:
            fp.write(crl_pem)
        return self.X509Verifier(bundle, crl_path=crl_path)

    def test_not_revoked(self, tmp_path):
        crl = make_crl(self.ca_key, self.ca_cert, revoked_serials=[])
        v = self._verifier(tmp_path, crl)
        # Must verify first to populate the cert cache (matched by serial).
        res = v.verify_credential(cert_der(self.leaf))
        assert res.status is ZtaStatus.VERIFIED
        rev = v.check_revocation(res.credential_hash)
        assert rev.status is ZtaStatus.VERIFIED
        assert "not revoked" in rev.reason

    def test_revoked(self, tmp_path):
        crl = make_crl(self.ca_key, self.ca_cert,
                       revoked_serials=[self.leaf.serial_number])
        v = self._verifier(tmp_path, crl)
        res = v.verify_credential(cert_der(self.leaf))
        assert res.status is ZtaStatus.VERIFIED
        rev = v.check_revocation(res.credential_hash)
        assert rev.status is ZtaStatus.REVOKED
