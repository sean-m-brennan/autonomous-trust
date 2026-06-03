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

import pytest

from autonomous_trust.core.identity.zta import (
    ZtaStatus, NullVerifier, OidcVerifier, X509Verifier)

pytest.importorskip("cryptography")

# Repo root -> the existing C test CA (shared fixture set).
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
_CA_DIR = os.path.join(_ROOT, 'src', 'c', 'test', 'zta_test_ca', 'output')
_BUNDLE = os.path.join(_CA_DIR, 'ca-bundle.pem')
_CERTS = os.path.join(_CA_DIR, 'certs')

_have_ca = os.path.isfile(_BUNDLE) and os.path.isdir(_CERTS)
requires_ca = pytest.mark.skipif(not _have_ca, reason="test CA not generated")


def _cred(name: str) -> bytes:
    with open(os.path.join(_CERTS, name + '.der'), 'rb') as fp:
        return fp.read()


class TestNullVerifier:
    def test_always_verified(self):
        r = NullVerifier().verify_credential(b'anything')
        assert r.status is ZtaStatus.VERIFIED
        assert NullVerifier().is_available() is True

    def test_no_cred_still_verified(self):
        # Null verifier is the runtime-disabled path; it never rejects.
        assert NullVerifier().verify_credential(None).status is ZtaStatus.VERIFIED


class TestOidcVerifier:
    def test_unavailable(self):
        assert OidcVerifier().verify_credential(b'tok').status is ZtaStatus.UNAVAILABLE


@requires_ca
class TestX509Verifier:
    def setup_method(self):
        self.v = X509Verifier(_BUNDLE)

    def test_valid_cert_verified(self):
        for name in ('drone_alpha', 'squad_leader', 'command_post'):
            r = self.v.verify_credential(_cred(name))
            assert r.status is ZtaStatus.VERIFIED, (name, r.reason)
            assert len(r.credential_hash) == 32

    def test_unknown_issuer_rejected(self):
        r = self.v.verify_credential(_cred('unknown_ca'))
        assert r.status is ZtaStatus.REJECTED
        assert len(r.credential_hash) == 32  # hash still computed for binding

    def test_expired_cert(self):
        r = self.v.verify_credential(_cred('expired'))
        assert r.status is ZtaStatus.EXPIRED

    def test_no_credential_rejected(self):
        r = self.v.verify_credential(None)
        assert r.status is ZtaStatus.REJECTED
        assert r.reason == 'no credential data'

    def test_malformed_credential_rejected(self):
        r = self.v.verify_credential(b'not a certificate')
        assert r.status is ZtaStatus.REJECTED
        assert 'parse' in r.reason

    def test_credential_hash_stable(self):
        cred = _cred('drone_alpha')
        assert self.v.credential_hash(cred) == self.v.credential_hash(cred)

    def test_is_available_with_bundle(self):
        assert self.v.is_available() is True

    def test_missing_bundle_rejects_all(self):
        v = X509Verifier(os.path.join(_CA_DIR, 'does-not-exist.pem'))
        assert v.is_available() is False
        # Empty store -> valid cert can't find its issuer -> rejected.
        assert v.verify_credential(_cred('drone_alpha')).status is ZtaStatus.REJECTED
