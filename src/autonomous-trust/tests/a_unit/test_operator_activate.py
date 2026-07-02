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
"""Operator activation: PIV challenge-response -> credential binding -> policy."""
import hashlib
import os
import sys

import pytest

pytest.importorskip("cryptography")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_keypair, ca_bundle_pem, cert_der)

from autonomous_trust.core.identity.zta import ZtaStatus, ZtaPolicy, MfaChain  # noqa: E402
from autonomous_trust.core.identity.zta.piv.piv_verifier import PivVerifier  # noqa: E402
from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken  # noqa: E402
from autonomous_trust.core.operator import activate as act  # noqa: E402


def _pki(tmp_path):
    ca_key, ca_cert = make_ca("Activate Test Root")
    leaf_key, leaf_cert = make_leaf_keypair("operator-1", ca_key, ca_cert)
    bundle = os.path.join(str(tmp_path), 'agency-ca.pem')
    with open(bundle, 'wb') as fp:
        fp.write(ca_bundle_pem(ca_cert))
    token = SoftwareToken(cert_der(leaf_cert), leaf_key)
    return ca_key, ca_cert, leaf_cert, token, bundle


class TestBinding:
    def test_piv_issuer_from_cert(self, tmp_path):
        _, _, leaf_cert, _, _ = _pki(tmp_path)
        issuer = act.piv_issuer(cert_der(leaf_cert))
        assert issuer.startswith('PIV:')
        assert 'operator-1' in issuer

    def test_piv_issuer_bad_cert(self):
        assert act.piv_issuer(b'not a cert') == 'PIV:unknown'

    def test_write_operator_policy_roundtrips(self, tmp_path):
        path = act.write_operator_policy(str(tmp_path), '/etc/at/agency.pem')
        assert os.path.isfile(path)
        loaded = ZtaPolicy.load(str(tmp_path))
        assert loaded.enabled is True
        assert loaded.verifier_type == 'mfa'
        assert loaded.factors and loaded.factors[0]['type'] == 'piv'
        # The written policy builds a PIV-primary MFA chain.
        v = loaded.create_verifier()
        assert isinstance(v, MfaChain)
        assert isinstance(v.factors[0], PivVerifier)


class TestActivate:
    def test_activate_verified_no_cfg(self, tmp_path):
        _, _, leaf_cert, token, bundle = _pki(tmp_path)
        result = act.activate(token, bundle, identity_id='op-1')
        assert result.status is ZtaStatus.VERIFIED
        assert result.credential_hash == hashlib.sha256(cert_der(leaf_cert)).digest()
        assert result.issuer.startswith('PIV:')

    def test_activate_rogue_denied(self, tmp_path):
        # Token cert not chained to the agency bundle -> denied, nothing bound.
        _, _, _, _, bundle = _pki(tmp_path)
        rogue_key, rogue_cert = make_ca("Rogue", org="Rogue")
        rkey, rcert = make_leaf_keypair("operator-1", rogue_key, rogue_cert)
        rogue_token = SoftwareToken(cert_der(rcert), rkey)
        result = act.activate(rogue_token, bundle, identity_id='op-1')
        assert result.status is ZtaStatus.REJECTED

    def test_activate_binds_identity_and_writes_policy(self, tmp_path):
        _, _, leaf_cert, token, bundle = _pki(tmp_path)
        cfg_dir = str(tmp_path)
        _write_identity_file(cfg_dir)
        result = act.activate(token, bundle, cfg_dir=cfg_dir, identity_id='op-1')
        assert result.status is ZtaStatus.VERIFIED
        # Identity now carries the bound credential + hash + PIV issuer.
        from autonomous_trust.core.identity import Identity
        ident = Identity.from_file(os.path.join(cfg_dir, 'identity' + Identity.file_ext))
        assert ident.zta_credential == cert_der(leaf_cert)
        assert ident.zta_credential_hash == hashlib.sha256(cert_der(leaf_cert)).digest()
        assert ident.zta_issuer.startswith('PIV:')
        # Policy written.
        assert os.path.isfile(os.path.join(cfg_dir, 'zta_policy.cfg.json'))

    def test_bind_identity_file_absent_is_noop(self, tmp_path):
        assert act.bind_identity_file(str(tmp_path), b'cert') is None


class TestActivateWithTotp:
    def _totp(self):
        from autonomous_trust.core.identity.zta import generate_totp_secret, totp_now
        secret = generate_totp_secret()
        return secret, totp_now(secret)

    def test_valid_second_factor_activates(self, tmp_path):
        _, _, leaf_cert, token, bundle = _pki(tmp_path)
        secret, code = self._totp()
        result = act.activate(token, bundle, identity_id='op-1',
                              totp_secret=secret, totp_code=code)
        assert result.status is ZtaStatus.VERIFIED
        assert result.credential_hash == hashlib.sha256(cert_der(leaf_cert)).digest()

    def test_missing_second_factor_blocks(self, tmp_path):
        _, _, _, token, bundle = _pki(tmp_path)
        secret, _ = self._totp()
        result = act.activate(token, bundle, identity_id='op-1',
                              totp_secret=secret, totp_code='')
        assert result.status is ZtaStatus.REJECTED

    def test_invalid_second_factor_blocks(self, tmp_path):
        _, _, _, token, bundle = _pki(tmp_path)
        secret, _ = self._totp()
        result = act.activate(token, bundle, identity_id='op-1',
                              totp_secret=secret, totp_code='000000')
        assert result.status is ZtaStatus.REJECTED

    def test_totp_secret_persisted_and_loadable(self, tmp_path):
        _, _, _, token, bundle = _pki(tmp_path)
        cfg_dir = str(tmp_path)
        _write_identity_file(cfg_dir)
        secret, code = self._totp()
        result = act.activate(token, bundle, cfg_dir=cfg_dir, identity_id='op-1',
                              totp_secret=secret, totp_code=code)
        assert result.status is ZtaStatus.VERIFIED
        # The TOTP factor (with secret) is persisted and round-trips.
        loaded = ZtaPolicy.load(cfg_dir)
        totp_factors = [f for f in loaded.factors if f.get('type') == 'totp']
        assert totp_factors and totp_factors[0]['secret'] == secret
        assert act.load_totp_secret(cfg_dir) == secret

    def test_enroll_totp_returns_secret_and_uri(self):
        secret, uri = act.enroll_totp('operator-1', issuer='AT')
        assert secret and uri.startswith('otpauth://totp/')


def _write_identity_file(cfg_dir: str) -> None:
    """Create a minimal real Identity file to bind against."""
    from autonomous_trust.core.identity import Identity
    ident = Identity.initialize('operator-node', 'operator', '127.0.0.1')
    ident.to_file(os.path.join(cfg_dir, 'identity' + Identity.file_ext))
