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
"""TOTP second-factor verifier tests (RFC 6238 / pyotp)."""
import pytest

pytest.importorskip("pyotp")

from autonomous_trust.core.identity.zta import (  # noqa: E402
    TotpVerifier, generate_totp_secret, totp_provisioning_uri, totp_now,
    ZtaStatus)


class TestTotpVerifier:
    def setup_method(self):
        self.secret = generate_totp_secret()
        self.v = TotpVerifier(self.secret, valid_window=1)

    def test_is_secondary_factor(self):
        assert self.v.secondary_factor is True

    def test_valid_code_verified(self):
        code = totp_now(self.secret).encode()
        assert self.v.verify_credential(code).status is ZtaStatus.VERIFIED

    def test_invalid_code_rejected(self):
        r = self.v.verify_credential(b'000000')
        # 000000 is almost never the live code; rejected.
        assert r.status is ZtaStatus.REJECTED
        assert 'invalid' in r.reason

    def test_no_code_rejected(self):
        r = self.v.verify_credential(b'')
        assert r.status is ZtaStatus.REJECTED
        assert 'no TOTP code' in r.reason

    def test_not_enrolled_rejected(self):
        r = TotpVerifier('').verify_credential(b'123456')
        assert r.status is ZtaStatus.REJECTED
        assert 'not enrolled' in r.reason

    def test_no_identity_hash(self):
        # Secondary factor contributes no binding hash.
        assert self.v.credential_hash(b'whatever') == b''

    def test_is_available_when_enrolled(self):
        assert self.v.is_available() is True
        assert TotpVerifier('').is_available() is False

    def test_string_code_accepted(self):
        # A str code (not bytes) also verifies.
        assert self.v.verify_credential(totp_now(self.secret)).status \
            is ZtaStatus.VERIFIED

    def test_provisioning_uri(self):
        uri = totp_provisioning_uri(self.secret, 'operator-1', issuer='AT')
        assert uri.startswith('otpauth://totp/')
        assert 'issuer=AT' in uri


class TestTotpInPolicy:
    def test_policy_builds_totp_factor(self):
        from autonomous_trust.core.identity.zta import ZtaPolicy, MfaChain
        secret = generate_totp_secret()
        v = ZtaPolicy(enabled=True, verifier_type='mfa',
                      factors=[{'type': 'piv'},
                               {'type': 'totp', 'secret': secret}]).create_verifier()
        assert isinstance(v, MfaChain)
        assert isinstance(v.factors[1], TotpVerifier)
        assert v.factors[1].secondary_factor is True
