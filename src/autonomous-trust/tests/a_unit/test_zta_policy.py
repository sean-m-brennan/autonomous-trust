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

from autonomous_trust.core.identity.zta import ZtaPolicy, NullVerifier, OidcVerifier
from autonomous_trust.core.config.configuration import from_json_string, to_json_string


class TestZtaPolicy:
    def test_defaults_disabled(self):
        p = ZtaPolicy.defaults()
        assert p.enabled is False
        assert p.require_at_admission is True
        assert p.verifier_type == 'x509'
        assert p.ddil_fallback_reputation_cap == 0.5

    def test_disabled_creates_null_verifier(self):
        # Disabled -> NullVerifier regardless of verifier_type.
        assert isinstance(ZtaPolicy(enabled=False, verifier_type='x509')
                          .create_verifier(), NullVerifier)

    def test_oidc_verifier_selected(self):
        assert isinstance(ZtaPolicy(enabled=True, verifier_type='oidc')
                          .create_verifier(), OidcVerifier)

    def test_unknown_type_falls_back_to_null(self):
        assert isinstance(ZtaPolicy(enabled=True, verifier_type='bogus')
                          .create_verifier(), NullVerifier)

    def test_json_roundtrip(self):
        p = ZtaPolicy(enabled=True, verifier_type='x509',
                      ca_bundle_path='/etc/pki/ca.pem',
                      ddil_fallback_reputation_cap=0.3,
                      reverify_interval_sec=900)
        restored = from_json_string(to_json_string(p))
        assert isinstance(restored, ZtaPolicy)
        assert restored.enabled is True
        assert restored.ca_bundle_path == '/etc/pki/ca.pem'
        assert restored.ddil_fallback_reputation_cap == 0.3
        assert restored.reverify_interval_sec == 900

    def test_load_absent_returns_defaults(self, tmp_path):
        p = ZtaPolicy.load(str(tmp_path))
        assert p.enabled is False

    def test_load_from_file(self, tmp_path):
        src = ZtaPolicy(enabled=True, ca_bundle_path='/x/y.pem')
        path = os.path.join(str(tmp_path), ZtaPolicy.CONFIG_KEY + ZtaPolicy.file_ext)
        src.to_file(path)
        loaded = ZtaPolicy.load(str(tmp_path))
        assert loaded.enabled is True
        assert loaded.ca_bundle_path == '/x/y.pem'
