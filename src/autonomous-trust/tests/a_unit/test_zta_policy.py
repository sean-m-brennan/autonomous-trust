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
import os

import pytest

from autonomous_trust.core.identity.zta import (
    ZtaPolicy, NullVerifier, OidcVerifier, MfaChain, X509Verifier,
    BINDING_MODE_OFF, BINDING_MODE_PREFER, BINDING_MODE_REQUIRE)
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

    def test_mfa_no_factors_builds_null_chain(self):
        # P0 exit criterion: enabled mfa with no factors -> MfaChain([NullVerifier]).
        v = ZtaPolicy(enabled=True, verifier_type='mfa').create_verifier()
        assert isinstance(v, MfaChain)
        assert len(v.factors) == 1
        assert isinstance(v.factors[0], NullVerifier)

    def test_mfa_builds_factor_chain(self):
        v = ZtaPolicy(enabled=True, verifier_type='mfa',
                      factors=[{'type': 'oidc'}, {'type': 'null'}]).create_verifier()
        assert isinstance(v, MfaChain)
        assert len(v.factors) == 2
        assert isinstance(v.factors[0], OidcVerifier)

    def test_mfa_disabled_still_null_verifier(self):
        assert isinstance(ZtaPolicy(enabled=False, verifier_type='mfa')
                          .create_verifier(), NullVerifier)

    def test_mfa_piv_factor_builds_piv_verifier(self):
        from autonomous_trust.core.identity.zta.piv.piv_verifier import PivVerifier
        v = ZtaPolicy(enabled=True, verifier_type='mfa',
                      ca_bundle_path='/etc/pki/agency.pem',
                      factors=[{'type': 'piv'}]).create_verifier()
        assert isinstance(v, MfaChain)
        assert isinstance(v.factors[0], PivVerifier)

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

    def test_json_roundtrip_mfa_fields(self):
        p = ZtaPolicy(enabled=True, verifier_type='mfa',
                      factors=[{'type': 'piv', 'slot': 0},
                               {'type': 'totp', 'issuer': 'AT'}],
                      operator_allow_ddil_relay=False,
                      operator_privileged_requires_full_verify=True)
        restored = from_json_string(to_json_string(p))
        assert isinstance(restored, ZtaPolicy)
        assert restored.verifier_type == 'mfa'
        assert restored.factors == [{'type': 'piv', 'slot': 0},
                                     {'type': 'totp', 'issuer': 'AT'}]
        assert restored.operator_allow_ddil_relay is False
        assert restored.operator_privileged_requires_full_verify is True

    def test_new_fields_default(self):
        p = ZtaPolicy.defaults()
        assert p.factors == []
        assert p.operator_allow_ddil_relay is True
        assert p.operator_privileged_requires_full_verify is True

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


class TestAnchors:
    """Named trust anchors, one per agency. Multiple credentials arise only at a
    network gateway bridging agencies; an ordinary node carries one."""

    def test_legacy_config_synthesizes_the_pair_it_already_had(self):
        """The whole point of the additive design: a config written before anchors
        existed resolves to exactly its two historical anchors, in the same roles."""
        p = ZtaPolicy(enabled=True, verifier_type='x509',
                      ca_bundle_path='/peer.pem',
                      operator_ca_bundle_path='/op.pem')
        assert [(a['name'], a['ca_bundle_path'], a['operator'])
                for a in p.resolved_anchors()] == [
            ('peer', '/peer.pem', False), ('operator', '/op.pem', True)]

    def test_legacy_config_without_operator_anchor(self):
        p = ZtaPolicy(enabled=True, verifier_type='x509', ca_bundle_path='/peer.pem')
        assert [a['name'] for a in p.resolved_anchors()] == ['peer']

    def test_no_bundles_at_all_resolves_to_nothing(self):
        assert ZtaPolicy(enabled=True, verifier_type='x509').resolved_anchors() == []

    def test_explicit_anchors_win_over_legacy_fields(self):
        p = ZtaPolicy(enabled=True, verifier_type='x509',
                      ca_bundle_path='/ignored.pem', anchors=[
                          {'name': 'dod', 'ca_bundle_path': '/dod.pem'}])
        assert [a['name'] for a in p.resolved_anchors()] == ['dod']

    def test_gateway_anchors_keep_order_and_operator_flags(self):
        p = ZtaPolicy(enabled=True, verifier_type='x509', anchors=[
            {'name': 'dod', 'ca_bundle_path': '/dod.pem'},
            {'name': 'dhs', 'ca_bundle_path': '/dhs.pem'},
            {'name': 'piv', 'ca_bundle_path': '/piv.pem', 'operator': True}])
        assert [(a['name'], a['operator']) for a in p.resolved_anchors()] == [
            ('dod', False), ('dhs', False), ('piv', True)]

    def test_pathless_anchor_dropped(self):
        # An anchor that trusts nothing can verify nothing; keeping it would only
        # produce confusing per-anchor failures.
        p = ZtaPolicy(enabled=True, verifier_type='x509', anchors=[
            {'name': 'dod', 'ca_bundle_path': '/dod.pem'},
            {'name': 'empty', 'ca_bundle_path': ''}])
        assert [a['name'] for a in p.resolved_anchors()] == ['dod']

    def test_duplicate_name_cannot_count_twice(self):
        """Gateway authority is per anchor name, so a repeated name must not let one
        credential earn two anchors' worth of authority."""
        p = ZtaPolicy(enabled=True, verifier_type='x509', anchors=[
            {'name': 'dod', 'ca_bundle_path': '/first.pem'},
            {'name': 'dod', 'ca_bundle_path': '/second.pem'}])
        resolved = p.resolved_anchors()
        assert len(resolved) == 1
        assert resolved[0]['ca_bundle_path'] == '/first.pem'

    def test_verifier_per_anchor(self):
        p = ZtaPolicy(enabled=True, verifier_type='x509', anchors=[
            {'name': 'dod', 'ca_bundle_path': '/dod.pem'},
            {'name': 'piv', 'ca_bundle_path': '/piv.pem', 'operator': True}])
        built = p.create_anchor_verifiers()
        assert [(n, o) for n, _, o in built] == [('dod', False), ('piv', True)]
        assert all(isinstance(v, X509Verifier) for _, v, _ in built)

    def test_disabled_policy_builds_no_anchor_verifiers(self):
        p = ZtaPolicy(enabled=False, verifier_type='x509', ca_bundle_path='/x.pem')
        assert p.create_anchor_verifiers() == []

    def test_non_x509_type_yields_the_single_configured_verifier(self):
        """An anchor *is* a CA bundle, so there is nothing to enumerate for mfa/oidc;
        the caller's logic must stay unchanged rather than silently lose its
        verifier."""
        p = ZtaPolicy(enabled=True, verifier_type='oidc')
        built = p.create_anchor_verifiers()
        assert len(built) == 1
        assert built[0][0] == 'default'
        assert isinstance(built[0][1], OidcVerifier)

    def test_anchors_round_trip(self, tmp_path):
        src = ZtaPolicy(enabled=True, verifier_type='x509', anchors=[
            {'name': 'dod', 'ca_bundle_path': '/dod.pem'},
            {'name': 'piv', 'ca_bundle_path': '/piv.pem', 'operator': True}])
        path = os.path.join(str(tmp_path), ZtaPolicy.CONFIG_KEY + ZtaPolicy.file_ext)
        src.to_file(path)
        loaded = ZtaPolicy.load(str(tmp_path))
        assert [(a['name'], a['operator']) for a in loaded.resolved_anchors()] == [
            ('dod', False), ('piv', True)]


class TestBindingMode:
    def test_defaults_to_require(self):
        # TOFU is the whole of ISSUES §1.5, so the default must be the strict one.
        assert ZtaPolicy.defaults().binding_mode == BINDING_MODE_REQUIRE

    @pytest.mark.parametrize('mode', [BINDING_MODE_REQUIRE, BINDING_MODE_PREFER,
                                      BINDING_MODE_OFF])
    def test_recognized_modes_kept(self, mode):
        assert ZtaPolicy(binding_mode=mode).binding_mode == mode

    def test_case_insensitive(self):
        assert ZtaPolicy(binding_mode='PREFER').binding_mode == BINDING_MODE_PREFER

    @pytest.mark.parametrize('mode', ['whatever', '', None])
    def test_unrecognized_mode_fails_closed(self, mode):
        """An unrecognized mode must not become the most permissive thing; a typo in
        a policy file should tighten the gate, never open it."""
        assert ZtaPolicy(binding_mode=mode).binding_mode == BINDING_MODE_REQUIRE

    def test_san_template_default_and_override(self):
        assert ZtaPolicy.defaults().san_uri_template == 'at://{uuid}'
        assert ZtaPolicy(san_uri_template='').san_uri_template == ''

    def test_binding_fields_round_trip(self, tmp_path):
        src = ZtaPolicy(enabled=True, binding_mode=BINDING_MODE_PREFER,
                        san_uri_template='spiffe://mission/{uuid}')
        path = os.path.join(str(tmp_path), ZtaPolicy.CONFIG_KEY + ZtaPolicy.file_ext)
        src.to_file(path)
        loaded = ZtaPolicy.load(str(tmp_path))
        assert loaded.binding_mode == BINDING_MODE_PREFER
        assert loaded.san_uri_template == 'spiffe://mission/{uuid}'
