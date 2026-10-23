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
"""ZTA's answer to the join policy's "is this identity anchored"
(RD_14.4_HOSTILE_JOIN_PLAN.md Phase 2).

``zta`` needs a credential that chains to a held anchor AND is bound to the
identity presenting it, whatever the admission binding_mode: a certificate is
public, so a cohort could hand a joiner anyone's. ``operator`` additionally
needs an operator-class credential and a verified operator-key binding naming
THIS node's operator key (the user's call, 2026-10-23). Real CAs, real
signatures, as test_zta_multi_credential.
"""
import pytest

pytest.importorskip("cryptography")

from tests.a_unit.test_zta_multi_credential import (# noqa: E402
    _Gate, _bind, _identity, _leaf, _policy, _sign, _zta, agencies)  # noqa: F401
from autonomous_trust.core._python.identity.operator_binding import (# noqa: E402
    operator_binding_preimage)
from autonomous_trust.zta import BINDING_MODE_OFF, ZtaPolicy  # noqa: E402

GUARDIAN = bytes(range(32))
OTHER_GUARDIAN = bytes(range(1, 33))


class _Joiner(_Gate):
    anchor_classes = _zta('anchor_classes')


def _bound(agencies, tag='alpha', agency='dod'):
    peer = _identity(tag)
    key, cred = _leaf(agencies, agency)
    peer.zta_credential, peer.zta_credential_binding = cred, _bind(key, peer, cred)
    return peer, key, cred


def _operator_policy(agencies):
    return ZtaPolicy(enabled=True, require_at_admission=True, verifier_type='x509',
                     anchors=[{'name': 'dod', 'ca_bundle_path': agencies['dod'].bundle,
                               'operator': True}])


def _me(guardian):
    me = _identity('me', seed=b'33')
    me.operator_pubkey = guardian
    return me


def _with_operator_key(peer, key, guardian):
    peer.operator_pubkey = guardian
    peer.operator_key_binding = _sign(key, operator_binding_preimage(peer, guardian))
    return peer


def test_a_bound_credential_from_a_held_anchor_is_a_zta_anchor(agencies):
    peer, _key, _cred = _bound(agencies)
    assert _Joiner(_policy(agencies)).anchor_classes(peer) == {'zta'}


def test_an_unbound_credential_anchors_nobody_even_where_admission_allows_it(agencies):
    peer = _identity('alpha')
    _key, peer.zta_credential = _leaf(agencies, 'dod')
    joiner = _Joiner(_policy(agencies, mode=BINDING_MODE_OFF))
    assert joiner._zta_admit(peer) == 'admit'
    assert joiner.anchor_classes(peer) == frozenset()


def test_someone_elses_binding_anchors_nobody(agencies):
    victim, key, cred = _bound(agencies, tag='victim')
    impostor = _identity('impostor', seed=b'44')
    impostor.zta_credential = cred
    impostor.zta_credential_binding = victim.zta_credential_binding
    assert _Joiner(_policy(agencies)).anchor_classes(impostor) == frozenset()


def test_a_credential_from_an_unheld_anchor_anchors_nobody(agencies):
    peer, _key, _cred = _bound(agencies, agency='rogue')
    assert _Joiner(_policy(agencies)).anchor_classes(peer) == frozenset()


def test_a_disabled_policy_anchors_nobody(agencies):
    peer, _key, _cred = _bound(agencies)
    assert _Joiner(ZtaPolicy(enabled=False)).anchor_classes(peer) == frozenset()


def test_my_own_operator_key_makes_an_operator_anchor(agencies):
    peer, key, _cred = _bound(agencies)
    _with_operator_key(peer, key, GUARDIAN)
    joiner = _Joiner(_operator_policy(agencies), identity=_me(GUARDIAN))
    assert joiner.anchor_classes(peer) == {'zta', 'operator'}


def test_another_operators_key_is_not_an_operator_anchor(agencies):
    peer, key, _cred = _bound(agencies)
    _with_operator_key(peer, key, OTHER_GUARDIAN)
    joiner = _Joiner(_operator_policy(agencies), identity=_me(GUARDIAN))
    assert joiner.anchor_classes(peer) == {'zta'}


def test_a_node_with_no_operator_key_has_no_operator_anchors(agencies):
    peer, key, _cred = _bound(agencies)
    _with_operator_key(peer, key, GUARDIAN)
    joiner = _Joiner(_operator_policy(agencies), identity=_me(b''))
    assert joiner.anchor_classes(peer) == {'zta'}


def test_an_operator_key_on_a_non_operator_credential_is_not_an_anchor(agencies):
    peer, key, _cred = _bound(agencies)
    _with_operator_key(peer, key, GUARDIAN)
    joiner = _Joiner(_policy(agencies), identity=_me(GUARDIAN))
    assert joiner.anchor_classes(peer) == {'zta'}


def test_a_forged_operator_binding_is_not_an_anchor(agencies):
    peer, _key, _cred = _bound(agencies)
    other_key, _other = _leaf(agencies, 'dod', cn='other')
    _with_operator_key(peer, other_key, GUARDIAN)
    joiner = _Joiner(_operator_policy(agencies), identity=_me(GUARDIAN))
    assert 'operator' not in joiner.anchor_classes(peer)
