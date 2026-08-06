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
"""Unit tests for the ZTA admission decision (idprocess.welcoming_committee gate).

The decision logic (`_zta_admit`) is exercised in isolation by binding the real
IdentityProcess methods onto a lightweight stand-in, avoiding the heavyweight
process construction (queues/subsystems/network).
"""
import logging
import os
from types import SimpleNamespace

import pytest

from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.zta import (
    ZtaPolicy, ZtaResult, ZtaStatus, Verifier, BINDING_MODE_OFF)

pytest.importorskip("cryptography")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
_CA_DIR = os.path.join(_ROOT, 'src', 'c', 'test', 'zta_test_ca', 'output')
_BUNDLE = os.path.join(_CA_DIR, 'ca-bundle.pem')
_CERTS = os.path.join(_CA_DIR, 'certs')
_REVOKED_CRL = os.path.join(_CA_DIR, 'crl', 'intermediate-revoked.crl.pem')
_EMPTY_CRL = os.path.join(_CA_DIR, 'crl', 'intermediate.crl.pem')
_have_ca = os.path.isfile(_BUNDLE) and os.path.isdir(_CERTS)
requires_ca = pytest.mark.skipif(not _have_ca, reason="test CA not generated")


def _cred(name: str) -> bytes:
    with open(os.path.join(_CERTS, name + '.der'), 'rb') as fp:
        return fp.read()


class _GateProc:
    """Minimal stand-in carrying the real ZTA gate methods."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    # Operator-attended classification helpers (ethne D8/Q9) that _zta_admit now
    # calls in the VERIFIED branch — bind them so the stand-in behaves like the
    # real IdentityProcess (no operator anchor configured => operator_bound
    # stays False, which does not affect any admit/reject decision here).
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _is_operator_credential = IdentityProcess._is_operator_credential
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)
    _zta_admit = IdentityProcess._zta_admit
    _zta_credential_replayed = IdentityProcess._zta_credential_replayed
    # Multi-credential admission (ISSUES §1.5): the credential list, the per-anchor
    # chain walk, and the anchor-verifier seam _zta_admit now goes through.
    _zta_credentials = IdentityProcess._zta_credentials
    _zta_match_anchors = IdentityProcess._zta_match_anchors
    _zta_anchor_verifiers = IdentityProcess._zta_anchor_verifiers

    def __init__(self, policy: ZtaPolicy, peers=None, identity=None):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_operator_verifier_cache = None
        self._zta_anchor_cache = None
        self._operator_verified = set()
        self._zta_capped = set()
        self.logger = logging.getLogger('test.zta')
        # Roster / own identity for the credential-uniqueness gate. Default
        # empty (no prior binding), matching the original single-peer tests.
        self.peers = peers if peers is not None else SimpleNamespace(all=[])
        self.identity = identity


def _peer(cred: bytes = b'', nick='sensor-2', uuid='uuid-sensor-2'):
    return SimpleNamespace(zta_credential=cred, nickname=nick, uuid=uuid)


class _UnavailableVerifier(Verifier):
    def verify_credential(self, cred_data):
        return ZtaResult.set(ZtaStatus.UNAVAILABLE, 'infra unreachable')


class TestZtaAdmissionDisabled:
    def test_disabled_policy_is_noop(self):
        proc = _GateProc(ZtaPolicy(enabled=False))
        assert proc._zta_admit(_peer(b'')) == 'admit'

    def test_enabled_but_not_required_is_noop(self):
        proc = _GateProc(ZtaPolicy(enabled=True, require_at_admission=False))
        assert proc._zta_admit(_peer(b'')) == 'admit'


@requires_ca
class TestZtaAdmissionX509:
    """Chain validity only. These fixtures predate the credential->identity binding
    and provision none, so they run `binding_mode: off` -- otherwise every one of
    them would reject for the unrelated reason that nothing is bound, and stop
    testing the chain walk. Binding enforcement has its own tests below and in
    test_zta_binding.py."""

    def _proc(self, **kw):
        kw.setdefault('binding_mode', BINDING_MODE_OFF)
        return _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE, **kw))

    def test_valid_credential_admitted(self):
        assert self._proc()._zta_admit(_peer(_cred('drone_alpha'))) == 'admit'

    def test_unsigned_rejected(self):
        # No credential at all (the "unsigned" forgery mode).
        assert self._proc()._zta_admit(_peer(b'')) == 'reject'

    def test_untrusted_issuer_rejected(self):
        # Self-signed / unknown-CA cert not chained to the mission roster.
        assert self._proc()._zta_admit(_peer(_cred('unknown_ca'))) == 'reject'

    def test_expired_rejected(self):
        assert self._proc()._zta_admit(_peer(_cred('expired'))) == 'reject'


@requires_ca
class TestZtaAdmissionRevocation:
    """§7.1 caveat 2: a chain-valid but CRL-revoked cert must be rejected at
    admission. drone_alpha is the cert revoked in intermediate-revoked.crl.pem;
    it is otherwise valid (admitted above when no CRL is configured).

    `binding_mode: off` for the same reason as TestZtaAdmissionX509."""

    def _proc(self, **kw):
        kw.setdefault('binding_mode', BINDING_MODE_OFF)
        return _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE, **kw))

    @pytest.mark.skipif(not os.path.isfile(_REVOKED_CRL),
                        reason="revoked CRL not generated")
    def test_revoked_credential_rejected(self):
        proc = self._proc(crl_path=_REVOKED_CRL)
        assert proc._zta_admit(_peer(_cred('drone_alpha'))) == 'reject'

    @pytest.mark.skipif(not os.path.isfile(_EMPTY_CRL),
                        reason="empty CRL not generated")
    def test_unrevoked_credential_admitted_with_crl(self):
        # Same cert, an (empty) CRL configured -> not on the list -> admit.
        proc = self._proc(crl_path=_EMPTY_CRL)
        assert proc._zta_admit(_peer(_cred('drone_alpha'))) == 'admit'

    def test_no_crl_source_still_admits(self):
        # Backward compat: no revocation source -> check_revocation is
        # UNAVAILABLE, which does NOT block (only an affirmative REVOKED does).
        proc = self._proc()
        assert proc._zta_admit(_peer(_cred('drone_alpha'))) == 'admit'


@requires_ca
class TestZtaCredentialReplay:
    """ISSUES §1.5: a chain-valid credential harvested from one peer's announce
    and re-presented under a DIFFERENT identity must be rejected as a replay.
    Uniqueness is enforced against credentials already bound to known peers (the
    roster, built from announces propagated across the mesh) and our own
    identity."""

    def _proc(self, peers=None, identity=None):
        # `binding_mode: off` deliberately: this class pins the ROSTER-based
        # first-use-wins check, which is what an unbound credential still relies on.
        # A bound credential does not need it (the signature names the node), so
        # running these under `require` would test the binding instead.
        return _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE,
                                   binding_mode=BINDING_MODE_OFF),
                         peers=peers, identity=identity)

    def test_same_credential_different_identity_rejected(self):
        cred = _cred('drone_alpha')
        incumbent = _peer(cred, nick='drone-alpha', uuid='uuid-A')
        proc = self._proc(peers=SimpleNamespace(all=[incumbent]))
        # A different identity presents the SAME (valid) credential -> replay.
        attacker = _peer(cred, nick='drone-alpha-clone', uuid='uuid-B')
        assert proc._zta_admit(attacker) == 'reject'

    def test_same_identity_reannounce_admitted(self):
        cred = _cred('drone_alpha')
        incumbent = _peer(cred, nick='drone-alpha', uuid='uuid-A')
        proc = self._proc(peers=SimpleNamespace(all=[incumbent]))
        # The SAME identity re-announcing its own credential is not a replay.
        assert proc._zta_admit(_peer(cred, nick='drone-alpha', uuid='uuid-A')) == 'admit'

    def test_distinct_credentials_admitted(self):
        incumbent = _peer(_cred('drone_alpha'), nick='drone-alpha', uuid='uuid-A')
        proc = self._proc(peers=SimpleNamespace(all=[incumbent]))
        # A different identity with its OWN distinct valid credential is fine.
        newcomer = _peer(_cred('drone_bravo'), nick='drone-bravo', uuid='uuid-B')
        assert proc._zta_admit(newcomer) == 'admit'

    def test_replay_of_own_credential_rejected(self):
        cred = _cred('drone_alpha')
        me = _peer(cred, nick='me', uuid='uuid-self')
        proc = self._proc(identity=me)
        # Someone else wearing OUR credential -> replay.
        assert proc._zta_admit(_peer(cred, nick='impostor', uuid='uuid-X')) == 'reject'

    def test_no_roster_admits_valid_credential(self):
        # Empty roster + no own identity: nothing previously seen -> admit.
        assert self._proc()._zta_admit(_peer(_cred('drone_alpha'))) == 'admit'


class TestZtaDdilFallback:
    def _proc(self, allow_fallback):
        proc = _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE,
                                   binding_mode=BINDING_MODE_OFF,
                                   allow_ddil_fallback=allow_fallback,
                                   ddil_fallback_reputation_cap=0.5))
        # Injected at the anchor-verifier seam, which is what the multi-credential
        # gate walks; _zta_verifier_cache is no longer on that path.
        proc._zta_anchor_cache = [('default', _UnavailableVerifier(), False)]
        return proc

    def test_deferred_admitted_capped_when_fallback_on(self):
        proc = self._proc(allow_fallback=True)
        peer = _peer(_cred('drone_alpha') if _have_ca else b'x')
        assert proc._zta_admit(peer) == 'admit_capped'
        assert peer.uuid in proc._zta_capped

    def test_deferred_rejected_when_fallback_off(self):
        proc = self._proc(allow_fallback=False)
        peer = _peer(_cred('drone_alpha') if _have_ca else b'x')
        assert proc._zta_admit(peer) == 'reject'
        assert peer.uuid not in proc._zta_capped
