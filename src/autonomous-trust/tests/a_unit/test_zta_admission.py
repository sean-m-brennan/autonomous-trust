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
    ZtaPolicy, ZtaResult, ZtaStatus, Verifier)

pytest.importorskip("cryptography")

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


class _GateProc:
    """Minimal stand-in carrying the real ZTA gate methods."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_admit = IdentityProcess._zta_admit

    def __init__(self, policy: ZtaPolicy):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_capped = set()
        self.logger = logging.getLogger('test.zta')


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
    def _proc(self, **kw):
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


class TestZtaDdilFallback:
    def _proc(self, allow_fallback):
        proc = _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE,
                                   allow_ddil_fallback=allow_fallback,
                                   ddil_fallback_reputation_cap=0.5))
        proc._zta_verifier_cache = _UnavailableVerifier()  # force UNAVAILABLE
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
