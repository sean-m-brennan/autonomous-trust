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
"""ZTA hardening, the identity half: the gate publishes its finding, and background
re-verification turns a revocation into a standing (doc/architecture/zta-integration.md).
Split from the core's test_peer_standing.py (FEATURE_SPLIT_PLAN Phase 6), which keeps
the carrier, the ceiling and the unwind.

Two claims, both of which were previously false in a way nothing detected.

**The cap.** ``ddil_fallback_reputation_cap`` existed in the policy, was
serialized, and was printed in operator-facing logs as though it were being
enforced -- "admitting with reputation cap 0.50" -- while being read by
nothing. ``admit_capped`` was only ever compared against *reject*, so a capped
admission was byte-for-byte an ordinary one, and Python's ``_zta_capped`` set
was written and never read. A peer admitted on a deferred or unbound credential
accrued reputation with no ceiling at all.

**The failure.** The C twin's ``_send_reputation_penalty`` was blocked twice
over: it stamped ``task_uuid = 0``, which the reputation process discards by
design as the "system score" sentinel, and it sent ``score = -penalty``, which
``tx_score_in_range`` has rejected since doc/architecture/reputation.md put the scale at [0, 1] with no
negatives. A revocation therefore produced a log line and nothing else.

So the tests here assert the *effect* on the score, never that a message was
sent -- sending was exactly what used to happen while nothing moved.
"""
import hashlib
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import TransactionHistory
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.peer_standing import (
    PeerStanding, STANDING_PROVED, STANDING_CAPPED, STANDING_FAILED,
    STANDING_SOURCE_ZTA, STANDING_SOURCE_ETHNE)
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.zta.zta_policy import (
    ZtaPolicy, BINDING_MODE_OFF)
from .test_zta_admission import (_GateProc, _UnavailableVerifier, _peer,
                                 _BUNDLE)
import threading
from types import SimpleNamespace
from autonomous_trust.zta.zta_verifier import (
    Verifier, ZtaResult, ZtaStatus)
from autonomous_trust.zta import admission as _zta_admission

def _zta(name):
    """One of ZTA's admission functions (autonomous_trust.zta.admission), as a
    method for a stand-in process: they were IdentityProcess methods before
    FEATURE_SPLIT_PLAN Phase 6 moved them out of the core."""
    fn = getattr(_zta_admission, name)

    def method(self, *args, **kwargs):
        return fn(self, *args, **kwargs)
    method.__name__ = '_' + name
    return method



CAP = 0.5
TX_SCORE = 0.9


def _identity(tag: str, uuid=None) -> Identity:
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _make_rep_process(identity=None):
    log_q = queue.Queue()
    if identity is None:
        identity = _identity('self-node')
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    peer_store = MagicMock()
    peer_store.all = []
    rp = ReputationProcess({'processes': procs,
                            CfgIds.identity: identity,
                            CfgIds.peers: peer_store,
                            CfgIds.group: MagicMock()},
                           ProcessTracker(), log_q, suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    return rp


def _stand(rp, peer_uuid, status, ceiling=None, verified_at=None, reason='t',
           source=None):
    """Deliver one authority finding the way IdentityProcess does -- through
    Protocol, not by poking reputation's private state, so the IPC hand-off is
    part of what these tests cover. `source` defaults to zta."""
    rp.protocol.run_message_handlers(
        {CfgIds.reputation: queue.Queue()},
        PeerStanding(peer_uuid, status, ceiling, verified_at, reason, source))


def _supported(n, score=TX_SCORE):
    """The ceiling `n` transactions at `score` support, per the runtime's own
    shrinkage. Spelled out rather than hard-coded so the assertion says "what
    the evidence supports" instead of a magic number."""
    k = ReputationProcess.RESTORE_SHRINKAGE_K
    neutral = ReputationProcess.PREREP_NEUTRAL
    return (n * score + k * neutral) / (n + k)


# --- the carrier ------------------------------------------------------------

class TestIdentityPublishesTheFinding:
    """The gate is where the verdict is known; reputation is where it can bite.
    These cover the hand-off between them -- including the case that must send
    NOTHING, which is the one a naive implementation gets wrong."""

    def _published(self, proc, new_id):
        """What the gate hands to the other processes. `_GateProc` is a partial
        stand-in that binds only the methods its own tests needed, so bind the
        real publish path onto it rather than reimplementing it here -- a
        reimplementation would test the test."""
        sent = []
        proc.update = lambda obj, queues: sent.append(obj)
        proc.logger = MagicMock()
        _zta_admission.publish_zta_decision(proc, {}, new_id)
        return sent

    def test_a_capped_admission_publishes_the_policy_cap(self):
        proc = _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE,
                                   binding_mode=BINDING_MODE_OFF,
                                   allow_ddil_fallback=True,
                                   ddil_fallback_reputation_cap=0.42))
        proc._zta_anchor_cache = [('default', _UnavailableVerifier(), False)]
        peer = _peer(b'x')
        assert proc._zta_admit(peer) == 'admit_capped'
        sent = self._published(proc, peer)
        assert len(sent) == 1
        assert sent[0].status == STANDING_CAPPED
        # The number the operator log promises is the number reputation gets.
        assert sent[0].ceiling == 0.42
        assert sent[0].verified_at is None

    def test_a_disabled_policy_publishes_nothing(self):
        """Not 'proved' -- nothing. Reputation must never be told a peer's
        credential checks out because nobody looked; silence leaves the peer
        unbounded, which is what disabling ZTA already means."""
        proc = _GateProc(ZtaPolicy(enabled=False))
        peer = _peer(b'')
        assert proc._zta_admit(peer) == 'admit'
        assert self._published(proc, peer) == []

    def test_the_pending_finding_is_consumed_once(self):
        """Otherwise the next admission republishes the previous peer's
        verdict -- against the wrong peer."""
        proc = _GateProc(ZtaPolicy(enabled=True, require_at_admission=True,
                                   verifier_type='x509', ca_bundle_path=_BUNDLE,
                                   binding_mode=BINDING_MODE_OFF,
                                   allow_ddil_fallback=True,
                                   ddil_fallback_reputation_cap=0.42))
        proc._zta_anchor_cache = [('default', _UnavailableVerifier(), False)]
        peer = _peer(b'x')
        proc._zta_admit(peer)
        assert len(self._published(proc, peer)) == 1
        assert self._published(proc, peer) == []

    def test_a_propagation_failure_does_not_break_admission(self):
        """Losing a ceiling is bad; refusing to admit anyone because a queue
        was full is worse. It must be logged, though -- a silently dropped
        ceiling is a peer scoring unbounded with nothing saying why."""
        proc = _GateProc(ZtaPolicy(enabled=False))
        proc.logger = MagicMock()

        def _boom(_obj, _queues):
            raise RuntimeError('queue full')
        proc.update = _boom
        _zta_admission.publish_zta_standing(proc, {}, 'peer-1',
                                              STANDING_CAPPED, 0.5)
        assert proc.logger.warning.called


# --- background re-verification (the C-only gap, now closed) ----------------

class _ReverifyProc:
    """Stand-in exposing just the sweep and what it reaches for.

    IdentityProcess proper needs a whole process tree to construct; the sweep
    needs a policy, a verifier seam, a peer list and somewhere to publish. The
    real methods are bound here rather than reimplemented, so what runs is the
    shipping code path.
    """
    _ZTA_REVERIFY_CHECK_SEC = _zta_admission.ZTA_REVERIFY_CHECK_SEC
    _periodic_zta_reverify = _zta('periodic_zta_reverify')
    _zta_reverify_one = _zta('zta_reverify_one')
    _zta_credentials = _zta('zta_credentials')
    _zta_match_anchors = _zta('zta_match_anchors')
    _zta_anchor_verifiers = _zta('zta_anchor_verifiers')
    _publish_zta_standing = _zta('publish_zta_standing')

    def __init__(self, policy, peers, verifier):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_anchor_cache = [('default', verifier, False)]
        self._zta_capped = set()
        self._last_zta_reverify = None
        self.lock = threading.RLock()
        self.logger = MagicMock()
        self.identity = SimpleNamespace(uuid='self-uuid')
        self.peers = SimpleNamespace(all=list(peers))
        self.published = []
        self.update = lambda obj, queues: self.published.append(obj)

    def _zta_policy(self):
        return self.configs[ZtaPolicy.CONFIG_KEY]

    def report_exception(self, err, where):   # surfaced, never swallowed
        raise AssertionError('%s raised %r' % (where, err))


class _FixedVerifier(Verifier):
    """Chain validity and revocation are asked SEPARATELY, and answered
    separately here -- because that is how the real verifier behaves.

    `verify_credential` walks the chain and expiry and does not consult the
    CRL/OCSP source (C's x509_verify_credential does the same). A revoked
    certificate therefore still verifies. Collapsing the two into one answer
    would have hidden a real defect: an early draft of the sweep reported
    `proved` on the chain walk alone, so it could never have detected the
    revocation it exists to catch, and a stub that answered REVOKED to both
    questions would have called that green.
    """

    def __init__(self, status, reason='t', revocation=None):
        self._status, self._reason = status, reason
        self._revocation = revocation or ZtaStatus.UNAVAILABLE

    def verify_credential(self, cred_data):
        return ZtaResult.set(self._status, self._reason)

    def check_revocation(self, cred_hash):
        return ZtaResult.set(self._revocation, 'crl says %s'
                             % self._revocation.value)


def _cred_peer(nick='sensor', uuid='peer-1', cred=b'DER'):
    return SimpleNamespace(zta_credential=cred, zta_credentials=[],
                           zta_credential_binding=b'', zta_issuer='',
                           nickname=nick, uuid=uuid)


def _sweep(status, peer=None, revocation=None, **policy_kw):
    policy_kw.setdefault('enabled', True)
    policy_kw.setdefault('reverify_interval_sec', 3600)
    # binding_mode off by default: these fixtures provision no binding, and
    # `off` keeps each case testing the chain/revocation question it names.
    # The binding cases below set the mode they mean explicitly.
    policy_kw.setdefault('binding_mode', BINDING_MODE_OFF)
    proc = _ReverifyProc(ZtaPolicy(**policy_kw), [peer or _cred_peer()],
                         _FixedVerifier(status, revocation=revocation))
    proc._periodic_zta_reverify({})
    return proc


class TestBackgroundReverification:
    def test_a_revoked_credential_is_detected_after_admission(self):
        """The gap this closes. Python verified once, at admission, and never
        again -- so on a Python node a credential revoked afterwards was never
        noticed at all, whatever the C nodes in the same fleet did.

        The certificate still WALKS ITS CHAIN here (VERIFIED); only the CRL
        says otherwise. That is the realistic shape, and the one a sweep built
        on the chain walk alone would miss entirely."""
        proc = _sweep(ZtaStatus.VERIFIED, revocation=ZtaStatus.REVOKED)
        assert len(proc.published) == 1
        assert proc.published[0].status == STANDING_FAILED
        assert 'REVOKED' in proc.published[0].reason

    def test_expiry_is_graded_more_leniently_than_revocation(self):
        """Lapsed is not lying. Mirrors the C twin's half-weight penalty for
        EXPIRED, so the two runtimes bound the same peer the same way."""
        revoked = _sweep(ZtaStatus.VERIFIED,
                         revocation=ZtaStatus.REVOKED).published[0]
        expired = _sweep(ZtaStatus.EXPIRED).published[0]
        assert expired.ceiling > revoked.ceiling
        # ...and both derive from the one operator-facing knob.
        penalty = ZtaPolicy().revocation_reputation_penalty
        assert revoked.ceiling == pytest.approx(1.0 - penalty)
        assert expired.ceiling == pytest.approx(1.0 - penalty * 0.5)

    def test_a_still_valid_credential_reports_proved(self):
        proc = _sweep(ZtaStatus.VERIFIED)
        assert proc.published[0].status == STANDING_PROVED
        assert proc.published[0].ceiling is None
        # It also re-anchors the unwind: what the peer earns from here rests on
        # a credential that verified just now.
        assert proc.published[0].verified_at is not None

    def test_a_returning_verifier_lifts_a_ddil_cap(self):
        """The half a disconnected deployment actually feels: without a sweep,
        a peer admitted under DDIL stayed capped for ever, even once the
        infrastructure came back."""
        peer = _cred_peer()
        proc = _ReverifyProc(
            ZtaPolicy(enabled=True, binding_mode=BINDING_MODE_OFF), [peer],
            _FixedVerifier(ZtaStatus.VERIFIED))
        proc._zta_capped.add(peer.uuid)
        proc._periodic_zta_reverify({})
        assert peer.uuid not in proc._zta_capped
        assert proc.published[0].status == STANDING_PROVED

    def test_an_unreachable_verifier_says_nothing(self):
        """DDIL is not a finding about the peer. Publishing 'failed' because
        nobody could answer would punish every disconnected deployment;
        publishing 'proved' would be a lie. Silence leaves the standing the
        peer already had."""
        for status in (ZtaStatus.UNAVAILABLE, ZtaStatus.DEFERRED):
            assert _sweep(status).published == []

    def test_a_peer_with_no_credential_is_not_a_finding(self):
        peer = _cred_peer(cred=b'')
        assert _sweep(ZtaStatus.VERIFIED, peer=peer,
                      revocation=ZtaStatus.REVOKED).published == []

    def test_a_disabled_policy_never_sweeps(self):
        assert _sweep(ZtaStatus.VERIFIED, revocation=ZtaStatus.REVOKED,
                      enabled=False).published == []

    def test_a_zero_interval_disables_the_sweep(self):
        """Mirrors the C policy contract: reverify_interval_sec 0 disables
        periodic re-checks."""
        assert _sweep(ZtaStatus.VERIFIED, revocation=ZtaStatus.REVOKED,
                      reverify_interval_sec=0).published == []

    def test_the_interval_paces_the_walk(self):
        """A chain walk per peer is not free; the sweep must not run it on
        every wake."""
        proc = _sweep(ZtaStatus.VERIFIED, revocation=ZtaStatus.REVOKED)
        assert len(proc.published) == 1
        proc._periodic_zta_reverify({})
        proc._periodic_zta_reverify({})
        assert len(proc.published) == 1

    def test_the_first_pass_sweeps_immediately(self):
        """A node that was down while a credential was revoked must not wait a
        full interval to find out."""
        proc = _ReverifyProc(
            ZtaPolicy(enabled=True, binding_mode=BINDING_MODE_OFF),
            [_cred_peer()],
            _FixedVerifier(ZtaStatus.VERIFIED, revocation=ZtaStatus.REVOKED))
        assert proc._last_zta_reverify is None
        proc._periodic_zta_reverify({})
        assert len(proc.published) == 1

    def test_an_unbound_credential_stays_capped_under_prefer(self):
        """The sweep must not lift a cap it did not earn.

        Under `binding_mode: prefer` a peer is admitted CAPPED when its
        credential chains but carries no binding. Its chain keeps verifying for
        ever, so a sweep that reported `proved` on the chain walk alone would
        silently lift that cap on its first pass -- handing an unbound peer the
        standing of a bound one, for free, minutes after admission.
        """
        from autonomous_trust.zta.zta_policy import (
            BINDING_MODE_PREFER)
        proc = _sweep(ZtaStatus.VERIFIED, binding_mode=BINDING_MODE_PREFER)
        assert len(proc.published) == 1
        assert proc.published[0].status == STANDING_CAPPED
        assert proc.published[0].ceiling == \
            ZtaPolicy().ddil_fallback_reputation_cap

    def test_an_unbound_credential_fails_under_require(self):
        """`require` means the peer would not be admitted today. Graded at the
        gentler expiry weight, not the revocation one: unbound is a
        provisioning state, not a lie."""
        from autonomous_trust.zta.zta_policy import (
            BINDING_MODE_REQUIRE)
        proc = _sweep(ZtaStatus.VERIFIED, binding_mode=BINDING_MODE_REQUIRE)
        assert len(proc.published) == 1
        assert proc.published[0].status == STANDING_FAILED
        assert proc.published[0].ceiling == pytest.approx(
            1.0 - ZtaPolicy().revocation_reputation_penalty * 0.5)


