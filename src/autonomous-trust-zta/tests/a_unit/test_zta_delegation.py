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
"""Members' ZTA findings leave the node and are acted on (ISSUES §2.20).

The decisions themselves are pinned in both runtimes by the conformance
scenarios ``zta-delegation-vouch`` and ``zta-delegation-alert``. What those
cannot reach is the wiring around them, which is where §2.20 actually was: the
vouch and the alert were built and then never sent, and nothing received them.
So these drive the identity-side code: the sweep sends, the handlers receive,
a finding waits for the sender's reputation, and a reputation answer is taken
only from this node's own reputation process.
"""
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.core._python.identity.peer_standing import (
    STANDING_CAPPED, STANDING_FAILED, STANDING_PROVED)
from autonomous_trust.core.extensions import process_alias
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.system import CfgIds
from autonomous_trust.zta import admission as _zta_admission
from autonomous_trust.zta import delegation
from autonomous_trust.zta.zta_policy import BINDING_MODE_OFF, ZtaPolicy
from autonomous_trust.zta.zta_verifier import Verifier, ZtaResult, ZtaStatus

CRED_HASH = bytes(range(32))


class _Queue(list):
    def put(self, item, block=True, timeout=None):  # noqa: ARG002
        self.append(item)


class _Verifier(Verifier):
    """The chain walk and the revocation lookup, answered separately (the real
    verifier asks them separately too)."""

    def __init__(self, chain, revocation=ZtaStatus.UNAVAILABLE):
        self.chain, self.revocation = chain, revocation

    def verify_credential(self, cred_data):
        return ZtaResult.set(self.chain, 'chain %s' % self.chain.value)

    def check_revocation(self, cred_hash):
        return ZtaResult.set(self.revocation, 'crl %s' % self.revocation.value)


_COUNT = iter(range(1, 250))


def _peer(credential=True):
    """A real Identity (Message refuses anything else as a recipient); only the
    peer under test carries a credential, so only it is re-verified."""
    n = next(_COUNT)
    peer = Identity.initialize('p%d' % n, 'p%d' % n, '10.0.9.%d' % n)
    if credential:
        peer.zta_credential, peer.zta_credential_hash = b'DER', CRED_HASH
    return peer


class _Proc:
    """An identity process as the ZTA functions see it: a policy, a verifier,
    a peer table, a group address map, queues to send on and somewhere to
    publish a standing."""

    def __init__(self, verifier, peers, members, quorum=1):
        self.name = CfgIds.identity
        self.q_cadence = 0.01
        self.lock = threading.RLock()
        self.logger = MagicMock()
        self.identity = SimpleNamespace(uuid=str(uuid4()))
        self.peers = SimpleNamespace(all=list(peers))
        self.group = SimpleNamespace(_address_map={u: '10.0.0.%d' % i
                                                   for i, u in enumerate(members)})
        self.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(
            enabled=True, reverify_interval_sec=3600, binding_mode=BINDING_MODE_OFF,
            delegated_verification_quorum=quorum)}
        self.protocol = SimpleNamespace(handlers={})
        self.protocol.register_handler = self.protocol.handlers.__setitem__
        _zta_admission.init_state(self)
        self._zta_anchor_cache = [('default', verifier, False)]
        self.published = []
        self.update = lambda obj, queues: self.published.append(obj)
        self.queues = {CfgIds.network: _Queue(), CfgIds.reputation: _Queue()}

    def report_exception(self, err, where):
        raise AssertionError('%s raised %r' % (where, err))


def _finding(proc, verb, sender, peer, status='REVOKED', cred_hash=CRED_HASH):
    return SimpleNamespace(
        process=proc.name, function=verb, from_whom=SimpleNamespace(uuid=sender),
        obj='{"credential_hash": "%s", "peer_uuid": "%s", "reason": "", "status": "%s"}'
            % (cred_hash.hex(), peer, status))


def _rep_answer(proc, uuid, score, from_whom=None):
    return SimpleNamespace(
        process=proc.name, function=_zta_admission.REP_LOCAL_RESPONSE,
        from_whom=from_whom,
        obj='{"peer_uuid": "%s", "score": %s, "found": true}' % (uuid, score))


class TestTheSweepTellsTheGroup:
    def _setup(self, verifier):
        subject = _peer()
        member = _peer(credential=False)
        stranger = _peer(credential=False)
        proc = _Proc(verifier, [subject, member, stranger],
                     members=[str(subject.uuid), str(member.uuid)])
        proc.group._address_map[proc.identity.uuid] = '10.0.0.99'
        return proc, subject, member

    def test_a_revocation_is_sent_to_every_other_member(self):
        proc, subject, member = self._setup(_Verifier(ZtaStatus.VERIFIED, ZtaStatus.REVOKED))
        _zta_admission.periodic_zta_reverify(proc, proc.queues)
        sent = proc.queues[CfgIds.network]
        # Not to the subject, not to ourselves, not to a non-member.
        assert [str(m.to_whom[0].uuid) for m in sent] == [str(member.uuid)]
        assert sent[0].function == delegation.ZTA_PROTO_REVOCATION_ALERT
        assert sent[0].process == delegation.ZTA_PROCESS
        assert sent[0].encrypt

    def test_a_proved_credential_is_vouched_for(self):
        proc, _subject, _member = self._setup(_Verifier(ZtaStatus.VERIFIED))
        _zta_admission.periodic_zta_reverify(proc, proc.queues)
        assert [m.function for m in proc.queues[CfgIds.network]] == \
            [delegation.ZTA_PROTO_VERIFICATION]

    def test_ddil_sends_nothing_and_marks_the_peer_as_waiting(self):
        proc, subject, _member = self._setup(_Verifier(ZtaStatus.DEFERRED))
        _zta_admission.periodic_zta_reverify(proc, proc.queues)
        assert proc.queues[CfgIds.network] == []
        assert proc._zta_deleg.peers[str(subject.uuid)].unverified


class TestFindingsAreActedOn:
    def test_an_alert_is_rechecked_and_our_own_answer_is_published(self):
        subject, member = _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.VERIFIED, ZtaStatus.REVOKED),
                     [subject, member], [str(subject.uuid), str(member.uuid)])
        assert _zta_admission.handle_zta_finding(
            proc, proc.queues, _finding(proc, 'zta_revoked', str(member.uuid), str(subject.uuid)),
            delegation.ALERT)
        assert [p.status for p in proc.published] == [STANDING_FAILED]
        # The re-check needed no reputation answer.
        assert proc.queues[CfgIds.reputation] == []

    def test_an_alert_our_verifier_contradicts_changes_nothing(self):
        subject, member = _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.VERIFIED, ZtaStatus.VERIFIED),
                     [subject, member], [str(subject.uuid), str(member.uuid)])
        _zta_admission.handle_zta_finding(
            proc, proc.queues, _finding(proc, 'zta_revoked', str(member.uuid), str(subject.uuid)),
            delegation.ALERT)
        assert proc.published == []

    def test_a_vouch_waits_for_the_senders_reputation(self):
        subject, member = _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.DEFERRED), [subject, member],
                     [str(subject.uuid), str(member.uuid)])
        proc._zta_deleg.own_result(str(subject.uuid), ZtaStatus.DEFERRED)
        _zta_admission.handle_zta_finding(
            proc, proc.queues,
            _finding(proc, 'zta_verified', str(member.uuid), str(subject.uuid), 'VERIFIED'),
            delegation.VOUCH)
        # Asked of our reputation process, and held.
        asked = proc.queues[CfgIds.reputation]
        assert len(asked) == 1 and asked[0].function == 'local_rep_query'
        assert proc.published == [] and len(proc._zta_pending_findings) == 1
        # The answer releases it: quorum 1, so the cap lifts.
        _zta_admission.handle_rep_response(proc, proc.queues,
                                           _rep_answer(proc, str(member.uuid), 0.9))
        assert [p.status for p in proc.published] == [STANDING_PROVED]
        assert proc._zta_pending_findings == []

    def test_a_reputation_answer_off_the_wire_is_refused(self):
        """A member forging one would set its own score past the bar."""
        subject, member = _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.DEFERRED), [subject, member],
                     [str(subject.uuid), str(member.uuid)])
        proc._zta_deleg.own_result(str(subject.uuid), ZtaStatus.DEFERRED)
        _zta_admission.handle_zta_finding(
            proc, proc.queues,
            _finding(proc, 'zta_verified', str(member.uuid), str(subject.uuid), 'VERIFIED'),
            delegation.VOUCH)
        _zta_admission.handle_rep_response(
            proc, proc.queues, _rep_answer(proc, str(member.uuid), 1.0,
                                           from_whom=SimpleNamespace(uuid=str(member.uuid))))
        assert proc._zta_rep_cache == {}
        assert proc.published == []

    def test_quorum_of_alerts_caps_a_peer_we_cannot_check(self):
        subject, a, b = _peer(), _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.DEFERRED), [subject, a, b],
                     [str(subject.uuid), str(a.uuid), str(b.uuid)], quorum=2)
        for sender in (a, b):
            proc._zta_rep_cache[str(sender.uuid)] = (0.9, 1e18)
        for sender in (a, b):
            _zta_admission.handle_zta_finding(
                proc, proc.queues, _finding(proc, 'zta_revoked', str(sender.uuid), str(subject.uuid)),
                delegation.ALERT)
        assert [(p.status, p.ceiling) for p in proc.published] == \
            [(STANDING_CAPPED, ZtaPolicy().ddil_fallback_reputation_cap)]

    def test_a_finding_with_no_sender_or_a_bad_body_is_refused(self):
        subject, member = _peer(), _peer()
        proc = _Proc(_Verifier(ZtaStatus.VERIFIED, ZtaStatus.REVOKED),
                     [subject, member], [str(subject.uuid), str(member.uuid)])
        nobody = _finding(proc, 'zta_revoked', str(member.uuid), str(subject.uuid))
        nobody.from_whom = None
        bad = _finding(proc, 'zta_revoked', str(member.uuid), str(subject.uuid))
        bad.obj = '{"peer_uuid": "not-a-uuid"}'
        for message in (nobody, bad):
            assert _zta_admission.handle_zta_finding(proc, proc.queues, message,
                                                     delegation.ALERT)
        assert proc.published == []


class TestRouting:
    def test_c_process_name_reaches_identity(self):
        """C sends to its zta_verify process; Python's ZTA rides identity."""
        assert process_alias(delegation.ZTA_PROCESS) == CfgIds.identity
        assert process_alias('no_such_process') is None

    def test_handlers_are_registered_on_identity_only(self):
        proc = _Proc(_Verifier(ZtaStatus.VERIFIED), [], [])
        _zta_admission.register_delegation_handlers(proc)
        assert set(proc.protocol.handlers) == {
            delegation.ZTA_PROTO_VERIFICATION, delegation.ZTA_PROTO_REVOCATION_ALERT,
            _zta_admission.REP_LOCAL_RESPONSE}


class TestReputationAnswersLocally:
    def _rep(self, score):
        peer = uuid4()
        rep = SimpleNamespace(reputations={peer: score}, q_cadence=0.01,
                              logger=MagicMock(),
                              identity=SimpleNamespace(uuid=str(uuid4())))
        return rep, peer

    def _ask(self, rep, peer, from_whom=None):
        queues = {CfgIds.identity: _Queue()}
        message = SimpleNamespace(
            function='local_rep_query', from_whom=from_whom,
            obj='{"peer_uuid": "%s", "return_process": "identity"}' % peer)
        assert ReputationProcess.handle_local_rep_query(rep, queues, message)
        return queues[CfgIds.identity]

    def test_a_local_query_is_answered(self):
        rep, peer = self._rep(0.85)
        reply = self._ask(rep, peer)
        assert len(reply) == 1 and reply[0].function == 'local_rep_response'
        assert '0.85' in reply[0].obj and 'true' in reply[0].obj

    def test_a_query_off_the_wire_is_refused(self):
        rep, peer = self._rep(0.85)
        assert self._ask(rep, peer, from_whom=SimpleNamespace(uuid=str(uuid4()))) == []
