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
"""ZTA hardening: the DDIL cap is real, and a failure unwinds (doc/architecture/zta-integration.md).

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
from types import SimpleNamespace

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

class TestCarrier:
    def test_it_survives_the_pickle_that_ipc_requires(self):
        """It crosses a process boundary, so this is a hard requirement, not a
        nicety -- an unpicklable carrier drops the ceiling silently."""
        import pickle
        original = PeerStanding(uuid4(), STANDING_CAPPED, 0.5, 1234.0, 'DDIL')
        back = pickle.loads(pickle.dumps(original))
        assert (back.peer_uuid, back.status, back.ceiling, back.verified_at) \
            == (original.peer_uuid, STANDING_CAPPED, 0.5, 1234.0)

    def test_protocol_records_it_per_peer_and_source(self):
        """Filed under "<peer>|<source>", not under the peer alone (P4.1).

        Two authorities may bound the same peer for unrelated reasons, so a
        single slot per peer would let whichever spoke last erase the other.
        """
        rp = _make_rep_process()
        a, b = uuid4(), uuid4()
        _stand(rp, a, STANDING_CAPPED, CAP)
        _stand(rp, b, STANDING_PROVED, None, 10.0)
        assert rp.protocol.peer_standing['%s|zta' % a].ceiling == CAP
        assert rp.protocol.peer_standing['%s|zta' % b].ceiling is None
        assert str(a) not in rp.protocol.peer_standing

    def test_two_authorities_both_bind_and_the_strictest_wins(self):
        """The reduction is MINIMUM over sources, and neither authority may
        clear the other's finding -- a ZTA re-verification says nothing about
        whether a community expelled the person holding the credential."""
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, 0.15)
        _stand(rp, peer, STANDING_CAPPED, 0.20, source=STANDING_SOURCE_ETHNE)
        # Different ceilings, stricter one first: last-write-wins would give 0.20.
        assert rp._standing_ceiling(peer) == 0.15
        # The polity readmits. ZTA's bound survives.
        _stand(rp, peer, STANDING_PROVED, None, source=STANDING_SOURCE_ETHNE)
        assert rp._standing_ceiling(peer) == 0.15

    def test_an_unknown_authority_is_refused(self):
        """A ceiling filed under a source nothing reduces over would bound
        nobody while looking, in the map, exactly like one that did."""
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, 0.15, source='nonsense')
        assert rp._standing_ceiling(peer) is None

    def test_a_later_verdict_replaces_an_earlier_one(self):
        """Re-verification must be able to lift a cap, or a peer that repairs
        its credential stays bounded forever."""
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, CAP)
        assert rp._standing_ceiling(peer) == CAP
        _stand(rp, peer, STANDING_PROVED, None, 10.0)
        assert rp._standing_ceiling(peer) is None


# --- the cap actually binds -------------------------------------------------

class TestCeilingIsEnforced:
    def test_a_capped_peer_is_bounded(self):
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, CAP)
        assert rp._apply_standing_ceiling(peer, 0.95) == CAP

    def test_a_score_already_below_the_cap_is_untouched(self):
        """The cap is a ceiling, not an assignment: it must never RAISE a peer
        that the ordinary algebra scored lower."""
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, CAP)
        assert rp._apply_standing_ceiling(peer, 0.11) == 0.11

    def test_a_proved_peer_is_unbounded(self):
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_PROVED, None, 10.0)
        assert rp._apply_standing_ceiling(peer, 0.95) == 0.95

    def test_silence_does_not_bound_anyone(self):
        """A deployment that has not enabled ZTA is not bounded by it. This is
        the no-change-in-behavior setting, and it is why IdentityProcess sends
        nothing at all when the policy is disabled rather than sending
        'proved'."""
        rp = _make_rep_process()
        assert rp._apply_standing_ceiling(uuid4(), 0.95) == 0.95

    def test_the_bound_lands_on_the_stored_score_not_just_the_report(self):
        """Enforced where the score is WRITTEN. A ceiling applied only at read
        time leaves the unbounded value in the store, and the next consumer to
        report it -- persistence, the app carrier, a rep_req answer -- leaks
        the number the cap was supposed to withhold."""
        rp = _make_rep_process()
        peer = uuid4()
        _stand(rp, peer, STANDING_CAPPED, CAP)
        rp._pure_reputation = MagicMock(return_value=0.97)
        rp._contrite_tit_for_tat = MagicMock(return_value=0.97)
        rp._persist_reputations = MagicMock()
        rp._compute_reputation(peer, MagicMock(), MagicMock())
        assert rp.reputations.current[peer] == CAP


    def test_a_cap_republishes_the_tier_it_allows(self):
        """A cap gates THE MOMENT IT LANDS (Phase 4 P4.1, found writing
        moderation_cohort.sh). Identity's tier-gates read the tier reputation
        last published; a capped standing used to publish nothing, so a tier-2
        peer capped into tier 1 kept clearing tier-2 gates until its score next
        happened to be recomputed. The stored score is left alone. Mirrors the
        C twin's test_a_cap_republishes_the_tier_it_allows."""
        rp = _make_rep_process()
        peer = uuid4()
        rp.reputations.update(peer, 0.70)                     # tier 2
        rp._publish_tier_change = MagicMock()
        _stand(rp, peer, STANDING_CAPPED, 0.55, source=STANDING_SOURCE_ETHNE)
        rp._apply_peer_standings({})
        rp._publish_tier_change.assert_called_once()
        assert rp._publish_tier_change.call_args[0][2] == 0.55  # tier 1
        assert rp.reputations.current[peer] == 0.70
        rp._apply_peer_standings({})                           # restated: no-op
        assert rp._publish_tier_change.call_count == 1


# --- the unwind -------------------------------------------------------------

class TestUnwind:
    def _with_history(self, rp, peer, n_before, n_after):
        """`n_before` bilateral txs, then the ZTA proof point, then `n_after`.
        Returns the anchor index, so a test can state the boundary it expects
        the unwind to respect."""
        me = rp.identity.uuid
        for i in range(n_before):
            tid = UUID(int=i + 1)
            rp.history.update(tid, me, TX_SCORE)
            rp.history.update(tid, peer, TX_SCORE)
        _stand(rp, peer, STANDING_PROVED, None, 10.0)
        rp._apply_peer_standings({})
        anchor = rp._peer_proved_index['%s|zta' % peer]
        for i in range(n_after):
            tid = UUID(int=1000 + i)
            rp.history.update(tid, me, TX_SCORE)
            rp.history.update(tid, peer, TX_SCORE)
        return anchor

    def test_the_anchor_is_the_chain_position_at_proof_time(self):
        rp = _make_rep_process()
        peer = uuid4()
        anchor = self._with_history(rp, peer, n_before=2, n_after=5)
        # Two bilateral txs committed before the proof, so the anchor sits past
        # them and before everything that followed.
        assert anchor == 2

    def test_only_pre_anchor_evidence_supports_the_unwound_score(self):
        """The doc/architecture/zta-integration.md answer to 'how far back': back to the last proved
        verification. Standing earned while nobody could confirm the peer is
        what the failure calls into question; standing earned before it is
        not."""
        rp = _make_rep_process()
        peer = uuid4()
        anchor = self._with_history(rp, peer, n_before=2, n_after=8)
        # Judged on 2 transactions, not the 10 the chain now holds.
        assert rp._standing_unwind_ceiling(peer, anchor) == pytest.approx(_supported(2))

    def test_a_failure_unwinds_the_live_score(self):
        rp = _make_rep_process()
        peer = uuid4()
        anchor = self._with_history(rp, peer, n_before=2, n_after=8)
        rp.reputations.update(peer, 0.95)
        rp._persist_reputations = MagicMock()
        rp._publish_tier_change = MagicMock()
        rp._publish_reputation_change = MagicMock()
        _stand(rp, peer, STANDING_FAILED, reason='REVOKED')
        rp._apply_peer_standings({})
        assert rp.reputations.current[peer] == pytest.approx(_supported(2))
        assert rp.reputations.current[peer] < 0.95
        # Demotion is the action -- the tier machinery is what reacts to it.
        assert rp._publish_tier_change.called
        assert anchor == 2

    def test_a_peer_never_proved_keeps_nothing(self):
        """It operated unverified for its whole life, so no part of its
        standing rests on a credential anyone confirmed."""
        rp = _make_rep_process()
        peer = uuid4()
        rp.reputations.update(peer, 0.95)
        rp._persist_reputations = MagicMock()
        rp._publish_tier_change = MagicMock()
        rp._publish_reputation_change = MagicMock()
        _stand(rp, peer, STANDING_FAILED, reason='REVOKED')
        rp._apply_peer_standings({})
        floor = rp._tier_ceiling(rp.UNVERIFIED_RESTORE_TIER)
        assert rp.reputations.current[peer] == floor

    def test_the_unwind_never_raises_a_peer(self):
        """A peer already below what the pre-anchor evidence would support must
        not be lifted by its own credential failing."""
        rp = _make_rep_process()
        peer = uuid4()
        self._with_history(rp, peer, n_before=5, n_after=0)
        rp.reputations.update(peer, 0.02)
        rp._persist_reputations = MagicMock()
        rp._publish_tier_change = MagicMock()
        _stand(rp, peer, STANDING_FAILED, reason='REVOKED')
        rp._apply_peer_standings({})
        assert rp.reputations.current[peer] == 0.02
        assert not rp._publish_tier_change.called

    def test_repeating_the_same_verdict_does_not_unwind_twice(self):
        """Periodic re-verification restates an unchanged verdict by the hour.
        Acting on each restatement would ratchet a peer down for a single
        offence."""
        rp = _make_rep_process()
        peer = uuid4()
        self._with_history(rp, peer, n_before=2, n_after=8)
        rp.reputations.update(peer, 0.95)
        rp._persist_reputations = MagicMock()
        rp._publish_tier_change = MagicMock()
        rp._publish_reputation_change = MagicMock()
        _stand(rp, peer, STANDING_FAILED, reason='REVOKED')
        rp._apply_peer_standings({})
        first = rp.reputations.current[peer]
        rp._apply_peer_standings({})
        rp._apply_peer_standings({})
        assert rp.reputations.current[peer] == first
        assert rp._publish_tier_change.call_count == 1

    def test_the_cap_is_not_a_penalty_in_disguise(self):
        """A ceiling says 'this peer may not rise above X while unproved'. It
        must not itself drive a peer downward -- that is what the unwind is
        for, and only an affirmative failure justifies it. Conflating the two
        would punish every DDIL deployment for being disconnected."""
        rp = _make_rep_process()
        peer = uuid4()
        rp.reputations.update(peer, 0.30)
        _stand(rp, peer, STANDING_CAPPED, CAP)
        rp._apply_peer_standings({})
        assert rp.reputations.current[peer] == 0.30

    def test_a_failure_also_leaves_the_peer_bounded_going_forward(self):
        """Unwinding once is not enough: the peer keeps transacting. A failed
        peer that could immediately re-earn its old score would be unwound and
        restored in the same breath."""
        rp = _make_rep_process()
        peer = uuid4()
        self._with_history(rp, peer, n_before=2, n_after=0)
        rp.reputations.update(peer, 0.95)
        rp._persist_reputations = MagicMock()
        rp._publish_tier_change = MagicMock()
        rp._publish_reputation_change = MagicMock()
        _stand(rp, peer, STANDING_FAILED, ceiling=CAP, reason='REVOKED')
        rp._apply_peer_standings({})
        assert rp._apply_standing_ceiling(peer, 0.95) == CAP


# --- the app hands the core an authority finding (Phase 4 P4.1) -------------

class _StandingProc:
    """Enough of IdentityProcess for apply_peer_standing: a peer roster, a
    logger, and a capturing update(). Bound the same way _GateProc is, so the
    REAL method runs rather than a reimplementation of it."""

    def __init__(self, admitted=()):
        self.sent = []
        self.logger = MagicMock()
        self.peers = SimpleNamespace(all=[SimpleNamespace(uuid=u)
                                          for u in admitted])
        self.update = lambda obj, queues: self.sent.append(obj)
        self.apply_peer_standing = \
            IdentityProcess.apply_peer_standing.__get__(self)


class TestTheAppHandsUsAFinding:
    """Twin of C peer_standing_verb_test.c. An Ethne expulsion is decided in
    the app -- this process holds no Ethne -- so what is checked here is the
    SHAPE of a finding, never its truth. Every refusal has a matching case in
    the C suite, in the same order, because a fleet is only as strict as its
    weaker runtime."""

    def test_an_expulsion_becomes_a_ceiling(self):
        """The control. A method that refused everything would satisfy all
        four refusals below."""
        peer = uuid4()
        proc = _StandingProc([peer])
        assert proc.apply_peer_standing({}, peer, STANDING_FAILED,
                                        ceiling=0.20,
                                        source=STANDING_SOURCE_ETHNE,
                                        reason='expelled') is True
        assert len(proc.sent) == 1
        assert proc.sent[0].status == STANDING_FAILED
        assert proc.sent[0].ceiling == 0.20
        assert proc.sent[0].source == STANDING_SOURCE_ETHNE

    def test_a_reinstatement_lifts_the_bound(self):
        """'Not a hard cut' has to be true in both directions."""
        peer = uuid4()
        proc = _StandingProc([peer])
        assert proc.apply_peer_standing({}, peer, STANDING_PROVED,
                                        source=STANDING_SOURCE_ETHNE) is True
        assert proc.sent[0].status == STANDING_PROVED
        # None, not 0.0 -- a zero would floor the peer instead of freeing it.
        assert proc.sent[0].ceiling is None

    def test_the_app_may_not_speak_as_the_credential_authority(self):
        """An app cannot know what ZTA proved, so letting it claim a ZTA
        standing would let it forge a `proved` and clear a real certificate
        ceiling. Per-source keying makes that a total bypass."""
        peer = uuid4()
        proc = _StandingProc([peer])
        assert proc.apply_peer_standing({}, peer, STANDING_PROVED,
                                        source=STANDING_SOURCE_ZTA) is False
        assert proc.apply_peer_standing({}, peer, STANDING_FAILED,
                                        ceiling=0.2,
                                        source='nonsense') is False
        assert proc.sent == []

    def test_an_off_scale_ceiling_is_refused(self):
        """Above 1.0 is not a bound on this scale. BELOW zero is not an error
        -- it is 'no bound' -- so only the high side is refused."""
        peer = uuid4()
        proc = _StandingProc([peer])
        assert proc.apply_peer_standing({}, peer, STANDING_FAILED,
                                        ceiling=1.5,
                                        source=STANDING_SOURCE_ETHNE) is False
        assert proc.sent == []
        assert proc.apply_peer_standing({}, peer, STANDING_FAILED,
                                        ceiling=-1.0,
                                        source=STANDING_SOURCE_ETHNE) is True
        assert proc.sent[0].ceiling is None

    def test_a_finding_about_a_stranger_is_refused(self):
        """A bound on somebody never admitted bounds nothing, and is far
        likelier a mistake than a decision."""
        proc = _StandingProc([])          # nobody admitted
        assert proc.apply_peer_standing({}, uuid4(), STANDING_FAILED,
                                        ceiling=0.20,
                                        source=STANDING_SOURCE_ETHNE) is False
        assert proc.sent == []

    def test_an_unknown_standing_is_refused(self):
        peer = uuid4()
        proc = _StandingProc([peer])
        assert proc.apply_peer_standing({}, peer, 'banished', ceiling=0.2,
                                        source=STANDING_SOURCE_ETHNE) is False
        assert proc.sent == []


# --- what IdentityProcess actually publishes --------------------------------

def test_a_lifted_ceiling_is_rescored_when_it_lifts():
    """Moderation cohort mod-2518340 (2026-09-23): after a lift the stored
    score stayed at the capped value, because nothing made a steady peer due;
    mod-2531555 then read it in the seconds before the next sweep. A lift
    rescores at once. Mirrors C test_a_lifted_ceiling_is_rescored_when_it_lifts."""
    rp = _make_rep_process()
    peer = str(uuid4())
    rp.reputations.update(peer, 0.3)                 # the capped score, stored
    _stand(rp, peer, STANDING_CAPPED, ceiling=0.3, source=STANDING_SOURCE_ETHNE)
    rp._apply_peer_standings({})
    scored = []
    real = rp._compute_reputation
    rp._compute_reputation = lambda p, *a, **k: (scored.append(str(p)),
                                                  real(p, *a, **k))[1]
    _stand(rp, peer, STANDING_PROVED, source=STANDING_SOURCE_ETHNE)
    rp._apply_peer_standings({})
    assert scored == [peer]
