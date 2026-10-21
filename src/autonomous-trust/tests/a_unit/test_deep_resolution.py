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
"""Deep resolution: one peer, on demand, at any depth (doc/architecture/gateway-reputation-tree.md).

A gateway scores a peer against the chain that peer's transactions landed in,
and holds chains only for groups it belongs to. Two levels down, that chain
belongs to somebody else. Rather than enumerate the whole subtree on every
query -- a cost that grows with the TREE to answer a question about one PEER
-- the query is relayed toward the holder and the answer comes back carrying
its own proof.

Two properties carry the design, and most of what follows exists to pin them:

* **Opacity.** The query names no originator and the answer travels back the
  way the query came, so no node outside a boundary ever exchanges a message
  with a node inside it. A relay's only state is "who do I hand the answer to".
* **The answer proves itself.** It crosses nodes the requestor has no reason
  to trust, so it carries the quorum-signed window rather than a number. The
  verifier recomputes the root from the entries, which is what makes OMISSION
  detectable -- an inclusion proof would show that the entries present are
  real while saying nothing about the ones withheld, and a holder shading its
  own subtree would omit rather than invent.
"""
import hashlib
import json
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, SignedCheckpoint, TransactionHistory,
    RESOLVE_TTL_MAX, consensus_score_from_window, resolve_query_from_dict,
    resolve_query_to_dict, resolved_from_dict, resolved_to_dict,
    verify_resolved, window_root_of,
)
from autonomous_trust.core._python.identity.identity import (
    Identity, public_identity_to_canonical)
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds


TX_SCORE = 0.9


def _identity(tag: str, uuid=None) -> Identity:
    """A real identity with a per-tag signing key. Distinct keys are what let
    the negative signature cases fail for the right reason."""
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _group(nickname='child', members=()):
    enc = Encryptor(hashlib.sha256(nickname.encode()).hexdigest().encode('ascii'),
                    public_only=False)
    addr_map = {str(m.uuid): getattr(m, 'address', '10.0.0.1') for m in members}
    return Group(uuid4(), addr_map, nickname, enc, _public_only=False)


def _chain_with(holder: Identity, peer_uuid, count=3, score=TX_SCORE):
    """`count` committed bilateral transactions between holder and peer."""
    history = TransactionHistory()
    for i in range(count):
        tid = UUID(int=i + 1)
        history.update(tid, holder.uuid, score)
        history.update(tid, peer_uuid, score)
    return history


def _signed(history, proposer: Identity, cosigners):
    window = history._indexed_window()
    ckpt = Checkpoint(proposer_uuid=proposer.uuid, root=history.window_root(),
                      epoch=4, first_index=window[0].index if window else 0,
                      count=len(window))
    sigs = {str(i.uuid): i.sign(ckpt.designation).signature.decode('ascii')
            for i in cosigners}
    return SignedCheckpoint(ckpt, sigs)


def _make_rep_process(identity=None, peers=(), child_groups=None):
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
    peer_store.all = list(peers)
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: peer_store,
        CfgIds.group: MagicMock(),
    }
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    rp.logger = MagicMock()
    rp.q_cadence = 0.01
    if child_groups:
        rp.protocol.child_groups = dict(child_groups)
    return rp


def _queues():
    return {CfgIds.network: queue.Queue(), CfgIds.reputation: queue.Queue()}


def _inbound(function, obj, from_whom, verified=True):
    msg = MagicMock()
    msg.function = function
    msg.obj = obj
    msg.from_whom = from_whom
    msg.verified = verified
    return msg


def _always(_voter, _signer):
    return True


def _verify_with(identities):
    """A verify_signature callback backed by a fixed identity set, so the
    evidence tests exercise verify_resolved without a process around it."""
    by_uuid = {str(i.uuid): i for i in identities}

    def _verify(designation, voter, sig, _signer):
        ident = by_uuid.get(str(voter))
        if ident is None or sig is None:
            return False
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        try:
            ident.signature.public.verify(
                designation, HexEncoder.decode(sig.encode('ascii')))
        except (BadSignatureError, ValueError, TypeError):
            return False
        return True
    return _verify


# --- the pure primitives ----------------------------------------------------


class TestPrimitives:
    """The extracted functions a verifier uses must agree with the methods the
    holder uses, or a correct answer would be refused as often as a forged one
    is accepted."""

    def test_window_root_of_matches_the_chain_method(self):
        holder = _identity('holder')
        peer = uuid4()
        history = _chain_with(holder, peer, count=5)
        assert window_root_of(history._indexed_window()) == history.window_root()

    def test_window_root_of_ignores_uncommitted_entries(self):
        holder = _identity('holder')
        peer = uuid4()
        history = _chain_with(holder, peer, count=3)
        # A one-sided (not yet bilateral) entry has no index and is not
        # evidence of anything; it must not move the root.
        history.update(UUID(int=99), holder.uuid, 0.1)
        assert window_root_of(list(history)) == history.window_root()

    def test_score_from_window_matches_the_process_fold(self):
        holder = _identity('holder')
        peer = uuid4()
        history = _chain_with(holder, peer, count=4)
        rp = _make_rep_process(identity=holder)
        mine = rp._consensus_reputation(peer, chain=history)
        theirs = consensus_score_from_window(
            peer, history._indexed_window(), rp.CONSENSUS_EMA_HALF_LIFE)
        assert theirs == pytest.approx(mine)

    def test_score_from_window_is_none_without_bilateral_entries(self):
        holder = _identity('holder')
        history = _chain_with(holder, uuid4(), count=2)
        assert consensus_score_from_window(
            uuid4(), history._indexed_window(), 20) is None

    def test_query_ttl_is_bounded_not_clamped(self):
        q = resolve_query_to_dict('q', uuid4(), ttl=RESOLVE_TTL_MAX + 1)
        with pytest.raises(ValueError):
            resolve_query_from_dict(q)

    def test_query_carries_no_originator(self):
        """Opacity at the payload level: a deep holder must not be able to
        learn who wanted to know."""
        q = resolve_query_to_dict('q', uuid4())
        assert set(q) == {'query_id', 'peer_uuid', 'ttl', 'requesting_process'}
        blob = json.dumps(q)
        assert 'uuid' not in blob.replace('peer_uuid', '')


# --- evidence verification --------------------------------------------------


class TestVerifyResolved:

    def _answer(self, count=3, cosigners=None):
        holder = _identity('holder')
        peer = uuid4()
        signers = cosigners or [holder, _identity('cosigner-a')]
        history = _chain_with(holder, peer, count=count)
        signed = _signed(history, holder, signers)
        doc = resolved_to_dict(
            'q1', peer, history._indexed_window(), signed,
            signers=[public_identity_to_canonical(i) for i in signers],
            score=0.9)
        return holder, peer, signers, doc

    def test_honest_answer_verifies(self):
        _holder, _peer, signers, doc = self._answer()
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, reason = verify_resolved(chain, signed, carried,
                                     _verify_with(signers), _always)
        assert ok, reason
        assert 'root reproduced' in reason

    def test_withheld_entry_is_refused(self):
        """The property the whole payload shape exists for. An inclusion proof
        over the remaining entries would still verify; recomputing the root
        does not."""
        _holder, _peer, signers, doc = self._answer(count=4)
        doc['chain'] = doc['chain'][:-1]
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, reason = verify_resolved(chain, signed, carried,
                                     _verify_with(signers), _always)
        assert not ok
        assert 'withheld' in reason or 'does not reproduce' in reason

    def test_edited_score_is_refused(self):
        _holder, _peer, signers, doc = self._answer()
        doc['chain'][0]['p2_score'] = 0.01
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, _reason = verify_resolved(chain, signed, carried,
                                      _verify_with(signers), _always)
        assert not ok

    def test_added_entry_is_refused(self):
        _holder, _peer, signers, doc = self._answer()
        extra = dict(doc['chain'][0])
        extra['index'] = 99
        doc['chain'].append(extra)
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, _reason = verify_resolved(chain, signed, carried,
                                      _verify_with(signers), _always)
        assert not ok

    def test_unattested_window_is_refused(self):
        _holder, _peer, signers, doc = self._answer()
        doc['checkpoint'] = None
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, reason = verify_resolved(chain, signed, carried,
                                     _verify_with(signers), _always)
        assert not ok
        assert 'unattested' in reason

    def test_untrusted_signers_are_refused(self):
        """Signatures alone prove only that somebody holding some key signed.
        Without the anchor gate an answer could ship its own quorum."""
        _holder, _peer, signers, doc = self._answer()
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, reason = verify_resolved(chain, signed, carried,
                                     _verify_with(signers),
                                     trust_signer=lambda _u, _s: False)
        assert not ok
        assert '0 signer(s) verified' in reason

    def test_min_signers_is_enforced(self):
        _holder, _peer, signers, doc = self._answer(
            cosigners=[_identity('lonely-signer')])
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        ok, reason = verify_resolved(chain, signed, carried,
                                     _verify_with(signers), _always,
                                     min_signers=3)
        assert not ok
        assert 'needed 3' in reason

    def test_reason_states_quorum_is_not_checkable(self):
        """Honesty in the diagnostic: the one thing this cannot check from
        outside the boundary is whether the signers are a MAJORITY, because
        that needs a membership the subtree deliberately withholds."""
        _holder, _peer, signers, doc = self._answer()
        _q, _p, _s, chain, signed, carried = resolved_from_dict(doc)
        _ok, reason = verify_resolved(chain, signed, carried,
                                      _verify_with(signers), _always)
        assert 'quorum size not checkable' in reason


# --- the relay ---------------------------------------------------------------


class TestRelay:

    def test_holder_answers_from_the_chain_it_holds(self):
        holder = _identity('holder')
        asker = _identity('asker')
        peer = uuid4()
        rp = _make_rep_process(identity=holder, peers=[asker])
        rp.history = _chain_with(holder, peer, count=3)
        signed = _signed(rp.history, holder, [holder])
        rp._checkpoints[''] = signed.checkpoint
        rp._checkpoint_sigs_final[''] = signed.sigs
        q = _queues()
        query = resolve_query_to_dict('q1', peer)
        assert rp.handle_resolve(q, _inbound(
            ReputationProtocol.rep_resolve, to_json_string(query), asker))
        msg = q[CfgIds.network].get_nowait()
        assert msg.function == ReputationProtocol.rep_resolved
        _qid, got_peer, _score, chain, ck, _signers = \
            resolved_from_dict(json.loads(msg.obj))
        assert got_peer == str(peer)
        assert window_root_of(chain) == ck.checkpoint.root

    def test_holder_without_a_checkpoint_does_not_answer(self):
        """An unattested window is true but unverifiable two hops away, and
        sending one would only teach requestors to accept what they cannot
        check."""
        holder = _identity('holder')
        asker = _identity('asker')
        peer = uuid4()
        rp = _make_rep_process(identity=holder, peers=[asker])
        rp.history = _chain_with(holder, peer, count=3)
        q = _queues()
        rp.handle_resolve(q, _inbound(ReputationProtocol.rep_resolve,
                                      to_json_string(resolve_query_to_dict('q1', peer)),
                                      asker))
        assert q[CfgIds.network].empty()

    def test_unknown_peer_is_relayed_down_and_recorded(self):
        holder = _identity('gateway')
        asker = _identity('asker')
        child = _group('field')
        rp = _make_rep_process(identity=holder, peers=[asker],
                               child_groups={str(child.uuid): child})
        q = _queues()
        query = resolve_query_to_dict('q1', uuid4(), ttl=3)
        rp.handle_resolve(q, _inbound(ReputationProtocol.rep_resolve,
                                      to_json_string(query), asker))
        out = q[CfgIds.network].get_nowait()
        assert out.function == ReputationProtocol.rep_resolve
        assert json.loads(out.obj)['ttl'] == 2, 'ttl must decrement per hop'
        assert 'q1' in rp._resolve_pending
        assert rp._resolve_pending['q1'][0] == str(asker.uuid)

    def test_exhausted_ttl_stops_and_leaves_no_state(self):
        holder = _identity('gateway')
        asker = _identity('asker')
        child = _group('field')
        rp = _make_rep_process(identity=holder, peers=[asker],
                               child_groups={str(child.uuid): child})
        q = _queues()
        rp.handle_resolve(q, _inbound(
            ReputationProtocol.rep_resolve,
            to_json_string(resolve_query_to_dict('q1', uuid4(), ttl=0)), asker))
        assert q[CfgIds.network].empty()
        assert 'q1' not in rp._resolve_pending

    def test_leaf_with_no_children_is_a_dead_end(self):
        holder = _identity('leaf')
        asker = _identity('asker')
        rp = _make_rep_process(identity=holder, peers=[asker])
        q = _queues()
        rp.handle_resolve(q, _inbound(
            ReputationProtocol.rep_resolve,
            to_json_string(resolve_query_to_dict('q1', uuid4())), asker))
        assert q[CfgIds.network].empty()
        assert not rp._resolve_pending

    def test_repeated_query_id_is_dropped(self):
        """The loop guard. A briefly cyclic tree would otherwise circulate a
        query until its TTL burned down at every node it touched."""
        holder = _identity('gateway')
        asker = _identity('asker')
        child = _group('field')
        rp = _make_rep_process(identity=holder, peers=[asker],
                               child_groups={str(child.uuid): child})
        q = _queues()
        query = to_json_string(resolve_query_to_dict('q1', uuid4(), ttl=3))
        rp.handle_resolve(q, _inbound(ReputationProtocol.rep_resolve, query, asker))
        q[CfgIds.network].get_nowait()
        rp.handle_resolve(q, _inbound(ReputationProtocol.rep_resolve, query, asker))
        assert q[CfgIds.network].empty()

    def test_unverified_query_is_rejected(self):
        holder = _identity('gateway')
        asker = _identity('asker')
        child = _group('field')
        rp = _make_rep_process(identity=holder, peers=[asker],
                               child_groups={str(child.uuid): child})
        q = _queues()
        rp.handle_resolve(q, _inbound(
            ReputationProtocol.rep_resolve,
            to_json_string(resolve_query_to_dict('q1', uuid4())), asker,
            verified=False))
        assert q[CfgIds.network].empty()
        assert not rp._resolve_pending

    def test_malformed_query_is_refused(self):
        holder = _identity('gateway')
        asker = _identity('asker')
        rp = _make_rep_process(identity=holder, peers=[asker])
        q = _queues()
        rp.handle_resolve(q, _inbound(ReputationProtocol.rep_resolve,
                                      to_json_string({'ttl': 99}), asker))
        assert q[CfgIds.network].empty()

    def test_answer_is_relayed_verbatim_to_the_recorded_neighbour(self):
        """Relays carry, they do not curate: the signatures are over bytes, so
        a re-encode could invalidate evidence this node has no business
        invalidating."""
        gateway = _identity('gateway')
        asker = _identity('asker')
        downstream = _identity('downstream')
        holder = _identity('holder')
        peer = uuid4()
        rp = _make_rep_process(identity=gateway, peers=[asker, downstream])
        history = _chain_with(holder, peer, count=3)
        signed = _signed(history, holder, [holder])
        doc = resolved_to_dict('q1', peer, history._indexed_window(), signed,
                               signers=[public_identity_to_canonical(holder)],
                               score=0.9)
        rp._resolve_pending['q1'] = (str(asker.uuid), 1e18, '')
        q = _queues()
        rp.handle_resolved(q, _inbound(ReputationProtocol.rep_resolved,
                                       to_json_string(doc), downstream))
        out = q[CfgIds.network].get_nowait()
        assert json.loads(out.obj) == doc
        assert 'q1' not in rp._resolve_pending, 'first answer wins'

    def test_unsolicited_answer_is_dropped(self):
        gateway = _identity('gateway')
        stranger = _identity('stranger')
        holder = _identity('holder')
        peer = uuid4()
        rp = _make_rep_process(identity=gateway, peers=[stranger])
        history = _chain_with(holder, peer, count=2)
        signed = _signed(history, holder, [holder])
        doc = resolved_to_dict('never-asked', peer, history._indexed_window(),
                               signed, signers=[], score=0.5)
        q = _queues()
        rp.handle_resolved(q, _inbound(ReputationProtocol.rep_resolved,
                                       to_json_string(doc), stranger))
        assert q[CfgIds.network].empty()
        assert not rp.resolved_reps

    def test_expiry_clears_relayed_and_outstanding_queries(self):
        rp = _make_rep_process()
        rp._resolve_pending['old'] = ('x', 0.0, '')
        rp._resolve_outstanding['mine'] = (str(uuid4()), 0.0)
        rp._prune_resolve_state()
        assert not rp._resolve_pending
        assert not rp._resolve_outstanding


# --- the requestor -----------------------------------------------------------


class TestRequestor:

    def _resolved_process(self, cosigners, peer, history):
        """A requestor that knows the co-signers (so signature verification
        has keys) and has an outstanding query for `peer`."""
        me = _identity('requestor')
        rp = _make_rep_process(identity=me, peers=list(cosigners))
        rp._resolve_outstanding['q1'] = (str(peer), 1e18)
        return rp

    def test_accepted_answer_records_our_own_recomputed_score(self):
        """The recorded number is the one WE compute from the attested
        window, not the one the holder sent."""
        holder = _identity('holder')
        peer = uuid4()
        history = _chain_with(holder, peer, count=4)
        signed = _signed(history, holder, [holder])
        doc = resolved_to_dict('q1', peer, history._indexed_window(), signed,
                               signers=[public_identity_to_canonical(holder)],
                               score=0.123)
        rp = self._resolved_process([holder], peer, history)
        q = _queues()
        rp.handle_resolved(q, _inbound(ReputationProtocol.rep_resolved,
                                       to_json_string(doc), holder))
        score, verified, reason = rp.resolved_reps[str(peer)]
        assert verified
        expected = consensus_score_from_window(
            peer, history._indexed_window(), rp.CONSENSUS_EMA_HALF_LIFE)
        assert score == pytest.approx(expected)
        assert 'holder reported 0.1230' in reason, \
            'a divergent holder value is surfaced, not silently taken'

    def test_refused_answer_records_the_reason(self):
        """feedback_operator_diagnostics: a bare False tells an operator
        nothing about which gate failed."""
        holder = _identity('holder')
        peer = uuid4()
        history = _chain_with(holder, peer, count=3)
        signed = _signed(history, holder, [holder])
        doc = resolved_to_dict('q1', peer, history._indexed_window(), signed,
                               signers=[public_identity_to_canonical(holder)],
                               score=0.9)
        doc['chain'] = doc['chain'][:-1]
        rp = self._resolved_process([holder], peer, history)
        q = _queues()
        rp.handle_resolved(q, _inbound(ReputationProtocol.rep_resolved,
                                       to_json_string(doc), holder))
        score, verified, reason = rp.resolved_reps[str(peer)]
        assert score is None and not verified
        assert 'root' in reason

    def test_answer_whose_signers_we_cannot_trust_is_refused(self):
        """The requestor holds no identity from the deep group and the
        carried signer presents no anchored credential."""
        stranger = _identity('stranger-holder')
        peer = uuid4()
        history = _chain_with(stranger, peer, count=3)
        signed = _signed(history, stranger, [stranger])
        doc = resolved_to_dict('q1', peer, history._indexed_window(), signed,
                               signers=[public_identity_to_canonical(stranger)],
                               score=0.9)
        me = _identity('requestor')
        rp = _make_rep_process(identity=me, peers=[])
        rp._resolve_outstanding['q1'] = (str(peer), 1e18)
        q = _queues()
        rp.handle_resolved(q, _inbound(ReputationProtocol.rep_resolved,
                                       to_json_string(doc), stranger))
        _score, verified, reason = rp.resolved_reps[str(peer)]
        assert not verified
        assert 'verified and trusted' in reason

    def test_resolve_reputation_sends_down_and_tracks(self):
        gateway = _identity('gateway')
        child = _group('field')
        rp = _make_rep_process(identity=gateway,
                               child_groups={str(child.uuid): child})
        q = _queues()
        peer = uuid4()
        qid = rp.resolve_reputation(q, peer)
        assert qid in rp._resolve_outstanding
        out = q[CfgIds.network].get_nowait()
        assert out.function == ReputationProtocol.rep_resolve
        assert json.loads(out.obj)['peer_uuid'] == str(peer)

    def test_our_own_query_id_is_not_answered_by_us_on_return(self):
        """A query we originated must not be treated as one we are relaying;
        the two tables are distinct on purpose."""
        gateway = _identity('gateway')
        child = _group('field')
        rp = _make_rep_process(identity=gateway,
                               child_groups={str(child.uuid): child})
        q = _queues()
        qid = rp.resolve_reputation(q, uuid4())
        assert qid not in rp._resolve_pending


# --- the whole point: an answer that crosses two boundaries ------------------


class TestEndToEnd:
    """Three real processes, messages shuttled by hand:

        requestor  --(rep_resolve)-->  gateway  --(rep_resolve)-->  holder
        requestor  <--(rep_resolved)--  gateway  <--(rep_resolved)-- holder

    The requestor never addresses the holder and never learns it exists; the
    holder never learns who asked. Each of the unit tests above pins one hop
    of this, but only running the whole path shows the relay actually composes
    -- the earlier identity-side walk shipped a routing bug that every
    single-address-space test agreed was correct
    (doc/architecture/gateway-reputation-tree.md, reply-routing note)."""

    def _wire(self):
        requestor = _identity('e2e-requestor')
        gateway = _identity('e2e-gateway')
        holder = _identity('e2e-holder')
        peer = uuid4()

        # A genuine 3-deep tree: the requestor gateways the middle group (the
        # gateway is its member), and the gateway in turn gateways the deep
        # group (the holder is its member). The requestor has no child group
        # in common with the holder, which is the whole situation being
        # tested -- wiring it to gateway the deep group directly would make
        # the "two hops" below a hand-shuttled fiction.
        mid_group = _group('mid', members=[gateway])
        deep_group = _group('deep', members=[holder])
        req = _make_rep_process(identity=requestor, peers=[gateway],
                                child_groups={str(mid_group.uuid): mid_group})
        gw = _make_rep_process(identity=gateway, peers=[requestor, holder],
                               child_groups={str(deep_group.uuid): deep_group})
        hold = _make_rep_process(identity=holder, peers=[gateway])
        # Only the holder has the peer's chain, checkpointed and self-signed.
        hold.history = _chain_with(holder, peer, count=4)
        signed = _signed(hold.history, holder, [holder])
        hold._checkpoints[''] = signed.checkpoint
        hold._checkpoint_sigs_final[''] = signed.sigs
        return requestor, gateway, holder, peer, req, gw, hold

    def test_answer_crosses_two_hops_and_verifies(self):
        requestor, gateway, holder, peer, req, gw, hold = self._wire()
        # The requestor trusts the gateway (a peer) but holds no identity from
        # the deep group -- so the holder's signature must verify against the
        # identity the ANSWER carries, and be trusted because... it cannot be.
        # Give the requestor the holder as a known peer to stand in for the
        # anchor check, which has its own test above.
        req.peers.all = [gateway, holder]

        qa, qb, qc = _queues(), _queues(), _queues()
        qid = req.resolve_reputation(qa, peer)

        down = qa[CfgIds.network].get_nowait()
        assert gw.handle_resolve(qb, _inbound(
            ReputationProtocol.rep_resolve, down.obj, requestor))
        onward = qb[CfgIds.network].get_nowait()
        assert json.loads(onward.obj)['ttl'] < json.loads(down.obj)['ttl']

        assert hold.handle_resolve(qc, _inbound(
            ReputationProtocol.rep_resolve, onward.obj, gateway))
        answer = qc[CfgIds.network].get_nowait()
        assert answer.function == ReputationProtocol.rep_resolved

        # Back up the path: the gateway relays to the requestor it recorded.
        assert gw.handle_resolved(qb, _inbound(
            ReputationProtocol.rep_resolved, answer.obj, holder))
        relayed = qb[CfgIds.network].get_nowait()
        assert json.loads(relayed.obj) == json.loads(answer.obj), 'verbatim'

        assert req.handle_resolved(qa, _inbound(
            ReputationProtocol.rep_resolved, relayed.obj, gateway))
        score, verified, reason = req.resolved_reps[str(peer)]
        assert verified, reason
        assert score == pytest.approx(
            consensus_score_from_window(peer, hold.history._indexed_window(),
                                        req.CONSENSUS_EMA_HALF_LIFE))
        assert qid not in req._resolve_outstanding
        assert not gw._resolve_pending, 'relay state released once answered'

    def test_the_requestor_never_addresses_the_holder(self):
        """Opacity, stated as the property rather than as a message count."""
        requestor, gateway, holder, peer, req, gw, hold = self._wire()
        qa, qb = _queues(), _queues()
        req.resolve_reputation(qa, peer)
        down = qa[CfgIds.network].get_nowait()
        gw.handle_resolve(qb, _inbound(ReputationProtocol.rep_resolve,
                                       down.obj, requestor))
        onward = qb[CfgIds.network].get_nowait()
        # Nothing the requestor emitted names the holder, and nothing the
        # gateway forwarded names the requestor.
        assert str(holder.uuid) not in json.dumps(json.loads(down.obj))
        assert str(requestor.uuid) not in json.dumps(json.loads(onward.obj))

    def test_a_dark_subtree_times_out_rather_than_hanging(self):
        requestor, _gateway, _holder, peer, req, gw, _hold = self._wire()
        qa, qb = _queues(), _queues()
        req.resolve_reputation(qa, peer)
        down = qa[CfgIds.network].get_nowait()
        gw.handle_resolve(qb, _inbound(ReputationProtocol.rep_resolve,
                                       down.obj, requestor))
        # The holder never answers. Both sides must forget on their own.
        for proc in (req, gw):
            for table in (proc._resolve_pending, proc._resolve_outstanding):
                for key in list(table):
                    entry = table[key]
                    table[key] = (entry[0], 0.0) if len(entry) == 2 \
                        else (entry[0], 0.0, entry[2])
            proc._prune_resolve_state()
        assert not req._resolve_outstanding
        assert not gw._resolve_pending
