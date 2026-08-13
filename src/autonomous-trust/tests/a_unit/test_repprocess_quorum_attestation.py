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
"""Quorum attestation for the slash and checkpoint rounds.

Both rounds used to collect co-signature bytes and throw them away: the
proposer credited the voter uuid CLAIMED in the payload, the finalizer
broadcast ``sigs={}``, and the ``*_final`` handlers applied the decision on
transport authentication alone. A receiver therefore could not tell a
quorum-finalized decision from one member's unilateral claim -- and since a
slash floors a peer below ``COMM_CUTOFF`` into exclusion that is sticky
(recovery only by explicit REASON_REHABILITATE), that was an insider primitive
for permanently excluding any peer.

These tests pin the three properties that close it, each with the negative
control that fails against the old code:

1. a co-signature must VERIFY to count (not merely be asserted);
2. a vote belongs to the AUTHENTICATED sender, so one peer cannot vote as many;
3. the receiver checks quorum itself, against its own view of the group.

See doc/architecture/reputation.md (Quorum attestation).
"""
import hashlib
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, SignedCheckpoint, SlashAttestation, SignedSlash,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string, from_json_string


def _identity(tag: str, uuid=None) -> Identity:
    """A real identity whose signing key is DISTINCT per tag.

    Distinct keys are load-bearing here: the forgery controls below sign with
    one member's key and present the signature as another's, which only fails
    if the keys actually differ. Deterministic in the tag (not `hash()`, which
    is salted per process) so a failure reproduces.
    """
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _rep_process(members=(), self_tag='self-node'):
    """A ReputationProcess whose peer roster holds real member identities, so
    co-signature verification has public keys to work against."""
    identity = _identity(self_tag, uuid=uuid4())
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    rp = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                           suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    rp.protocol.peers.all = list(members)
    return rp


def _sig(signer: Identity, designation: bytes) -> str:
    return signer.sign(designation).signature.decode('ascii')


def _att(slasher_uuid, target_uuid, floor=0.1, epoch=1) -> SlashAttestation:
    return SlashAttestation(slasher_uuid=slasher_uuid, target_uuid=target_uuid,
                            reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
                            floor_score=floor, epoch=epoch)


def _ckpt(proposer_uuid, epoch=1) -> Checkpoint:
    return Checkpoint(proposer_uuid=proposer_uuid, root=b'a' * 64, epoch=epoch,
                      first_index=0, count=2)


def _final(rp, function, payload, sender):
    msg = Message(CfgIds.reputation, function, to_json_string(payload),
                  rp.group, from_whom=sender)
    msg.verified = True
    return msg


# --- designation byte-pins (the cross-language hazard) ----------------------

class TestDesignationBytes:
    """The co-signature covers these exact bytes, so a drift between
    SlashAttestation.designation / Checkpoint.designation and their C twins
    (_slash_designation / _checkpoint_designation in rep_proc.c) makes every
    co-signature verify on neither side. The same two literals are asserted by
    C's rep_quorum_test.c, so the pin has to be edited in both places."""

    def test_slash_designation_pinned(self):
        att = SlashAttestation(
            slasher_uuid='11111111-1111-1111-1111-111111111111',
            target_uuid='22222222-2222-2222-2222-222222222222',
            reason=SlashAttestation.REASON_PEER_EXCLUDE,
            floor_score=0.1, epoch=7)
        assert att.designation == (
            b'AT-SLASH\x00'
            b'11111111-1111-1111-1111-111111111111|'
            b'22222222-2222-2222-2222-222222222222|peer_exclude|0.100000|7')

    def test_checkpoint_designation_pinned(self):
        ck = Checkpoint(
            proposer_uuid='11111111-1111-1111-1111-111111111111',
            root=b'044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556',
            epoch=7, first_index=0, count=3)
        assert ck.designation == (
            b'AT-CKPT\x00'
            b'11111111-1111-1111-1111-111111111111|'
            b'044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556'
            b'|7|0|3')

    def test_floor_is_fixed_precision(self):
        """The one field where a float formatting difference would silently
        break interop: C uses %.6f, so Python must too."""
        att = SlashAttestation(slasher_uuid='a', target_uuid='b',
                              reason='r', floor_score=0.1, epoch=1)
        assert b'|0.100000|' in att.designation


# --- signature verification -------------------------------------------------

class TestCosignatureVerification:
    def test_valid_cosignature_verifies(self):
        member = _identity('member')
        rp = _rep_process([member])
        att = _att(member.uuid, uuid4())
        assert rp._verify_cosignature(att.designation, member.uuid,
                                      _sig(member, att.designation)) is True

    def test_signature_over_different_bytes_fails(self):
        """A signature is bound to the exact designation. Re-presenting one
        made over a different floor / epoch / target must not count."""
        member = _identity('member')
        rp = _rep_process([member])
        signed_over = _att(member.uuid, uuid4(), floor=0.1, epoch=1)
        presented_as = _att(member.uuid, uuid4(), floor=0.9, epoch=1)
        assert rp._verify_cosignature(presented_as.designation, member.uuid,
                                      _sig(member, signed_over.designation)) is False

    def test_another_members_signature_fails(self):
        """The forgery control: sign with one key, claim another member made
        it. Passes only if the two members really hold different keys."""
        member = _identity('member')
        other = _identity('other')
        rp = _rep_process([member, other])
        att = _att(member.uuid, uuid4())
        assert rp._verify_cosignature(att.designation, other.uuid,
                                      _sig(member, att.designation)) is False

    def test_unknown_voter_cannot_be_verified(self):
        """No key for the claimed voter means the signature is uncheckable,
        which must read as "not a vote" rather than "assume good"."""
        stranger = _identity('stranger')
        rp = _rep_process([_identity('member')])
        att = _att(uuid4(), uuid4())
        assert rp._verify_cosignature(att.designation, stranger.uuid,
                                      _sig(stranger, att.designation)) is False

    def test_malformed_signatures_are_not_votes(self):
        member = _identity('member')
        rp = _rep_process([member])
        att = _att(member.uuid, uuid4())
        for bad in (None, '', 'not-hex', 'ab', b'\x00\x01', 'zz' * 64):
            assert rp._verify_cosignature(att.designation, member.uuid,
                                          bad) is False

    def test_self_signature_verifies(self):
        """The proposer's own seeded signature has to verify like any other --
        it travels on the finalizer and recipients check it."""
        rp = _rep_process()
        att = _att(rp.identity.uuid, uuid4())
        assert rp._verify_cosignature(att.designation, rp.identity.uuid,
                                      _sig(rp.identity, att.designation)) is True


class TestVerifiedCosignerCounting:
    def test_only_verifying_signatures_are_counted(self):
        good = _identity('good')
        bad = _identity('bad')
        rp = _rep_process([good, bad])
        att = _att(good.uuid, uuid4())
        sigs = {str(good.uuid): _sig(good, att.designation),
                str(bad.uuid): _sig(good, att.designation)}  # forged for `bad`
        assert rp._verified_cosigners(att.designation, sigs) == {str(good.uuid)}

    def test_non_dict_sigs_count_as_none(self):
        rp = _rep_process([_identity('member')])
        att = _att(uuid4(), uuid4())
        for shape in (None, [], 'sigs', 0):
            assert rp._verified_cosigners(att.designation, shape) == set()

    def test_quorum_sized_against_our_own_roster(self):
        """The finalizer does not get to choose the bar it must clear: quorum
        comes from the receiver's own member count."""
        a, b, c = (_identity('a'), _identity('b'), _identity('c'))
        rp = _rep_process([a, b, c])            # quorum floor(3/2) = 1
        att = _att(a.uuid, uuid4())
        one = {str(a.uuid): _sig(a, att.designation)}
        two = dict(one, **{str(b.uuid): _sig(b, att.designation)})
        assert rp._quorum_met(att.designation, one) is False
        assert rp._quorum_met(att.designation, two) is True


# --- vote attribution -------------------------------------------------------

class TestVoteAttribution:
    def test_one_peer_cannot_vote_as_many(self):
        """The replay/impersonation control. Pre-fix, the tally credited the
        uuid in the payload, so a single peer could post acks naming every
        member and finalize alone; the C twin counted bare messages and so
        could be driven past quorum by replaying ONE ack."""
        voter = _identity('voter')
        others = [_identity('m%d' % i) for i in range(3)]
        rp = _rep_process([voter] + others)
        att = _att(uuid4(), uuid4(), epoch=4)
        rp._slash_pending[att.key()] = att
        net_q = queue.Queue()
        for claimed in others:
            ack = (str(att.target_uuid), att.epoch, str(claimed.uuid),
                   _sig(voter, att.designation))
            msg = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                          to_json_string(ack), rp.group, from_whom=voter)
            msg.verified = True
            assert rp.handle_slash_sign({CfgIds.network: net_q}, msg) is True
        # Every ack was refused: each claimed a voter it was not.
        assert rp._slash_sigs.get(att.key(), {}) == {}
        assert net_q.empty()

    def test_harvested_signature_cannot_be_relayed_under_another_name(self):
        """What attribution-by-SENDER buys over signature verification alone.

        Verification already bounds the tally to signatures the sender could
        obtain -- so this is the case where the two rules differ: the attacker
        holds another member's GENUINE signature (the finalizer broadcasts
        every co-signature, so they are not secret) and posts it as an ack of
        its own. Crediting the payload's claim would count it; crediting the
        authenticated sender does not, because the ack was not sent by the
        member it names. Defense in depth rather than the primary check, and
        it also catches the plain bug of a node mislabelling its own ack.
        """
        attacker = _identity('attacker')
        harvested_from = _identity('m1')
        rp = _rep_process([attacker, harvested_from, _identity('m2')])
        att = _att(uuid4(), uuid4(), epoch=7)
        rp._slash_pending[att.key()] = att
        ack = (str(att.target_uuid), att.epoch, str(harvested_from.uuid),
               _sig(harvested_from, att.designation))   # valid for m1 ...
        msg = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                      to_json_string(ack), rp.group, from_whom=attacker)
        msg.verified = True                             # ... but sent by the attacker
        net_q = queue.Queue()
        assert rp.handle_slash_sign({CfgIds.network: net_q}, msg) is True
        assert rp._slash_sigs.get(att.key(), {}) == {}
        assert net_q.empty()

    def test_replayed_ack_counts_once(self):
        voter = _identity('voter')
        rp = _rep_process([voter, _identity('m1'), _identity('m2')])
        att = _att(uuid4(), uuid4(), epoch=5)
        rp._slash_pending[att.key()] = att
        net_q = queue.Queue()
        ack = (str(att.target_uuid), att.epoch, str(voter.uuid),
               _sig(voter, att.designation))
        for _ in range(4):
            msg = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                          to_json_string(ack), rp.group, from_whom=voter)
            msg.verified = True
            rp.handle_slash_sign({CfgIds.network: net_q}, msg)
        # A map keyed by voter, so four deliveries are one vote -- under the
        # quorum of floor(3/2)=1, hence no finalizer went out.
        assert list(rp._slash_sigs[att.key()]) == [str(voter.uuid)]
        assert net_q.empty()

    def test_unverifiable_ack_is_not_counted(self):
        voter = _identity('voter')
        rp = _rep_process([voter])
        att = _att(uuid4(), uuid4(), epoch=6)
        rp._slash_pending[att.key()] = att
        ack = (str(att.target_uuid), att.epoch, str(voter.uuid), 'ff' * 64)
        msg = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                      to_json_string(ack), rp.group, from_whom=voter)
        msg.verified = True
        net_q = queue.Queue()
        assert rp.handle_slash_sign({CfgIds.network: net_q}, msg) is True
        assert rp._slash_sigs.get(att.key(), {}) == {}
        assert net_q.empty()

    def test_checkpoint_ack_attribution(self):
        voter = _identity('voter')
        rp = _rep_process([voter, _identity('m1'), _identity('m2')])
        ck = _ckpt(rp.identity.uuid, epoch=3)
        rp._checkpoint_pending[ck.key()] = ck
        net_q = queue.Queue()
        # Claiming to be someone else is refused ...
        ack = (str(ck.proposer_uuid), ck.epoch, str(rp.identity.uuid),
               _sig(voter, ck.designation))
        msg = Message(CfgIds.reputation, ReputationProtocol.checkpoint_sign,
                      to_json_string(ack), rp.group, from_whom=voter)
        msg.verified = True
        rp.handle_checkpoint_sign({CfgIds.network: net_q}, msg)
        assert rp._checkpoint_sigs.get(ck.key(), {}) == {}
        # ... signing as itself is counted.
        ack = (str(ck.proposer_uuid), ck.epoch, str(voter.uuid),
               _sig(voter, ck.designation))
        msg = Message(CfgIds.reputation, ReputationProtocol.checkpoint_sign,
                      to_json_string(ack), rp.group, from_whom=voter)
        msg.verified = True
        rp.handle_checkpoint_sign({CfgIds.network: net_q}, msg)
        assert list(rp._checkpoint_sigs[ck.key()]) == [str(voter.uuid)]


# --- receiver-side quorum enforcement ---------------------------------------

class TestSlashFinalQuorum:
    def _setup(self, member_count=3):
        members = [_identity('m%d' % i) for i in range(member_count)]
        rp = _rep_process(members)
        return rp, members

    def test_quorum_of_verified_signatures_applies_the_floor(self):
        rp, members = self._setup()             # quorum floor(3/2) = 1
        target = uuid4()
        att = _att(members[0].uuid, target, floor=0.1, epoch=1)
        sigs = {str(m.uuid): _sig(m, att.designation) for m in members[:2]}
        msg = _final(rp, ReputationProtocol.slash_final,
                     SignedSlash(attestation=att, sigs=sigs), members[0])
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()},
                                     msg) is True
        assert str(target) in rp._slashed

    def test_no_signatures_refused(self):
        """The exclusion primitive: pre-fix this floored the target on
        transport authentication alone."""
        rp, members = self._setup()
        target = uuid4()
        att = _att(members[0].uuid, target, floor=0.1, epoch=2)
        msg = _final(rp, ReputationProtocol.slash_final,
                     SignedSlash(attestation=att, sigs={}), members[0])
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()},
                                     msg) is True
        assert str(target) not in rp._slashed

    def test_sub_quorum_refused(self):
        rp, members = self._setup(member_count=5)   # quorum floor(5/2) = 2
        target = uuid4()
        att = _att(members[0].uuid, target, floor=0.1, epoch=3)
        sigs = {str(m.uuid): _sig(m, att.designation) for m in members[:2]}
        msg = _final(rp, ReputationProtocol.slash_final,
                     SignedSlash(attestation=att, sigs=sigs), members[0])
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()},
                                     msg) is True
        assert str(target) not in rp._slashed

    def test_forged_signatures_refused(self):
        """A finalizer that mints the whole sigs map itself: every entry is
        made with ITS key and labelled with a different member's uuid."""
        rp, members = self._setup(member_count=5)
        attacker = members[0]
        target = uuid4()
        att = _att(attacker.uuid, target, floor=0.1, epoch=4)
        sigs = {str(m.uuid): _sig(attacker, att.designation)
                for m in members}
        msg = _final(rp, ReputationProtocol.slash_final,
                     SignedSlash(attestation=att, sigs=sigs), attacker)
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()},
                                     msg) is True
        assert str(target) not in rp._slashed

    def test_duplicate_signature_entries_cannot_pad_quorum(self):
        """Padding the map with the same signature under different labels.
        Only the correctly-labelled entry verifies, so the count does not
        move -- one signature is one vote however it is spelled."""
        rp, members = self._setup(member_count=5)
        signer = members[0]
        target = uuid4()
        att = _att(signer.uuid, target, floor=0.1, epoch=5)
        sig = _sig(signer, att.designation)
        sigs = {str(m.uuid): sig for m in members}
        msg = _final(rp, ReputationProtocol.slash_final,
                     SignedSlash(attestation=att, sigs=sigs), signer)
        rp.handle_slash_final({CfgIds.network: queue.Queue()}, msg)
        assert rp._verified_cosigners(att.designation, sigs) == {str(signer.uuid)}
        assert str(target) not in rp._slashed


class TestCheckpointFinalQuorum:
    def test_quorum_stores_the_root(self):
        members = [_identity('m%d' % i) for i in range(3)]
        rp = _rep_process(members)
        ck = _ckpt(members[0].uuid, epoch=1)
        sigs = {str(m.uuid): _sig(m, ck.designation) for m in members[:2]}
        msg = _final(rp, ReputationProtocol.checkpoint_final,
                     SignedCheckpoint(checkpoint=ck, sigs=sigs), members[0])
        assert rp.handle_checkpoint_final({CfgIds.network: queue.Queue()},
                                         msg) is True
        assert rp._checkpoint is not None
        assert rp._checkpoint.key() == ck.key()

    def test_unattested_root_refused(self):
        """This root is the anchor _verify_slash_evidence measures evidence
        against, precisely so it is not "chosen by the accuser" -- which only
        holds if the receiver checks a quorum."""
        members = [_identity('m%d' % i) for i in range(3)]
        rp = _rep_process(members)
        ck = _ckpt(members[0].uuid, epoch=2)
        msg = _final(rp, ReputationProtocol.checkpoint_final,
                     SignedCheckpoint(checkpoint=ck, sigs={}), members[0])
        assert rp.handle_checkpoint_final({CfgIds.network: queue.Queue()},
                                          msg) is True
        assert rp._checkpoint is None

    def test_forged_root_cannot_gate_slash_evidence(self):
        """End-to-end statement of the attack that motivated this: install a
        chosen checkpoint root, then slash against evidence rooted in it. The
        checkpoint is refused, so the evidence has nothing to verify against
        and the slash dies too."""
        members = [_identity('m%d' % i) for i in range(5)]
        rp = _rep_process(members)
        attacker = members[0]
        forged = _ckpt(attacker.uuid, epoch=9)
        ck_msg = _final(rp, ReputationProtocol.checkpoint_final,
                        SignedCheckpoint(checkpoint=forged, sigs={}), attacker)
        rp.handle_checkpoint_final({CfgIds.network: queue.Queue()}, ck_msg)
        assert rp._checkpoint is None

        target = uuid4()
        att = _att(attacker.uuid, target, floor=0.0, epoch=1)
        att.evidence_ref = {'task_id': str(uuid4()),
                            'leaf': 'aa' * 32,
                            'proof': [],
                            'root': (b'a' * 64).decode('ascii')}
        sl_msg = _final(rp, ReputationProtocol.slash_final,
                        SignedSlash(attestation=att,
                                    sigs={str(attacker.uuid):
                                          _sig(attacker, att.designation)}),
                        attacker)
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()},
                                     sl_msg) is True
        assert str(target) not in rp._slashed


class TestFinalizerCarriesSignatures:
    def test_slash_finalizer_broadcasts_retained_signatures(self):
        voter = _identity('voter')
        rp = _rep_process([voter])              # quorum floor(1/2) = 0
        net_q = queue.Queue()
        att = _att(None, uuid4(), floor=0.1)
        rp.forward_slash({CfgIds.network: net_q}, att)
        net_q.get_nowait()                     # drain the propose
        ack = (str(att.target_uuid), att.epoch, str(voter.uuid),
               _sig(voter, att.designation))
        msg = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                      to_json_string(ack), rp.group, from_whom=voter)
        msg.verified = True
        rp.handle_slash_sign({CfgIds.network: net_q}, msg)
        final = net_q.get_nowait()
        signed = (final.obj if isinstance(final.obj, SignedSlash)
                  else from_json_string(final.obj))
        # Both the proposer's own signature and the voter's, and both must
        # survive JSON round-tripping to be verifiable at the far end.
        assert set(signed.sigs) == {str(rp.identity.uuid), str(voter.uuid)}
        assert rp._verified_cosigners(att.designation, signed.sigs) == \
            set(signed.sigs)

    def test_checkpoint_finalizer_broadcasts_retained_signatures(self):
        voter = _identity('voter')
        rp = _rep_process([voter])
        net_q = queue.Queue()
        rp.history.update(uuid4(), uuid4(), 0.7)
        rp.forward_checkpoint({CfgIds.network: net_q}, Checkpoint(None, b''))
        net_q.get_nowait()
        ck = rp._checkpoint
        ack = (str(ck.proposer_uuid), ck.epoch, str(voter.uuid),
               _sig(voter, ck.designation))
        msg = Message(CfgIds.reputation, ReputationProtocol.checkpoint_sign,
                      to_json_string(ack), rp.group, from_whom=voter)
        msg.verified = True
        rp.handle_checkpoint_sign({CfgIds.network: net_q}, msg)
        final = net_q.get_nowait()
        signed = (final.obj if isinstance(final.obj, SignedCheckpoint)
                  else from_json_string(final.obj))
        assert set(signed.sigs) == {str(rp.identity.uuid), str(voter.uuid)}
        assert rp._verified_cosigners(ck.designation, signed.sigs) == \
            set(signed.sigs)
