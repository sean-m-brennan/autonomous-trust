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
"""Simultaneous group-key rotation must CONVERGE, not fork.

WHERE THIS CAME FROM. A three-node live cohort (agora business-post, 2026-09-21)
deadlocked twice in a way no unit or conformance test could see: two members
that were happily sharing a group key both rotated within 51 ms of a third
node's arrival, ended on different keys at the SAME epoch, and never
reconciled. Everything the forked member sent afterwards was undecryptable to
the others, permanently -- the partition machinery repaired the group UUID and
never touched the key.

Reading 25 preserved cohort runs afterwards: 107 rotations minted, NOT ONE ever
adopted, and 19 explicit "rejecting unverified group key rotation" warnings.
The group only ever converges through the MERGE path (different group uuids),
which is why two nodes bootstrap fine and a third joining forks them.

WHAT THESE TESTS PIN, at the handler level where the live failure happened
(``Group.accept_rotation`` itself is already covered, and is not the gap):

  1. Two members rotating at the same instant converge on ONE key, given
     verified updates. This is the contract; if it ever regresses, a cohort
     goes silently deaf rather than failing loudly.
  2. The convergence is DETERMINISTIC and order-independent -- the same key
     wins whichever side processes first. A tiebreak that depended on arrival
     order would "pass" a test like this half the time.
  3. An UNVERIFIED update is not adopted. That is the current gate, and it is
     the proximate cause of the live fork: it is stated here so that changing
     it is a deliberate act against a test that says what today's behaviour is,
     rather than a quiet edit.

Test 3 documents present behaviour, NOT a desired property. The open question
it stands over -- why a decrypted, signed group_key_update between two live
peers arrives unverified at all -- belongs to the wire layer and needs a host
run to answer; see .claude/TODO.md.
"""
from __future__ import annotations

import logging
import tempfile
from unittest.mock import MagicMock, patch

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.system import CfgIds

_MOCK_ADDRESSES = ['10.0.0.1']
_TMPDIRS: list = []


class _FakeQueue:
    def __init__(self):
        self.items = []

    def put(self, item, **_kwargs):
        self.items.append(item)

    def put_nowait(self, item):
        self.items.append(item)


def _new_identity(name, address):
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


def _build_process(identity, group):
    """A minimally-populated IdentityProcess: exactly what handle_group_update
    and its helpers reach for. Mirrors test_partition_recovery's fixture."""
    proc = object.__new__(IdentityProcess)
    proc.identity = identity
    proc.group = group
    proc.peers = Peers()
    proc.protocol = Protocol(CfgIds.identity, logging.getLogger('test'), None)
    proc.protocol.group = group
    proc.protocol.peers = proc.peers
    proc.name = CfgIds.identity
    proc.logger = logging.getLogger('test.idproc.groupkey')
    proc.q_cadence = 0.01
    proc.phase = 3
    proc.choosing = False
    proc.merging = False
    proc.lock = MagicMock()
    proc.lock.__enter__ = MagicMock(return_value=proc.lock)
    proc.lock.__exit__ = MagicMock(return_value=False)
    proc._partition_probe_cooldown = {}
    proc._partition_response_cooldown = {}
    proc._partition_recovery_in_progress = None
    proc._probe_seq = None
    tmp = tempfile.mkdtemp(prefix='at-groupkey-')
    _TMPDIRS.append(tmp)
    proc._record_group = MagicMock()
    proc._update_group = MagicMock()
    return proc


def _queues():
    return {CfgIds.network: _FakeQueue(), CfgIds.identity: _FakeQueue()}


def _shared_group(a_ident, b_ident):
    """One group both members hold, with the SAME key — the state a healthy
    two-node cohort is in before anybody rotates."""
    addrs = {str(a_ident.uuid): a_ident.address,
             str(b_ident.uuid): b_ident.address}
    grp = Group.initialize(addrs, 'cohort')
    other = Group.from_canonical(grp.to_canonical())
    return grp, other


def _update_from(sender_group, verified=True):
    """The group_key_update a member sends after rotating: its whole group,
    private key included (that is what makes it a rotation), as the canonical
    wire form the C side also emits."""
    msg = Message(CfgIds.identity, IdentityProtocol.update,
                  Group.from_canonical(sender_group.to_canonical()),
                  encrypt=True)
    msg.verified = verified
    return msg


def _key_of(group):
    return group.encryptor.publish()


class TestSimultaneousRotationConverges:
    def test_two_members_rotating_at_once_end_on_one_key(self):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        a_grp, b_grp = _shared_group(a_id, b_id)
        assert _key_of(a_grp) == _key_of(b_grp), 'precondition: one cohort key'

        a = _build_process(a_id, a_grp)
        b = _build_process(b_id, b_grp)

        # The live failure: both rotate on the same membership event, so both
        # mint THIS epoch and neither claims a higher one.
        a.group.rotate_key()
        b.group.rotate_key()
        assert a.group.key_epoch == b.group.key_epoch
        assert _key_of(a.group) != _key_of(b.group), 'precondition: forked'

        # Each hands the other its freshly rotated key.
        a_says = _update_from(a.group)
        b_says = _update_from(b.group)
        a.handle_group_update(_queues(), b_says)
        b.handle_group_update(_queues(), a_says)

        assert _key_of(a.group) == _key_of(b.group), (
            'a simultaneous rotation left the cohort on two keys: every '
            'multicast from one side is now undecryptable to the other, '
            'permanently')

    def test_the_winner_is_the_same_whichever_side_goes_first(self):
        """Order-independence. A tiebreak that depended on who processed first
        would converge in one direction and fork in the other — and would pass
        a single-order test half the time."""
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')

        # ONE pair of rotated keys, replayed in both orders. Minting fresh
        # keys per iteration would compare two unrelated coin flips and fail
        # for a reason that has nothing to do with determinism — which is
        # exactly what the first version of this test did.
        seed_a, seed_b = _shared_group(a_id, b_id)
        seed_a.rotate_key()
        seed_b.rotate_key()
        rotated_a = seed_a.to_canonical()
        rotated_b = seed_b.to_canonical()

        winners = []
        for order in ('a-first', 'b-first'):
            a = _build_process(a_id, Group.from_canonical(rotated_a))
            b = _build_process(b_id, Group.from_canonical(rotated_b))
            a_says = _update_from(Group.from_canonical(rotated_a))
            b_says = _update_from(Group.from_canonical(rotated_b))
            if order == 'a-first':
                b.handle_group_update(_queues(), a_says)
                a.handle_group_update(_queues(), b_says)
            else:
                a.handle_group_update(_queues(), b_says)
                b.handle_group_update(_queues(), a_says)
            assert _key_of(a.group) == _key_of(b.group), order
            winners.append(_key_of(a.group))

        assert winners[0] == winners[1], (
            'the surviving key depends on arrival order — the tiebreak is not '
            'deterministic, so two members can each believe they won')

    def test_an_unverified_rotation_is_not_adopted(self):
        """PRESENT BEHAVIOUR, pinned so that changing it is deliberate.

        The tiebreak only runs on a verified message. In the live cohort these
        updates arrive unverified, so this path — not the tiebreak — is what
        leaves the cohort forked. Whoever fixes that should come here first and
        decide, on purpose, what an unverified key-carrying update deserves.
        """
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        a_grp, b_grp = _shared_group(a_id, b_id)
        a = _build_process(a_id, a_grp)
        b = _build_process(b_id, b_grp)
        a.group.rotate_key()
        b.group.rotate_key()
        before = _key_of(a.group)

        a.handle_group_update(_queues(), _update_from(b.group, verified=False))

        assert _key_of(a.group) == before, (
            'an unverified key-carrying update was adopted — that is the '
            'attack surface the gate exists for')


class TestRotationRefusalIsNamed:
    """Every refusal used to read the same ("ours stands" in C, nothing at all
    in Python), so a forked cohort (three-way boot rotation, rep-2368077) could
    not be told from one that settled. The reason is now named, the phrases
    match C group_rotation_refusal, and accept_rotation refuses exactly when
    a reason is given."""

    def _assert_refusal(self, mine, offer, expect):
        assert mine.rotation_refusal(offer) == expect
        probe = Group.from_canonical(mine.to_canonical())
        probe._previous_keys = list(getattr(mine, '_previous_keys', []) or [])
        assert probe.accept_rotation(offer) == (expect is None)

    def test_each_reason(self):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        mine, theirs = _shared_group(a_id, b_id)
        first = Group.from_canonical(mine.to_canonical())
        mine.rotate_key()                       # epoch 1; `first` now retired
        theirs = Group.from_canonical(theirs.to_canonical())
        theirs.rotate_key()
        theirs.rotate_key()                     # epoch 2, a live key
        self._assert_refusal(mine, theirs, None)

        self._assert_refusal(mine, None, 'no group to compare')
        foreign = Group.initialize({str(a_id.uuid): a_id.address}, 'other')
        self._assert_refusal(mine, foreign, 'a different group')
        stale = Group.from_canonical(first.to_canonical())
        stale._key_epoch = 0
        self._assert_refusal(mine, stale, 'a lower epoch (a replay)')
        public_only = theirs.publish()
        public_only._key_epoch = theirs.key_epoch
        self._assert_refusal(mine, public_only, 'it carries no private key')
        replay = Group.from_canonical(first.to_canonical())
        replay._key_epoch = 5
        self._assert_refusal(mine, replay, 'a key we already retired')
        self._assert_refusal(mine, Group.from_canonical(mine.to_canonical()),
                             'already our key')

        rival = Group.from_canonical(theirs.to_canonical())
        rival._key_epoch = mine.key_epoch
        lower = bytes(rival.encryptor.public) < bytes(mine.encryptor.public)
        self._assert_refusal(mine, rival, None if lower else
                             'ours stands (the lower key wins the tiebreak)')

    def test_the_refusal_is_logged_with_both_keys(self, caplog):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        a_grp, b_grp = _shared_group(a_id, b_id)
        a = _build_process(a_id, a_grp)
        b = _build_process(b_id, b_grp)
        a.group.rotate_key()
        b.group.rotate_key()
        a_says, b_says = _update_from(a.group), _update_from(b.group)
        a_key, b_key = _key_of(a.group)[:16].decode(), _key_of(b.group)[:16].decode()
        with caplog.at_level(logging.INFO):
            a.handle_group_update(_queues(), b_says)
            b.handle_group_update(_queues(), a_says)
        lines = [r.getMessage() for r in caplog.records if 'not adopted' in r.getMessage()]
        # Exactly the winner refuses, with the tiebreak named and both keys.
        assert len(lines) == 1, lines
        assert 'ours stands (the lower key wins the tiebreak)' in lines[0]
        assert a_key in lines[0] and b_key in lines[0]

    def test_a_sibling_names_the_key_it_installs_once(self, caplog):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        grp, _ = _shared_group(a_id, b_id)
        sibling = Protocol(CfgIds.network, logging.getLogger('test.sibling'), None)
        # A copy per hand-off, as a queue delivers it.
        def wire(g):
            return Group.from_canonical(g.to_canonical())
        with caplog.at_level(logging.INFO, logger='test.sibling'):
            sibling.run_message_handlers(_queues(), wire(grp))
            sibling.run_message_handlers(_queues(), wire(grp))  # same key: quiet
            grp.rotate_key()
            sibling.run_message_handlers(_queues(), wire(grp))
        lines = [r.getMessage() for r in caplog.records if 'installed group key' in r.getMessage()]
        assert len(lines) == 2, lines
        assert lines[1].startswith('network: installed group key %s… epoch 1'
                                   % _key_of(grp)[:16].decode())

    def test_an_outgoing_update_names_its_key(self, caplog):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        grp, _ = _shared_group(a_id, b_id)
        proc = _build_process(a_id, grp)
        del proc._update_group                   # the real one, not the mock
        proc.peers.hierarchy[0][str(b_id.uuid)] = b_id.publish()
        queues = _queues()
        with caplog.at_level(logging.DEBUG):
            proc._update_group(queues, grp, 0)
            proc._update_group(queues, grp, 0)
        sent = [r for r in caplog.records if 'Sending group update' in r.getMessage()]
        assert [r.levelno for r in sent] == [logging.INFO, logging.DEBUG]
        assert ('with key %s… epoch 0 (carries_key=1) to 1 member(s)'
                % _key_of(grp)[:16].decode()) in sent[0].getMessage()


class TestAdoptedKeyReachesSiblings:
    """The adopted key must reach the NETWORK process, not only identity.

    Partition cohort part-3310971 (2026-09-28): four nodes each logged the
    adoption of the same rotated key, then multicast under three different
    keys and could open none of each other's frames. A rotation changes no
    membership, so the update that carries it is equal-or-smaller than ours,
    and handle_group_update's quiet no-op return was the only exit: the key
    changed in identity and never went out to the siblings.
    """

    def test_an_equal_size_rotation_is_recorded(self):
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        a_grp, b_grp = _shared_group(a_id, b_id)
        a = _build_process(a_id, a_grp)
        b_grp.rotate_key()   # b supersedes: higher epoch, same membership

        a.handle_group_update(_queues(), _update_from(b_grp))

        assert _key_of(a.group) == _key_of(b_grp), 'precondition: adopted'
        a._record_group.assert_called()

    def test_a_declined_rotation_records_nothing(self):
        """Control: when our key stands, siblings already hold it."""
        a_id = _new_identity('a', '10.0.0.1')
        b_id = _new_identity('b', '10.0.0.2')
        a_grp, b_grp = _shared_group(a_id, b_id)
        a = _build_process(a_id, a_grp)
        a.group.rotate_key()
        a.group.rotate_key()   # ours is two epochs ahead; b's is stale

        a.handle_group_update(_queues(), _update_from(b_grp))

        a._record_group.assert_not_called()
