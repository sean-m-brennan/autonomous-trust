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
"""Anchor-first join selection and provisional marking (RD_14.4_HOSTILE_JOIN_PLAN.md
Phase 3, D1 (c) + (d)).

Under an enabled join policy a history OFFERED BY an anchor beats one that is
not, below the returning node's persisted group; length decides within each.
`_merge_to_mesh` puts anchors ahead of `created`, with a group of one tying an
anchored candidate so two mutual anchors converge rather than swap (the user's
calls, 2026-10-23). Members the adopted history introduced, unanchored and not
already held, are provisional and persisted. Inert, nothing changes.
"""
import json
import os
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core._python.identity.join_policy import JoinPolicy
from autonomous_trust.core._python.identity.idprocess import PROVISIONAL_FILE

from tests.a_unit.test_bridged_group import _peer, _queues
from tests.a_unit.test_choose_group import _chooser, _group

ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


def _policy(node, anchors, policy=ON):
    """Turn the policy on and answer "anchored" for the identities given."""
    ids = {str(a.uuid) for a in anchors}
    node.join_policy = policy
    node.is_anchored = lambda ident: ident is not None and str(ident.uuid) in ids
    return node


def _offer(node, sender, group, steps, bundle=()):
    node.histories.append((group.to_canonical(), list(steps),
                           [p.publish() for p in bundle]))
    node._note_history_sender(sender)


def _provisional_file():
    return os.path.join(Configuration.get_cfg_dir(),
                        PROVISIONAL_FILE + Configuration.file_ext)


def test_an_offer_from_an_anchor_beats_a_longer_one():
    me, horde, friend = _peer('me'), _peer('horde'), _peer('friend')
    node = _policy(_chooser(me), [friend])
    node.histories = []
    long_, anchored = _group(horde, name='long'), _group(friend, name='anchored')
    _offer(node, horde, long_, ['s1', 's2', 's3'])
    _offer(node, friend, anchored, ['s1'])
    node.choose_group(_queues())
    assert node.group == anchored


def test_containing_an_anchor_is_not_being_offered_by_one():
    """A cohort can list a verified contact in its map and bundle; only the
    sender counts."""
    me, horde, friend = _peer('me'), _peer('horde'), _peer('friend')
    node = _policy(_chooser(me), [friend])
    node.histories = []
    claims, honest = _group(horde, friend, name='claims'), _group(friend, name='honest')
    _offer(node, horde, claims, ['s1', 's2'], bundle=[friend])
    _offer(node, None, honest, ['s1'])
    node.choose_group(_queues())
    assert node.group == claims  # neither offered by an anchor: longest


def test_with_no_anchored_offer_the_longest_wins():
    me, a, b = _peer('me'), _peer('a'), _peer('b')
    node = _policy(_chooser(me), [])
    node.histories = []
    short, long_ = _group(a, name='short'), _group(b, name='long')
    _offer(node, a, short, ['s1'])
    _offer(node, b, long_, ['s1', 's2'])
    node.choose_group(_queues())
    assert node.group == long_


def test_the_longer_of_two_anchored_offers_wins():
    me, f1, f2 = _peer('me'), _peer('f1'), _peer('f2')
    node = _policy(_chooser(me), [f1, f2])
    node.histories = []
    short, long_ = _group(f1, name='short'), _group(f2, name='long')
    _offer(node, f1, short, ['s1'])
    _offer(node, f2, long_, ['s1', 's2'])
    node.choose_group(_queues())
    assert node.group == long_


def test_the_persisted_group_still_comes_first():
    me, a, friend = _peer('me'), _peer('a'), _peer('friend')
    ours = _group(me, a, name='ours')
    node = _policy(_chooser(me, configured=ours), [friend])
    node.histories = []
    _offer(node, friend, _group(friend, name='anchored'), ['s1', 's2'])
    _offer(node, a, ours, [])
    node.choose_group(_queues())
    assert node.group == ours


def test_an_inert_policy_ignores_the_sender():
    me, horde, friend = _peer('me'), _peer('horde'), _peer('friend')
    node = _policy(_chooser(me), [friend], policy=JoinPolicy())
    node.histories = []
    long_ = _group(horde, name='long')
    _offer(node, horde, long_, ['s1', 's2'])
    _offer(node, friend, _group(friend, name='anchored'), ['s1'])
    node.choose_group(_queues())
    assert node.group == long_
    assert node.provisional_members == set()
    assert not os.path.exists(_provisional_file())


def test_a_stashed_history_without_a_sender_ranks_unanchored():
    me, a, friend = _peer('me'), _peer('a'), _peer('friend')
    node = _policy(_chooser(me), [friend])
    first = _group(a, name='first')
    node.histories = [(first.to_canonical(), ['s1'], [])]  # no sender noted
    _offer(node, friend, _group(friend, name='anchored'), ['s1'])
    node.choose_group(_queues())
    assert node.history_senders[0] is None
    assert node.group.nickname == 'anchored'


def test_adopted_members_are_provisional_unless_anchored_or_held():
    me, friend, held, horde = _peer('me'), _peer('friend'), _peer('held'), _peer('horde')
    node = _policy(_chooser(me, peers=[held]), [friend])
    node.histories = []
    g = _group(friend, held, horde)
    _offer(node, friend, g, ['s1'], bundle=[friend, held, horde])
    node.choose_group(_queues())
    assert node.provisional_members == {str(horde.uuid)}
    with open(_provisional_file()) as f:
        assert json.load(f) == [str(horde.uuid)]


def test_an_anchored_sender_only_in_the_map_is_not_provisional():
    """The welcomer is in its own map and need not be in any bundle; its
    identity is the sender's."""
    me, friend, other = _peer('me'), _peer('friend'), _peer('other')
    node = _policy(_chooser(me), [friend])
    node.histories = []
    _offer(node, friend, _group(friend, other), ['s1'])
    node.choose_group(_queues())
    assert node.provisional_members == {str(other.uuid)}


def test_the_provisional_set_survives_a_restart():
    me, horde = _peer('me'), _peer('horde')
    with open(_provisional_file(), 'w') as f:
        json.dump([str(horde.uuid)], f)
    node = _chooser(me)
    assert node._load_provisional_members() == {str(horde.uuid)}


def test_a_corrupt_provisional_file_is_left_in_place():
    me = _peer('me')
    with open(_provisional_file(), 'w') as f:
        f.write('{"not": "a list"}')
    node = _chooser(me)
    assert node._load_provisional_members() == set()
    assert os.path.exists(_provisional_file())
    node.logger.error.assert_called_once()


# --- _merge_to_mesh: anchors break, lone ties ---

def _merger(me, peers=(), mine_members=None, created=100.0):
    node = _chooser(me, peers)
    node.histories = []
    node.history_senders = []
    node.self_bootstrapped, node.merging = True, True
    node._partition_recovery_in_progress = None
    node._partition_probe_cooldown = set()
    node._update_group = MagicMock()
    node._broadcast_request_access = MagicMock()
    node.peers.mid_level = None
    node.group = _group(*(mine_members or [me]), name='mine')
    node.group._created = created
    return node


def _candidate(sender, *members, created):
    g = _group(*members, name='cand')
    g._created = created
    return g


def test_merge_an_anchored_candidate_ties_a_lone_group():
    """Mutual anchors that self-bootstrap at once each see the other as an
    anchored candidate: the tie goes to created, so both pick the same one."""
    me, friend = _peer('me'), _peer('friend')
    node = _policy(_merger(me, created=100.0), [friend])
    cand = _candidate(friend, friend, created=200.0)  # younger
    _offer(node, friend, cand, ['s1'])
    mine = node.group
    node._merge_to_mesh(_queues())
    assert node.group == mine


def test_merge_an_anchored_group_of_ours_keeps_off_an_older_horde():
    me, friend, horde = _peer('me'), _peer('friend'), _peer('horde')
    node = _policy(_merger(me, peers=[friend], mine_members=[me, friend],
                           created=200.0), [friend])
    _offer(node, horde, _candidate(horde, horde, created=1.0), ['s1'])
    mine = node.group
    node._merge_to_mesh(_queues())
    assert node.group == mine


def test_merge_an_anchored_candidate_beats_an_unanchored_group_of_ours():
    me, other, friend = _peer('me'), _peer('other'), _peer('friend')
    node = _policy(_merger(me, peers=[other], mine_members=[me, other],
                           created=100.0), [friend])
    cand = _candidate(friend, friend, created=200.0)  # younger, but anchored
    _offer(node, friend, cand, ['s1'])
    node._merge_to_mesh(_queues())
    assert node.group == cand


def test_merge_inert_keeps_the_created_rule():
    me, other, friend = _peer('me'), _peer('other'), _peer('friend')
    node = _policy(_merger(me, peers=[other], mine_members=[me, other],
                           created=100.0), [friend], policy=JoinPolicy())
    _offer(node, friend, _candidate(friend, friend, created=200.0), ['s1'])
    mine = node.group
    node._merge_to_mesh(_queues())
    assert node.group == mine


def test_merge_marks_the_adopted_members_provisional():
    me, friend, horde = _peer('me'), _peer('friend'), _peer('horde')
    node = _policy(_merger(me, created=200.0), [friend])
    cand = _candidate(horde, horde, friend, created=1.0)
    _offer(node, horde, cand, ['s1'], bundle=[horde, friend])
    node._merge_to_mesh(_queues())
    assert node.group == cand
    assert node.provisional_members == {str(horde.uuid)}


def test_merge_adopts_a_zero_step_history():
    """As choose_group and C (the user's call, 2026-10-23): a lone node's
    freshly minted group is eligible when nothing longer is offered."""
    me, other = _peer('me'), _peer('other')
    node = _policy(_merger(me, created=200.0), [], policy=JoinPolicy())
    cand = _candidate(other, other, created=100.0)  # older
    _offer(node, other, cand, [])
    node._merge_to_mesh(_queues())
    assert node.group == cand
