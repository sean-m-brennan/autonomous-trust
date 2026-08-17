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
"""Runtime cross-group join, and the key rotation it forced (ISSUES.md §10.2).

A gateway used to acquire a child cohort's key only from a seeded
`group_child_*.cfg.json` file. It can now ask the cohort to admit it, and the
cohort decides — the ordinary `request_access` / welcoming-committee vote /
`full_history` path, aimed at a named group instead of at whoever answers.

Two things make that safe, and both are asserted below:

* **The cohort still decides.** The join gate bounds who may SOLICIT (a proved
  shared anchor, and out-ranking the cohort); it does not admit anyone. And a
  group arriving without a matching pending join is never adopted, or any peer
  could hand us a cohort and install itself in our tree.

* **Admission rotates the shared key.** The key was permanent, so handing it to
  a joiner also handed over the ability to decrypt cohort traffic the joiner had
  recorded BEFORE it was admitted. Rotation closes that; the epoch is what makes
  a rotation safe to accept, since without it a captured old key could be
  replayed back over a newer one.

The grace window is the deliberate loose end: a rotation is not synchronous
across a cohort, so a retired key keeps decrypting for a bounded period rather
than dropping every frame from a member that has not yet caught up.
"""
import hashlib
import queue
import time
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.config import to_json_string
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.protocol import IdentityProtocol
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.core.system import CfgIds


def _identity(tag: str) -> Identity:
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.%d' % (abs(hash(tag)) % 200 + 1), '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _group(nickname='cohort', members=(), uuid=None):
    enc = Encryptor(hashlib.sha256(nickname.encode()).hexdigest().encode('ascii'),
                    public_only=False)
    addr_map = {str(m.uuid): m.address for m in members}
    return Group(uuid or uuid4(), addr_map, nickname, enc, _public_only=False)


def _node(identity=None, group=None, peers=(), rank=0):
    """A minimally-wired IdentityProcess. The suite's established stand-in
    style: real state, mocked plumbing."""
    node = object.__new__(IdentityProcess)
    node.name = CfgIds.identity
    node.identity = identity or _identity('self')
    node.logger = MagicMock()
    node.q_cadence = 0.01
    node.lock = MagicMock()
    node.lock.__enter__ = MagicMock(return_value=None)
    node.lock.__exit__ = MagicMock(return_value=False)
    node.phase = 3
    node.group = group
    node.child_groups = {}
    node.child_gateways = {}
    node.peer_hierarchy = {}
    node.peer_ranks = {}
    node._pending_joins = set()
    node.peers = MagicMock()
    node.peers.all = list(peers)
    node.peers.find_by_uuid = lambda u: next(
        (p for p in node.peers.all if str(p.uuid) == str(u)), None)
    node.identity._rank = rank
    node._adopt_child_group = MagicMock()
    node.report_exception = MagicMock()
    return node


def _queues():
    return {CfgIds.network: queue.Queue()}


def _announceable(node):
    """Fill in what _broadcast_request_access reads. `capabilities` is a
    read-only property over the protocol object, so the stand-in supplies the
    protocol rather than assigning through it."""
    node.package_hash = 'ph'
    node.protocol = MagicMock()
    node.protocol.capabilities.to_list = lambda: []
    node._refresh_operator_attestation = MagicMock()
    node._operator_attestation = lambda: {}


# --- soliciting a cohort ----------------------------------------------------


class TestSolicit:

    def test_request_names_the_target_cohort(self):
        node = _node(group=_group('primary'))
        _announceable(node)
        target = str(uuid4())
        q = _queues()
        assert node.request_cohort_join(q, target)
        msg = q[CfgIds.network].get_nowait()
        assert msg.function == IdentityProtocol.announce
        from autonomous_trust.core.config import from_json_string
        parts = from_json_string(msg.obj)
        assert len(parts) == 4 and parts[3] == target
        assert target in node._pending_joins

    def test_ordinary_announce_is_unchanged(self):
        """The 4th element is absent on a normal request, so a peer on an
        older build reads exactly what it always read."""
        node = _node(group=_group('primary'))
        _announceable(node)
        q = _queues()
        node._broadcast_request_access(q)
        from autonomous_trust.core.config import from_json_string
        parts = from_json_string(q[CfgIds.network].get_nowait().obj)
        assert len(parts) == 3

    def test_will_not_solicit_a_cohort_we_are_already_in(self):
        grp = _group('primary')
        node = _node(group=grp)
        assert not node.request_cohort_join(_queues(), grp.uuid)
        node.child_groups = {'abc': MagicMock()}
        assert not node.request_cohort_join(_queues(), 'abc')


# --- the gate ---------------------------------------------------------------


class TestJoinGate:

    def _cohort_node(self, own_rank=1, enforcing=True, own_anchors=('agency-a',)):
        node = _node(group=_group('cohort'), rank=own_rank)
        policy = MagicMock()
        policy.enabled = enforcing
        policy.require_at_admission = enforcing
        node._zta_policy = lambda: policy
        node._own_zta_anchors = lambda: set(own_anchors)
        return node

    def _requester(self, rank=5, anchors=('agency-a',)):
        ident = _identity('joiner')
        ident._rank = rank
        ident.zta_anchors = list(anchors)
        return ident

    def test_authorized_requester_passes(self):
        node = self._cohort_node()
        assert node._join_authorized(self._requester())

    def test_foreign_anchor_is_refused(self):
        """§10.5's rule, applied to admission: a peer holding only another
        agency's credential is not ours to admit."""
        node = self._cohort_node()
        assert not node._join_authorized(self._requester(anchors=('agency-b',)))

    def test_equal_or_lower_rank_is_refused(self):
        """A cohort is joined from ABOVE, by the node that will gateway it.
        Sideways joins would let any anchored peer collect cohort keys."""
        node = self._cohort_node(own_rank=5)
        assert not node._join_authorized(self._requester(rank=5))
        assert not node._join_authorized(self._requester(rank=1))

    def test_gate_is_inert_without_enforcement(self):
        """Same inert conditions as _gateway_authorized: refusing everyone in a
        non-ZTA deployment would break joins rather than protect anything."""
        node = self._cohort_node(enforcing=False)
        assert node._join_authorized(self._requester(anchors=('agency-b',)))

    def test_gate_is_inert_when_we_hold_no_anchors(self):
        node = self._cohort_node(own_anchors=())
        assert node._join_authorized(self._requester(anchors=()))


# --- adopting what comes back ------------------------------------------------


class TestAdoption:

    def _answer(self, group):
        return [group.to_canonical(), [], []]

    def test_solicited_cohort_is_adopted_as_a_child(self):
        node = _node(group=_group('primary'))
        cohort = _group('field')
        node._pending_joins = {str(cohort.uuid)}
        assert node._adopt_solicited_group(_queues(), self._answer(cohort))
        node._adopt_child_group.assert_called_once()
        adopted = node._adopt_child_group.call_args[0][1]
        assert str(adopted.uuid) == str(cohort.uuid)
        assert not node._pending_joins, 'the pending mark is consumed'

    def test_unsolicited_group_is_not_adopted(self):
        """Otherwise any peer could hand us a cohort and install itself in our
        tree."""
        node = _node(group=_group('primary'))
        assert not node._adopt_solicited_group(_queues(),
                                               self._answer(_group('field')))
        node._adopt_child_group.assert_not_called()

    def test_answer_without_the_shared_key_is_refused(self):
        """A public-only group cannot decrypt cohort traffic; adopting it would
        record a membership that can hear nothing."""
        node = _node(group=_group('primary'))
        cohort = _group('field')
        node._pending_joins = {str(cohort.uuid)}
        payload = cohort.publish().to_canonical()
        assert not node._adopt_solicited_group(_queues(), [payload, [], []])
        node._adopt_child_group.assert_not_called()
        assert node._pending_joins, 'still pending; a half-join is not recorded'

    def test_primary_group_is_untouched_by_a_join(self):
        primary = _group('primary')
        node = _node(group=primary)
        cohort = _group('field')
        node._pending_joins = {str(cohort.uuid)}
        node._adopt_solicited_group(_queues(), self._answer(cohort))
        assert node.group is primary, \
            'joining a child cohort must not replace our own group'


# --- rotation ----------------------------------------------------------------


class TestRotation:

    def test_rotation_changes_the_key_and_bumps_the_epoch(self):
        grp = _group('cohort')
        before = grp.encryptor.publish()
        assert grp.key_epoch == 0
        assert grp.rotate_key() == 1
        assert grp.encryptor.publish() != before

    def test_a_public_only_group_cannot_be_rotated(self):
        """Minting a key we cannot already decrypt with would fork the cohort
        into halves that cannot hear each other."""
        with pytest.raises(RuntimeError):
            _group('cohort').publish().rotate_key()

    def test_higher_epoch_supersedes(self):
        mine = _group('cohort')
        theirs = Group.from_canonical(mine.to_canonical())
        theirs.rotate_key()
        assert mine.accept_rotation(theirs)
        assert mine.key_epoch == theirs.key_epoch
        assert mine.encryptor.publish() == theirs.encryptor.publish()

    def test_equal_or_lower_epoch_is_replay(self):
        """The property the epoch exists for: a captured old key must not be
        reinstatable over a newer one."""
        mine = _group('cohort')
        stale = Group.from_canonical(mine.to_canonical())
        mine.rotate_key()
        assert not mine.accept_rotation(stale)
        assert mine.key_epoch == 1

    def test_rotation_from_another_group_is_not_a_rotation(self):
        mine = _group('cohort')
        other = _group('elsewhere')
        other.rotate_key()
        assert not mine.accept_rotation(other)

    def test_retired_key_still_decrypts_inside_the_grace_window(self):
        """A rotation is not synchronous: a member that has not processed the
        update is still sending under the old key."""
        grp = _group('cohort')
        sender = Group.from_canonical(grp.to_canonical())
        blob = sender.encrypt(b'in flight', sender)
        grp.rotate_key()
        assert grp.decrypt(blob, sender) == b'in flight'

    def test_retired_key_stops_working_after_the_window(self):
        grp = _group('cohort')
        sender = Group.from_canonical(grp.to_canonical())
        blob = sender.encrypt(b'too late', sender)
        grp.rotate_key(now_ts=time.time() - Group.PREVIOUS_KEY_GRACE - 1)
        with pytest.raises(Exception):
            grp.decrypt(blob, sender)

    def test_a_joiner_cannot_read_pre_join_traffic(self):
        """The whole point of rotating on admission."""
        cohort = _group('cohort')
        recorded = cohort.encrypt(b'before you arrived', cohort)
        cohort.rotate_key()
        # What the joiner is handed is the post-rotation group.
        joiner_view = Group.from_canonical(cohort.to_canonical())
        assert joiner_view.key_epoch == 1
        with pytest.raises(Exception):
            joiner_view.decrypt(recorded, joiner_view)


class TestRotationOnTheWire:

    def _node_with_peers(self):
        peers = [_identity('m1'), _identity('m2')]
        grp = _group('cohort', members=peers)
        node = _node(group=grp, peers=peers)
        return node, grp, peers

    def test_admission_rotates_and_tells_every_member(self):
        node, grp, peers = self._node_with_peers()
        q = _queues()
        assert node._rotate_group_key(q)
        assert grp.key_epoch == 1
        sent = []
        while not q[CfgIds.network].empty():
            sent.append(q[CfgIds.network].get_nowait())
        assert len(sent) == len(peers)
        assert all(m.function == IdentityProtocol.update for m in sent)
        from autonomous_trust.core.config import from_json_string
        carried = Group.from_canonical(from_json_string(sent[0].obj))
        assert carried.key_epoch == 1
        assert carried.owns_private_key, \
            'a member that cannot decrypt is not a member'

    def test_unverified_rotation_is_rejected(self):
        """The epoch says which key is newer; it says nothing about whether the
        sender had any business rotating."""
        node, grp, _peers = self._node_with_peers()
        rotated = Group.from_canonical(grp.to_canonical())
        rotated.rotate_key()
        msg = MagicMock()
        msg.function = IdentityProtocol.update
        msg.obj = to_json_string(rotated.to_canonical())
        msg.verified = False
        node.handle_group_update(_queues(), msg)
        assert grp.key_epoch == 0, 'unverified rotation must not be adopted'

    def test_verified_rotation_is_adopted(self):
        node, grp, _peers = self._node_with_peers()
        rotated = Group.from_canonical(grp.to_canonical())
        rotated.rotate_key()
        msg = MagicMock()
        msg.function = IdentityProtocol.update
        msg.obj = to_json_string(rotated.to_canonical())
        msg.verified = True
        node.handle_group_update(_queues(), msg)
        assert grp.key_epoch == 1
        assert grp.encryptor.publish() == rotated.encryptor.publish()


class TestRotationSurvivesAConfigReload:
    """A rotated group has to still load off disk.

    `config_json_decoder` rebuilds every Configuration via `cls(**kwargs)`, so
    any attribute the encoder writes has to be a constructor parameter. Key
    rotation added `_previous_keys` and nothing checked that invariant, which
    took out every node that wrote its group config and restarted --
    `TypeError: Group.__init__() got an unexpected keyword argument
    '_previous_keys'`, raised in `load_configs` before the process was even
    running. The grace-window keys are process-local (see `Group.to_dict`), so
    the fix keeps them out of the file rather than into the signature.
    """

    def test_the_group_under_test_carries_the_fix(self):
        """Runs first so a STALE package says so, instead of the four cases
        below failing as though the fix were wrong.

        They are indistinguishable otherwise: a package predating the fix
        produces exactly the mutation-check symptoms. This happens whenever
        tests and package arrive by different routes — the test image copies
        `tests` fresh onto whatever `autonomous_trust` its devel base layer
        baked in, so rebuilding only `test` gives new tests over old code.
        """
        import inspect
        assert '_previous_keys' in inspect.getsource(Group.to_dict), (
            'The Group under test does not drop _previous_keys in to_dict, so '
            'every case below will fail as if the fix were absent -- because in '
            'this package it is.\n  Group loaded from: %s\n'
            'If that is not the file you edited, refresh the package under test '
            '(rebuild the devel image before the test image, reinstall, or fix '
            'PYTHONPATH) rather than the tests.' % inspect.getfile(Group))

    def _rotated(self):
        grp = _group('cohort', members=[_identity('m1')])
        grp.rotate_key()
        assert grp.key_epoch == 1
        return grp

    def test_a_rotated_group_round_trips_through_its_config_form(self):
        from autonomous_trust.core.config import from_json_string
        grp = self._rotated()
        back = from_json_string(to_json_string(grp))
        assert isinstance(back, Group)
        assert back.uuid == grp.uuid
        assert back.key_epoch == 1
        assert back.encryptor.publish() == grp.encryptor.publish()
        assert back.owns_private_key

    def test_retired_private_keys_are_not_written_to_the_file(self):
        grp = _group('cohort', members=[_identity('m1')])
        retiring = grp.encryptor.serialize()
        if isinstance(retiring, bytes):
            retiring = retiring.decode('ascii')
        grp.rotate_key()
        text = to_json_string(grp)
        assert '_previous_keys' not in text
        # The superseded key itself must not be sitting in the config either.
        assert retiring not in text

    def test_a_config_written_before_the_fix_still_loads(self):
        """Files carrying the stray key already exist on disk."""
        import json
        from autonomous_trust.core.config import from_json_string
        grp = self._rotated()
        raw = json.loads(to_json_string(grp))
        raw['_previous_keys'] = []          # what the old encoder emitted
        back = from_json_string(json.dumps(raw))
        assert isinstance(back, Group)
        assert back.key_epoch == 1
        assert back._previous_keys == []

    def test_every_serialized_field_is_a_constructor_parameter(self):
        """Fails on the next attribute added without a matching kwarg, instead
        of at the next process start."""
        import inspect
        grp = self._rotated()
        params = set(inspect.signature(Group.__init__).parameters) - {'self'}
        assert set(grp.to_dict()) <= params, \
            'serialized but not constructible: %s' % (
                sorted(set(grp.to_dict()) - params),)
