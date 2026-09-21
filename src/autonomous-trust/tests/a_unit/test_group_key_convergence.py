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
