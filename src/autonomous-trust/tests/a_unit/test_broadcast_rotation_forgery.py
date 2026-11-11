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
"""A stranger on the broadcast channel must not be able to rotate our key.

The broadcast channel cannot attribute a frame to a peer we hold, so
Message.parse reconstructs the sender from the envelope's own from_* fields
and checks the signature against the key the envelope names. Any keypair
signs its own frame validly, so such a frame always comes out verified.
group_key_update is admitted on that channel, and handle_group_update raises
the epoch on any verified update for our group uuid. Together, anyone who
knows the group uuid can hand a member a key of their own choosing.

These tests drive a forged rotation through the real network routing
(NetworkProcess._msg_to_queue on the multicast path) into the identity
process and assert the member keeps its key.
"""
from __future__ import annotations

import logging

from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.identity import Group
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_group_key_convergence import (_build_process, _new_identity,
                                                     _queues, _shared_group, _key_of)


def _routed(raw, from_addr):
    """Route ``raw`` as the multicast/stranger channel does and return what
    reached the identity queue (empty when the network layer refused it)."""
    net = object.__new__(NetworkProcess)
    net.logger = logging.getLogger('test.net.forgery')
    net.q_cadence = 0.01
    net._child_group_of = lambda _addr: None
    queues = _queues()
    net._msg_to_queue(raw, from_addr, queues, 'multicast', validate=False)
    return queues[CfgIds.identity].items


def _forged_rotation(target_group, forger, claimed=None):
    """What a stranger mints: our group's uuid, a higher epoch, a fresh
    private key, signed by ``forger``. ``claimed`` optionally names a real
    member's uuid in the envelope while keeping the forger's own keys."""
    rogue = Group.from_canonical(target_group.to_canonical())
    rogue.rotate_key()
    rogue.rotate_key()
    msg = Message(CfgIds.identity, IdentityProtocol.update,
                  to_json_string(rogue.to_canonical()), from_whom=forger,
                  encrypt=False)
    raw = bytes(msg)
    if claimed is not None:
        raw = raw.replace(str(forger.uuid).encode(), str(claimed.uuid).encode())
    return raw, rogue


def _member():
    member_id = _new_identity('member', '10.0.0.1')
    other_id = _new_identity('other', '10.0.0.2')
    mine, _ = _shared_group(member_id, other_id)
    proc = _build_process(member_id, mine)
    proc.peers.add(other_id.publish(), 0)
    return proc, other_id, mine


class TestBroadcastRotationForgery:
    def test_a_strangers_rotation_is_not_adopted(self):
        member, _, mine = _member()
        mallory = _new_identity('mallory', '10.0.0.9')
        before = _key_of(mine)
        raw, rogue = _forged_rotation(mine, mallory)

        delivered = _routed(raw, '10.0.0.9')
        assert len(delivered) == 1, 'broadcast channel no longer admits group_key_update'
        for msg in delivered:
            member.handle_group_update(_queues(), msg)

        assert member.group.key_epoch == 0, (
            'a stranger rotated our group key to epoch %d' % member.group.key_epoch)
        assert _key_of(member.group) == before
        assert _key_of(member.group) != _key_of(rogue)

    def test_a_rotation_claiming_a_members_uuid_is_not_adopted(self):
        member, other_id, mine = _member()
        mallory = _new_identity('mallory', '10.0.0.9')
        before = _key_of(mine)
        raw, _ = _forged_rotation(mine, mallory, claimed=other_id)

        for msg in _routed(raw, '10.0.0.9'):
            member.handle_group_update(_queues(), msg)

        assert member.group.key_epoch == 0
        assert _key_of(member.group) == before

    def test_a_held_peer_outside_the_group_cannot_rotate_it(self):
        """A peer we hold is attributed by the transport, so its frame verifies
        against its real key. Holding it says nothing about whether it belongs
        to this group."""
        member, _, mine = _member()
        outsider = _new_identity('outsider', '10.0.0.8')
        member.peers.add(outsider.publish(), 0)
        before = _key_of(mine)
        raw, _ = _forged_rotation(mine, outsider)
        msg = Message.parse(raw, outsider.publish())
        assert msg.verified, 'precondition: verified against the held key'

        member.handle_group_update(_queues(), msg)

        assert member.group.key_epoch == 0
        assert _key_of(member.group) == before
