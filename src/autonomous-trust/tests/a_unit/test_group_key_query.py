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
"""A node behind on the group key asks a member for the current group.

Hostile-join run, 2026-11-03: two joiners admitted during the cohort's burst
of rotations ended on a forked key, two epochs behind, and the cohort never
resent, because it saw them as members already. Re-verifying held updates
recovers what the node held; ``group_key_query`` recovers what it never
received. The answer is an ordinary signed ``group_key_update``, so the asker
takes it through the same verified gate as any other: a query can make a
member resend the group, never make anyone accept a key it would otherwise
refuse.

Mirrors C test/group_key_query_test.c.
"""
from __future__ import annotations

import json

from nacl.encoding import HexEncoder

from autonomous_trust.core.identity import Group
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_group_key_convergence import (
    _build_process, _new_identity, _queues, _shared_group)


def _query(asker, group, epoch=None):
    """``asker``'s group_key_query, as identity receives it from the wire."""
    body = json.dumps({'group_uuid': str(group.uuid),
                       'epoch': group.key_epoch if epoch is None else epoch})
    msg = Message(CfgIds.identity, IdentityProtocol.key_query, body,
                  from_whom=asker)
    msg.from_whom = asker.publish()
    return msg


def _stale(address):
    """The network's local signal: a group frame from ``address`` would not open."""
    return Message(CfgIds.identity, IdentityProtocol.key_stale, address, encrypt=False)


def _sent(queues, function):
    return [m for m in queues[CfgIds.network].items if m.function == function]


def _member_and_asker():
    member_id = _new_identity('member', '10.0.0.2')
    asker_id = _new_identity('asker', '10.0.0.3')
    grp, asker_copy = _shared_group(member_id, asker_id)
    member = _build_process(member_id, grp)
    member.peers.add(asker_id.publish(), 0)
    return member, member_id, asker_id, grp, asker_copy


class TestResponder:
    def test_a_member_gets_the_group_signed(self):
        member, member_id, asker_id, grp, _ = _member_and_asker()
        grp.rotate_key()
        queues = _queues()
        member.handle_key_query(queues, _query(asker_id, grp, epoch=0))
        [reply] = _sent(queues, IdentityProtocol.update)
        assert reply.to_whom[0].uuid == asker_id.uuid
        sent = Group.from_canonical(json.loads(reply.obj))
        assert sent.key_epoch == 1 and sent.owns_private_key
        content = Message._signable_content(reply.process, reply.function, reply._obj_b64())
        member_id.signature.public.verify(content.encode(), HexEncoder.decode(reply.signature))

    def test_a_non_member_gets_nothing(self):
        member, _, _, grp, _ = _member_and_asker()
        stranger = _new_identity('stranger', '10.0.0.7')
        member.peers.add(stranger.publish(), 0)
        queues = _queues()
        member.handle_key_query(queues, _query(stranger, grp))
        assert _sent(queues, IdentityProtocol.update) == []

    def test_a_member_we_do_not_hold_gets_nothing(self):
        # The reply is sealed to the key we hold for the asker; with none held,
        # there is nothing to seal it to.
        member_id = _new_identity('member', '10.0.0.2')
        asker_id = _new_identity('asker', '10.0.0.3')
        grp, _ = _shared_group(member_id, asker_id)
        member = _build_process(member_id, grp)
        queues = _queues()
        member.handle_key_query(queues, _query(asker_id, grp))
        assert _sent(queues, IdentityProtocol.update) == []

    def test_another_group_gets_nothing(self):
        member, _, asker_id, grp, _ = _member_and_asker()
        other = Group.initialize({str(asker_id.uuid): asker_id.address}, 'other')
        queues = _queues()
        member.handle_key_query(queues, _query(asker_id, other))
        assert _sent(queues, IdentityProtocol.update) == []

    def test_before_phase_3_nothing_is_answered(self):
        member, _, asker_id, grp, _ = _member_and_asker()
        member.phase = 2
        queues = _queues()
        member.handle_key_query(queues, _query(asker_id, grp))
        assert _sent(queues, IdentityProtocol.update) == []

    def test_one_answer_per_asker_per_interval(self):
        member, _, asker_id, grp, _ = _member_and_asker()
        queues = _queues()
        member.handle_key_query(queues, _query(asker_id, grp))
        member.handle_key_query(queues, _query(asker_id, grp))
        assert len(_sent(queues, IdentityProtocol.update)) == 1


class TestAsker:
    def _asker_holding(self, member_id, asker_id, grp):
        asker = _build_process(asker_id, grp)
        asker.peers.add(member_id.publish(), 0)
        return asker

    def test_a_stale_signal_queries_the_member_at_that_address(self):
        member_id = _new_identity('member', '10.0.0.2')
        asker_id = _new_identity('asker', '10.0.0.3')
        _, grp = _shared_group(member_id, asker_id)
        asker = self._asker_holding(member_id, asker_id, grp)
        queues = _queues()
        asker.handle_key_stale(queues, _stale('10.0.0.2'))
        [query] = _sent(queues, IdentityProtocol.key_query)
        assert query.to_whom[0].uuid == member_id.uuid
        assert json.loads(query.obj) == {'group_uuid': str(grp.uuid), 'epoch': 0}
        assert query.signature is not None

    def test_one_query_per_member_per_interval(self):
        member_id = _new_identity('member', '10.0.0.2')
        asker_id = _new_identity('asker', '10.0.0.3')
        _, grp = _shared_group(member_id, asker_id)
        asker = self._asker_holding(member_id, asker_id, grp)
        queues = _queues()
        asker.handle_key_stale(queues, _stale('10.0.0.2'))
        asker.handle_key_stale(queues, _stale('10.0.0.2'))
        assert len(_sent(queues, IdentityProtocol.key_query)) == 1

    def test_a_signal_from_the_wire_is_refused(self):
        # group_key_stale is the network process's, never a peer's.
        member_id = _new_identity('member', '10.0.0.2')
        asker_id = _new_identity('asker', '10.0.0.3')
        _, grp = _shared_group(member_id, asker_id)
        asker = self._asker_holding(member_id, asker_id, grp)
        forged = _stale('10.0.0.2')
        forged.from_whom = member_id.publish()
        queues = _queues()
        asker.handle_key_stale(queues, forged)
        assert _sent(queues, IdentityProtocol.key_query) == []

    def test_an_address_that_is_no_member_is_not_queried(self):
        member_id = _new_identity('member', '10.0.0.2')
        asker_id = _new_identity('asker', '10.0.0.3')
        _, grp = _shared_group(member_id, asker_id)
        asker = self._asker_holding(member_id, asker_id, grp)
        queues = _queues()
        asker.handle_key_stale(queues, _stale('10.0.0.8'))
        assert _sent(queues, IdentityProtocol.key_query) == []

    def test_reaching_phase_3_queries_a_few_members(self):
        asker_id = _new_identity('asker', '10.0.0.3')
        members = [_new_identity('m%d' % i, '10.0.1.%d' % i) for i in range(1, 6)]
        addrs = {str(asker_id.uuid): asker_id.address}
        addrs.update({str(m.uuid): m.address for m in members})
        grp = Group.initialize(addrs, 'cohort')
        asker = _build_process(asker_id, grp)
        for m in members:
            asker.peers.add(m.publish(), 0)
        asker._key_pull_due = 0.0          # phase 3 reached, settle elapsed
        queues = _queues()
        asker._maybe_pull_key(queues)
        queries = _sent(queues, IdentityProtocol.key_query)
        assert len(queries) == 3
        assert asker._key_pull_due is None
        asker._maybe_pull_key(queues)      # once per phase-3 entry
        assert len(_sent(queues, IdentityProtocol.key_query)) == 3
