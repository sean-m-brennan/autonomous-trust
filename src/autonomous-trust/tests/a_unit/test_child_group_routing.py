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
"""A gateway's child-cohort traffic stays with the child group.

A gateway holds its primary group and one child group per cohort below it. The
network process tags a frame whose sender is in a child cohort (and not in the
primary) with that child's uuid, and the identity process applies a tagged
group update or confirmation to the child. Untagged, both read as news about
the primary: a larger child group won the size rule and replaced the gateway's
primary, and every field joiner a field member confirmed went into the primary's
address map, so the command cohort ended up holding the field cohort."""
import logging
import queue
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_partition_recovery import _build_process, _build_queues, _new_identity


def _group(nickname, *idents):
    return Group.initialize({str(i.uuid): i.address for i in idents}, nickname)


# ---- the network process tags a child cohort's frames ----------------------

def _net_proc(primary, children, me):
    proc = MagicMock(spec=NetworkProcess)
    proc.name = CfgIds.network
    proc.q_cadence = 0
    proc.logger = logging.getLogger('test.net.child')
    from autonomous_trust.core._python.network.presence import PresenceTracker
    proc._presence = PresenceTracker(30.0, 90.0)
    proc._foreign_format_counts = {}
    proc.group = primary
    proc.child_groups = {str(c.uuid): c for c in children}
    proc.myself = me
    for name in ('_msg_to_queue', '_child_group_of', '_crosses_gateway',
                 '_groups_containing', '_held_groups', '_group_for_sender'):
        setattr(proc, name, getattr(NetworkProcess, name).__get__(proc))
    return proc


def _queued(qs, name=CfgIds.identity):
    return qs[name].get_nowait()


class TestNetworkTag:
    gw = _new_identity('gw', '10.0.0.7')
    boss = _new_identity('boss', '10.0.0.3')
    field = _new_identity('field', '172.20.0.9')

    def _deliver(self, sender, addr):
        primary = _group('cmd', self.gw, self.boss)
        child = _group('fld', self.gw, self.field)
        proc = _net_proc(primary, [child], self.gw)
        qs = {CfgIds.identity: queue.Queue(), CfgIds.network: queue.Queue()}
        frame = bytes(Message(CfgIds.identity, IdentityProtocol.update, '{}',
                              from_whom=sender))
        # A decrypted frame arrives with its sender's identity, as from
        # _route_decrypted.
        proc._msg_to_queue(frame, sender, qs, 'point-to-point', validate=False)
        return _queued(qs), child

    def test_a_child_cohort_frame_names_the_child(self):
        msg, child = self._deliver(self.field, '172.20.0.9')
        assert msg.child_group == str(child.uuid)

    def test_a_primary_frame_names_no_child(self):
        msg, _ = self._deliver(self.boss, '10.0.0.3')
        assert msg.child_group is None

    def test_a_leaf_node_tags_nothing(self):
        primary = _group('cmd', self.gw, self.boss)
        proc = _net_proc(primary, [], self.gw)
        assert proc._child_group_of('172.20.0.9') is None
        assert Message(CfgIds.identity, 'x', '').child_group is None


# ---- the identity process applies a tagged message to the child ------------

def _gateway():
    gw = _new_identity('gw', '10.0.0.7')
    boss = _new_identity('boss', '10.0.0.3')
    anchor = _new_identity('anchor', '172.20.0.11')
    primary = _group('cmd', gw, boss)
    child = _group('fld', gw, anchor)
    proc = _build_process(gw, primary, Peers())
    proc.child_groups = {str(child.uuid): child}
    proc._record_group = MagicMock()
    proc._record_child_groups = MagicMock()
    proc._update_group = MagicMock()
    return proc, primary, child, anchor


def _tagged(function, obj, child, sender):
    msg = Message(CfgIds.identity, function, obj, from_whom=sender)
    msg.child_group = str(child.uuid)
    msg.verified = True
    return msg


class TestChildUpdate:
    def test_a_larger_child_group_grows_the_child_not_the_primary(self):
        proc, primary, child, anchor = _gateway()
        joiners = [_new_identity('j%d' % i, '172.20.0.%d' % (20 + i)) for i in range(3)]
        bigger = Group(child.uuid, dict(child._address_map), child.nickname,
                       child.encryptor, _public_only=False)
        for j in joiners:
            bigger.add_address(str(j.uuid), j.address)
        proc.handle_group_update(_build_queues(), _tagged(IdentityProtocol.update, bigger,
                                                          child, anchor))
        assert proc.group is primary
        assert len(list(primary.addresses)) == 2
        held = proc.child_groups[str(child.uuid)]
        assert {j.address for j in joiners} <= set(held.addresses)
        proc._record_child_groups.assert_called()
        proc._record_group.assert_not_called()

    def test_a_foreign_group_from_the_child_cohort_changes_nothing(self):
        proc, primary, child, anchor = _gateway()
        others = [_new_identity('o%d' % i, '172.20.0.%d' % (40 + i)) for i in range(5)]
        foreign = _group('other', anchor, *others)
        proc.handle_group_update(_build_queues(), _tagged(IdentityProtocol.update, foreign,
                                                          child, anchor))
        assert proc.group is primary
        assert proc.child_groups == {str(child.uuid): child}
        assert str(foreign.uuid) not in proc.child_groups

    def test_an_untagged_update_still_reaches_the_primary(self):
        proc, primary, child, anchor = _gateway()
        boss2 = _new_identity('boss2', '10.0.0.4')
        bigger = Group(primary.uuid, dict(primary._address_map), primary.nickname,
                       primary.encryptor, _public_only=False)
        bigger.add_address(str(boss2.uuid), boss2.address)
        boss = _new_identity('boss', '10.0.0.3')   # a primary member
        msg = Message(CfgIds.identity, IdentityProtocol.update, bigger, from_whom=boss)
        msg.verified = True
        proc.handle_group_update(_build_queues(), msg)
        assert boss2.address in set(proc.group.addresses)


class TestChildConfirm:
    def test_a_child_confirmation_joins_the_child_and_the_peer_list(self):
        proc, primary, child, anchor = _gateway()
        joiner = _new_identity('joiner', '172.20.0.30')
        proc.peer_potentials = {}
        proc._provisional_confirmations = {}
        proc._admission_quorum = 1
        proc._send_caps_query = MagicMock()
        proc._history = MagicMock()
        proc.peer_capabilities = MagicMock()
        proc._record_peers = MagicMock()
        proc.freshness = MagicMock()
        proc.freshness.accept.return_value = True
        from autonomous_trust.core._python.identity.identity import public_identity_to_canonical
        body = {'peer': public_identity_to_canonical(joiner), 'seq': 1}
        import json
        msg = _tagged(IdentityProtocol.confirm, json.dumps(body), child, anchor)
        with patch('autonomous_trust.core._python.identity.idprocess.identity_hooks',
                   return_value=[]):
            qs = _build_queues()
            qs[CfgIds.main] = MagicMock()
            qs[CfgIds.negotiation] = MagicMock()
            proc.handle_confirm_peer(qs, msg)
        assert proc._history.insert_peer.call_args[0][0].uuid == joiner.uuid
        assert joiner.address in set(proc.child_groups[str(child.uuid)].addresses)
        assert joiner.address not in set(primary.addresses)
        proc._update_group.assert_not_called()


# ---- a gateway sends a group's update only to that group's members ---------

def _to_addr(message):
    who = message.to_whom
    return (who[0] if isinstance(who, list) else who).address


class TestUpdateScope:
    def test_the_primary_update_skips_the_child_cohort(self):
        """_update_group addresses every peer at the level, and a gateway's peers
        include its field cohort. The primary group, key and all, went to field
        nodes; one that had not yet joined took it, its address landed in the
        primary, and the size rule then swapped the primary for the field
        group."""
        proc, primary, child, anchor = _gateway()
        proc.peers.add(anchor, proc.peers.mid_level)
        boss_in = [a for a in primary.addresses if a != proc.identity.address][0]
        boss = _new_identity('boss', boss_in)
        proc.peers.add(boss, proc.peers.mid_level)
        sent = []
        qs = {CfgIds.network: MagicMock()}
        qs[CfgIds.network].put.side_effect = lambda m, **kw: sent.append(_to_addr(m))
        IdentityProcess._update_group(proc, qs, primary, proc.peers.mid_level)
        assert boss.address in sent
        assert anchor.address not in sent

    def test_a_leaf_node_still_updates_every_peer(self):
        proc, primary, child, anchor = _gateway()
        proc.child_groups = {}
        proc.peers.add(anchor, proc.peers.mid_level)
        sent = []
        qs = {CfgIds.network: MagicMock()}
        qs[CfgIds.network].put.side_effect = lambda m, **kw: sent.append(_to_addr(m))
        IdentityProcess._update_group(proc, qs, primary, proc.peers.mid_level)
        assert anchor.address in sent


class TestUntaggedChildFrame:
    def test_identity_places_an_untagged_sender_itself(self):
        """The network process learns the child groups from identity, so a frame
        that lands in the instant between identity adopting a child and the
        network process hearing of it arrives untagged. Identity holds the
        child groups itself and places the sender by address."""
        proc, primary, child, anchor = _gateway()
        joiners = [_new_identity('k%d' % i, '172.20.0.%d' % (60 + i)) for i in range(3)]
        bigger = Group(child.uuid, dict(child._address_map), child.nickname,
                       child.encryptor, _public_only=False)
        for j in joiners:
            bigger.add_address(str(j.uuid), j.address)
        msg = Message(CfgIds.identity, IdentityProtocol.update, bigger, from_whom=anchor)
        msg.verified = True
        assert msg.child_group is None
        proc.handle_group_update(_build_queues(), msg)
        assert proc.group is primary
        assert {j.address for j in joiners} <= set(proc.child_groups[str(child.uuid)].addresses)


class TestUnplacedSender:
    def test_a_gateway_ignores_a_group_from_a_sender_it_cannot_place(self):
        """A field joiner the gateway has not yet recorded is in neither map,
        so its update read as news about the primary, and its larger field
        group won the size rule. A gateway's primary changes only through its
        own members."""
        proc, primary, child, anchor = _gateway()
        stranger = _new_identity('sensor', '172.20.0.23')
        others = [_new_identity('o%d' % i, '172.20.0.%d' % (70 + i)) for i in range(5)]
        foreign = _group('field', stranger, *others)
        msg = Message(CfgIds.identity, IdentityProtocol.update, foreign, from_whom=stranger)
        msg.verified = True
        proc.handle_group_update(_build_queues(), msg)
        assert proc.group is primary
        assert len(list(primary.addresses)) == 2

    def test_a_leaf_node_still_merges_with_a_stranger(self):
        proc, primary, child, anchor = _gateway()
        proc.child_groups = {}
        stranger = _new_identity('sensor', '172.20.0.23')
        others = [_new_identity('o%d' % i, '172.20.0.%d' % (70 + i)) for i in range(5)]
        foreign = _group('field', stranger, *others)
        msg = Message(CfgIds.identity, IdentityProtocol.update, foreign, from_whom=stranger)
        msg.verified = True
        proc.handle_group_update(_build_queues(), msg)
        assert proc.group is not primary


# ---- one guard on every primary change ---------------------------------------
#
# Every identity path that sets or merges the primary (an update, a welcomer's
# history, partition recovery, choosing among histories) assumes one cohort per
# node. Rather than teach each one about child groups, the primary refuses any
# group that would make it span the gateway: invariant G as a postcondition.

class TestPrimaryGuard:
    def test_no_assignment_makes_the_primary_span_the_gateway(self):
        proc, primary, child, anchor = _gateway()
        spanning = _group('mixed', proc.identity, anchor,
                          _new_identity('boss', '10.0.0.3'))
        proc.group = spanning
        assert proc.group is primary
        proc.group = Group(child.uuid, dict(child._address_map), 'fld', child.encryptor,
                           _public_only=False)
        assert proc.group is primary

    def test_an_ordinary_assignment_still_takes(self):
        proc, primary, child, anchor = _gateway()
        other = _group('cmd2', proc.identity, _new_identity('boss', '10.0.0.3'))
        proc.group = other
        assert proc.group is other

    def test_a_primary_member_cannot_merge_the_field_in(self):
        """A command member whose own group already lists field members (it was
        polluted some other way) sends a larger same-uuid update."""
        proc, primary, child, anchor = _gateway()
        boss = _new_identity('boss', '10.0.0.3')
        bigger = Group(primary.uuid, dict(primary._address_map), primary.nickname,
                       primary.encryptor, _public_only=False)
        bigger.add_address(str(anchor.uuid), anchor.address)
        bigger.add_address(str(boss.uuid), boss.address)
        msg = Message(CfgIds.identity, IdentityProtocol.update, bigger, from_whom=boss)
        msg.verified = True
        msg.child_group = None
        proc.handle_group_update(_build_queues(), msg)
        assert anchor.address not in set(proc.group.addresses)

    def test_confirmation_does_not_add_a_child_member_to_the_primary(self):
        proc, primary, child, anchor = _gateway()
        proc._record_group = MagicMock()
        proc._update_group = MagicMock()
        proc._confirm_group_membership(_build_queues(), anchor)
        assert anchor.address not in set(proc.group.addresses)

    def test_a_leaf_node_is_unguarded(self):
        proc, primary, child, anchor = _gateway()
        proc.child_groups = {}
        spanning = _group('mixed', proc.identity, anchor)
        proc.group = spanning
        assert proc.group is spanning


class TestChildResync:
    def test_a_gateway_backfills_a_child_member_it_missed(self):
        """A field peer that joined before its gateway was up never reached the
        gateway's peer list (it missed the confirm broadcast), and identity
        resync, the recovery path, refused its response as not in our group
        because only the primary was consulted. Its gateway then never
        subscribed to it, and at 96 nodes the MQ-800's readings never left its
        cohort."""
        from autonomous_trust.core.config import to_json_string
        proc, primary, child, anchor = _gateway()
        late = _new_identity('mq800', '172.20.0.12')
        child.add_address(str(late.uuid), late.address)
        proc._record_peers = MagicMock()
        payload = to_json_string({'from_identity': late.publish(),
                                  'from_address': late.address})
        msg = Message(CfgIds.identity, IdentityProtocol.id_response, payload,
                      from_whom=late, encrypt=False)
        proc.handle_identity_response(_build_queues(), msg)
        assert proc.peers.find_by_uuid(late.uuid) is not None
        assert late.address not in set(primary.addresses)

    def test_a_gateway_queries_each_child_cohort_it_lacks(self):
        """A resync query names one group, and only that group's members
        answer. The gateway's query named its primary, so its field cohort
        never answered it; it also queries each child cohort missing
        identities."""
        from autonomous_trust.core.config import from_json_string
        proc, primary, child, anchor = _gateway()
        proc.peers.add(_new_identity('boss', [a for a in primary.addresses
                                              if a != proc.identity.address][0]),
                       proc.peers.mid_level)
        proc.choosing = False
        queues = _build_queues()
        proc._periodic_identity_resync(queues)
        named = [from_json_string(m.obj)['group_uuid'] for m in queues[CfgIds.network].items
                 if m.function == IdentityProtocol.id_query]
        assert str(child.uuid) in named


class TestUpdateAllowList:
    def test_the_primary_update_skips_a_peer_the_gateway_cannot_place(self):
        """A field joiner the gateway has heard of but not yet placed in a child
        map got the command group, key and all; one whose own group was smaller
        took it. On a gateway the primary's update goes to its members only."""
        proc, primary, child, anchor = _gateway()
        joiner = _new_identity('joiner', '172.20.0.40')    # in neither map
        boss = _new_identity('boss', [a for a in primary.addresses
                                      if a != proc.identity.address][0])
        proc.peers.add(joiner, proc.peers.mid_level)
        proc.peers.add(boss, proc.peers.mid_level)
        sent = []
        qs = {CfgIds.network: MagicMock()}
        qs[CfgIds.network].put.side_effect = lambda m, **kw: sent.append(_to_addr(m))
        IdentityProcess._update_group(proc, qs, primary, proc.peers.mid_level)
        assert boss.address in sent
        assert joiner.address not in sent


class TestChildResyncByUuid:
    def test_a_stranger_at_a_child_members_address_is_not_backfilled(self):
        """A response is signed by the identity it carries, which ties it to that
        uuid and nothing else; anyone can broadcast one naming a field member's
        address. Child membership is by uuid."""
        from autonomous_trust.core.config import to_json_string
        proc, primary, child, anchor = _gateway()
        proc._record_peers = MagicMock()
        stranger = _new_identity('stranger', anchor.address)
        payload = to_json_string({'from_identity': stranger.publish(),
                                  'from_address': stranger.address})
        msg = Message(CfgIds.identity, IdentityProtocol.id_response, payload,
                      from_whom=stranger, encrypt=False)
        proc.handle_identity_response(_build_queues(), msg)
        assert proc.peers.find_by_uuid(stranger.uuid) is None
