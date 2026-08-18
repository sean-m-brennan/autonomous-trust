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
"""Runtime hierarchy roots — identity protocol step 7 (doc/architecture/gateway-reputation-tree.md).

The gateway hierarchy used to exist only in seeded config: `parent_gateway` was
initialized and never assigned, and a second group could not arrive at runtime
at all (the different-uuid path treats it as a partition to converge). These
cover the two halves of the fix:

  * **derive** — our OWN parent is our own conclusion, taken from rank among
    members that can prove a shared trust anchor, and never accepted from a
    peer that claims to be it;
  * **advertise** — every node states its own position on the encrypted group
    channel, so the mesh agrees on the topology instead of each node inferring
    it privately; a peer's claim is recorded only when that peer is authorized,
    and it outranks rank-inference when picking a recursion target.

Deliberately absent, and asserted so: nothing here moves a group key. Acquiring
a second cohort's key at runtime is a separate question, because the group key
is the confidentiality boundary.
"""
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.group import Group
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import from_json_string, to_json_string

_MOCK_ADDRESSES = {'mac_bcast': 'ff:ff:ff:ff:ff:ff'}


def _new_identity(name, address):
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


def _group(uuid, members):
    """A stand-in group for the pure-derivation tests, which only read
    `_address_map`. The SEND paths need a real Group (Message validates
    to_whom), so those use `_real_group`."""
    return SimpleNamespace(uuid=uuid, _address_map=dict(members),
                           addresses=list(members.values()),
                           nickname='grp-%s' % uuid)


def _real_group(members):
    """A real Group, required wherever a Message is actually constructed."""
    return Group.initialize(dict(members), 'hier-test')


class _Peers:
    """Peer table exposing just the rank read _member_rank performs."""

    def __init__(self, ranks):
        self._ranks = ranks

    def find_by_uuid(self, uuid):
        rank = self._ranks.get(str(uuid))
        if rank is None:
            return None
        return SimpleNamespace(effective_rank=rank, _rank=rank)


def _node(uuid='me', primary=None, child_groups=None, child_gateways=None,
          ranks=None, own_rank=0, authorized=True, identity=None):
    proc = IdentityProcess.__new__(IdentityProcess)
    proc.identity = identity if identity is not None else SimpleNamespace(
        uuid=uuid, address='addr-%s' % uuid, nickname='node-%s' % uuid,
        effective_rank=own_rank, _rank=own_rank)
    proc.group = primary
    proc.child_groups = child_groups or {}
    proc.child_gateways = child_gateways or {}
    proc.peer_hierarchy = {}
    proc._last_hierarchy_claim = None
    proc._hierarchy_requested = False
    proc.parent_gateway = None
    proc.roster_private = False
    proc.peers = _Peers(ranks or {})
    proc.name = CfgIds.identity
    proc.q_cadence = 0.01
    proc.logger = MagicMock()
    proc.report_exception = MagicMock()
    # Gateway authority is doc/architecture/zta-integration.md's proved-shared-anchor gate; the tests that
    # care about it override this.
    proc._gateway_authorized = (lambda u: True) if authorized is True else authorized
    return proc


# --- derive: our own parent -------------------------------------------------

class TestDeriveParent:
    def test_highest_ranked_superior_is_the_parent(self):
        node = _node(primary=_group('g0', {'me': 'a0', 'mid': 'a1', 'top': 'a2'}),
                     ranks={'mid': 2, 'top': 5}, own_rank=1)
        assert node._derive_parent_gateway() == 'top'

    def test_a_node_that_tops_its_cohort_has_no_parent(self):
        """The highest-rank member of a cohort is nobody's child. This is the
        one place the rule differs from _discover_child_gateway: there we pick
        somebody else's leader, here we ask who leads US."""
        node = _node(primary=_group('g0', {'me': 'a0', 'low': 'a1'}),
                     ranks={'low': 1}, own_rank=9)
        assert node._derive_parent_gateway() is None

    def test_equal_rank_is_not_a_parent(self):
        node = _node(primary=_group('g0', {'me': 'a0', 'peer': 'a1'}),
                     ranks={'peer': 3}, own_rank=3)
        assert node._derive_parent_gateway() is None

    def test_ties_break_deterministically_by_uuid(self):
        node = _node(primary=_group('g0', {'me': 'a0', 'aaa': 'a1', 'zzz': 'a2'}),
                     ranks={'aaa': 4, 'zzz': 4}, own_rank=1)
        # Greater uuid wins, matching _discover_child_gateway so C agrees.
        assert node._derive_parent_gateway() == 'zzz'

    def test_unauthorized_candidate_is_passed_over(self):
        """See doc/architecture/zta-integration.md's rule applied upward: a peer holding only a foreign agency's
        credential is never federated through, even at higher rank."""
        node = _node(primary=_group('g0', {'me': 'a0', 'foreign': 'a1',
                                           'ours': 'a2'}),
                     ranks={'foreign': 9, 'ours': 2}, own_rank=1,
                     authorized=lambda u: u != 'foreign')
        assert node._derive_parent_gateway() == 'ours'

    def test_no_group_no_parent(self):
        assert _node(primary=None)._derive_parent_gateway() is None


# --- advertise -------------------------------------------------------------

class TestAdvertise:
    def _queues(self):
        return {CfgIds.network: queue.Queue()}

    def test_claim_shape_is_about_ourselves_only(self):
        node = _node(primary=_group('g0', {'me': 'a0'}),
                     child_groups={'c1': _group('c1', {})}, own_rank=4)
        node.parent_gateway = 'top'
        claim = node._hierarchy_claim()
        assert claim == {'node': 'me', 'parent': 'top', 'children': ['c1'],
                         'rank': 4}
        # No key material, and nothing about anybody else's position.
        assert 'key' not in claim and 'encryptor' not in claim

    def test_advertises_on_change_and_stays_quiet_otherwise(self):
        """Re-broadcasting an unchanged claim tells nobody anything, and echoing
        is how a topology broadcast becomes a flood (the equal-size
        group_update storm is the standing lesson)."""
        me = _new_identity('me', '10.0.0.1')
        node = _node(primary=_real_group({str(me.uuid): 'a0'}), identity=me)
        queues = self._queues()
        node._advertise_hierarchy(queues)
        assert queues[CfgIds.network].qsize() == 1
        node._advertise_hierarchy(queues)
        assert queues[CfgIds.network].qsize() == 1     # unchanged -> silent
        node.child_groups = {'c9': _group('c9', {})}
        node._advertise_hierarchy(queues)
        assert queues[CfgIds.network].qsize() == 2     # changed -> stated
        # The send path must not be failing silently: _advertise_hierarchy
        # swallows exceptions by design, so assert nothing was warned.
        node.logger.warning.assert_not_called()

    def test_advertisement_is_encrypted_group_traffic(self):
        me = _new_identity('me', '10.0.0.1')
        node = _node(primary=_real_group({str(me.uuid): 'a0'}), identity=me)
        queues = self._queues()
        node._advertise_hierarchy(queues)
        msg = queues[CfgIds.network].get_nowait()
        assert msg.function == IdentityProtocol.hierarchy
        # Not in the plaintext allowlist: the topology rides the group channel.
        from autonomous_trust.core.identity.protocol import UNENCRYPTED_VERBS
        assert IdentityProtocol.hierarchy not in UNENCRYPTED_VERBS
        assert IdentityProtocol.hierarchy_req not in UNENCRYPTED_VERBS

    def test_refresh_records_derived_parent_then_advertises(self):
        me = _new_identity('me', '10.0.0.1')
        node = _node(primary=_real_group({str(me.uuid): 'a0', 'top': 'a1'}),
                     ranks={'top': 7}, identity=me)
        queues = self._queues()
        node._refresh_hierarchy(queues)
        assert node.parent_gateway == 'top'
        claim = from_json_string(queues[CfgIds.network].get_nowait().obj)
        assert claim['parent'] == 'top'

    def test_query_is_one_shot(self):
        me = _new_identity('me', '10.0.0.1')
        node = _node(primary=_real_group({str(me.uuid): 'a0'}), identity=me)
        queues = self._queues()
        node._request_hierarchy(queues)
        node._request_hierarchy(queues)
        assert queues[CfgIds.network].qsize() == 1
        assert queues[CfgIds.network].get_nowait().function == \
            IdentityProtocol.hierarchy_req


# --- receive ---------------------------------------------------------------

class TestReceive:
    def _claim_msg(self, sender, payload, verified=True):
        msg = Message(CfgIds.identity, IdentityProtocol.hierarchy,
                      to_json_string(payload), from_whom=sender)
        msg.verified = verified
        return msg

    def _node_pair(self):
        me = _new_identity('me', '10.0.0.1')
        them = _new_identity('them', '10.0.0.2')
        node = _node(primary=_real_group({str(me.uuid): 'a0',
                                          str(them.uuid): 'a1'}),
                     identity=me)
        return node, them

    def test_authorized_claim_is_recorded(self):
        node, them = self._node_pair()
        msg = self._claim_msg(them, {'node': str(them.uuid), 'parent': '',
                                     'children': ['c1', 'c2'], 'rank': 3})
        assert node.handle_hierarchy({}, msg) is True
        rec = node.peer_hierarchy[str(them.uuid)]
        assert rec['children'] == ['c1', 'c2'] and rec['rank'] == 3
        assert rec['parent'] is None

    def test_unauthorized_claim_is_dropped(self):
        """The recorded value is what a roster query recurses into, so a peer
        that could install itself there would receive queries for a cohort it
        has no standing in."""
        node, them = self._node_pair()
        node._gateway_authorized = lambda u: False
        msg = self._claim_msg(them, {'node': str(them.uuid),
                                     'children': ['c1'], 'rank': 3})
        assert node.handle_hierarchy({}, msg) is True
        assert node.peer_hierarchy == {}

    def test_unverified_claim_is_dropped(self):
        node, them = self._node_pair()
        msg = self._claim_msg(them, {'node': str(them.uuid),
                                     'children': ['c1']}, verified=False)
        assert node.handle_hierarchy({}, msg) is True
        assert node.peer_hierarchy == {}

    def test_claim_naming_someone_else_is_refused(self):
        """A claim is about its sender. The two disagreeing is either a bug or
        an attempt, and neither should quietly become a recorded fact."""
        node, them = self._node_pair()
        msg = self._claim_msg(them, {'node': 'somebody-else',
                                     'children': ['c1']})
        assert node.handle_hierarchy({}, msg) is True
        assert node.peer_hierarchy == {}

    def test_a_peer_cannot_make_itself_our_parent(self):
        """Our parent is derived. A peer asserting it leads us changes nothing —
        otherwise any node could insert itself into every rollup we perform."""
        node, them = self._node_pair()
        node.parent_gateway = None
        msg = self._claim_msg(them, {'node': str(them.uuid), 'parent': '',
                                     'children': [str(node.group.uuid)],
                                     'rank': 99})
        node.handle_hierarchy({}, msg)
        assert node.parent_gateway is None
        # ...and it is still None after a refresh, because the peer's RANK in
        # our own peer table is what decides, not its claim.
        node._refresh_hierarchy({CfgIds.network: queue.Queue()})
        assert node.parent_gateway is None

    def test_malformed_payload_is_survivable(self):
        node, them = self._node_pair()
        msg = Message(CfgIds.identity, IdentityProtocol.hierarchy,
                      'not json at all', from_whom=them)
        msg.verified = True
        assert node.handle_hierarchy({}, msg) is True
        assert node.peer_hierarchy == {}

    def test_query_is_answered_to_the_asker(self):
        node, them = self._node_pair()
        req = Message(CfgIds.identity, IdentityProtocol.hierarchy_req,
                      to_json_string({'requestor': str(them.uuid)}),
                      from_whom=them)
        req.verified = True
        queues = {CfgIds.network: queue.Queue()}
        assert node.handle_hierarchy_request(queues, req) is True
        reply = queues[CfgIds.network].get_nowait()
        assert reply.function == IdentityProtocol.hierarchy
        # Message normalizes to_whom to a list of recipients.
        assert them in (reply.to_whom if isinstance(reply.to_whom, list)
                        else [reply.to_whom])
        # An answer does not consume the change-suppression budget: the next
        # genuine change still broadcasts.
        assert node._last_hierarchy_claim is None


# --- what the advertisement is FOR -----------------------------------------

class TestRecursionTargetPrecedence:
    def test_advertisement_beats_rank_inference(self):
        """Direct evidence over a guess: "I gateway cohort X" outranks "it is
        the highest-rank member of X"."""
        child = _group('c1', {'low': 'a1', 'high': 'a2'})
        node = _node(primary=_group('g0', {'me': 'a0'}),
                     child_groups={'c1': child},
                     ranks={'low': 1, 'high': 9})
        assert node._child_gateway_uuids() == ['high']      # rank inference
        node.peer_hierarchy['low'] = {'parent': None, 'children': ['c1'],
                                      'rank': 1}
        assert node._child_gateway_uuids() == ['low']        # its own claim

    def test_explicit_config_still_wins(self):
        child = _group('c1', {'low': 'a1', 'high': 'a2'})
        node = _node(primary=_group('g0', {'me': 'a0'}),
                     child_groups={'c1': child},
                     child_gateways={'c1': 'pinned'},
                     ranks={'low': 1, 'high': 9})
        node.peer_hierarchy['low'] = {'parent': None, 'children': ['c1'],
                                      'rank': 1}
        assert node._child_gateway_uuids() == ['pinned']

    def test_two_claimants_break_by_rank_then_uuid(self):
        child = _group('c1', {'aaa': 'a1', 'zzz': 'a2'})
        node = _node(primary=_group('g0', {'me': 'a0'}),
                     child_groups={'c1': child}, ranks={'aaa': 4, 'zzz': 4})
        for u in ('aaa', 'zzz'):
            node.peer_hierarchy[u] = {'parent': None, 'children': ['c1'],
                                      'rank': 4}
        assert node._child_gateway_uuids() == ['zzz']

    def test_claim_for_a_cohort_we_do_not_gateway_is_inert(self):
        node = _node(primary=_group('g0', {'me': 'a0'}))
        node.peer_hierarchy['other'] = {'parent': None,
                                        'children': ['not-ours'], 'rank': 5}
        assert node._child_gateway_uuids() == []
