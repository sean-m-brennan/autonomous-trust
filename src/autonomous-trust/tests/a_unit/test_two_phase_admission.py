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
"""Two-phase (provisional -> confirmed) admission — doc/architecture/identity-protocol.md.

A member receiving a `confirm` broadcast holds the peer PROVISIONAL (known in
self.peers/history but the group key is withheld) until `_admission_quorum`
DISTINCT confirmers have corroborated, then promotes to CONFIRMED (propagates
the group key). Quorum 1 (default) reproduces the historical single-welcomer
behavior; quorum >1 exercises the two-phase path. These tests drive
handle_confirm_peer directly and assert which admission stage runs.
"""
import logging
import tempfile
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.identity import public_identity_to_canonical
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core._python.freshness import Freshness

_MOCK_ADDRESSES = {
    'ip4': '192.168.1.1', 'ip6': '::1', 'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}


def _new_identity(name, address):
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


def _build_process(identity, group, quorum=1):
    proc = object.__new__(IdentityProcess)
    proc.identity = identity
    proc.group = group
    proc.peers = Peers()
    proc.name = CfgIds.identity
    proc.logger = logging.getLogger('test.idproc.twophase')
    proc.q_cadence = 0.01
    proc.phase = 3
    proc.peer_potentials = {}
    proc._provisional_confirmations = {}
    proc._admission_quorum = quorum
    proc.lock = MagicMock()
    proc.lock.__enter__ = MagicMock(return_value=proc.lock)
    proc.lock.__exit__ = MagicMock(return_value=False)
    # Isolate the state machine: stub the peer-add / group-propagation halves
    # and the caps-query recovery. _add_peer records the peer in self.peers so
    # the "first_add" branch flips exactly as production does.
    proc._confirm_group_membership = MagicMock()
    proc._send_caps_query = MagicMock()

    def _fake_add_peer(queues, ident, amnesia=False, confirmed=True):
        proc.peers.add(ident)
        if confirmed:
            proc._confirm_group_membership(queues, ident)
    proc._add_peer = MagicMock(side_effect=_fake_add_peer)
    # Freshness state in a per-test temp dir: a confirm carries the confirmer's
    # monotonic sequence and the receiver keeps a per-(sender, verb) high-water
    # mark, so the handler cannot run without it.
    tmp = tempfile.mkdtemp(prefix='at-freshness-')
    with patch.object(Configuration, 'get_cfg_dir', staticmethod(lambda: tmp)):
        proc.freshness = Freshness(CfgIds.identity, proc.logger)
    return proc


_CONFIRM_SEQ = [0]


def _confirm_msg(peer, confirmer, seq=None):
    """A confirm envelope: the canonical identity plus the confirmer's
    freshness sequence.

    Sequences advance by default so successive confirms in one test are
    distinct rounds; pass an explicit ``seq`` to replay a round.
    """
    if seq is None:
        _CONFIRM_SEQ[0] += 1
        seq = _CONFIRM_SEQ[0]
    msg = MagicMock()
    msg.function = IdentityProtocol.confirm
    msg.obj = {'peer': public_identity_to_canonical(peer), 'seq': seq}
    msg.from_whom = confirmer
    return msg


class TestTwoPhaseAdmission:
    def _setup(self, quorum):
        me = _new_identity('member', '10.0.0.1')
        grp = Group.initialize({str(me.uuid): me.address}, 'member-grp')
        proc = _build_process(me, grp, quorum=quorum)
        peer = _new_identity('newcomer', '10.0.0.9')
        return proc, peer

    def test_quorum_one_promotes_on_first_confirm(self):
        """Default quorum: the first confirm confirms group membership."""
        proc, peer = self._setup(quorum=1)
        bg = _new_identity('bg', '10.0.0.2')
        proc.handle_confirm_peer({CfgIds.network: MagicMock()}, _confirm_msg(peer, bg))
        assert proc._confirm_group_membership.called
        assert proc.peers.find_by_uuid(peer.uuid) is not None
        assert str(peer.uuid) not in proc._provisional_confirmations

    def test_quorum_two_holds_provisional_then_confirms(self):
        proc, peer = self._setup(quorum=2)
        bg1 = _new_identity('bg1', '10.0.0.2')
        bg2 = _new_identity('bg2', '10.0.0.3')

        # First confirm: PROVISIONAL — peer known, group key withheld.
        proc.handle_confirm_peer({CfgIds.network: MagicMock()}, _confirm_msg(peer, bg1))
        assert proc.peers.find_by_uuid(peer.uuid) is not None
        assert not proc._confirm_group_membership.called
        assert len(proc._provisional_confirmations[str(peer.uuid)]) == 1

        # Second DISTINCT confirmer: CONFIRMED — group key propagated.
        proc.handle_confirm_peer({CfgIds.network: MagicMock()}, _confirm_msg(peer, bg2))
        assert proc._confirm_group_membership.called
        assert str(peer.uuid) not in proc._provisional_confirmations

    def test_duplicate_confirmer_does_not_reach_quorum(self):
        """Two confirms from the SAME border-guard stay provisional."""
        proc, peer = self._setup(quorum=2)
        bg1 = _new_identity('bg1', '10.0.0.2')

        proc.handle_confirm_peer({CfgIds.network: MagicMock()}, _confirm_msg(peer, bg1))
        proc.handle_confirm_peer({CfgIds.network: MagicMock()}, _confirm_msg(peer, bg1))
        assert not proc._confirm_group_membership.called
        assert len(proc._provisional_confirmations[str(peer.uuid)]) == 1

    def test_replayed_confirm_does_not_readmit_a_removed_peer(self):
        """A confirm is good once.

        This verb re-admits a peer and, at quorum, reissues the CURRENT group
        key to it (_confirm_group_membership). Unstamped, it was replayable:
        capture one confirm off the group channel and a peer that had since
        been removed could be put back, with a live key.
        """
        proc, peer = self._setup(quorum=1)
        confirmer = _new_identity('bg', '10.0.0.2')
        queues = {}
        msg = _confirm_msg(peer, confirmer, seq=5)
        proc.handle_confirm_peer(queues, msg)
        assert proc.peers.find_by_uuid(peer.uuid) is not None
        assert proc._confirm_group_membership.call_count == 1

        # The SAME confirm is presented again. Asserted on the handler's
        # actions rather than on peer-set contents: _add_peer is the
        # re-admission and _confirm_group_membership is the key reissue, and
        # neither may fire a second time.
        proc._add_peer.reset_mock()
        proc.handle_confirm_peer(queues, msg)
        assert proc._add_peer.call_count == 0
        assert proc._confirm_group_membership.call_count == 1

    def test_unstamped_confirm_refused(self):
        """No lenient path for a confirm with no sequence."""
        proc, peer = self._setup(quorum=1)
        confirmer = _new_identity('bg', '10.0.0.2')
        msg = MagicMock()
        msg.function = IdentityProtocol.confirm
        msg.obj = {'peer': public_identity_to_canonical(peer)}  # no 'seq'
        msg.from_whom = confirmer
        proc.handle_confirm_peer({}, msg)
        assert proc.peers.find_by_uuid(peer.uuid) is None
        assert proc._add_peer.call_count == 0

    def test_later_confirm_from_same_confirmer_still_admits(self):
        """The guard bounds replay, not legitimate later admissions."""
        proc, first = self._setup(quorum=1)
        second = _new_identity('newcomer-2', '10.0.0.10')
        confirmer = _new_identity('bg', '10.0.0.2')
        proc.handle_confirm_peer({}, _confirm_msg(first, confirmer, seq=1))
        proc.handle_confirm_peer({}, _confirm_msg(second, confirmer, seq=2))
        assert proc.peers.find_by_uuid(first.uuid) is not None
        assert proc.peers.find_by_uuid(second.uuid) is not None
