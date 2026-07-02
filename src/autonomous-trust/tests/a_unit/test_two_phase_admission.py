# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Two-phase (provisional -> confirmed) admission — ISSUES.md §3.1-a.

A member receiving a `confirm` broadcast holds the peer PROVISIONAL (known in
self.peers/history but the group key is withheld) until `_admission_quorum`
DISTINCT confirmers have corroborated, then promotes to CONFIRMED (propagates
the group key). Quorum 1 (default) reproduces the historical single-welcomer
behavior; quorum >1 exercises the two-phase path. These tests drive
handle_confirm_peer directly and assert which admission stage runs.
"""
import logging
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.identity import public_identity_to_canonical
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds

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
    return proc


def _confirm_msg(peer, confirmer):
    msg = MagicMock()
    msg.function = IdentityProtocol.confirm
    msg.obj = public_identity_to_canonical(peer)  # dict -> from_canonical path
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
