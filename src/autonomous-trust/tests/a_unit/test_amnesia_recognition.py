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
"""Who the welcoming committee readmits without a vote, and who duplicate
detection lets through to one (doc/architecture/identity-protocol.md, "Amnesia").

Readmission hands over the group key, so only a MEMBER of our group, presenting
the keys it is known by, is readmitted; its address and nickname may have
changed. A known uuid under other keys is refused. Any other peer -- a
first-contact direct peer, a provisional admission -- takes the ordinary path:
the admission gate, then the vote, where a recorded contact is not mistaken for
a sybil of itself.
"""
import threading
from queue import Queue
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.core._python.config import to_json_string
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.history.history import IdentityHistory, IdentityObj
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.core._python.identity.peers import Peers
from autonomous_trust.core._python.identity.protocol import IdentityProtocol
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.system import CfgIds


def _identity(nickname, address):
    return Identity(uuid4(), address, nickname, Signature.generate(),
                    Encryptor.generate(), _public_only=False).publish()


def _as(who, address=None, nickname=None, rekeyed=False):
    """``who`` as it presents itself again: same uuid, maybe elsewhere."""
    return Identity(who.uuid, address or who.address, nickname or who.nickname,
                    Signature.generate() if rekeyed else who.signature,
                    Encryptor.generate() if rekeyed else who.encryptor,
                    _public_only=not rekeyed).publish()


class _Guard:
    """A border guard in phase 3, with its own group, and nothing else real."""

    def __init__(self, known=(), members=()):
        me = _identity('bg', '10.0.0.1')
        node = object.__new__(IdentityProcess)
        node.logger = MagicMock()
        node.phase = 3
        node.identity = me
        node.package_hash = b''
        node.lock = threading.RLock()
        node.peers = Peers()
        node.peer_capabilities = MagicMock()
        node.peer_capabilities.get.return_value = []
        node.peer_potentials = {}
        node.border_guard_mode = True
        node.group = Group(uuid4(), {me.uuid: me.address}, 'grp',
                           Encryptor.generate(), False)
        node._record_peers = MagicMock()
        node._record_group = MagicMock()
        node._update_group = MagicMock()
        node._peer_accepted = MagicMock()
        node._admission_gate = MagicMock(return_value='admit')
        node._spawn = MagicMock()
        node._package_hash_admissible = MagicMock(return_value=(True, ''))
        node.extensions = ()
        for who in known:
            node.peers.add(who)
        for who in members:
            node.group.add_address(str(who.uuid), who.address)
        self.node = node
        self.network = Queue()
        self.queues = {CfgIds.network: self.network}

    def ask(self, who):
        msg = MagicMock()
        msg.function = IdentityProtocol.announce
        msg.from_whom = who
        msg.obj = to_json_string((b'', []))
        return self.node.welcoming_committee(self.queues, msg)

    def readmitted(self):
        return [c for c in self.node._peer_accepted.call_args_list
                if c.kwargs.get('amnesia')]

    def proposed(self):
        sent = []
        while not self.network.empty():
            sent.append(self.network.get_nowait().function)
        return sent.count(IdentityProtocol.propose)


def test_a_member_with_its_keys_is_readmitted_without_a_vote():
    member = _identity('m', '10.0.0.2')
    bg = _Guard(known=[member], members=[member])
    assert bg.ask(_as(member)) is True
    assert len(bg.readmitted()) == 1
    assert bg.proposed() == 0


def test_a_peer_that_is_not_a_member_goes_to_the_vote():
    contact = _identity('c', '10.0.0.3')
    bg = _Guard(known=[contact])
    assert bg.ask(_as(contact)) is True
    assert bg.readmitted() == []
    bg.node._admission_gate.assert_called_once()
    assert bg.proposed() == 1


def test_the_admission_gate_still_decides_for_a_non_member_peer():
    contact = _identity('c', '10.0.0.3')
    bg = _Guard(known=[contact])
    bg.node._admission_gate.return_value = 'reject'
    bg.ask(_as(contact))
    assert bg.readmitted() == []
    assert bg.proposed() == 0


def test_a_members_uuid_under_new_keys_is_refused():
    member = _identity('m', '10.0.0.2')
    bg = _Guard(known=[member], members=[member])
    assert bg.ask(_as(member, rekeyed=True)) is True
    assert bg.readmitted() == []
    assert bg.proposed() == 0
    bg.node._admission_gate.assert_not_called()
    assert 'different keys' in bg.node.logger.warning.call_args.args[0]


def test_a_non_members_uuid_under_new_keys_is_refused_not_voted():
    # Sent to the vote, it would rest on every voter's duplicate check, and a
    # guard alone in its group admits on its own vote.
    contact = _identity('c', '10.0.0.3')
    bg = _Guard(known=[contact])
    bg.ask(_as(contact, rekeyed=True))
    assert bg.proposed() == 0
    bg.node._admission_gate.assert_not_called()


def test_a_member_that_moved_is_readmitted_and_readdressed():
    member = _identity('m', '10.0.0.2')
    bg = _Guard(known=[member], members=[member])
    bg.ask(_as(member, address='10.0.77.9', nickname='m2'))
    assert len(bg.readmitted()) == 1
    assert bg.node.group._address_map[str(member.uuid)] == '10.0.77.9'
    assert bg.node.peers.find_by_uuid(member.uuid).address == '10.0.77.9'
    assert bg.node.peers.find_by_address('10.0.0.2') is None
    assert [p.nickname for p in bg.node.peers.all] == ['m2']
    bg.node._update_group.assert_called_once()


def test_a_stranger_is_unaffected():
    bg = _Guard()
    bg.ask(_identity('s', '10.0.0.4'))
    assert bg.readmitted() == []
    assert bg.proposed() == 1


# -- duplicate detection: a recorded contact is not a sybil of itself --------

def _voter(candidate, contact, member=False):
    bg = _Guard(known=[candidate], members=[candidate] if member else [])
    bg.node._history = MagicMock()
    bg.node._history.prove.return_value = 'proof'
    bg.node.identity = Identity(uuid4(), '10.0.0.1', 'bg', Signature.generate(),
                                Encryptor.generate(), _public_only=False)
    bg.node.confirmed_block = []
    bg.node._is_contact = MagicMock(return_value=contact)
    return bg.node


def test_a_recorded_contact_with_its_keys_is_voted_on():
    who = _identity('c', '10.0.0.3')
    node = _voter(who, contact=True)
    assert node._process_id(IdentityObj(_as(who), who.uuid)) is not None


def test_a_peer_that_is_not_a_recorded_contact_still_collides():
    who = _identity('c', '10.0.0.3')
    node = _voter(who, contact=False)
    assert node._process_id(IdentityObj(_as(who), who.uuid)) is None


def test_a_recorded_contact_under_new_keys_still_collides():
    who = _identity('c', '10.0.0.3')
    node = _voter(who, contact=True)
    assert node._process_id(IdentityObj(_as(who, rekeyed=True), who.uuid)) is None


def test_a_contact_that_is_already_a_member_still_collides():
    who = _identity('c', '10.0.0.3')
    node = _voter(who, contact=True, member=True)
    assert node._process_id(IdentityObj(_as(who), who.uuid)) is None


def test_the_exemption_does_not_cover_another_peers_keys():
    # A contact's exemption is for its own record: a candidate reusing ANOTHER
    # peer's signing key still collides with that peer.
    who = _identity('c', '10.0.0.3')
    other = _identity('o', '10.0.0.5')
    node = _voter(who, contact=True)
    node.peers.add(other)
    thief = Identity(who.uuid, who.address, who.nickname, other.signature,
                     who.encryptor, _public_only=True)
    assert node._process_id(IdentityObj(thief, who.uuid)) is None


# -- history: a promoted contact is recorded although Peers holds it ----------

def test_a_promoted_peer_is_recorded_in_history():
    me = Identity(uuid4(), '10.0.0.1', 'me', Signature.generate(),
                  Encryptor.generate(), _public_only=False)
    contact = _identity('c', '10.0.0.3')
    peers = Peers()
    peers.add(contact)
    history = IdentityHistory(me, peers, Queue())
    history.insert_peer(contact)
    assert contact not in history       # what used to happen to a contact
    history.insert_peer(contact, promoted=True)
    assert contact in history
