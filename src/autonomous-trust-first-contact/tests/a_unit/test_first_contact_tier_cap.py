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
"""FIRST_CONTACT_PLAN §10.3, enforced: an unverified contact may message, and
higher-trust actions wait for verification.

``first_contact.capped_tier`` holds an unverified contact at tier 1
(communication) when it asks negotiation to run a capability -- including one
that is also a child-group member; only own-group members are exempt. Also: a direct peer is asked for
its capabilities the moment it is admitted.
"""
import queue
import types
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.first_contact import Contact, Contacts
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.core.negotiation.negotiation import Task, TaskParameters
from autonomous_trust.core.negotiation.negprocess import NegotiationProcess
from autonomous_trust.core.negotiation.protocol import NegotiationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds


def _make_neg_process():
    """A negotiation process over mocked peers (as the core's
    test_negprocess._make_neg_process): every sender unknown (tier 0) unless a
    test sets a record."""
    mock_net_proc = MagicMock()
    mock_net_proc.name = CfgIds.network
    mock_id_proc = MagicMock()
    mock_id_proc.name = CfgIds.identity
    mock_neg_proc = MagicMock()
    mock_neg_proc.name = CfgIds.negotiation
    configs = {
        'processes': [mock_net_proc, mock_id_proc, mock_neg_proc],
        CfgIds.identity: MagicMock(),
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    np = NegotiationProcess(configs, ProcessTracker(), queue.Queue(), suppress_log=True)
    np.protocol.peers.find_by_uuid = MagicMock(return_value=None)
    return np


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    fc._verified_cache.clear()


@pytest.fixture
def bob():
    return Identity.initialize('bob@ex', 'bob@ex', '10.0.0.2')


def _proc(members=(), child_members=()):
    grp = types.SimpleNamespace(_address_map={str(u): 'x' for u in members})
    child = types.SimpleNamespace(_address_map={str(u): 'y' for u in child_members})
    return types.SimpleNamespace(group=grp, child_groups={'c1': child})


def _record(who, verified):
    store = Contacts.load()
    c = Contact(who.publish())
    if verified:
        c.mark_verified()
    store.add(c)
    store.save()


# -- the rule ----------------------------------------------------------------
def test_an_unverified_contact_is_held_at_communication(bob):
    _record(bob, verified=False)
    assert fc.capped_tier(_proc(), bob.uuid, 4) == fc.UNVERIFIED_TIER_CAP == 1


def test_a_missing_record_does_not_lift_the_cap(bob):
    """No store at all, or a store without this peer: still capped."""
    assert fc.capped_tier(_proc(), bob.uuid, 3) == 1
    _record(Identity.initialize('carol@ex', 'carol@ex', '10.0.0.3'), verified=True)
    assert fc.capped_tier(_proc(), bob.uuid, 3) == 1


def test_a_verified_contact_uses_what_it_earned(bob):
    _record(bob, verified=True)
    assert fc.capped_tier(_proc(), bob.uuid, 4) == 4


@pytest.mark.parametrize('recorded', [None, False, True])
def test_an_own_group_member_is_never_capped(bob, recorded):
    if recorded is not None:
        _record(bob, verified=recorded)
    assert fc.capped_tier(_proc(members=[bob.uuid]), bob.uuid, 4) == 4


def test_a_child_group_member_with_no_contact_record_is_not_capped(bob):
    """An ordinary child member never went through first contact."""
    assert fc.capped_tier(_proc(child_members=[bob.uuid]), bob.uuid, 4) == 4


def test_a_child_group_member_who_is_an_unverified_contact_is_capped(bob):
    """The child's vote does not vouch for what first contact introduced."""
    _record(bob, verified=False)
    assert fc.capped_tier(_proc(child_members=[bob.uuid]), bob.uuid, 4) == 1


def test_a_child_group_member_who_is_a_verified_contact_is_not_capped(bob):
    _record(bob, verified=True)
    assert fc.capped_tier(_proc(child_members=[bob.uuid]), bob.uuid, 4) == 4


def test_a_low_tier_is_left_alone(bob):
    assert fc.capped_tier(_proc(), bob.uuid, 0) == 0
    assert fc.capped_tier(_proc(), bob.uuid, 1) == 1


def test_no_cap_while_first_contact_is_off(bob, monkeypatch):
    monkeypatch.delenv('AT_FIRST_CONTACT')
    assert fc.capped_tier(_proc(), bob.uuid, 4) == 4


def test_verifying_later_lifts_the_cap_on_the_next_ask(bob):
    """The store is re-read when it changes, not once per process."""
    _record(bob, verified=False)
    assert fc.capped_tier(_proc(), bob.uuid, 3) == 1
    store = Contacts.load()
    store.get(str(bob.uuid)).mark_verified()
    import os
    import time
    time.sleep(0.01)
    store.save()
    os.utime(Contacts.default_path())     # a distinct mtime on coarse clocks
    assert fc.capped_tier(_proc(), bob.uuid, 3) == 3


# -- where it bites: negotiation's acceptance gate ---------------------------
_seq = iter(range(1, 1_000_000))


def _invite(np, sender_uuid, sender_tier, required_tier):
    """One invitation from ``sender_uuid`` (earned ``sender_tier``) for a
    capability this node registered at ``required_tier``; returns the verb of
    the reply. The capability is REALLY registered: ``Capabilities`` is a real
    object, so patching ``__contains__`` on the instance would do nothing and
    every invite would be refused as "not capable" instead of by the gate."""
    peer = MagicMock()
    peer.uuid = sender_uuid
    peer.nickname, peer.address = 'bob@ex', '10.0.0.2'
    record = MagicMock()
    record._tier = sender_tier
    np.protocol.peers.find_by_uuid = MagicMock(return_value=record)
    np.protocol.capabilities.register_ability('files', None,
                                              required_tier=required_tier)
    task = Task(TaskParameters(np.protocol.capabilities['files'],
                               when=datetime(2020, 1, 1, tzinfo=UTC)), peer)
    task.seq = next(_seq)       # fresh, or the freshness guard drops a repeat
    task.to_json_string = MagicMock(return_value='{}')
    task.parameters.acceptable = MagicMock(return_value=True)
    net_q = queue.Queue()
    np.handle_invite({CfgIds.network: net_q},
                     Message(CfgIds.negotiation, NegotiationProtocol.announce,
                             task, from_whom=peer))
    return net_q.get_nowait().function


def test_negotiation_refuses_services_to_an_unverified_contact(bob):
    np = _make_neg_process()
    np.protocol.group = types.SimpleNamespace(_address_map={})
    _record(bob, verified=False)
    # Earned tier 3, but a tier-2 capability is refused until verified...
    assert _invite(np, bob.uuid, 3, 2) == NegotiationProtocol.refusal
    # ...while a tier-1 (communication) capability is served.
    assert _invite(np, bob.uuid, 3, 1) == NegotiationProtocol.acceptance


def test_negotiation_serves_a_verified_contact_what_it_earned(bob):
    np = _make_neg_process()
    np.protocol.group = types.SimpleNamespace(_address_map={})
    _record(bob, verified=True)
    assert _invite(np, bob.uuid, 3, 2) == NegotiationProtocol.acceptance


def test_negotiation_serves_a_group_member_what_it_earned(bob):
    np = _make_neg_process()
    np.protocol.group = types.SimpleNamespace(_address_map={str(bob.uuid): 'x'})
    assert _invite(np, bob.uuid, 3, 2) == NegotiationProtocol.acceptance


# -- capabilities on admission ------------------------------------------------
def test_a_direct_peer_is_asked_for_its_capabilities_on_admission(bob):
    asked = []
    proc = types.SimpleNamespace(
        peers=Peers(), _record_peers=lambda q: None,
        _send_caps_query=lambda q, who: asked.append(who))
    assert fc._admit_direct_peer(proc, {}, bob.publish()) is True
    assert [str(w.uuid) for w in asked] == [str(bob.uuid)]
    # Re-admitting the same identity is idempotent and asks nothing more.
    fc._admit_direct_peer(proc, {}, proc.peers.find_by_uuid(bob.uuid))
    assert len(asked) == 1
