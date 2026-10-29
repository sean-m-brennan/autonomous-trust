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
"""The join selection, pinned (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 1, D10).

choose_group takes the group this node persisted if a history offers it,
otherwise the longest history (first arrival on a tie), and a history with no
steps is eligible when nothing longer is offered (the user's call,
2026-10-23). Peers are unioned across every history. With none usable it
restores group.cfg.json before minting. C does the same (group_adopt_test.c,
group_file_test.c); C_FILE below was written by C's group_file_write and is
read here through the same restore path.
"""
import json
import os

import pytest

from autonomous_trust.core.identity import Group, Identity
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_bridged_group import _node, _peer, _queues, _sent
from types import SimpleNamespace
from unittest.mock import MagicMock

from autonomous_trust.core._python.identity.history import IdentityByAuthority


# Written by C (group_file_write): Python's schema, read back by Python.
C_FILE = (
    '[{"__type__":"autonomous_trust.core._python.identity.group.Group",'
    '"_uuid":"c74d6b0d-8cb5-4c13-87ab-9785a39d19fb","_address_map":'
    '{"22222222-2222-4222-8222-222222222222":"10.0.0.8"},"_nickname":"",'
    '"_encryptor":{"__type__":"autonomous_trust.core._python.identity.encrypt.'
    'Encryptor","hex_seed":{"__type__":"bytes","__value__":"MGQzZWRlM2I1YWI3Zj'
    'FmMjczZDBmMmY2NjU0NTk5NDI4NTQwN2Y4MTcxZTQzNjdhYTNkZDIyNTVjOWMyMjllZg=="},'
    '"public_only":false},"_public_only":false,"_created":1792700000.5,'
    '"_key_epoch":3,"_wire_format":"json"},{"step_dag":[{"__type__":'
    '"autonomous_trust.core._python.structures.dag.LinkedStep","payload":'
    '{"__type__":"bytes","__value__":"Y2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNk'
    'Y2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZA=="},"uuid":{"__type__":'
    '"UUID","__value__":"b1d8104b-ed19-405b-a3fe-58ef942ac0b7"},"timestamp":'
    '{"__type__":"datetime","__value__":"2026-10-23T02:04:43.067288+00:00"}}],'
    '"blacklist":[]}]')


def _chooser(me, peers=(), configured=None):
    node = _node(me, list(peers))
    node.choosing = False
    node.configs = {} if configured is None else {CfgIds.group: configured}
    node.cadence = 0.01
    node.init_timeout = 5
    node.phase = 2
    node._record_group = MagicMock()
    node._populate_peers_from_history = MagicMock()
    node._tell_bridged_group = MagicMock()
    node._history = MagicMock()
    node._history.catch_up.return_value = []
    node.report_exception = MagicMock(side_effect=AssertionError)
    node.identity = me
    return node


def _group(*members, name='g'):
    return Group.initialize({m.uuid: m.address for m in members}, name)


def test_the_longest_history_wins():
    me, a, b = _peer('me'), _peer('a'), _peer('b')
    short, long_ = _group(a, name='short'), _group(b, name='long')
    node = _chooser(me)
    node.histories = [(short.to_canonical(), ['s1'], []),
                      (long_.to_canonical(), ['s1', 's2'], [])]
    node.choose_group(_queues())
    assert node.group == long_


def test_a_tie_goes_to_the_first_arrival():
    me, a, b = _peer('me'), _peer('a'), _peer('b')
    first, second = _group(a, name='first'), _group(b, name='second')
    node = _chooser(me)
    node.histories = [(first.to_canonical(), ['s1'], []),
                      (second.to_canonical(), ['s1'], [])]
    node.choose_group(_queues())
    assert node.group == first


def test_a_zero_step_history_is_adopted_when_nothing_longer_is():
    """The user's call, 2026-10-23 (C's rule): a lone node's freshly minted
    group is adopted, so the two share one key at once."""
    me, lone = _peer('me'), _peer('lone')
    g = _group(lone, name='lone')
    node = _chooser(me)
    node.histories = [(g.to_canonical(), [], [])]
    node.choose_group(_queues())
    assert node.group == g


def test_a_zero_step_adoption_completes_the_join():
    """With a real history, not the mock: catch_up cannot take an empty
    branch, so a zero-step adoption merges nothing and sends no diff (as C)
    instead of raising out of choose_group mid-join."""
    me, lone = _peer('me'), _peer('lone')
    node = _chooser(me)
    node._history = IdentityByAuthority(me, SimpleNamespace(all=[]), None, 2)
    node.histories = [(_group(lone, name='lone').to_canonical(), [], [])]
    queues = _queues()
    node.choose_group(queues)  # report_exception raises
    assert (node.phase, node.choosing) == (3, False)
    assert not [m for m in _sent(queues) if m.function == IdentityProtocol.diff]


def test_a_longer_history_beats_a_zero_step_one():
    me, a, b = _peer('me'), _peer('a'), _peer('b')
    empty, longer = _group(a, name='empty'), _group(b, name='longer')
    node = _chooser(me)
    node.histories = [(empty.to_canonical(), [], []),
                      (longer.to_canonical(), ['s1'], [])]
    node.choose_group(_queues())
    assert node.group == longer


def test_a_returning_node_rejoins_its_own_group():
    me, a, b = _peer('me'), _peer('a'), _peer('b')
    ours, theirs = _group(me, a, name='ours'), _group(b, name='theirs')
    node = _chooser(me, configured=ours)
    node.histories = [(theirs.to_canonical(), ['s1', 's2', 's3'], []),
                      (ours.to_canonical(), [], [])]
    node.choose_group(_queues())
    assert node.group == ours


def test_peers_are_unioned_across_every_history():
    me, a, b, c = _peer('me'), _peer('a'), _peer('b'), _peer('c')
    g = _group(a, b, c)
    node = _chooser(me)
    node.histories = [(g.to_canonical(), ['s1'], [a.publish(), b.publish()]),
                      (g.to_canonical(), ['s1'], [b.publish(), c.publish()])]
    node.choose_group(_queues())
    unioned = node._populate_peers_from_history.call_args.args[1]
    assert {str(p.uuid) for p in unioned} == {str(a.uuid), str(b.uuid), str(c.uuid)}


def test_an_adoption_sends_the_history_diff():
    me, a = _peer('me'), _peer('a')
    g = _group(a)
    node = _chooser(me)
    node._history.catch_up.return_value = ['ours']
    node.histories = [(g.to_canonical(), ['s1'], [])]
    queues = _queues()
    node.choose_group(queues)
    diffs = [m for m in _sent(queues) if m.function == IdentityProtocol.diff]
    assert len(diffs) == 1


def test_with_no_history_a_persisted_group_is_restored(tmp_path, monkeypatch):
    """...including a file C wrote (group_file_write), so a config directory
    is runtime-neutral (the user's call, 2026-10-23)."""
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    from autonomous_trust.core.config import Configuration
    cfg_dir = Configuration.get_cfg_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, 'group' + Configuration.file_ext), 'w') as f:
        f.write(C_FILE)
    me = _peer('me')
    node = _chooser(me)
    node.histories = []
    node.init_timeout = 0
    node.choose_group(_queues())
    assert str(node.group.uuid) == 'c74d6b0d-8cb5-4c13-87ab-9785a39d19fb'
    assert node.group.key_epoch == 3
    steps = node._history.populate.call_args.args[0]['step_dag']
    assert str(steps[0].uuid) == 'b1d8104b-ed19-405b-a3fe-58ef942ac0b7'
    assert steps[0].payload == b'cd' * 32
    assert steps[0].timestamp.tzinfo is not None


# ---- a joiner keeps asking until it is admitted -----------------------------
#
# A joiner used to broadcast request_access once and found a group of its own
# five seconds later. On a loaded host a large share of UDP sends is dropped at
# the sender while the kernel reports success, and in a large deployment a
# cohort's admitter can come up minutes after its members; at 96 nodes either
# was enough to split a cohort into self-founded groups.

def _waiting_chooser(me, patience=0.0):
    node = _chooser(me)
    node.histories = []
    node.init_timeout = 0.3
    node.rejoin_interval = 0.05
    node.rejoin_interval_cap = 0.2
    node.join_patience = patience
    node._broadcast_request_access = MagicMock()
    return node


def test_a_joiner_re_announces_while_it_waits(monkeypatch, tmp_path):
    from autonomous_trust.core.config import Configuration
    monkeypatch.setattr(Configuration, 'get_cfg_dir', staticmethod(lambda: str(tmp_path)))
    node = _waiting_chooser(_peer('me'))
    node.choose_group(_queues())
    assert node._broadcast_request_access.call_count >= 3


def test_patience_waits_past_the_init_timeout_for_a_late_admitter(monkeypatch, tmp_path):
    """With patience set, a joiner that hears nothing in init_timeout keeps
    asking; the admitter's history, arriving later, is adopted instead of a
    group of one."""
    from autonomous_trust.core.config import Configuration
    monkeypatch.setattr(Configuration, 'get_cfg_dir', staticmethod(lambda: str(tmp_path)))
    me, admitter = _peer('me'), _peer('anchor')
    cohort = _group(admitter, name='field')
    node = _waiting_chooser(me, patience=3.0)
    calls = []

    def announce(queues, target_group=None):
        calls.append(1)
        if len(calls) == 8:                     # well past init_timeout
            node.histories.append((cohort.to_canonical(), ['s1'], []))
    node._broadcast_request_access.side_effect = announce
    node.choose_group(_queues())
    assert node.group == cohort


def test_without_patience_the_joiner_still_founds_its_own_group(monkeypatch, tmp_path):
    from autonomous_trust.core.config import Configuration
    monkeypatch.setattr(Configuration, 'get_cfg_dir', staticmethod(lambda: str(tmp_path)))
    me = _peer('me')
    node = _waiting_chooser(me)
    import time
    t = time.monotonic()
    node.choose_group(_queues())
    assert time.monotonic() - t < 2.0
    assert node.group is not None and str(me.uuid) in {str(k) for k in node.group._address_map}


def test_a_gateway_skips_a_history_whose_group_spans_it():
    """A gateway offered a command history and a longer field history used to
    pick the field one and then have the guard refuse it, adopting neither
    (and, in Python, half-applying the refused one). The spanning history is
    filtered out before the longest is chosen."""
    me, boss, drone = _peer('gw'), _peer('boss'), _peer('drone')
    command = _group(boss, name='command')
    child = _group(drone, name='field')
    field_history = _group(drone, _peer('d2'), name='field2')
    node = _chooser(me)
    node.child_groups = {str(child.uuid): child}
    node.histories = [(command.to_canonical(), ['s1'], []),
                      (field_history.to_canonical(), ['s1', 's2', 's3'], [])]
    assert node._adopt_from_histories(_queues()) is True
    assert node.group == command


# ---- a welcome is re-sent ----------------------------------------------------
#
# The welcomer used to send access_granted and full_history once. On a loaded
# host a joiner's request may be one of a hundred that got through, and if that
# one welcome is then lost the joiner never hears back (the MQ-800 at 96 nodes:
# 114 requests, one received, its welcome lost). A re-sent copy the joiner
# already has is refused as a replay by its freshness stamp.

def test_a_welcome_is_re_sent_after_the_delays(monkeypatch):
    import autonomous_trust.core._python.identity.idprocess as idp
    clock = [100.0]
    monkeypatch.setattr(idp.time, 'monotonic', lambda: clock[0])
    node = _chooser(_peer('anchor'))
    node.WELCOME_RESEND_AFTER = (2.0, 6.0)
    grant, history = object(), object()
    node._schedule_welcome_resend([grant, history])
    queues = _queues()
    node._resend_welcomes(queues)
    assert _sent(queues) == []
    clock[0] = 102.5
    node._resend_welcomes(queues)
    assert _sent(queues) == [grant, history]
    clock[0] = 106.5
    node._resend_welcomes(queues)
    node._resend_welcomes(queues)
    assert _sent(queues) == [grant, history, grant, history]
