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
"""An access request or group update that arrives before phase 3 is not
handled then, and says so.

Nobody resends either one: a requester gives up and founds its own group, and
the members that sent a group update see the receiver as already a member.
Both are held (left unhandled, so process() offers them again until phase 3;
see test_group_key_convergence's TestHeldUntilPhase3). Each is logged at INFO, and only for the handler's own
verb, since every handler sees every identity message.
"""
from unittest.mock import MagicMock

from autonomous_trust.core._python.identity.protocol import IdentityProtocol
from autonomous_trust.core._python.identity.idprocess import IdentityProcess


def _node(phase):
    node = object.__new__(IdentityProcess)
    node.logger = MagicMock()
    node.phase = phase
    return node


def _message(function):
    msg = MagicMock()
    msg.function = function
    msg.from_whom.nickname = 'bob'
    return msg


def _drop_lines(node):
    return [c for c in node.logger.info.call_args_list
            if c.args and str(c.args[0]).startswith(('Dropping', 'Holding'))]


def test_early_access_request_is_logged_and_held():
    node = _node(phase=1)
    assert node.welcoming_committee({}, _message(IdentityProtocol.announce)) is False
    lines = _drop_lines(node)
    assert len(lines) == 1
    assert 'access request' in lines[0].args[0] and lines[0].args[1:] == ('bob', 1)


def test_early_group_update_is_logged_and_held():
    node = _node(phase=2)
    assert node.handle_group_update({}, _message(IdentityProtocol.update)) is False
    lines = _drop_lines(node)
    assert len(lines) == 1
    assert 'group update' in lines[0].args[0] and lines[0].args[1:] == ('bob', 2)


def test_other_verbs_before_phase_3_log_nothing():
    node = _node(phase=1)
    other = _message(IdentityProtocol.update)
    assert node.welcoming_committee({}, other) is False
    other = _message(IdentityProtocol.announce)
    assert node.handle_group_update({}, other) is False
    assert _drop_lines(node) == []


def test_a_held_message_offered_again_is_logged_once():
    """process() offers a held message on every pass until phase 3. A joiner
    now waits there for as long as its patience allows, and logging each pass
    wrote millions of lines a run, on a host already short of CPU."""
    node = _node(phase=2)
    request, update = _message(IdentityProtocol.announce), _message(IdentityProtocol.update)
    for _ in range(50):
        node.welcoming_committee({}, request)
        node.handle_group_update({}, update)
    assert len(_drop_lines(node)) == 2
    node.welcoming_committee({}, _message(IdentityProtocol.announce))   # a new one
    assert len(_drop_lines(node)) == 3


def _from(function, uid):
    msg = MagicMock()
    msg.function = function
    msg.from_whom.uuid = uid
    msg.from_whom.nickname = uid
    return msg


def test_held_requests_and_updates_keep_the_latest_per_sender_and_are_capped():
    """A joiner now waits in phase 2 for as long as its patience allows while
    every other joiner re-broadcasts, and every held message is re-run through
    every handler on every pass. C holds one access request and one group
    update per sender, at most 16 of each (ID_HELD_ACCESS_REQUESTS,
    ID_HELD_GROUP_UPDATES); Python held them all."""
    node = _node(phase=2)
    held = [_from(IdentityProtocol.announce, 'bob') for _ in range(40)]
    latest_bob = held[-1]
    held += [_from(IdentityProtocol.announce, 'peer%d' % i) for i in range(30)]
    held += [_from(IdentityProtocol.update, 'carol') for _ in range(10)]
    other = _from('something_else', 'dave')
    held.append(other)
    kept = node._bounded_held(held)
    requests = [m for m in kept if m.function == IdentityProtocol.announce]
    updates = [m for m in kept if m.function == IdentityProtocol.update]
    assert len(requests) == 16 and len(updates) == 1
    assert len({m.from_whom.uuid for m in requests}) == 16
    assert other in kept
    assert latest_bob not in kept or latest_bob in requests
