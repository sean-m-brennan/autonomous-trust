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
