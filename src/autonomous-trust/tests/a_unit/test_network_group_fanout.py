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
"""Group fan-out keeps going past a member that cannot be reached.

A member address can fail to resolve, for example a container hostname whose
container has not started yet. That failure must cost only that member's copy,
not the copies for every member after it in the address list."""

import socket
from unittest.mock import MagicMock

from autonomous_trust.core._python.network.netprocess import NetworkProcess


def _proc(unresolvable: str) -> MagicMock:
    proc = MagicMock()
    proc.myself.address = '10.0.0.1'
    proc._groups_containing.return_value = ['g']
    proc.reject_message.return_value = False
    proc.peers.find_by_address.return_value = None

    def send_group(msg, addr):
        if addr == unresolvable:
            raise socket.gaierror(-2, 'Name or service not known')
    proc.send_group.side_effect = send_group
    return proc


def test_unresolvable_member_does_not_stop_fanout():
    proc = _proc('jet-1')
    NetworkProcess._send_to_group_members(
        proc, b'msg', ['jet-1', '10.0.0.2', '10.0.0.3'])
    sent_to = [c.args[1] for c in proc.send_group.call_args_list]
    assert sent_to == ['jet-1', '10.0.0.2', '10.0.0.3']
    proc.track_send_error.assert_called_once()


def test_failure_is_logged_with_the_address():
    proc = _proc('jet-1')
    NetworkProcess._send_to_group_members(proc, b'msg', ['jet-1'])
    logged = ' '.join(str(a) for c in proc.logger.error.call_args_list
                      for a in c.args)
    assert 'jet-1' in logged


def test_own_address_is_skipped():
    proc = _proc('none')
    NetworkProcess._send_to_group_members(proc, b'msg', ['10.0.0.1', '10.0.0.2'])
    sent_to = [c.args[1] for c in proc.send_group.call_args_list]
    assert sent_to == ['10.0.0.2']
