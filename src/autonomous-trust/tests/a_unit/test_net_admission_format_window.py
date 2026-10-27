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
"""The moment of admission into a proto-format cohort.

The admitter counts the joiner a member, and so speaks the cohort's format to
it, the instant it admits it; the joiner learns that format only when its group
arrives a beat later. Both directions used to lose frames in that gap: the
joiner refused the admitter's proto frames on a JSON path, and the admitter
refused the joiner's JSON on a proto one. Now the joiner defers a decrypted
frame from a known peer it cannot place yet, and holds its own point-to-point
traffic to an admitter until it can say which format that admitter expects.
"""
import time
from collections import deque
from types import SimpleNamespace
from unittest.mock import MagicMock

from autonomous_trust.core.config import NetWireFormat
from autonomous_trust.core.identity import Group
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.network.message import Message, WireFormatMismatch
from autonomous_trust.core._python.network.netprocess import NetworkProcess

ADMITTER = '10.0.0.1'


def _cohort():
    return Group('7f4b0c1e-1111-4222-8333-444455556666',
                 {'a-uuid': ADMITTER, 'b-uuid': '10.0.0.2'}, 'cohort',
                 None, _wire_format=NetWireFormat.proto)


def _node():
    node = object.__new__(NetworkProcess)
    node.logger = MagicMock()
    node.protocol = SimpleNamespace(group=None, child_groups={})
    node.mystery_max_age_s = 30
    node._admission_pending = {}
    node._held_for_admission = deque()
    node.reject_message = lambda addr: False
    node._crosses_gateway = lambda addr: False
    node._unicast_carrier = lambda uuid: None
    node._also_unicast = lambda *args: None
    node.track_send_stats = lambda *args: None
    node._presence = SimpleNamespace(sent=lambda *args: None)
    node.sent = []
    node.send_peer = lambda msg, addr: node.sent.append((addr, msg))
    node.routed = []
    node.dropped = []

    def msg_to_queue(msg, peer, queues, rcvd_by, validate=True,
                     wire_format=NetWireFormat.json, opaque=False):
        # The real routing's parse-and-refuse, without the dispatch behind it.
        try:
            node.routed.append(Message.parse(msg, peer, validate=False,
                                             wire_format=wire_format))
        except WireFormatMismatch:
            if opaque:
                raise
            node.dropped.append(msg)
    node._msg_to_queue = msg_to_queue
    return node


def _admitter():
    return SimpleNamespace(address=ADMITTER, uuid='a-uuid', nickname='admitter')


def _msg(function='invitation', process=CfgIds.negotiation):
    return Message(process, function, 'payload', encrypt=False)


def _admitted(node):
    node._note_admission(_msg(IdentityProtocol.accept, CfgIds.identity), ADMITTER)


# ---- receiving: defer, never drop -----------------------------------------

def test_a_proto_frame_from_a_known_peer_we_cannot_place_is_deferred():
    node = _node()
    frame = _msg().to_wire(NetWireFormat.proto)
    assert node._route_decrypted(frame, _admitter(), ADMITTER, {}) is False
    assert node.routed == [] and node.dropped == []


def test_the_deferred_frame_reads_in_the_group_format_once_placed():
    node = _node()
    frame = _msg().to_wire(NetWireFormat.proto)
    node._route_decrypted(frame, _admitter(), ADMITTER, {})
    node.protocol.group = _cohort()
    assert node._route_decrypted(frame, _admitter(), ADMITTER, {}) is True
    assert [m.function for m in node.routed] == ['invitation']


def test_a_json_frame_from_a_peer_we_cannot_place_still_routes():
    node = _node()
    frame = _msg().to_wire(NetWireFormat.json)
    assert node._route_decrypted(frame, _admitter(), ADMITTER, {}) is True
    assert len(node.routed) == 1


def test_a_member_in_the_wrong_format_is_still_a_drop():
    node = _node()
    node.protocol.group = _cohort()
    frame = _msg().to_wire(NetWireFormat.json)
    assert node._route_decrypted(frame, _admitter(), ADMITTER, {}) is True
    assert node.routed == [] and node.dropped == [frame]


# ---- sending: hold until the format is known -------------------------------

def test_without_an_admission_traffic_goes_out_at_once():
    node = _node()
    node._unicast(_msg(), _admitter())
    assert len(node.sent) == 1


def test_traffic_to_an_admitter_is_held_until_it_can_be_placed():
    node = _node()
    _admitted(node)
    node._unicast(_msg('first'), _admitter())
    node._unicast(_msg('second'), _admitter())
    assert node.sent == []
    node._release_admission_holds({})
    assert node.sent == []
    node.protocol.group = _cohort()
    node._release_admission_holds({})
    assert [Message.parse(m, None, validate=False,
                          wire_format=NetWireFormat.proto).function
            for _a, m in node.sent] == ['first', 'second']
    assert not node._held_for_admission and not node._admission_pending


def test_bootstrap_is_never_held():
    node = _node()
    _admitted(node)
    node._unicast(_msg(IdentityProtocol.history, CfgIds.identity), _admitter())
    assert len(node.sent) == 1


def test_a_hold_that_outlives_the_bound_goes_out_as_the_lookup_says():
    node = _node()
    _admitted(node)
    node._unicast(_msg(), _admitter())
    node._admission_pending[ADMITTER] = time.monotonic() - 1
    node._release_admission_holds({})
    assert len(node.sent) == 1
    assert Message.parse(node.sent[0][1], None, validate=False).function == 'invitation'


def test_an_access_granted_from_a_member_starts_no_hold():
    node = _node()
    node.protocol.group = _cohort()
    _admitted(node)
    assert node._admission_pending == {}
