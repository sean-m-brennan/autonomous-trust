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

import pytest

try:
    from autonomous_trust.core.protobuf.simulator import sim_data_pb2
    _has_proto = True
except (ImportError, ModuleNotFoundError):
    sim_data_pb2 = None
    _has_proto = False

pytestmark = pytest.mark.skipif(not _has_proto, reason='simulator protobuf not available')


def test_sim_data_pb2_has_messages():
    assert hasattr(sim_data_pb2, 'Ident')
    assert hasattr(sim_data_pb2, 'SimState')
    assert hasattr(sim_data_pb2, 'ReachabilityRow')


def test_ident_has_message():
    from autonomous_trust.simulator.sim_data import Ident
    from autonomous_trust.services.peer.position import GeoPosition
    ident = Ident(GeoPosition(1.0, 2.0), 5.0, 'sensor', 'alice')
    assert hasattr(ident, 'message')
    assert isinstance(ident.message, sim_data_pb2.Ident)


def test_sim_state_has_message():
    from autonomous_trust.simulator.sim_data import SimState
    state = SimState()
    assert hasattr(state, 'message')
    assert isinstance(state.message, sim_data_pb2.SimState)
