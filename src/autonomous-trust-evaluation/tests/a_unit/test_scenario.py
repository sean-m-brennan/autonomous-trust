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

from datetime import timedelta

import pytest

from autonomous_trust.evaluation.scenarios.scenario import (
    GeoPosition,
    PeerState,
    PeerRole,
    PhaseEvent,
    ScenarioEvent,
    Phase,
    Scenario,
)


# Concrete subclass for testing the abstract Scenario
class SimpleScenario(Scenario):
    @property
    def name(self):
        return 'test-scenario'

    @property
    def description(self):
        return 'A simple test scenario'

    def define(self):
        self.add_peer(PeerRole(
            name='alice', agency='TestOrg', kind='sensor',
            position=GeoPosition(34.7, -86.6),
            join_phase=0,
        ))
        self.add_peer(PeerRole(
            name='bob', agency='TestOrg', kind='sensor',
            position=GeoPosition(34.8, -86.5),
            join_phase=1,
        ))
        self.add_phase(Phase(
            name='Formation', start=timedelta(seconds=0),
            description='Initial formation',
        ))
        self.add_phase(Phase(
            name='Operations', start=timedelta(seconds=30),
            description='Normal operations',
        ))


class EmptyScenario(Scenario):
    @property
    def name(self):
        return 'empty'

    @property
    def description(self):
        return 'No peers or phases'

    def define(self):
        pass


# --- Data class tests ---

class TestPeerRole:
    def test_defaults(self):
        role = PeerRole(name='p1', agency='A', kind='sensor',
                        position=GeoPosition(0, 0))
        assert role.color == '#4A90D9'
        assert role.join_phase == 0
        assert role.capabilities == []
        assert role.metadata == {}

    def test_custom_fields(self):
        role = PeerRole(
            name='p1', agency='A', kind='drone',
            position=GeoPosition(1.0, 2.0, 100.0),
            color='#FF0000', join_phase=2,
            capabilities=['camera', 'gps'],
            metadata={'serial': '12345'},
        )
        assert role.capabilities == ['camera', 'gps']
        assert role.metadata['serial'] == '12345'
        assert role.position.alt == 100.0


class TestScenarioEvent:
    def test_to_dict(self):
        evt = ScenarioEvent(
            timestamp=timedelta(seconds=10),
            event_type=PhaseEvent.PEER_JOIN,
            peer_name='alice',
            description='alice joins',
        )
        d = evt.to_dict()
        assert d['t'] == 10.0
        assert d['type'] == 'PEER_JOIN'
        assert d['peer'] == 'alice'
        assert d['description'] == 'alice joins'
        assert d['data'] == {}

    def test_defaults(self):
        evt = ScenarioEvent(
            timestamp=timedelta(0),
            event_type=PhaseEvent.ANNOTATION,
        )
        assert evt.peer_name is None
        assert evt.description == ''


class TestPhase:
    def test_defaults(self):
        phase = Phase(name='Phase1', start=timedelta(0))
        assert phase.description == ''
        assert phase.events == []

    def test_events_list(self):
        evt = ScenarioEvent(timedelta(seconds=5), PhaseEvent.CUSTOM)
        phase = Phase(name='P', start=timedelta(0), events=[evt])
        assert len(phase.events) == 1


# --- Scenario builder tests ---

class TestScenarioBuilder:
    def test_add_peer(self):
        s = SimpleScenario()
        assert 'alice' in s.peers
        assert 'bob' in s.peers
        assert len(s.peers) == 2

    def test_duplicate_peer_raises(self):
        class DupScenario(Scenario):
            name = 'dup'
            description = 'dup'
            def define(self):
                role = PeerRole('a', 'X', 'y', GeoPosition(0, 0))
                self.add_peer(role)
                self.add_peer(role)  # duplicate

        with pytest.raises(ValueError, match='Duplicate peer name'):
            DupScenario()

    def test_phases_ordered(self):
        s = SimpleScenario()
        assert len(s.phases) == 2
        assert s.phases[0].name == 'Formation'
        assert s.phases[1].name == 'Operations'

    def test_out_of_order_phase_raises(self):
        class BadOrder(Scenario):
            name = 'bad'
            description = 'bad'
            def define(self):
                self.add_phase(Phase('B', timedelta(seconds=30)))
                self.add_phase(Phase('A', timedelta(seconds=10)))

        with pytest.raises(ValueError, match='before previous phase'):
            BadOrder()

    def test_add_event_to_phase(self):
        s = SimpleScenario()
        evt = ScenarioEvent(timedelta(seconds=5), PhaseEvent.CUSTOM,
                            description='test event')
        s.add_event('Formation', evt)
        assert len(s.phases[0].events) == 1

    def test_add_event_unknown_phase_raises(self):
        s = SimpleScenario()
        evt = ScenarioEvent(timedelta(0), PhaseEvent.CUSTOM)
        with pytest.raises(ValueError, match='Unknown phase'):
            s.add_event('NonExistent', evt)

    def test_initial_peer_states(self):
        s = SimpleScenario()
        assert s.peer_states['alice'] == PeerState.PENDING
        assert s.peer_states['bob'] == PeerState.PENDING


# --- Scenario runtime tests ---

class TestScenarioRuntime:
    def test_advance_auto_joins_phase0_peers(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=1))
        assert s.peer_states['alice'] == PeerState.ACTIVE
        assert s.peer_states['bob'] == PeerState.PENDING

    def test_advance_auto_joins_phase1_peers(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=31))
        assert s.peer_states['alice'] == PeerState.ACTIVE
        assert s.peer_states['bob'] == PeerState.ACTIVE

    def test_phase_transition(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=0))
        assert s.current_phase.name == 'Formation'
        s.advance_to(timedelta(seconds=31))
        assert s.current_phase.name == 'Operations'

    def test_event_fires_once(self):
        s = SimpleScenario()
        evt = ScenarioEvent(timedelta(seconds=5), PhaseEvent.CUSTOM,
                            description='one-shot')
        s.add_event('Formation', evt)
        s.advance_to(timedelta(seconds=10))
        s.advance_to(timedelta(seconds=15))
        # Count how many times the custom event appears in log
        custom_count = sum(1 for e in s.event_log
                          if e['type'] == 'CUSTOM')
        assert custom_count == 1

    def test_apply_event_compromise(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=1))  # join alice
        evt = ScenarioEvent(timedelta(seconds=5),
                            PhaseEvent.COMPROMISE_START, peer_name='alice')
        s.add_event('Formation', evt)
        s.advance_to(timedelta(seconds=10))
        assert s.peer_states['alice'] == PeerState.COMPROMISED

    def test_apply_event_exclude(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=1))
        evt = ScenarioEvent(timedelta(seconds=5),
                            PhaseEvent.PEER_EXCLUDE, peer_name='alice')
        s.add_event('Formation', evt)
        s.advance_to(timedelta(seconds=10))
        assert s.peer_states['alice'] == PeerState.EXCLUDED

    def test_event_listener_called(self):
        s = SimpleScenario()
        received = []
        s.on_event(lambda evt: received.append(evt))
        s.advance_to(timedelta(seconds=1))
        assert len(received) > 0
        assert any(e.event_type == PhaseEvent.PEER_JOIN for e in received)

    def test_event_log_records(self):
        s = SimpleScenario()
        s.advance_to(timedelta(seconds=1))
        assert len(s.event_log) > 0
        assert all('t' in e and 'type' in e for e in s.event_log)


# --- Serialization tests ---

class TestScenarioExport:
    def test_export_structure(self):
        s = SimpleScenario()
        d = s.export_scenario_def()
        assert d['name'] == 'test-scenario'
        assert d['description'] == 'A simple test scenario'
        assert len(d['peers']) == 2
        assert len(d['phases']) == 2
        assert 'alice' in d['peers']
        assert d['peers']['alice']['agency'] == 'TestOrg'

    def test_export_phase_timing(self):
        s = SimpleScenario()
        d = s.export_scenario_def()
        assert d['phases'][0]['start_sec'] == 0.0
        assert d['phases'][1]['start_sec'] == 30.0

    def test_duration_default(self):
        s = EmptyScenario()
        assert s.duration == timedelta(minutes=10)

    def test_duration_with_phases(self):
        s = SimpleScenario()
        # last phase at 30s + 60s buffer = 90s
        assert s.duration == timedelta(seconds=90)

    def test_stop(self):
        s = SimpleScenario()
        s._running = True
        s.stop()
        assert not s._running
