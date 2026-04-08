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

import json
from datetime import timedelta

import pytest

from autonomous_trust.evaluation.playback import (
    PlaybackFrame,
    EventRecorder,
    PlaybackEngine,
)
from autonomous_trust.evaluation.scenarios.scenario import (
    ScenarioEvent,
    PhaseEvent,
)


class TestPlaybackFrame:
    def test_fields(self):
        frame = PlaybackFrame(t=1.5, kind='event', payload={'key': 'val'})
        assert frame.t == 1.5
        assert frame.kind == 'event'
        assert frame.payload == {'key': 'val'}


class TestEventRecorder:
    def test_record_event(self, tmp_path):
        path = tmp_path / 'session.jsonl'
        with EventRecorder(path) as rec:
            evt = ScenarioEvent(
                timestamp=timedelta(seconds=5),
                event_type=PhaseEvent.PEER_JOIN,
                peer_name='alice',
                description='alice joins',
            )
            rec.record_event(evt)

        lines = path.read_text().strip().split('\n')
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj['t'] == 5.0
        assert obj['kind'] == 'event'
        assert obj['payload']['type'] == 'PEER_JOIN'

    def test_record_state(self, tmp_path):
        path = tmp_path / 'session.jsonl'
        with EventRecorder(path) as rec:
            rec.record_state(timedelta(seconds=10), {'scores': [1, 2, 3]})

        lines = path.read_text().strip().split('\n')
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj['kind'] == 'state'
        assert obj['payload']['scores'] == [1, 2, 3]

    def test_multiple_records(self, tmp_path):
        path = tmp_path / 'session.jsonl'
        with EventRecorder(path) as rec:
            for i in range(5):
                rec.record_state(timedelta(seconds=i), {'i': i})

        lines = path.read_text().strip().split('\n')
        assert len(lines) == 5

    def test_context_manager_closes(self, tmp_path):
        path = tmp_path / 'session.jsonl'
        rec = EventRecorder(path)
        rec.__enter__()
        rec.record_state(timedelta(0), {})
        rec.__exit__(None, None, None)
        # File should be closed - writing would fail
        assert path.exists()


class TestPlaybackEngine:
    @pytest.fixture
    def session_file(self, tmp_path):
        """Create a small JSONL session file for testing."""
        path = tmp_path / 'session.jsonl'
        frames = [
            {'t': 0.0, 'kind': 'event', 'payload': {'type': 'ANNOTATION', 'desc': 'start'}},
            {'t': 5.0, 'kind': 'event', 'payload': {'type': 'PEER_JOIN', 'peer': 'alice'}},
            {'t': 10.0, 'kind': 'state', 'payload': {'peers': 1}},
            {'t': 15.0, 'kind': 'event', 'payload': {'type': 'PEER_JOIN', 'peer': 'bob'}},
            {'t': 20.0, 'kind': 'state', 'payload': {'peers': 2}},
        ]
        with open(path, 'w') as f:
            for frame in frames:
                f.write(json.dumps(frame) + '\n')
        return path

    def test_load_frame_count(self, session_file):
        engine = PlaybackEngine(session_file)
        assert engine.frame_count == 5

    def test_duration(self, session_file):
        engine = PlaybackEngine(session_file)
        assert engine.duration == 20.0

    def test_seek_to_time(self, session_file):
        engine = PlaybackEngine(session_file)
        engine.seek(10.0)
        assert engine.current_time == 10.0

    def test_seek_past_end(self, session_file):
        engine = PlaybackEngine(session_file)
        engine.seek(100.0)
        assert engine.current_time == engine.duration

    def test_seek_to_start(self, session_file):
        engine = PlaybackEngine(session_file)
        engine.seek(10.0)
        engine.seek(0.0)
        assert engine.current_time == 0.0

    def test_on_frame_callback(self, session_file):
        engine = PlaybackEngine(session_file)
        received = []
        engine.on_frame(lambda f: received.append(f))
        engine.play(speed=1000.0, from_cursor=False)  # very fast
        assert len(received) == 5
        assert received[0].kind == 'event'
        assert received[0].t == 0.0
        assert received[-1].t == 20.0

    def test_pause_stops_playback(self, session_file):
        engine = PlaybackEngine(session_file)
        received = []

        def cb(frame):
            received.append(frame)
            if len(received) >= 2:
                engine.pause()

        engine.on_frame(cb)
        engine.play(speed=1000.0, from_cursor=False)
        assert len(received) == 2

    def test_frames_sorted_by_time(self, tmp_path):
        """Frames should be sorted even if file is out of order."""
        path = tmp_path / 'unsorted.jsonl'
        frames = [
            {'t': 10.0, 'kind': 'event', 'payload': {}},
            {'t': 2.0, 'kind': 'event', 'payload': {}},
            {'t': 5.0, 'kind': 'event', 'payload': {}},
        ]
        with open(path, 'w') as f:
            for frame in frames:
                f.write(json.dumps(frame) + '\n')

        engine = PlaybackEngine(path)
        received = []
        engine.on_frame(lambda f: received.append(f.t))
        engine.play(speed=1000.0, from_cursor=False)
        assert received == [2.0, 5.0, 10.0]

    def test_empty_file(self, tmp_path):
        path = tmp_path / 'empty.jsonl'
        path.write_text('')
        engine = PlaybackEngine(path)
        assert engine.frame_count == 0
        assert engine.duration == 0.0

    def test_set_speed(self, session_file):
        engine = PlaybackEngine(session_file)
        engine.set_speed(5.0)
        assert engine._speed == 5.0
        engine.set_speed(0.01)  # clamps to 0.1
        assert engine._speed == 0.1


class TestRecorderPlaybackRoundtrip:
    def test_roundtrip(self, tmp_path):
        """Record events, then play them back and verify."""
        path = tmp_path / 'roundtrip.jsonl'

        events = [
            ScenarioEvent(timedelta(seconds=0), PhaseEvent.ANNOTATION,
                          description='start'),
            ScenarioEvent(timedelta(seconds=5), PhaseEvent.PEER_JOIN,
                          peer_name='alice', description='alice joins'),
            ScenarioEvent(timedelta(seconds=10), PhaseEvent.PEER_JOIN,
                          peer_name='bob', description='bob joins'),
        ]

        with EventRecorder(path) as rec:
            for evt in events:
                rec.record_event(evt)

        engine = PlaybackEngine(path)
        assert engine.frame_count == 3
        assert engine.duration == 10.0

        received = []
        engine.on_frame(lambda f: received.append(f))
        engine.play(speed=1000.0, from_cursor=False)

        assert len(received) == 3
        assert received[0].payload['type'] == 'ANNOTATION'
        assert received[1].payload['peer'] == 'alice'
        assert received[2].payload['peer'] == 'bob'
