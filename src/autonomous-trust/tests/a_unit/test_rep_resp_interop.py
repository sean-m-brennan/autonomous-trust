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
"""Reading a `reputation response`, whichever runtime sent it.

The defect these pin: a peer running the C library answered a reputation
request with plain JSON fields — `{peer_uuid, score, requesting_process}` — with
no `__type__` tag. That deserialized to a bare `dict`, and the consumer then
reached for `.peer_id` on it, raising `AttributeError` out of the message loop.
The consequence was silent in the only place anyone would look: a C peer's view
of the cohort reached neither `latest_reputation` nor `latest_reputation_pairs`,
so the inspector's trust graph simply had no C opinions in it.

Both halves are covered here. C now sends the tagged form, and the consumer no
longer trusts the shape it is handed — a mixed-version cohort keeps working, and
a malformed reply from one peer cannot stop the loop that serves every other.

See doc/architecture/reputation.md, "Asking others what they think".
"""
from unittest.mock import MagicMock

from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.reputation.reputation import Reputation
from autonomous_trust.core.config import to_json_string


# The entry normalizer is a staticmethod, and `_reputation_entries` needs only a
# logger, so neither test needs a running node.
class _Consumer(AutonomousTrust):
    def __init__(self):            # noqa - deliberately not calling super()
        self.logger = MagicMock()


class TestEntryNormalization:
    def test_already_a_reputation_passes_through(self):
        rep = Reputation('11111111-1111-1111-1111-111111111111', 0.75)
        assert AutonomousTrust._reputation_entry(rep) is rep

    def test_c_legacy_wire_shape_is_read(self):
        """THE regression guard: this is what a C peer used to send, and what
        used to raise `AttributeError` two lines later."""
        entry = AutonomousTrust._reputation_entry({
            'peer_uuid': '11111111-1111-1111-1111-111111111111',
            'score': 0.25,
            'requesting_process': 'monitor',
        })
        assert isinstance(entry, Reputation)
        assert str(entry.peer_id) == '11111111-1111-1111-1111-111111111111'
        assert entry.score == 0.25

    def test_peer_id_spelling_is_read(self):
        entry = AutonomousTrust._reputation_entry({'peer_id': 'abc', 'score': 1.0})
        assert entry.score == 1.0
        assert str(entry.peer_id) == 'abc'

    def test_integer_score_is_accepted_as_a_float(self):
        assert AutonomousTrust._reputation_entry({'peer_id': 'a', 'score': 1}).score == 1.0

    def test_missing_fields_are_refused(self):
        assert AutonomousTrust._reputation_entry({'score': 0.5}) is None
        assert AutonomousTrust._reputation_entry({'peer_id': 'a'}) is None

    def test_unparseable_score_is_refused(self):
        assert AutonomousTrust._reputation_entry({'peer_id': 'a', 'score': 'high'}) is None

    def test_anything_answering_peer_id_and_score_is_used_as_is(self):
        """The contract is the two attributes, not the class: a stand-in that
        answers them is passed through untouched (which is also how the existing
        automate tests drive this path)."""
        stand_in = MagicMock()
        stand_in.peer_id = 'abc'
        stand_in.score = 0.5
        assert AutonomousTrust._reputation_entry(stand_in) is stand_in

    def test_right_names_with_an_unusable_score_is_refused(self):
        """A string score is refused even from an object answering both names.

        Note the limit of a duck-typed check, deliberately not tested for: a
        bare MagicMock passes, because it answers every attribute AND defines
        __float__. That is a property of the test double, not of a payload — what
        actually arrives here is a deserialized Reputation, a mapping, or a
        scalar, and those are covered above and below."""
        stand_in = MagicMock()
        stand_in.peer_id = 'abc'
        stand_in.score = 'high'
        assert AutonomousTrust._reputation_entry(stand_in) is None

    def test_a_bare_value_is_not_guessed_at(self):
        # A score with no peer is not an observation of anything.
        for junk in ('nope', 0.5, None, ['a', 0.5]):
            assert AutonomousTrust._reputation_entry(junk) is None, junk


class TestPayloadNormalization:
    def test_single_reputation_becomes_one_entry(self):
        rep = Reputation('a', 0.5)
        assert _Consumer()._reputation_entries(rep) == [rep]

    def test_roster_json_string_becomes_many(self):
        """A gateway's subtree roster arrives as a JSON array string."""
        payload = to_json_string([Reputation('a', 0.5), Reputation('b', 0.25)])
        entries = _Consumer()._reputation_entries(payload)
        assert [str(e.peer_id) for e in entries] == ['a', 'b']
        assert [e.score for e in entries] == [0.5, 0.25]

    def test_c_shaped_json_string_becomes_one(self):
        payload = ('{"peer_uuid": "11111111-1111-1111-1111-111111111111", '
                   '"score": 0.25, "requesting_process": "monitor"}')
        entries = _Consumer()._reputation_entries(payload)
        assert len(entries) == 1
        assert entries[0].score == 0.25

    def test_one_bad_entry_does_not_lose_the_good_ones(self):
        """The loop this feeds services every inbound message, so a malformed
        reply must cost its own entry and nothing else."""
        consumer = _Consumer()
        entries = consumer._reputation_entries(
            [Reputation('a', 0.5), 'garbage', {'peer_id': 'b', 'score': 0.1}])
        assert [str(e.peer_id) for e in entries] == ['a', 'b']
        assert consumer.logger.warning.called

    def test_malformed_json_is_reported_not_raised(self):
        consumer = _Consumer()
        assert consumer._reputation_entries('{not json at all') == []
        assert consumer.logger.warning.called

    def test_warning_names_the_sender(self):
        """"Which peer is sending me nonsense" is the actionable part."""
        consumer = _Consumer()
        observer = MagicMock()
        observer.nickname = 'noaa-3'
        consumer._reputation_entries(['garbage'], observer=observer)
        assert 'noaa-3' in str(consumer.logger.warning.call_args)

    def test_empty_payload_is_empty_not_an_error(self):
        assert _Consumer()._reputation_entries([]) == []
