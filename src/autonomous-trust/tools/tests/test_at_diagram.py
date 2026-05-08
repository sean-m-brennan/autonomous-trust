# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

import shutil
from pathlib import Path

import pytest

from .. import at_diagram


_FIX = Path(__file__).resolve().parent / 'fixtures'


# ---------------------------------------------------------------------------
# Render rule coverage (one assertion per row of the rendering-rules table).
# ---------------------------------------------------------------------------


def _render(scenario: dict) -> str:
    return at_diagram.render(scenario)


def _base_scenario(steps: list[dict] | None = None,
                   participants: list[dict] | None = None) -> dict:
    return {
        'schema_version': '1',
        'kind': 'scenario',
        'protocol': 'identity',
        'name': 'unit-fixture',
        'participants': participants or [
            {'id': 'a', 'role': 'r1'},
            {'id': 'b', 'role': 'r2'},
        ],
        'steps': steps or [],
    }


class TestRenderRules:
    def test_header_is_fixed(self):
        out = _render(_base_scenario())
        assert out.startswith('sequenceDiagram\n')

    def test_participants_emit_in_order(self):
        out = _render(_base_scenario(participants=[
            {'id': 'p1', 'role': 'rA'},
            {'id': 'p2', 'role': 'rB'},
        ]))
        lines = out.splitlines()
        assert '    participant p1 as rA' in lines
        assert '    participant p2 as rB' in lines
        assert lines.index('    participant p1 as rA') < lines.index('    participant p2 as rB')

    def test_broadcast_step_renders_note_over(self):
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'broadcast', 'function': 'shout'},
        ]))
        assert '    Note over a: broadcast: shout' in out

    def test_direct_step_with_no_response_uses_solid_arrow(self):
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping'},
        ]))
        # No later step references step 1, so no activation +
        assert '    a->>b: ping' in out

    def test_direct_step_with_response_uses_dashed_arrow_and_re_clause(self):
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping'},
            {'id': 2, 'from': 'b', 'to': 'a', 'function': 'pong', 'in_response_to': 1},
        ]))
        # Step 1's recipient (b) is activated because step 2 replies to it.
        assert '    a->>+b: ping' in out
        # Step 2 is the response: dashed arrow, deactivates b, has (re: 1) clause.
        assert '    b-->>-a: pong (re: 1)' in out

    def test_description_renders_as_note_right_of(self):
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping',
             'description': 'this is a note'},
        ]))
        assert '    Note right of a: this is a note' in out

    def test_multiline_description_collapsed_to_single_line(self):
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping',
             'description': 'first line\n\nsecond line'},
        ]))
        # Collapsed so Mermaid doesn't try to interpret embedded newlines.
        assert '    Note right of a: first line second line' in out

    def test_annotate_state_emits_note_over(self):
        scenario = _base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping'},
        ])
        scenario['expected_state'] = {'a': {'phase': 3, 'peer_count': 2}}
        out = at_diagram.render(scenario, at_diagram.RenderOptions(annotate_state=True))
        assert '    Note over a: state: phase=3' in out
        assert '    Note over a: state: peer_count=2' in out

    def test_annotate_state_off_by_default(self):
        scenario = _base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping'},
        ])
        scenario['expected_state'] = {'a': {'phase': 3}}
        out = _render(scenario)
        assert 'state:' not in out

    def test_only_first_reply_deactivates_when_multiple_children(self):
        """When two steps reply to the same parent, only the first deactivates.

        Activation/deactivation in Mermaid is paired; the spec defines
        deactivation as 'when its reply is sent', singular, so a second
        reply to the same parent does not double-deactivate.
        """
        out = _render(_base_scenario(steps=[
            {'id': 1, 'from': 'a', 'to': 'b', 'function': 'ping'},
            {'id': 2, 'from': 'b', 'to': 'a', 'function': 'pong1', 'in_response_to': 1},
            {'id': 3, 'from': 'b', 'to': 'a', 'function': 'pong2', 'in_response_to': 1},
        ]))
        assert '    a->>+b: ping' in out
        assert '    b-->>-a: pong1 (re: 1)' in out  # first reply deactivates
        assert '    b-->>a: pong2 (re: 1)' in out  # second reply does NOT


# ---------------------------------------------------------------------------
# Golden file — exact-byte equivalence on a multi-rule fixture.
# ---------------------------------------------------------------------------


class TestGoldenFile:
    def test_sample_scenario_matches_expected_mmd(self):
        data = at_diagram.load_scenario(_FIX / 'sample-scenario.yaml')
        actual = at_diagram.render(data)
        expected = (_FIX / 'sample-scenario.mmd').read_text(encoding='utf-8')
        assert actual == expected, (
            f'\nGOLDEN MISMATCH\n--- expected ---\n{expected}--- actual ---\n{actual}'
        )

    def test_render_is_byte_stable(self):
        data = at_diagram.load_scenario(_FIX / 'sample-scenario.yaml')
        first = at_diagram.render(data)
        second = at_diagram.render(data)
        assert first == second


# ---------------------------------------------------------------------------
# Loader and validation
# ---------------------------------------------------------------------------


class TestLoad:
    def test_load_validates_against_schema(self, tmp_path):
        bad = tmp_path / 'bad.yaml'
        bad.write_text(
            'schema_version: "1"\nkind: scenario\nprotocol: identity\n'
            'name: x\nparticipants: []\nsteps:\n  - id: 1\n    from: a\n'
            '    to: b\n    function: f\n',
            encoding='utf-8',
        )
        # participants minItems=1 — this should fail validation.
        with pytest.raises(ValueError, match='schema'):
            at_diagram.load_scenario(bad)

    def test_load_skips_validation_when_asked(self, tmp_path):
        # A doc that's not even a scenario kind passes when validate=False.
        odd = tmp_path / 'odd.yaml'
        odd.write_text('schema_version: "1"\nkind: scenario\nfoo: bar\n', encoding='utf-8')
        data = at_diagram.load_scenario(odd, validate=False)
        assert data['foo'] == 'bar'


# ---------------------------------------------------------------------------
# --check drift detection
# ---------------------------------------------------------------------------


class TestCheck:
    def test_clean_real_scenario(self):
        # An existing real scenario should be clean for unrecognized functions
        # (we can't claim "unexercised" because the corpus is incomplete).
        path = (
            at_diagram.CORPUS_ROOT / 'scenarios' / 'identity'
            / 'amnesia-readmission.yaml'
        )
        report = at_diagram.check(path)
        assert report.unrecognized_functions == []
        assert report.schema_violations == []

    def test_unrecognized_function_flagged(self):
        report = at_diagram.check(_FIX / 'broken-function.yaml')
        assert 'definitely_not_a_real_function' in report.unrecognized_functions
        assert not report.is_clean

    def test_unexercised_functions_for_negotiation(self):
        # NegotiationProtocol defines `start` ('spawn task'), 'haggle',
        # 'report results' — the corpus's invite/status scenarios don't
        # exercise all of them. --check should surface that.
        path = (
            at_diagram.CORPUS_ROOT / 'scenarios' / 'negotiation'
            / 'invite-accept.yaml'
        )
        report = at_diagram.check(path)
        # Don't pin the exact unexercised list — additions over time would
        # break it. Just verify there is at least one entry.
        assert len(report.unexercised_functions) >= 1


# ---------------------------------------------------------------------------
# --embed
# ---------------------------------------------------------------------------


class TestEmbed:
    def test_embed_replaces_marked_block(self, tmp_path):
        target = tmp_path / 'doc.md'
        shutil.copyfile(_FIX / 'doc-with-markers.md', target)
        ok = at_diagram.embed(target)
        assert ok is True
        text = target.read_text(encoding='utf-8')
        # The placeholders should be gone, replaced by mermaid blocks.
        assert 'PLACEHOLDER' not in text
        assert '```mermaid' in text
        # Both marker pairs were processed.
        assert text.count('```mermaid') == 2
        # Surrounding text preserved.
        assert 'Some intro text' in text
        assert 'Trailing text' in text

    def test_embed_is_idempotent(self, tmp_path):
        target = tmp_path / 'doc.md'
        shutil.copyfile(_FIX / 'doc-with-markers.md', target)
        at_diagram.embed(target)
        first = target.read_text(encoding='utf-8')
        at_diagram.embed(target)
        second = target.read_text(encoding='utf-8')
        assert first == second

    def test_embed_errors_on_missing_close_marker(self, tmp_path):
        bad = tmp_path / 'bad.md'
        bad.write_text(
            '<!-- at_diagram:start protocol=identity scenario=amnesia-readmission -->\n'
            'no close marker\n',
            encoding='utf-8',
        )
        ok = at_diagram.embed(bad)
        assert ok is False

    def test_embed_errors_on_missing_attrs(self, tmp_path):
        bad = tmp_path / 'bad.md'
        bad.write_text(
            '<!-- at_diagram:start -->\n'
            '<!-- at_diagram:end -->\n',
            encoding='utf-8',
        )
        ok = at_diagram.embed(bad)
        assert ok is False


# ---------------------------------------------------------------------------
# Smoke: render every real scenario in the corpus without crashing.
# ---------------------------------------------------------------------------


class TestSmoke:
    def test_renders_all_existing_scenarios(self):
        scenario_dir = at_diagram.CORPUS_ROOT / 'scenarios'
        if not scenario_dir.is_dir():
            pytest.skip('no scenarios directory')
        rendered_count = 0
        for path in sorted(scenario_dir.rglob('*.yaml')):
            if path.name.startswith(('.', '_')):
                continue
            data = at_diagram.load_scenario(path)
            out = at_diagram.render(data)
            assert out.startswith('sequenceDiagram\n'), f'{path}'
            rendered_count += 1
        assert rendered_count >= 5  # at minimum the phases C/E/F scenarios
