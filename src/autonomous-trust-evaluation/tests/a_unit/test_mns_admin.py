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
"""Unit tests for the admin-overhead M&S (SOW Task 2.4, -25% net)."""
from autonomous_trust.evaluation.mns.admin import (
    AdminConfig, MissionValorMock, run, sweep)


def test_missionvalor_mock_mapping():
    mv = MissionValorMock()
    assert mv.derive(0.95) == (4, True)
    assert mv.derive(0.80) == (3, True)
    assert mv.derive(0.50) == (2, False)
    assert mv.derive(0.10) == (0, False)


def test_meets_target_at_representative_tempo():
    r = run(AdminConfig())                 # tempo x1
    assert r.meets_target
    assert 0.25 < r.net_reduction < 0.50   # honest, not a runaway claim


def test_at_added_classes_have_zero_baseline_and_positive_at():
    r = run(AdminConfig())
    added = [c for c in r.classes if c.added]
    assert {c.key for c in added} == {
        'operator_activation', 'false_exclusion', 'model_oversight'}
    for c in added:
        assert c.baseline == 0.0 and c.at > 0.0 and c.delta < 0.0


def test_reduced_classes_save():
    r = run(AdminConfig())
    for c in r.classes:
        if not c.added:
            assert c.baseline > c.at        # AT reduces these


def test_tempo_conditional_monotonic():
    rows = sweep()
    # Net reduction grows monotonically with tempo.
    nets = [row.net_reduction for row in rows]
    assert nets == sorted(nets)
    # Low tempo falls below the -25% target (added burden dominates); high tempo
    # clears it -- the honest conditionality.
    assert rows[0].net_reduction < 0.25
    assert rows[-1].net_reduction >= 0.25


def test_report_shape():
    rep = run(AdminConfig()).as_report()
    assert rep['modeled'] is True and rep['analytic'] is True
    assert len(rep['per_class']) == 7
    assert rep['meets_25pct_target'] in (True, False)
