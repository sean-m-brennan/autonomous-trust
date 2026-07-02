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
"""Resilience/threat M&S suite results (SOW Task 3.4), driving the behaviour
layer end-to-end over the threat-archetype population. Pins the M5 exit criteria:

  * a compromised-but-credentialed asset is detected and (governably) excluded
    under simulated attack;
  * the false-exclusion rate is reported against a realistic base rate; and
  * results are deterministic under a fixed seed.

and the load-bearing comparison: the governed ML sensor keeps near-zero false
exclusions (so precision survives the base-rate fallacy) where a static-policy
baseline does not. Runs the harness once (module-scoped) -- a few seconds.
"""
import pytest

from autonomous_trust.behaviour.redteam import (run, RedTeamConfig,
                                                COMPROMISED_CREDENTIAL, DDIL)

SEED = 1234


@pytest.fixture(scope='module')
def result():
    return run(RedTeamConfig(seed=SEED))


class TestDeterminism:
    def test_fixed_seed_reproduces_report(self):
        # admissibility: identical seed -> byte-identical metrics
        assert run(RedTeamConfig(seed=SEED)).as_report() == \
               run(RedTeamConfig(seed=SEED)).as_report()


class TestM5ExitCriteria:
    def test_compromised_credential_detected_and_excluded(self, result):
        # M5: the compromised-but-credentialed asset is detected + excluded.
        ml = result.ml
        assert ml.archetype_detection_rate(COMPROMISED_CREDENTIAL) == 1.0
        assert ml.tp >= 1                       # at least one true exclusion

    def test_false_exclusion_rate_is_reported(self, result):
        rep = result.as_report()['ml_governed_sensor']
        assert 'fpr_false_exclusion_rate' in rep
        assert 'ppv_at_base_rate' in rep        # reported against base rates
        assert set(rep['ppv_at_base_rate']) == {'0.10', '0.05', '0.01'}


class TestFalseExclusionDiscipline:
    def test_ml_never_excludes_benign_or_ddil(self, result):
        # the governed sensor's discipline: zero false exclusions, including the
        # benign-but-disrupted (DDIL) peers that look abnormal without malice.
        assert result.ml.fpr == 0.0
        assert result.ml.archetype_detection_rate(DDIL) == 0.0

    def test_static_baseline_false_excludes_ddil(self, result):
        # the contrast that motivates the learned per-peer envelope: a fixed
        # threshold excludes disrupted-but-benign peers wholesale.
        assert result.baseline.archetype_detection_rate(DDIL) == 1.0
        assert result.baseline.fpr > result.ml.fpr


class TestBaseRateFallacy:
    def test_ml_precision_survives_low_base_rate(self, result):
        # Axelsson: at a realistic 1% attack base rate the static baseline's
        # precision collapses (most alarms false), while the zero-FP governed
        # sensor stays precise -- the quantitative case for "ML proposes,
        # deterministic consensus disposes".
        ml = result.ml.ppv_at_base_rate(0.01)
        base = result.baseline.ppv_at_base_rate(0.01)
        assert ml >= 0.9
        assert base <= 0.1
        assert ml > base

    def test_ml_detects_faster_than_baseline(self, result):
        assert result.ml.latency_mean is not None
        assert result.baseline.latency_mean is not None
        assert result.ml.latency_mean < result.baseline.latency_mean


class TestReportShape:
    def test_population_and_confusion_total(self, result):
        m = result.ml
        assert m.tp + m.fp + m.fn + m.tn == result.population
        assert result.population == (30 + 8 + 8 + 5 + 5)   # default composition

    def test_markdown_renders(self, result):
        md = result.to_markdown()
        assert 'Resilience / Threat M&S' in md
        assert 'False-exclusion rate' in md and 'base-rate' in md

    def test_report_artifact_generator(self, tmp_path, capsys):
        # the SOW deliverable: a results artifact (markdown + JSON).
        import json
        from autonomous_trust.behaviour.redteam.__main__ import main
        out = tmp_path / 'redteam.json'
        main(['--seed', str(SEED), '--json', str(out)])
        assert 'Resilience / Threat M&S' in capsys.readouterr().out
        report = json.loads(out.read_text())
        assert report['seed'] == SEED
        assert 'ml_governed_sensor' in report and 'static_baseline' in report
