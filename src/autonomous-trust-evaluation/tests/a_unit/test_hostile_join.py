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
"""The hostile-join evaluation (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6): what the
join policy buys a joiner entering a colluding cohort. Pins the qualitative
result, small, so it runs with the suite."""
import os

import pytest

from autonomous_trust.evaluation.scenarios import hostile_join as hj


@pytest.fixture(autouse=True)
def _root(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(tmp_path / 'etc' / 'at', exist_ok=True)


def test_the_cohorts_word_alone_buys_tier_one_under_the_policy():
    assert hj.simulate(4, 'fail', False).told_tier_unprobed == 4
    assert hj.simulate(4, 'fail', True).told_tier_unprobed == 1


def test_failing_colluders_fall_only_under_the_policy():
    """Without it a colluding cohort's scores of itself outweigh the joiner's
    failed probes for the whole hour; with it the burst's verdicts take over
    once each colluder has own_evidence_min of them."""
    assert hj.simulate(4, 'fail', False).t_colluders is None
    with_policy = hj.simulate(4, 'fail', True)
    assert with_policy.t_colluders is not None
    assert with_policy.t_colluders <= 3 * 4 * 5.0


def test_the_burst_scales_with_the_cohort():
    small = hj.simulate(4, 'fail', True).t_colluders
    large = hj.simulate(8, 'fail', True).t_colluders
    assert small < large <= 3 * 8 * 5.0


def test_the_honest_contact_is_trusted_either_way():
    for policy in (False, True):
        assert hj.simulate(4, 'pass', policy).t_honest is not None
