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
"""Unit tests for the unauthorized-access reduction M&S (SOW Task 2.4, -90%)."""
from autonomous_trust.evaluation.mns.unauthorized import (
    GAPS_CLOSED_PAT, TAXONOMY, UnauthorizedConfig, run)


def test_taxonomy_weights_sum_to_one():
    assert abs(sum(t.weight for t in TAXONOMY) - 1.0) < 1e-9


def test_deterministic_under_seed():
    a = run(UnauthorizedConfig(seed=42, n_attempts=8000))
    b = run(UnauthorizedConfig(seed=42, n_attempts=8000))
    assert a.total_baseline == b.total_baseline
    assert a.total_at == b.total_at
    assert a.projected_at_gaps_closed == b.projected_at_gaps_closed


def test_at_reduces_unauthorized_access_substantially():
    r = run(UnauthorizedConfig(seed=1234))
    assert r.total_at < r.total_baseline
    # Honest modeled result: high but below the 90% target with current residuals.
    assert 0.80 < r.reduction < 0.90
    assert not r.meets_target


def test_closing_tracked_gaps_reaches_target():
    r = run(UnauthorizedConfig(seed=1234))
    assert r.reduction_gaps_closed > r.reduction
    assert r.reduction_gaps_closed >= 0.90


def test_compromised_credential_fully_blocked_by_at():
    # The M5 exit / headline behavioural case: p_at = 0.00 (measured 1.00 TPR).
    r = run(UnauthorizedConfig(seed=7))
    vca = next(o for o in r.per_type if o.atype.key == 'valid_cred_abuse')
    assert vca.success_at == 0
    assert vca.success_baseline > 0


def test_residual_lives_in_tracked_gaps():
    # The two gap keys must be exactly those with a GAPS_CLOSED override, and each
    # must currently leak more than the (already-closed) compromised-cred row.
    assert set(GAPS_CLOSED_PAT) == {'cred_replay', 'sybil_admission'}
    r = run(UnauthorizedConfig(seed=7))
    by = {o.atype.key: o for o in r.per_type}
    assert by['cred_replay'].success_at > 0
    assert by['sybil_admission'].success_at > 0


def test_report_shape():
    rep = run(UnauthorizedConfig(seed=1)).as_report()
    assert rep['modeled'] is True
    assert rep['baseline'].startswith('ZTA-only')
    assert len(rep['per_attack']) == len(TAXONOMY)
    assert 'reduction_projected_gaps_closed' in rep
