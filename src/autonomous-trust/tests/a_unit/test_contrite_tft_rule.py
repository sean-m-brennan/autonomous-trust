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
"""The contrite tit-for-tat rule, over the scores I gave a peer (`given`) and
the scores it gave me (`got`), oldest first.

Hostile-join run, 2026-11-04: a few cooperative transactions took an honest
joiner straight to 0.9, tier 4, and colluders that kept failing sat at a 0.51
floor, tier 1. The rule now shrinks the peer's standing toward the neutral
prior, so trust grows with the record, and drops the floor:

- shrunk(given) = (sum(given) + k * neutral) / (n + k);
- a defection is a transaction where the peer scored me below 0.5;
- the latest is no defection, or the first after one that was not: shrunk;
- the latest two are both defections: min(shrunk, 0.49).

The C twin is reputation_ctft_score (src/c/test/reputation3_test.c).
"""
import pytest

from autonomous_trust.core._python.reputation.repprocess import contrite_tft_of

N, K = 0.2, 3.0


def _tft(given, got, neutral=N, k=K):
    return contrite_tft_of(given, got, neutral, k)


def test_one_cooperative_transaction_is_not_a_track_record():
    assert _tft([0.9], [0.9]) == pytest.approx((0.9 + K * N) / (1 + K))  # 0.375


def test_trust_grows_with_the_record():
    assert _tft([0.9] * 3, [0.9] * 3) == pytest.approx(0.55)
    assert _tft([0.9] * 10, [0.9] * 10) == pytest.approx(9.6 / 13)


def test_a_first_defection_is_forgiven():
    given, got = [0.9] * 6, [0.9] * 5 + [0.2]
    assert _tft(given, got) == pytest.approx(6.0 / 9)


def test_a_repeat_defection_is_capped_below_tier_one():
    given, got = [0.9] * 6, [0.9] * 4 + [0.2, 0.2]
    assert _tft(given, got) == pytest.approx(0.49)


def test_a_defection_after_a_recovery_is_a_first_again():
    given, got = [0.9] * 6, [0.9, 0.9, 0.9, 0.2, 0.9, 0.2]
    assert _tft(given, got) == pytest.approx(6.0 / 9)


def test_a_defection_is_read_from_the_peers_score_of_me():
    # Scores I gave it below 0.5 are its record, not a defection: no cap.
    given, got = [0.9] * 4 + [0.3, 0.3], [0.9] * 6
    assert _tft(given, got) == pytest.approx((4.2 + 0.6) / 9)


def test_there_is_no_floor():
    # A peer that keeps failing and keeps scoring me low sinks to its record.
    assert _tft([0.0] * 3, [0.2] * 3) == pytest.approx(0.1)
    assert _tft([0.1] * 6, [0.9] * 6) == pytest.approx(1.2 / 9)


def test_the_prior_and_its_weight_are_the_callers():
    assert _tft([0.9], [0.9], neutral=0.5, k=1.0) == pytest.approx(0.7)
