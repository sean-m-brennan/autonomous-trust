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
"""Unit tests for access-stream feature extraction (SOW Task 3.1)."""
from autonomous_trust.behaviour import AccessEvent, BehaviorFeatures, FEATURE_NAMES


def _steady_stream(bf, n=80, dt=1.0, caps=('a', 'b'), start=0.0,
                   refused=False, score=None, counterparties=('x', 'y')):
    """A regular, low-entropy baseline access stream."""
    t = start
    for i in range(n):
        bf.observe(AccessEvent(
            time=t, capability=caps[i % len(caps)], refused=refused,
            score=score, counterparty=counterparties[i % len(counterparties)]))
        t += dt
    return t


class TestFeatureContract:
    def test_vector_matches_named_order_and_bounds(self):
        bf = BehaviorFeatures(window=32)
        _steady_stream(bf, n=40)
        vec = bf.vector()
        named = bf.named()
        assert len(vec) == BehaviorFeatures.n_features() == len(FEATURE_NAMES)
        assert vec == [named[name] for name in FEATURE_NAMES]
        assert all(0.0 <= v <= 1.0 for v in vec)

    def test_deterministic(self):
        a, b = BehaviorFeatures(window=32), BehaviorFeatures(window=32)
        ta = _steady_stream(a, n=50)
        tb = _steady_stream(b, n=50)
        assert ta == tb
        assert a.vector() == b.vector()

    def test_empty_is_neutral_and_bounded(self):
        bf = BehaviorFeatures()
        vec = bf.vector()
        assert all(0.0 <= v <= 1.0 for v in vec)
        # txn_score defaults neutral (0.5) with no transactions observed
        assert bf.named()['txn_score'] == 0.5


class TestFeatureSemantics:
    def test_refusal_rate_tracks_refusals(self):
        bf = BehaviorFeatures(window=20)
        # 20 events, every 4th refused -> ~0.25 refusal rate
        t = 0.0
        for i in range(20):
            bf.observe(AccessEvent(time=t, capability='a', refused=(i % 4 == 0)))
            t += 1.0
        assert abs(bf.named()['refusal'] - 0.25) < 0.06

    def test_capability_entropy_low_for_single_cap_high_for_mixed(self):
        single = BehaviorFeatures(window=40)
        _steady_stream(single, n=40, caps=('only',))
        mixed = BehaviorFeatures(window=40)
        _steady_stream(mixed, n=40, caps=('a', 'b', 'c', 'd'))
        assert single.named()['cap_entropy'] == 0.0
        assert mixed.named()['cap_entropy'] > 0.8

    def test_sequence_predictability_drops_on_novel_transitions(self):
        bf = BehaviorFeatures(window=40)
        # learn a strict a->b->a->b cycle
        _steady_stream(bf, n=60, caps=('a', 'b'))
        assert bf.named()['seq_predict'] > 0.9
        # now inject a long run of never-seen capabilities (> window) so the
        # recent-transition window fills with novel transitions
        t = 100.0
        for i in range(45):
            bf.observe(AccessEvent(time=t, capability=f'novel{i}'))
            t += 1.0
        assert bf.named()['seq_predict'] < 0.2

    def test_timing_irregularity_higher_for_jittery_stream(self):
        regular = BehaviorFeatures(window=40)
        _steady_stream(regular, n=40, dt=1.0)
        jittery = BehaviorFeatures(window=40)
        t = 0.0
        gaps = [0.1, 5.0, 0.2, 4.0, 0.1, 6.0]
        for i in range(40):
            jittery.observe(AccessEvent(time=t, capability='a'))
            t += gaps[i % len(gaps)]
        assert jittery.named()['timing'] > regular.named()['timing']

    def test_burst_rises_on_a_sudden_burst(self):
        bf = BehaviorFeatures(window=64, fast_half_life=2.0, slow_half_life=60.0)
        # a slow steady baseline...
        t = _steady_stream(bf, n=60, dt=5.0, caps=('a',))
        baseline_burst = bf.named()['burst']
        # ...then a rapid burst (fast rate >> slow rate)
        for _ in range(20):
            bf.observe(AccessEvent(time=t, capability='a'))
            t += 0.05
        assert bf.named()['burst'] > baseline_burst

    def test_cohort_diversity_tracks_distinct_counterparties(self):
        narrow = BehaviorFeatures(window=40)
        _steady_stream(narrow, n=40, counterparties=('solo',))
        wide = BehaviorFeatures(window=40)
        _steady_stream(wide, n=40, counterparties=('p', 'q', 'r', 's', 't'))
        assert narrow.named()['cohort'] == 0.0
        assert wide.named()['cohort'] > 0.8

    def test_txn_score_tracks_recent_scores(self):
        good = BehaviorFeatures(window=20)
        _steady_stream(good, n=20, score=0.9)
        bad = BehaviorFeatures(window=20)
        _steady_stream(bad, n=20, score=0.1)
        assert good.named()['txn_score'] > 0.8
        assert bad.named()['txn_score'] < 0.2


class TestBoundedMemory:
    def test_window_and_known_set_are_capped(self):
        bf = BehaviorFeatures(window=16, known_cap_seqs_cap=8)
        t = 0.0
        for i in range(1000):
            bf.observe(AccessEvent(time=t, capability=f'c{i}'))
            t += 1.0
        assert len(bf._events) == 16            # window deque capped
        assert len(bf._known_transitions) <= 8  # transition memory capped
        assert bf.count == 1000                 # but the counter is exact
