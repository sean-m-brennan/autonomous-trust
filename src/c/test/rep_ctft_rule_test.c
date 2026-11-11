/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

/** @file The contrite tit-for-tat rule (reputation_ctft_score).
 *
 *  Hostile-join run, 2026-11-04: a few cooperative transactions took an
 *  honest joiner straight to 0.9, tier 4, and colluders that kept failing sat
 *  at a 0.51 floor, tier 1. The rule now shrinks the peer's standing toward
 *  the neutral prior, so trust grows with the record, and drops the floor. A
 *  defection is a transaction where the peer scored this node below 0.5; the
 *  first is forgiven, and two in a row hold the score at min(standing, 0.49).
 *  The Python twin is tests/a_unit/test_contrite_tft_rule.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include "reputation/reputation.h"

/* Each case passes the sum of the scores this node gave the peer, their
 * count, and the last two scores the peer gave this node (-1: none). */
#define K_ PREREP_SHRINKAGE_K
#define N_ PREREP_NEUTRAL

DEFINE_TEST(test_ctft_one_cooperative_transaction_is_not_a_track_record)
{
    ck_assert_double_eq_tol(reputation_ctft_score(0.9, 1, 0.9, -1.0),
                            (0.9 + K_ * N_) / (1 + K_), 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_trust_grows_with_the_record)
{
    ck_assert_double_eq_tol(reputation_ctft_score(2.7, 3, 0.9, 0.9), 0.55, 1e-9);
    ck_assert_double_eq_tol(reputation_ctft_score(9.0, 10, 0.9, 0.9), 9.6 / 13, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_a_first_defection_is_forgiven)
{
    ck_assert_double_eq_tol(reputation_ctft_score(5.4, 6, 0.2, 0.9), 6.0 / 9, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_a_repeat_defection_is_capped_below_tier_one)
{
    ck_assert_double_eq_tol(reputation_ctft_score(5.4, 6, 0.2, 0.2), 0.49, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_a_defection_after_a_recovery_is_a_first_again)
{
    /* got: 0.9 0.9 0.9 0.2 0.9 0.2 -- the last two are 0.9 then 0.2. */
    ck_assert_double_eq_tol(reputation_ctft_score(5.4, 6, 0.2, 0.9), 6.0 / 9, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_a_defection_is_read_from_the_peers_score_of_me)
{
    /* given: four 0.9 and two 0.3 -- its record, not a defection. */
    ck_assert_double_eq_tol(reputation_ctft_score(4.2, 6, 0.9, 0.9),
                            (4.2 + 0.6) / 9, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ctft_there_is_no_floor)
{
    ck_assert_double_eq_tol(reputation_ctft_score(0.0, 3, 0.2, 0.2), 0.1, 1e-9);
    ck_assert_double_eq_tol(reputation_ctft_score(0.6, 6, 0.9, 0.9), 1.2 / 9, 1e-9);
}
END_TEST_DEFINITION()

/* Two failed probes in a row (reputation_probe_hold): the latest two of our
 * probe verdicts about a peer, both below 0.5 (-1: none). A gamer that turned
 * on its known answers kept tier 2..3 for twelve minutes (red-team batch,
 * 2026-11-10). Mirrors test_probe_hold_of_reads_the_latest_two_only in
 * tests/a_unit/test_probe_failure_hold.py. */
DEFINE_TEST(test_probe_hold_needs_two_failures_running)
{
    ck_assert(reputation_probe_hold(0.1, 0.1));
    ck_assert(!reputation_probe_hold(0.1, 0.9));
    ck_assert(!reputation_probe_hold(0.9, 0.1));
    ck_assert(!reputation_probe_hold(0.1, -1.0));
    ck_assert(!reputation_probe_hold(-1.0, -1.0));
    /* An out-of-tolerance time attestation scores 0.5: drift, not failure. */
    ck_assert(!reputation_probe_hold(0.1, 0.5));
    ck_assert_double_eq_tol(REP_PROBE_HOLD, 0.49, 1e-12);
}
END_TEST_DEFINITION()

RUN_TESTS(RepCtftRule,
          test_probe_hold_needs_two_failures_running,
          test_ctft_one_cooperative_transaction_is_not_a_track_record,
          test_ctft_trust_grows_with_the_record,
          test_ctft_a_first_defection_is_forgiven,
          test_ctft_a_repeat_defection_is_capped_below_tier_one,
          test_ctft_a_defection_after_a_recovery_is_a_first_again,
          test_ctft_a_defection_is_read_from_the_peers_score_of_me,
          test_ctft_there_is_no_floor)
