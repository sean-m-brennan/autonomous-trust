/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

/**
 * @file timeout_scale_test.c
 * @brief Unit tests for at_timeout_apply_scale() — the pure arithmetic
 *        kernel of the timeout-adaptation layer.
 *
 * The full at_timeout_scale_ms(base, proc) needs a process_t with a
 * populated peer_rtt_ms[]; that path is exercised indirectly by the
 * consumers. Here we pin down the invariants of the scaler itself.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include "utilities/timeout.h"

DEFINE_TEST(test_scale_fast_lan_is_noop)
{
    /* Pure-LAN deployment: max_rtt ≈ 50 ms × multiplier=3 = 150 ms.
     * base = 10_000 ms → scaler clamps to base (no slowdown). */
    ck_assert_int_eq(at_timeout_apply_scale(10000, 50, 3), 10000);
    ck_assert_int_eq(at_timeout_apply_scale(10000, 50, AT_TIMEOUT_DEFAULT_MULTIPLIER),
                     10000);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_dtn_expands_timeout)
{
    /* DTN link: max_rtt = 60_000 ms × multiplier=3 = 180_000 ms.
     * base = 10_000 ms → scaler returns 180_000. */
    ck_assert_int_eq(at_timeout_apply_scale(10000, 60000, 3), 180000);

    /* Higher multiplier amplifies further. */
    ck_assert_int_eq(at_timeout_apply_scale(10000, 60000, 10), 600000);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_never_shrinks_below_base)
{
    /* Even with very small RTT, scaler returns at least base. */
    ck_assert_int_eq(at_timeout_apply_scale(5000, 1, 1), 5000);
    ck_assert_int_eq(at_timeout_apply_scale(5000, 0, 1), 5000);
    /* Zero RTT (unknown) handled gracefully. */
    ck_assert_int_eq(at_timeout_apply_scale(5000, 0, AT_TIMEOUT_DEFAULT_MULTIPLIER),
                     5000);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_multiplier_defaults_when_zero_or_negative)
{
    /* multiplier <= 0 → use DEFAULT (= 3). */
    int expected = 50 * AT_TIMEOUT_DEFAULT_MULTIPLIER;  /* 150 */
    /* base=0 so the scaled value wins; otherwise clamped to base. */
    ck_assert_int_eq(at_timeout_apply_scale(0, 50, 0),    expected);
    ck_assert_int_eq(at_timeout_apply_scale(0, 50, -5),   expected);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_negative_rtt_treated_as_zero)
{
    /* Defensive: a negative RTT from a misbehaving link_class_ms should
     * not produce a negative or overflowed timeout. */
    ck_assert_int_eq(at_timeout_apply_scale(5000, -1000, 3), 5000);
    ck_assert_int_eq(at_timeout_apply_scale(5000, -1,    3), 5000);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_no_overflow_at_extreme_values)
{
    /* max_rtt * multiplier must not overflow int. The helper promotes
     * to long internally and clamps to INT_MAX on overflow. */
    int result = at_timeout_apply_scale(1000, 1000000, 10000);  /* 10^10 ms */
    ck_assert_int_eq(result, 0x7FFFFFFF);
    ck_assert(result > 0);  /* no sign flip */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_scale_ms_null_proc_returns_base)
{
    /* Pass-through when proc is NULL — LAN-only fallback. */
    ck_assert_int_eq(at_timeout_scale_ms(10000, NULL), 10000);
    ck_assert_int_eq(at_timeout_scale_ms(250,   NULL), 250);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scale_monotonic_in_multiplier)
{
    /* For fixed (base, rtt), increasing the multiplier never shrinks
     * the result. */
    int base = 1000, rtt = 200;
    int prev = at_timeout_apply_scale(base, rtt, 1);
    for (int m = 2; m <= 20; m++) {
        int cur = at_timeout_apply_scale(base, rtt, m);
        ck_assert(cur >= prev);
        prev = cur;
    }
}
END_TEST_DEFINITION()

RUN_TESTS(Timeout_Scale,
          test_scale_fast_lan_is_noop,
          test_scale_dtn_expands_timeout,
          test_scale_never_shrinks_below_base,
          test_scale_multiplier_defaults_when_zero_or_negative,
          test_scale_negative_rtt_treated_as_zero,
          test_scale_no_overflow_at_extreme_values,
          test_scale_scale_ms_null_proc_returns_base,
          test_scale_monotonic_in_multiplier)
