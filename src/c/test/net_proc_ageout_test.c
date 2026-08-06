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

/**
 * @file net_proc_ageout_test.c
 * @brief Tests for the deferred-message ("mystery handler") age-out + overflow
 *        eviction. The C node retries deferred encrypted messages on peer
 *        admission (event-driven, unlike Python's polling thread); these cover
 *        the reclamation half that keeps the bounded queue self-cleaning so a
 *        burst of un-resolvable frames can't permanently starve legitimate
 *        deferrals. Mirrors Python netprocess.py mystery_max_retries age-out.
 *
 * Unconditional (not AT_NET_ENVELOPE-gated): the age-out path lives in the
 * always-compiled defer_message, and these tests use the non-envelope
 * (from_addr-keyed) defer path via the net_proc_test_* hooks. Time is driven
 * deterministically with AT_MYSTERY_MAX_AGE_SEC + net_proc_test_backdate_deferred
 * — no sleeping.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>

#include "network/net_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

DEFINE_TEST(test_age_out_sweep_evicts_stale)
{
    /* With a 10s window, fresh entries survive a sweep; once backdated past
     * the window they are reclaimed. */
    setenv("AT_MYSTERY_MAX_AGE_SEC", "10", 1);
    net_proc_test_reset_deferred();

    uint8_t pay[4] = {1, 2, 3, 4};
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.1");
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.2");
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.3");
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 3);

    /* Nothing aged yet → sweep keeps all 3. */
    ck_assert_int_eq((int)net_proc_test_sweep_stale(), 3);

    /* Jump 11s past the window → all reclaimed. */
    net_proc_test_backdate_deferred(11);
    ck_assert_int_eq((int)net_proc_test_sweep_stale(), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 0);

    net_proc_test_reset_deferred();
    unsetenv("AT_MYSTERY_MAX_AGE_SEC");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_age_out_partial)
{
    /* Only entries past the window are reclaimed; fresher ones survive. */
    setenv("AT_MYSTERY_MAX_AGE_SEC", "10", 1);
    net_proc_test_reset_deferred();

    uint8_t pay[4] = {1, 2, 3, 4};
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.1");
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.2");
    /* Age these two past the window. */
    net_proc_test_backdate_deferred(11);
    /* A fresh one (defer's own sweep first drops the two stale → count 1). */
    net_proc_test_defer(pay, sizeof(pay), "10.0.0.3");
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);

    net_proc_test_reset_deferred();
    unsetenv("AT_MYSTERY_MAX_AGE_SEC");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_defer_self_cleans_under_pressure)
{
    /* defer_message sweeps before inserting, so deferring after time passes
     * reclaims aged slots without any polling thread. */
    setenv("AT_MYSTERY_MAX_AGE_SEC", "5", 1);
    net_proc_test_reset_deferred();

    uint8_t pay[4] = {9, 8, 7, 6};
    for (int i = 0; i < 10; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "10.1.0.%d", i);
        net_proc_test_defer(pay, sizeof(pay), addr);
    }
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 10);

    net_proc_test_backdate_deferred(6);          /* all now stale */
    net_proc_test_defer(pay, sizeof(pay), "10.1.0.99");  /* sweep drops 10 */
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);

    net_proc_test_reset_deferred();
    unsetenv("AT_MYSTERY_MAX_AGE_SEC");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_overflow_evicts_oldest_admits_newest)
{
    /* Full of fresh (un-aged) entries: a new deferral FIFO-evicts the OLDEST
     * so the newest is admitted, vs. the old behaviour that dropped the new. */
    setenv("AT_MYSTERY_MAX_AGE_SEC", "100000", 1);  /* disable age-out here */
    net_proc_test_reset_deferred();

    uint8_t pay[4] = {1, 2, 3, 4};
    char addr[32];
    for (int i = 0; i < 64; i++) {            /* MAX_DEFERRED */
        snprintf(addr, sizeof(addr), "10.0.%d.%d", i / 256, i % 256);
        net_proc_test_defer(pay, sizeof(pay), addr);
    }
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 64);

    /* One more fresh, distinct sender → still 64 (oldest evicted, not newest). */
    net_proc_test_defer(pay, sizeof(pay), "10.9.9.9");
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 64);

    /* Newest present at the tail (matched by from_addr in non-envelope mode). */
    public_identity_t newest = {0};
    uuid_fill(newest.uuid, 0xF0);  /* ignored: entry has no src_uuid */
    snprintf(newest.address, sizeof(newest.address), "%s", "10.9.9.9");
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(63, &newest), 1);

    /* Original oldest occupant of slot 0 is gone (evicted). */
    public_identity_t oldest = {0};
    snprintf(oldest.address, sizeof(oldest.address), "%s", "10.0.0.0");
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &oldest), 0);

    net_proc_test_reset_deferred();
    unsetenv("AT_MYSTERY_MAX_AGE_SEC");
}
END_TEST_DEFINITION()

RUN_TESTS(Net_Proc_Ageout,
          test_age_out_sweep_evicts_stale,
          test_age_out_partial,
          test_defer_self_cleans_under_pressure,
          test_overflow_evicts_oldest_admits_newest)
