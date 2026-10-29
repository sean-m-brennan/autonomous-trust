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

/** @file The placement pool survives a restart (doc/architecture/
 *  reputation.md, "Agreeing on an order").
 *
 *  A committed half waits in the pool until a placement writes its entry. Its
 *  round is over, so nobody proposes it again: were every holder to restart
 *  before it is placed, it would be gone. Each placing chain's pool is written
 *  to reputation-pool[-<chain>].cfg.json when it changes and put back at boot.
 *  The document is pinned byte for byte against Python's (compact form). Mirrors
 *  tests/a_unit/test_placement_pool_persist.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/allocation.h"

/* tests/a_unit/test_placement_pool_persist.py PINNED, compact. */
static const char PINNED[] =
    "{\"schema\":2,\"pool\":[{\"task\":\"00000000-0000-4000-8000-000000000001\""
    ",\"halves\":[{\"by\":\"aaaaaaaa-0000-4000-8000-000000000001\",\"score_mill"
    "i\":750,\"cert\":{\"bbbbbbbb-0000-4000-8000-000000000002\":\"abcd\"}}]},{\""
    "task\":\"00000000-0000-4000-8000-000000000002\",\"halves\":[{\"by\":\"bbbb"
    "bbbb-0000-4000-8000-000000000002\",\"score_milli\":500,\"channel\":\"probe"
    "\"},{\"by\":\"aaaaaaaa-0000-4000-8000-000000000001\",\"score_milli\":250}]"
    "},{\"task\":\"a66df013-666a-5797-bd91-108aa7b0ed44\",\"attested\":true,\"p"
    "1\":\"aaaaaaaa-0000-4000-8000-000000000001\",\"p1_score_milli\":250,\"p1_c"
    "hannel\":\"probe\",\"subject\":\"bbbbbbbb-0000-4000-8000-000000000002\",\""
    "evidence_digest\":\"ababababababababababababababababababababababababababab"
    "ababababab\",\"attest_sigs\":{\"cccc\":\"ef01\"}}]}";

static const char T1[] = "00000000-0000-4000-8000-000000000001";
static const char T2[] = "00000000-0000-4000-8000-000000000002";
static const char A[] = "aaaaaaaa-0000-4000-8000-000000000001";
static const char B[] = "bbbbbbbb-0000-4000-8000-000000000002";

static process_t *_mk_process(void)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    return proc;
}

static void _half(const char *task, const char *by, double score)
{
    uuid_t t, b;
    uuid_parse(task, t);
    uuid_parse(by, b);
    ck_assert(reputation_record_half(t, b, tx_score_to_milli(score), NULL, NULL) >= 0);
}

static bool _pooled(const char *task)
{
    uuid_t want, got[8];
    uuid_parse(task, want);
    int n = reputation_get_pool_tasks(got, 8);
    for (int i = 0; i < n; i++)
        if (uuid_compare(got[i], want) == 0)
            return true;
    return false;
}

static void _pool_path(const char *dir, char *out, size_t cap)
{
    snprintf(out, cap, "%s/reputation-pool.cfg.json", dir);
}

DEFINE_TEST(test_pythons_document_reads_and_writes_back_byte_for_byte)
{
    reputation_reset_state(1);
    ck_assert_int_eq(reputation_pool_load_json(PINNED), 3);
    ck_assert(_pooled(T1) && _pooled(T2));
    char *text = reputation_pool_json();
    ck_assert_ptr_nonnull(text);
    ck_assert_str_eq(text, PINNED);
    free(text);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_what_was_placed_meanwhile_stays_out)
{
    reputation_reset_state(1);
    /* A chain on which T2 is placed, loaded as catch-up loads one. */
    tx_history_t tmp;
    tx_history_init(&tmp);
    uuid_t t, a, b;
    uuid_parse(T2, t);
    uuid_parse(A, a);
    uuid_parse(B, b);
    tx_history_record_half(&tmp, t, b, 500, NULL, NULL);
    tx_history_record_half(&tmp, t, a, 250, NULL, NULL);
    transaction_t ready[1];
    ck_assert_int_eq(tx_history_ready_items(&tmp, ready, 1), 1);
    tx_history_apply_placed(&tmp, 0, ready, 1, NULL);
    json_t *arr = NULL;
    tx_history_era_to_json(&tmp, 0, tx_history_len(&tmp), &arr);
    ck_assert_int_eq(reputation_install_chain_json(arr), 0);
    json_decref(arr);
    tx_history_free(&tmp);
    uuid_t placed[2];
    ck_assert_int_eq(reputation_get_chain_tasks(placed, 2), 1);
    reputation_pool_load_json(PINNED);
    ck_assert(_pooled(T1));
    ck_assert(!_pooled(T2));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_pool_survives_a_restart)
{
    char dir[] = "/tmp/at-pool-test-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    reputation_set_placement_dir(dir);
    reputation_reset_state(1);
    process_t *proc = _mk_process();
    reputation_restore_pool(proc);
    _half(T1, A, 0.75);
    _half(T2, A, 0.25);
    _half(T2, B, 0.5);
    reputation_persist_pools(proc);

    reputation_reset_state(1);           /* the restart: memory is gone */
    ck_assert(!_pooled(T1));
    reputation_restore_pool(proc);
    ck_assert(_pooled(T1) && _pooled(T2));

    char path[128];
    _pool_path(dir, path, sizeof(path));
    unlink(path);
    rmdir(dir);
    reputation_set_placement_dir(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unchanged_pool_is_not_rewritten)
{
    char dir[] = "/tmp/at-pool-test-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    reputation_set_placement_dir(dir);
    reputation_reset_state(1);
    process_t *proc = _mk_process();
    char path[128];
    struct stat sb;
    _pool_path(dir, path, sizeof(path));
    unsigned rev = reputation_pool_rev();
    _half(T1, A, 0.75);
    ck_assert(reputation_pool_rev() != rev);
    reputation_persist_pools(proc);
    ck_assert_int_eq(stat(path, &sb), 0);
    unlink(path);
    reputation_persist_pools(proc);
    ck_assert(stat(path, &sb) != 0);
    _half(T1, B, 0.5);
    reputation_persist_pools(proc);
    ck_assert_int_eq(stat(path, &sb), 0);

    unlink(path);
    rmdir(dir);
    reputation_set_placement_dir(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unreadable_pool_starts_empty)
{
    char dir[] = "/tmp/at-pool-test-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    char path[128];
    _pool_path(dir, path, sizeof(path));
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs("{not json", f);
    fclose(f);
    reputation_set_placement_dir(dir);
    reputation_reset_state(1);
    reputation_restore_pool(_mk_process());
    uuid_t got[4];
    ck_assert_int_eq(reputation_get_pool_tasks(got, 4), 0);
    unlink(path);
    rmdir(dir);
    reputation_set_placement_dir(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlacePoolPersist,
          test_pythons_document_reads_and_writes_back_byte_for_byte,
          test_what_was_placed_meanwhile_stays_out,
          test_the_pool_survives_a_restart,
          test_an_unchanged_pool_is_not_rewritten,
          test_an_unreadable_pool_starts_empty)
