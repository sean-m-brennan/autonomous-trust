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

/* Unit tests for the data-source producer-side TransactionScore helpers that
 * let a C microdrone earn reputation: _ts_keep (per-batch decimation, which
 * MUST agree byte-for-byte with the Python _ts_keep) and _batch_task_id (the
 * metadata.task_id extraction that gates whether a batch gets scored). The
 * full producer-score → Paxos commit needs a live fleet (test-interop-cpython
 * .sh); these lock the pure decision logic. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <jansson.h>

#include "autonomous_trust/data_source/data_source_proc_priv.h"

/* _ts_keep parity vectors. The expected column was computed with the REAL
 * Python _ts_keep (examples/dod_mission/participant.py):
 *   int(task_id.replace('-','')[:8], 16) % denom == 0
 * Keep these in lockstep — a divergence here is a silent loss of bilateral
 * pairing (the coordinator and C producer would score different batches). */
DEFINE_TEST(test_ts_keep_python_parity)
{
    struct { const char *task_id; int denom; int expect; } cases[] = {
        { "00000000-0000-4000-8000-000000000000", 30, 1 },  /* 0 % 30 == 0 */
        { "0000001e-0000-4000-8000-000000000000", 30, 1 },  /* 0x1e=30 -> 0 */
        { "0000001d-0000-4000-8000-000000000000", 30, 0 },  /* 29 */
        { "00000002-0000-4000-8000-000000000000",  2, 1 },  /* even */
        { "00000003-0000-4000-8000-000000000000",  2, 0 },  /* odd  */
        { "ffffffff-0000-4000-8000-000000000000", 30, 0 },  /* 4294967295 % 30 = 15 */
        { "deadbeef-0000-4000-8000-000000000000", 30, 0 },  /* % 30 = 29 */
        { "12345678-0000-4000-8000-000000000000",  7, 0 },  /* % 7 = 5 */
        { "abcdefab-0000-4000-8000-000000000000",  1, 1 },  /* denom 1 -> always */
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        bool got = _ts_keep(cases[i].task_id, cases[i].denom);
        ck_assert_int_eq(got ? 1 : 0, cases[i].expect);
    }
}

/* denom <= 1 always keeps; a malformed (too-short) task_id is rejected. */
DEFINE_TEST(test_ts_keep_edge_cases)
{
    ck_assert_int_eq(_ts_keep("anything", 1) ? 1 : 0, 1);
    ck_assert_int_eq(_ts_keep("anything", 0) ? 1 : 0, 1);
    ck_assert_int_eq(_ts_keep("anything", -5) ? 1 : 0, 1);
    ck_assert_int_eq(_ts_keep("abc", 30) ? 1 : 0, 0);   /* < 8 hex chars */
    ck_assert_int_eq(_ts_keep("", 30) ? 1 : 0, 0);
}

/* Determinism: same task_id + denom always yields the same verdict (the
 * property both sides rely on to agree without communicating). */
DEFINE_TEST(test_ts_keep_deterministic)
{
    const char *tid = "12345678-1111-4222-8333-444455556666";
    bool a = _ts_keep(tid, 30);
    bool b = _ts_keep(tid, 30);
    ck_assert_int_eq(a ? 1 : 0, b ? 1 : 0);
}

/* A stamped batch (Reading.to_dict with metadata.task_id) yields the task_id. */
DEFINE_TEST(test_batch_task_id_stamped)
{
    const char *json =
        "[{\"t\":1.0,\"peer\":\"microdrone-1\",\"type\":\"x\",\"value\":1.0,"
        "\"unit\":\"\",\"metadata\":{\"task_id\":\"abcdef01-2345-6789-abcd-ef0123456789\"}},"
        "{\"t\":1.0,\"peer\":\"microdrone-1\",\"type\":\"y\",\"value\":2.0,"
        "\"unit\":\"\",\"metadata\":{\"task_id\":\"abcdef01-2345-6789-abcd-ef0123456789\"}}]";
    json_error_t err;
    json_t *arr = json_loads(json, 0, &err);
    ck_assert_ptr_nonnull(arr);
    char out[64] = {0};
    ck_assert(_batch_task_id(arr, out, sizeof(out)) == true);
    ck_assert_str_eq(out, "abcdef01-2345-6789-abcd-ef0123456789");
    json_decref(arr);
}

/* A synthetic batch (empty metadata, the C build_synthetic_readings shape) has
 * no task_id, so it is NOT scored — the no-op the producer path depends on. */
DEFINE_TEST(test_batch_task_id_synthetic)
{
    const char *json =
        "[{\"t\":0.5,\"peer\":\"c-node\",\"type\":\"motion_intensity\","
        "\"value\":0.1,\"unit\":\"\",\"quality\":1.0,\"metadata\":{}}]";
    json_error_t err;
    json_t *arr = json_loads(json, 0, &err);
    ck_assert_ptr_nonnull(arr);
    char out[64] = {0};
    ck_assert(_batch_task_id(arr, out, sizeof(out)) == false);
    json_decref(arr);
}

/* Metadata present but no task_id key, missing metadata, and empty array all
 * return false (no spurious scoring). */
DEFINE_TEST(test_batch_task_id_missing)
{
    json_error_t err;
    char out[64];

    json_t *no_key = json_loads(
        "[{\"peer\":\"x\",\"metadata\":{\"sensor_id\":\"s1\"}}]", 0, &err);
    ck_assert_ptr_nonnull(no_key);
    ck_assert(_batch_task_id(no_key, out, sizeof(out)) == false);
    json_decref(no_key);

    json_t *no_meta = json_loads("[{\"peer\":\"x\",\"value\":1.0}]", 0, &err);
    ck_assert_ptr_nonnull(no_meta);
    ck_assert(_batch_task_id(no_meta, out, sizeof(out)) == false);
    json_decref(no_meta);

    json_t *empty = json_loads("[]", 0, &err);
    ck_assert_ptr_nonnull(empty);
    ck_assert(_batch_task_id(empty, out, sizeof(out)) == false);
    json_decref(empty);

    ck_assert(_batch_task_id(NULL, out, sizeof(out)) == false);
}

RUN_TESTS(DataSource, test_ts_keep_python_parity, test_ts_keep_edge_cases,
          test_ts_keep_deterministic, test_batch_task_id_stamped,
          test_batch_task_id_synthetic, test_batch_task_id_missing)
