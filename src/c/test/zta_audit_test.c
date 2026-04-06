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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "zta/zta_audit.h"

/*
 * Tests for the ZTA audit log:
 * - Init and close
 * - Record and read back deferred entries
 * - Resolve a deferred entry
 * - Deferred count tracking
 */

static const char *TEST_LOG_PATH = "/tmp/zta_audit_test.jsonl";

DEFINE_TEST(test_audit_init_close)
{
    /* Clean up any previous test file */
    unlink(TEST_LOG_PATH);

    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));
    ck_assert(log.initialized == true);
    ck_assert_int_eq(zta_audit_deferred_count(&log), 0);

    zta_audit_close(&log);
    ck_assert(log.initialized == false);

    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_audit_record_non_deferred)
{
    unlink(TEST_LOG_PATH);
    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));

    zta_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    gettimeofday(&entry.timestamp, NULL);
    uuid_generate(entry.peer_uuid);
    snprintf(entry.action, ZTA_ACTION_LEN, "admission_check");
    zta_result_set(&entry.result, ZTA_VERIFIED, "test verified");
    entry.deferred = false;

    ck_assert_ret_ok(zta_audit_record(&log, &entry));

    /* Non-deferred entries should not be in the deferred list */
    ck_assert_int_eq(zta_audit_deferred_count(&log), 0);

    zta_audit_close(&log);
    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_audit_record_deferred)
{
    unlink(TEST_LOG_PATH);
    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));

    zta_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    gettimeofday(&entry.timestamp, NULL);
    uuid_generate(entry.peer_uuid);
    snprintf(entry.action, ZTA_ACTION_LEN, "admission_check");
    zta_result_set(&entry.result, ZTA_DEFERRED, "OCSP unreachable");
    entry.deferred = true;

    ck_assert_ret_ok(zta_audit_record(&log, &entry));
    ck_assert_int_eq(zta_audit_deferred_count(&log), 1);

    /* Read it back */
    zta_audit_entry_t retrieved;
    ck_assert_ret_ok(zta_audit_get_deferred(&log, 0, &retrieved));
    ck_assert(retrieved.deferred == true);
    ck_assert_int_eq(retrieved.result.status, ZTA_DEFERRED);
    ck_assert(uuid_compare(retrieved.peer_uuid, entry.peer_uuid) == 0);

    zta_audit_close(&log);
    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_audit_resolve)
{
    unlink(TEST_LOG_PATH);
    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));

    /* Record a deferred entry */
    zta_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    gettimeofday(&entry.timestamp, NULL);
    uuid_generate(entry.peer_uuid);
    snprintf(entry.action, ZTA_ACTION_LEN, "admission_check");
    zta_result_set(&entry.result, ZTA_DEFERRED, "OCSP unreachable");
    entry.deferred = true;

    ck_assert_ret_ok(zta_audit_record(&log, &entry));
    ck_assert_int_eq(zta_audit_deferred_count(&log), 1);

    /* Resolve it */
    zta_result_t resolution;
    zta_result_set(&resolution, ZTA_VERIFIED, "OCSP now reachable; verified");

    ck_assert_ret_ok(zta_audit_resolve(&log, entry.peer_uuid, &resolution));
    ck_assert_int_eq(zta_audit_deferred_count(&log), 0);

    zta_audit_close(&log);
    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_audit_resolve_not_found)
{
    unlink(TEST_LOG_PATH);
    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));

    uuid_t random_uuid;
    uuid_generate(random_uuid);
    zta_result_t resolution;
    zta_result_set(&resolution, ZTA_VERIFIED, "ok");

    /* Should return -1 since no deferred entries exist */
    ck_assert_int_eq(zta_audit_resolve(&log, random_uuid, &resolution), -1);

    zta_audit_close(&log);
    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_audit_multiple_deferred)
{
    unlink(TEST_LOG_PATH);
    zta_audit_log_t log;
    ck_assert_ret_ok(zta_audit_init(&log, TEST_LOG_PATH));

    /* Record 3 deferred entries */
    uuid_t uuids[3];
    for (int i = 0; i < 3; i++) {
        zta_audit_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        gettimeofday(&entry.timestamp, NULL);
        uuid_generate(uuids[i]);
        memcpy(entry.peer_uuid, uuids[i], sizeof(uuid_t));
        snprintf(entry.action, ZTA_ACTION_LEN, "admission_check");
        zta_result_set(&entry.result, ZTA_DEFERRED, "deferred");
        entry.deferred = true;
        ck_assert_ret_ok(zta_audit_record(&log, &entry));
    }
    ck_assert_int_eq(zta_audit_deferred_count(&log), 3);

    /* Resolve the middle one */
    zta_result_t resolution;
    zta_result_set(&resolution, ZTA_VERIFIED, "resolved");
    ck_assert_ret_ok(zta_audit_resolve(&log, uuids[1], &resolution));
    ck_assert_int_eq(zta_audit_deferred_count(&log), 2);

    zta_audit_close(&log);
    unlink(TEST_LOG_PATH);
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Audit,
    test_audit_init_close,
    test_audit_record_non_deferred,
    test_audit_record_deferred,
    test_audit_resolve,
    test_audit_resolve_not_found,
    test_audit_multiple_deferred)
