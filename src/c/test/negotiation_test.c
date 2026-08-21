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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#include "negotiation/task_priv.h"
#include "negotiation/negotiation.h"

DEFINE_TEST(test_job_queue_basic)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));
    ck_assert_int_eq(job_queue_count(&q), 0);

    job_t job1;
    memset(&job1, 0, sizeof(job1));
    uuid_generate(job1.task.uuid);
    job1.start_time = time(NULL);
    job1.end_time   = job1.start_time + 60;

    job_t job2;
    memset(&job2, 0, sizeof(job2));
    uuid_generate(job2.task.uuid);
    job2.start_time = job1.start_time + 120;
    job2.end_time   = job2.start_time + 60;

    ck_assert_ret_ok(job_queue_push(&q, &job1));
    ck_assert_ret_ok(job_queue_push(&q, &job2));
    ck_assert_int_eq(job_queue_count(&q), 2);

    job_t popped;
    ck_assert_ret_ok(job_queue_pop(&q, &popped));
    ck_assert_int_eq(job_queue_count(&q), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_task_tracker_basic)
{
    task_tracker_t tracker;
    uuid_t task_uuid;
    uuid_generate(task_uuid);

    ck_assert_ret_ok(task_tracker_init(&tracker, task_uuid, 2));
    ck_assert_int_eq(task_tracker_result_count(&tracker), 0);

    uuid_t peer1_uuid, peer2_uuid;
    uuid_generate(peer1_uuid);
    uuid_generate(peer2_uuid);

    const uint8_t result1[] = {0x01, 0x02, 0x03};
    const uint8_t result2[] = {0x04, 0x05, 0x06, 0x07};

    ck_assert_ret_ok(task_tracker_set_result(&tracker, peer1_uuid, result1, sizeof(result1)));
    ck_assert_ret_ok(task_tracker_set_result(&tracker, peer2_uuid, result2, sizeof(result2)));
    ck_assert_int_eq(task_tracker_result_count(&tracker), 2);

    task_tracker_free(&tracker);
}
END_TEST_DEFINITION()

/* Freshness sequence survives the protobuf round trip.
 *
 * `seq` is field 12 of negotiation/task.proto and the token that makes an
 * invitation non-replayable (utilities/freshness.h, and
 * doc/architecture/security-hardening.md "Replay resistance, per verb"). It
 * rides the same task_t that msg_types.c packs for a TASK_MESSAGE, so a field
 * lost in pack/unpack would silently turn every invitation unstamped — which
 * handle_invite refuses, taking the whole verb down rather than failing
 * visibly here. Hence pinning it at this level. */
DEFINE_TEST(test_task_proto_roundtrip_carries_seq)
{
    task_t out;
    memset(&out, 0, sizeof(out));
    uuid_generate(out.uuid);
    uuid_generate(out.requestor_uuid);
    strncpy(out.capability.name, "data_fetch", CAP_NAMELEN);
    out.timeout = 30;
    out.flexible = true;
    out.duration.days = 0;
    out.duration.seconds = 60;
    out.seq = 7;

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(task_to_proto(&out, sizeof(out), &data, &data_len));
    ck_assert_ptr_nonnull(data);

    task_t in;
    memset(&in, 0, sizeof(in));
    ck_assert_int_eq(proto_to_task((uint8_t *)data, data_len, &in), 0);
    ck_assert_int_eq((int)in.seq, 7);
    ck_assert_int_eq(uuid_compare(in.uuid, out.uuid), 0);
}
END_TEST_DEFINITION()

/* An unstamped task reads back as seq 0, the never-seen floor that
 * freshness_accept refuses. This is the flag-day encoding: a peer that has not
 * been rebuilt omits field 12, an omitted field unpacks as 0, and 0 is a
 * refusal — so no version check is needed to tell the two apart. */
DEFINE_TEST(test_task_proto_unstamped_reads_zero)
{
    task_t out;
    memset(&out, 0, sizeof(out));
    uuid_generate(out.uuid);
    strncpy(out.capability.name, "data_fetch", CAP_NAMELEN);
    /* out.seq deliberately left at 0 */

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(task_to_proto(&out, sizeof(out), &data, &data_len));

    task_t in;
    memset(&in, 0, sizeof(in));
    in.seq = 99;  /* must be overwritten, not merely left alone */
    ck_assert_int_eq(proto_to_task((uint8_t *)data, data_len, &in), 0);
    ck_assert_int_eq((int)in.seq, 0);
}
END_TEST_DEFINITION()

RUN_TESTS(Negotiation, test_job_queue_basic, test_task_tracker_basic,
          test_task_proto_roundtrip_carries_seq,
          test_task_proto_unstamped_reads_zero)
