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

RUN_TESTS(Negotiation, test_job_queue_basic, test_task_tracker_basic)
