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

DEFINE_TEST(test_job_queue_create_destroy)
{
    job_queue_t *q = NULL;
    ck_assert_ret_ok(job_queue_create(&q));
    ck_assert_ptr_nonnull(q);
    ck_assert_int_eq(job_queue_count(q), 0);

    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL);
    job.end_time = job.start_time + 60;
    ck_assert_ret_ok(job_queue_push(q, &job));
    ck_assert_int_eq(job_queue_count(q), 1);

    job_queue_destroy(q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_min)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    /* Min on empty queue should fail */
    job_t out;
    ck_assert_ret_nonzero(job_queue_min(&q, &out));

    /* Add two jobs with different start times */
    job_t job1, job2;
    memset(&job1, 0, sizeof(job1));
    memset(&job2, 0, sizeof(job2));
    uuid_generate(job1.task.uuid);
    uuid_generate(job2.task.uuid);
    job1.start_time = time(NULL) + 100;
    job1.end_time = job1.start_time + 60;
    job2.start_time = time(NULL) + 200;
    job2.end_time = job2.start_time + 60;

    ck_assert_ret_ok(job_queue_push(&q, &job1));
    ck_assert_ret_ok(job_queue_push(&q, &job2));

    /* Min should return first job */
    ck_assert_ret_ok(job_queue_min(&q, &out));
    ck_assert(uuid_compare(out.task.uuid, job1.task.uuid) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_contains)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL);
    job.end_time = job.start_time + 60;

    uuid_t other_uuid;
    uuid_generate(other_uuid);

    ck_assert(job_queue_contains(&q, job.task.uuid) == false);
    ck_assert_ret_ok(job_queue_push(&q, &job));
    ck_assert(job_queue_contains(&q, job.task.uuid) == true);
    ck_assert(job_queue_contains(&q, other_uuid) == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_clear)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    for (int i = 0; i < 5; i++) {
        job_t job;
        memset(&job, 0, sizeof(job));
        uuid_generate(job.task.uuid);
        job.start_time = time(NULL) + i * 60;
        job.end_time = job.start_time + 30;
        ck_assert_ret_ok(job_queue_push(&q, &job));
    }
    ck_assert_int_eq(job_queue_count(&q), 5);

    job_queue_clear(&q);
    ck_assert_int_eq(job_queue_count(&q), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_find_nearest_slot)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    /* Empty queue: slot should be now */
    time_t slot = 0;
    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 30, 1, &slot));
    ck_assert(slot > 0);

    /* Add a job and find a slot */
    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL) + 10;
    job.end_time = job.start_time + 60;
    ck_assert_ret_ok(job_queue_push(&q, &job));

    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 30, 2, &slot));
    ck_assert(slot > 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_task_tracker_create_destroy)
{
    uuid_t task_uuid;
    uuid_generate(task_uuid);

    task_tracker_t *tracker = NULL;
    ck_assert_ret_ok(task_tracker_create(&tracker, task_uuid, 3));
    ck_assert_ptr_nonnull(tracker);
    ck_assert_int_eq(task_tracker_result_count(tracker), 0);

    uuid_t peer;
    uuid_generate(peer);
    const uint8_t data[] = {0xAB, 0xCD};
    ck_assert_ret_ok(task_tracker_set_result(tracker, peer, data, sizeof(data)));
    ck_assert_int_eq(task_tracker_result_count(tracker), 1);

    task_tracker_destroy(tracker);
}
END_TEST_DEFINITION()

RUN_TESTS(Negotiation2, test_job_queue_create_destroy, test_job_queue_min,
          test_job_queue_contains, test_job_queue_clear,
          test_job_queue_find_nearest_slot, test_task_tracker_create_destroy)
