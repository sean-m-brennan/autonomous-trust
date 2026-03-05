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
#include <stdlib.h>
#include <time.h>
#include <uuid/uuid.h>

#include "negotiation/negotiation.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

/****************************
 * Job queue tests
 ****************************/

DEFINE_TEST(test_job_queue_init)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));
    ck_assert_int_eq(job_queue_count(&q), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_push_pop)
{
    job_queue_t q;
    job_queue_init(&q);

    job_t j1 = {0};
    uuid_generate(j1.task.uuid);
    j1.start_time = 100;
    j1.end_time = 200;

    job_t j2 = {0};
    uuid_generate(j2.task.uuid);
    j2.start_time = 50;
    j2.end_time = 150;

    job_t j3 = {0};
    uuid_generate(j3.task.uuid);
    j3.start_time = 300;
    j3.end_time = 400;

    ck_assert_ret_ok(job_queue_push(&q, &j1));
    ck_assert_ret_ok(job_queue_push(&q, &j2));
    ck_assert_ret_ok(job_queue_push(&q, &j3));
    ck_assert_int_eq(job_queue_count(&q), 3);

    /* Pop should return in sorted order (earliest first) */
    job_t out;
    ck_assert_ret_ok(job_queue_pop(&q, &out));
    ck_assert_int_eq((int)out.start_time, 50);

    ck_assert_ret_ok(job_queue_pop(&q, &out));
    ck_assert_int_eq((int)out.start_time, 100);

    ck_assert_ret_ok(job_queue_pop(&q, &out));
    ck_assert_int_eq((int)out.start_time, 300);

    ck_assert_int_eq(job_queue_count(&q), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_min)
{
    job_queue_t q;
    job_queue_init(&q);

    job_t j1 = {0};
    uuid_generate(j1.task.uuid);
    j1.start_time = 200;
    j1.end_time = 300;

    job_t j2 = {0};
    uuid_generate(j2.task.uuid);
    j2.start_time = 100;
    j2.end_time = 200;

    job_queue_push(&q, &j1);
    job_queue_push(&q, &j2);

    job_t min_job;
    ck_assert_ret_ok(job_queue_min(&q, &min_job));
    ck_assert_int_eq((int)min_job.start_time, 100);

    /* Min should not remove the job */
    ck_assert_int_eq(job_queue_count(&q), 2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_contains)
{
    job_queue_t q;
    job_queue_init(&q);

    job_t j1 = {0};
    uuid_generate(j1.task.uuid);
    j1.start_time = 100;
    j1.end_time = 200;

    job_queue_push(&q, &j1);

    ck_assert(job_queue_contains(&q, j1.task.uuid));

    uuid_t random_uuid;
    uuid_generate(random_uuid);
    ck_assert(!job_queue_contains(&q, random_uuid));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_find_nearest_slot)
{
    job_queue_t q;
    job_queue_init(&q);

    /* Empty queue should return current time */
    time_t slot;
    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 60, 2, &slot));

    /* Add some jobs */
    job_t j1 = {0};
    uuid_generate(j1.task.uuid);
    j1.start_time = 1000;
    j1.end_time = 1100;
    job_queue_push(&q, &j1);

    job_t j2 = {0};
    uuid_generate(j2.task.uuid);
    j2.start_time = 1050;
    j2.end_time = 1150;
    job_queue_push(&q, &j2);

    /* With max_concurrency=2, should still find a slot since only 2 jobs overlap */
    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 60, 2, &slot));

    /* With max_concurrency=1, should find slot after overlap */
    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 60, 1, &slot));
}
END_TEST_DEFINITION()

/****************************
 * Task tracker tests
 ****************************/

DEFINE_TEST(test_task_tracker_lifecycle)
{
    task_tracker_t tracker;
    uuid_t task_uuid;
    uuid_generate(task_uuid);

    ck_assert_ret_ok(task_tracker_init(&tracker, task_uuid, 3));
    ck_assert_int_eq(task_tracker_result_count(&tracker), 0);

    /* Add results */
    uuid_t peer1, peer2;
    uuid_generate(peer1);
    uuid_generate(peer2);

    uint8_t data1[] = {1, 2, 3};
    uint8_t data2[] = {4, 5, 6, 7};

    ck_assert_ret_ok(task_tracker_set_result(&tracker, peer1, data1, sizeof(data1)));
    ck_assert_int_eq(task_tracker_result_count(&tracker), 1);

    ck_assert_ret_ok(task_tracker_set_result(&tracker, peer2, data2, sizeof(data2)));
    ck_assert_int_eq(task_tracker_result_count(&tracker), 2);

    task_tracker_free(&tracker);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_clear)
{
    job_queue_t q;
    job_queue_init(&q);

    job_t j1 = {0};
    uuid_generate(j1.task.uuid);
    j1.start_time = 100;
    j1.end_time = 200;
    job_queue_push(&q, &j1);

    ck_assert_int_eq(job_queue_count(&q), 1);
    job_queue_clear(&q);
    ck_assert_int_eq(job_queue_count(&q), 0);
}
END_TEST_DEFINITION()

RUN_TESTS(Negotiation,
    test_job_queue_init,
    test_job_queue_push_pop,
    test_job_queue_min,
    test_job_queue_contains,
    test_job_queue_find_nearest_slot,
    test_task_tracker_lifecycle,
    test_job_queue_clear)
