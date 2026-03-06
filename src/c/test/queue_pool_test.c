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

#include <string.h>

#include "autonomous_trust/utilities/queue_pool.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

DEFINE_TEST(test_pool_init)
{
    queue_pool_t pool;
    ck_assert_ret_ok(queue_pool_init(&pool));
    ck_assert_int_eq(pool.initialized, 1);

    /* all queues should be free */
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
        ck_assert(!pool.pool[i].in_use);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pool_allocate_recycle)
{
    queue_pool_t pool;
    ck_assert_ret_ok(queue_pool_init(&pool));

    /* allocate a queue */
    queue_t *q1 = queue_pool_next(&pool);
    ck_assert_ptr_nonnull(q1);

    queue_t *q2 = queue_pool_next(&pool);
    ck_assert_ptr_nonnull(q2);
    ck_assert(q1 != q2);

    /* recycle q1 */
    ck_assert_ret_ok(queue_pool_recycle(&pool, q1));

    /* next allocation should reuse q1's slot */
    queue_t *q3 = queue_pool_next(&pool);
    ck_assert_ptr_nonnull(q3);
    ck_assert(q3 == q1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pool_exhaustion)
{
    queue_pool_t pool;
    ck_assert_ret_ok(queue_pool_init(&pool));

    /* exhaust all queues */
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
    {
        queue_t *q = queue_pool_next(&pool);
        ck_assert_ptr_nonnull(q);
    }

    /* next should return NULL */
    queue_t *q = queue_pool_next(&pool);
    ck_assert_ptr_null(q);
}
END_TEST_DEFINITION()

RUN_TESTS(queue_pool, test_pool_init, test_pool_allocate_recycle,
          test_pool_exhaustion)
