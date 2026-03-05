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

#include "structures/dag.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

DEFINE_TEST(test_genesis)
{
    step_t *g1 = dag_genesis();
    step_t *g2 = dag_genesis();
    ck_assert_ptr_nonnull(g1);
    /* Singleton */
    ck_assert_ptr_eq(g1, g2);
    ck_assert(dag_is_genesis(g1));
    ck_assert(uuid_is_null(g1->uuid));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_linked_step_create)
{
    linked_step_t *step = NULL;
    ck_assert_ret_ok(linked_step_create((void *)"payload1", NULL, &step));
    ck_assert_ptr_nonnull(step);
    ck_assert(!uuid_is_null(step->uuid));
    ck_assert_int_eq(step->length, 1);
    ck_assert(dag_is_genesis(step->parent));
    ck_assert_str_eq((char *)step->payload, "payload1");

    linked_step_t *step2 = NULL;
    ck_assert_ret_ok(linked_step_create((void *)"payload2", (step_t *)step, &step2));
    ck_assert_int_eq(step2->length, 2);
    ck_assert_ptr_eq(step2->parent, (step_t *)step);

    linked_step_free(step2);
    linked_step_free(step);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_create)
{
    step_dag_t *dag = NULL;
    ck_assert_ret_ok(step_dag_create(&dag));
    ck_assert_ptr_nonnull(dag);
    ck_assert_int_eq(step_dag_size(dag), 1); /* main branch */
    ck_assert_ptr_null(step_dag_main(dag));   /* empty main */

    dag_branch_t *main = step_dag_find_branch(dag, DAG_MAIN_BRANCH);
    ck_assert_ptr_nonnull(main);
    ck_assert_str_eq(main->name, DAG_MAIN_BRANCH);

    step_dag_free(dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_add_step)
{
    step_dag_t *dag = NULL;
    ck_assert_ret_ok(step_dag_create(&dag));

    linked_step_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ck_assert_ret_ok(linked_step_create((void *)"step1", NULL, &s1));
    ck_assert_ret_ok(linked_step_create((void *)"step2", NULL, &s2));
    ck_assert_ret_ok(linked_step_create((void *)"step3", NULL, &s3));

    ck_assert_ret_ok(step_dag_add_step(dag, s1, NULL));
    ck_assert_ptr_eq(step_dag_main(dag), s1);

    ck_assert_ret_ok(step_dag_add_step(dag, s2, NULL));
    ck_assert_ptr_eq(step_dag_main(dag), s2);
    /* s2's parent should be s1 */
    ck_assert_ptr_eq(s2->parent, (step_t *)s1);

    ck_assert_ret_ok(step_dag_add_step(dag, s3, NULL));
    ck_assert_ptr_eq(step_dag_main(dag), s3);
    ck_assert_ptr_eq(s3->parent, (step_t *)s2);

    step_dag_free(dag);
    linked_step_free(s1);
    linked_step_free(s2);
    linked_step_free(s3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_branch)
{
    step_dag_t *dag = NULL;
    ck_assert_ret_ok(step_dag_create(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create("base", NULL, &s1));
    ck_assert_ret_ok(step_dag_add_step(dag, s1, NULL));

    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create("branch_step", NULL, &s2));
    ck_assert_ret_ok(step_dag_branch(dag, "feature", s2, NULL));
    ck_assert_int_eq(step_dag_size(dag), 2);

    dag_branch_t *feat = step_dag_find_branch(dag, "feature");
    ck_assert_ptr_nonnull(feat);
    ck_assert_ptr_eq(feat->head, s2);
    /* Branch step's parent should be main's head */
    ck_assert_ptr_eq(s2->parent, (step_t *)s1);

    /* Duplicate branch name should fail */
    linked_step_t *s3 = NULL;
    ck_assert_ret_ok(linked_step_create("dup", NULL, &s3));
    ck_assert_ret_nonzero(step_dag_branch(dag, "feature", s3, NULL));

    step_dag_free(dag);
    linked_step_free(s1);
    linked_step_free(s2);
    linked_step_free(s3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_recite)
{
    step_dag_t *dag = NULL;
    ck_assert_ret_ok(step_dag_create(&dag));

    linked_step_t *steps[3];
    for (int i = 0; i < 3; i++)
    {
        ck_assert_ret_ok(linked_step_create(NULL, NULL, &steps[i]));
        ck_assert_ret_ok(step_dag_add_step(dag, steps[i], NULL));
    }

    linked_step_t **recited = NULL;
    size_t count = 0;
    ck_assert_ret_ok(step_dag_recite(dag, NULL, &recited, &count));
    ck_assert_int_eq(count, 3);
    /* Recite returns head-to-root order */
    ck_assert_ptr_eq(recited[0], steps[2]);
    ck_assert_ptr_eq(recited[1], steps[1]);
    ck_assert_ptr_eq(recited[2], steps[0]);

    free(recited);
    step_dag_free(dag);
    for (int i = 0; i < 3; i++)
        linked_step_free(steps[i]);
}

RUN_TESTS(DAG, test_genesis, test_linked_step_create, test_dag_create,
          test_dag_add_step, test_dag_branch, test_dag_recite)
