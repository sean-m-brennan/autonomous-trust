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

#include <string.h>
#include <sodium.h>

#include "autonomous_trust/structures/dag.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

DEFINE_TEST(test_dag_create_and_add)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        return;

    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create(NULL, NULL, &s1));
    ck_assert_ptr_nonnull(s1);
    ck_assert_int_eq(s1->length, 1);

    ck_assert_ret_ok(dag_add_step(&dag, s1, NULL));

    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create(NULL, NULL, &s2));
    ck_assert_ret_ok(dag_add_step(&dag, s2, NULL));
    ck_assert_int_eq(s2->length, 2);
    ck_assert(s2->parent == s1);

    linked_step_t *head = NULL;
    ck_assert_ret_ok(dag_fork(&dag, NULL, &head));
    ck_assert(head == s2);

    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_branch_and_merge)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create("aaaa-1111", NULL, &s1));
    ck_assert_ret_ok(dag_add_step(&dag, s1, NULL));

    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create("bbbb-2222", NULL, &s2));
    ck_assert_ret_ok(dag_add_step(&dag, s2, NULL));

    /* branch from main */
    linked_step_t *b1 = NULL;
    ck_assert_ret_ok(linked_step_create("cccc-3333", NULL, &b1));
    ck_assert_ret_ok(dag_branch(&dag, "feature", b1, DAG_MAIN_BRANCH));

    linked_step_t *b2 = NULL;
    ck_assert_ret_ok(linked_step_create("dddd-4444", NULL, &b2));
    ck_assert_ret_ok(dag_add_step(&dag, b2, "feature"));

    /* add to main too */
    linked_step_t *s3 = NULL;
    ck_assert_ret_ok(linked_step_create("eeee-5555", NULL, &s3));
    ck_assert_ret_ok(dag_add_step(&dag, s3, NULL));

    /* merge feature into main */
    ck_assert_ret_ok(dag_merge(&dag, "feature", NULL, false));

    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_diff)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create("1111", NULL, &s1));
    ck_assert_ret_ok(dag_add_step(&dag, s1, NULL));

    /* create branch from genesis */
    linked_step_t *b1 = NULL;
    ck_assert_ret_ok(linked_step_create("2222", NULL, &b1));
    ck_assert_ret_ok(dag_branch(&dag, "other", b1, "genesis"));

    int idx;
    linked_step_t *common;
    ck_assert_ret_ok(dag_diff(&dag, "other", DAG_MAIN_BRANCH, &idx, &common));
    ck_assert_int_eq(idx, 0);

    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_recite)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create("a1a1", NULL, &s1));
    ck_assert_ret_ok(dag_add_step(&dag, s1, NULL));

    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create("b2b2", NULL, &s2));
    ck_assert_ret_ok(dag_add_step(&dag, s2, NULL));

    linked_step_t *s3 = NULL;
    ck_assert_ret_ok(linked_step_create("c3c3", NULL, &s3));
    ck_assert_ret_ok(dag_add_step(&dag, s3, NULL));

    array_t *steps = NULL;
    ck_assert_ret_ok(dag_recite(&dag, NULL, NULL, &steps));
    ck_assert_ptr_nonnull(steps);

    /* recite returns head-to-root order */
    ck_assert_int_eq(array_size(steps), 3);

    array_free(steps);
    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_ingest_branch)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    /* create external steps */
    linked_step_t *ext[3];
    ck_assert_ret_ok(linked_step_create("ext-3", NULL, &ext[0]));  /* head */
    ck_assert_ret_ok(linked_step_create("ext-2", NULL, &ext[1]));
    ck_assert_ret_ok(linked_step_create("ext-1", NULL, &ext[2]));  /* root */

    char name[32];
    ck_assert_ret_ok(dag_ingest_branch(&dag, ext, 3, "incoming", name, sizeof(name)));
    ck_assert_str_eq(name, "incoming");

    linked_step_t *head = NULL;
    ck_assert_ret_ok(dag_fork(&dag, "incoming", &head));
    ck_assert_ptr_nonnull(head);

    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_branch_exists_error)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create(NULL, NULL, &s1));
    ck_assert_ret_ok(dag_branch(&dag, "test_br", s1, "genesis"));

    /* try creating same branch again */
    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create(NULL, NULL, &s2));
    ck_assert_ret_nonzero(dag_branch(&dag, "test_br", s2, "genesis"));

    dag_free(&dag);
}
END_TEST_DEFINITION()

/* Validator that always rejects — used to exercise the rejection
 * branch of dag_catch_up. Counts invocations via ctx so the test can
 * confirm the hook actually ran. */
static bool _always_reject_validator(step_dag_t *dag, const char *branch, void *ctx)
{
    (void)dag;
    (void)branch;
    if (ctx != NULL)
        (*(int *)ctx)++;
    return false;
}

DEFINE_TEST(test_dag_catch_up_success)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    /* NULL validator => always-valid, branch merged into main */
    linked_step_t *ext[3];
    ck_assert_ret_ok(linked_step_create("c-3", NULL, &ext[0]));  /* head */
    ck_assert_ret_ok(linked_step_create("c-2", NULL, &ext[1]));
    ck_assert_ret_ok(linked_step_create("c-1", NULL, &ext[2]));  /* root-side */

    array_t *diff = NULL;
    ck_assert_ret_ok(dag_catch_up(&dag, ext, 3, &diff));
    ck_assert_ptr_nonnull(diff);
    /* All three steps diverge from genesis, so the recited diff is the
     * full inbound chain. */
    ck_assert_int_eq(array_size(diff), 3);

    /* After merge, main's head equals the inbound head. */
    linked_step_t *main_head = NULL;
    ck_assert_ret_ok(dag_fork(&dag, NULL, &main_head));
    ck_assert_ptr_eq(main_head, ext[0]);

    array_free(diff);
    dag_free(&dag);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dag_catch_up_validation_rejected)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    int validator_calls = 0;
    dag_set_validator(&dag, _always_reject_validator, &validator_calls);

    linked_step_t *ext[2];
    ck_assert_ret_ok(linked_step_create("r-2", NULL, &ext[0]));  /* head */
    ck_assert_ret_ok(linked_step_create("r-1", NULL, &ext[1]));  /* root-side */

    array_t *diff = NULL;
    ck_assert_ret_ok(dag_catch_up(&dag, ext, 2, &diff));
    ck_assert_int_eq(validator_calls, 1);
    /* diff is still populated even though the merge was vetoed —
     * mirrors Python catch_up's "return branch_diff" regardless. */
    ck_assert_ptr_nonnull(diff);
    ck_assert_int_eq(array_size(diff), 2);

    /* Main's head must still be genesis since the merge was rejected. */
    linked_step_t *main_head = NULL;
    ck_assert_ret_ok(dag_fork(&dag, NULL, &main_head));
    ck_assert(main_head != ext[0]);

    array_free(diff);
    dag_free(&dag);
}
END_TEST_DEFINITION()

/* M8: dag_fork_all snapshots all branch heads into a fresh map. */
DEFINE_TEST(test_dag_fork_all)
{
    step_dag_t dag;
    ck_assert_ret_ok(dag_init(&dag));

    /* Add a step to main and a new branch so there are two heads. */
    linked_step_t *s1 = NULL;
    ck_assert_ret_ok(linked_step_create("fa-1", NULL, &s1));
    ck_assert_ret_ok(dag_add_step(&dag, s1, NULL));

    linked_step_t *s2 = NULL;
    ck_assert_ret_ok(linked_step_create("fa-2", NULL, &s2));
    ck_assert_ret_ok(dag_branch(&dag, "side", s2, "genesis"));

    map_t *snapshot = NULL;
    ck_assert_ret_ok(dag_fork_all(&dag, &snapshot));
    ck_assert_ptr_nonnull(snapshot);

    /* Both branches must be present in the snapshot. */
    data_t *main_val = NULL;
    data_t *side_val = NULL;
    ck_assert_ret_ok(map_get(snapshot, (map_key_t)"main", &main_val));
    ck_assert_ret_ok(map_get(snapshot, (map_key_t)"side", &side_val));
    ck_assert_ptr_nonnull(main_val);
    ck_assert_ptr_nonnull(side_val);

    /* The pointers reference the live nodes — shallow snapshot. */
    ptr_t main_p = NULL;
    ptr_t side_p = NULL;
    ck_assert_ret_ok(data_object_ptr(main_val, &main_p));
    ck_assert_ret_ok(data_object_ptr(side_val, &side_p));
    ck_assert_ptr_eq(main_p, s1);
    ck_assert_ptr_eq(side_p, s2);

    map_free(snapshot);
    dag_free(&dag);
}
END_TEST_DEFINITION()

RUN_TESTS(DAG, test_dag_create_and_add, test_dag_branch_and_merge,
          test_dag_diff, test_dag_recite, test_dag_ingest_branch,
          test_dag_branch_exists_error,
          test_dag_catch_up_success, test_dag_catch_up_validation_rejected,
          test_dag_fork_all)
