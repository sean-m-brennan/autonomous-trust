/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#include <stdlib.h>

#include "autonomous_trust/structures/redblack_priv.h"

DEFINE_TEST(test_tree_create_empty)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));
    ck_assert_ptr_nonnull(tree);
    ck_assert_int_eq(tree_size(tree), 0);
    ck_assert_int_eq(tree_depth(tree), 0);

    /* Find on empty tree returns NULL */
    ck_assert_ptr_null(tree_find(tree, 42));

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_insert_find)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int data1 = 100, data2 = 200, data3 = 300;
    ck_assert_ret_ok(tree_insert(tree, &data1, 10));
    ck_assert_ret_ok(tree_insert(tree, &data2, 20));
    ck_assert_ret_ok(tree_insert(tree, &data3, 5));

    ck_assert_int_eq(tree_size(tree), 3);
    ck_assert(tree_depth(tree) >= 1);

    /* Find existing keys */
    int *found = (int *)tree_find(tree, 10);
    ck_assert_ptr_nonnull(found);
    ck_assert_int_eq(*found, 100);

    found = (int *)tree_find(tree, 20);
    ck_assert_ptr_nonnull(found);
    ck_assert_int_eq(*found, 200);

    found = (int *)tree_find(tree, 5);
    ck_assert_ptr_nonnull(found);
    ck_assert_int_eq(*found, 300);

    /* Find non-existent key */
    ck_assert_ptr_null(tree_find(tree, 999));

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_delete)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int vals[] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++)
        ck_assert_ret_ok(tree_insert(tree, &vals[i], vals[i]));
    ck_assert_int_eq(tree_size(tree), 5);

    /* Delete middle element */
    ck_assert_ret_ok(tree_delete(tree, 30));
    ck_assert_int_eq(tree_size(tree), 4);
    ck_assert_ptr_null(tree_find(tree, 30));

    /* Other elements still present */
    ck_assert_ptr_nonnull(tree_find(tree, 10));
    ck_assert_ptr_nonnull(tree_find(tree, 50));

    /* Delete first and last */
    ck_assert_ret_ok(tree_delete(tree, 10));
    ck_assert_ret_ok(tree_delete(tree, 50));
    ck_assert_int_eq(tree_size(tree), 2);

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_duplicate_insert)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int data = 42;
    ck_assert_ret_ok(tree_insert(tree, &data, 10));
    /* Duplicate key should return error */
    ck_assert_ret_nonzero(tree_insert(tree, &data, 10));
    ck_assert_int_eq(tree_size(tree), 1);

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_delete_errors)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    /* Delete from empty tree */
    ck_assert_ret_nonzero(tree_delete(tree, 1));

    /* Insert, then delete non-existent key */
    int data = 42;
    ck_assert_ret_ok(tree_insert(tree, &data, 10));
    ck_assert_ret_nonzero(tree_delete(tree, 999));
    ck_assert_int_eq(tree_size(tree), 1);

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_large_insert)
{
    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    /* Insert 100 elements in shuffled order */
    int vals[100];
    int order[] = {50,25,75,12,37,62,87,6,18,31,43,56,68,81,93,
                   3,9,15,21,28,34,40,46,53,59,65,71,78,84,90,96,
                   1,4,7,10,13,16,19,22,26,29,32,35,38,41,44,47,
                   51,54,57,60,63,66,69,72,76,79,82,85,88,91,94,97,
                   2,5,8,11,14,17,20,23,27,30,33,36,39,42,45,48,
                   52,55,58,61,64,67,70,73,77,80,83,86,89,92,95,98,
                   24,49,74,99,0};
    for (int i = 0; i < 100; i++) {
        vals[i] = order[i] * 10;
        ck_assert_ret_ok(tree_insert(tree, &vals[i], order[i]));
    }
    ck_assert_int_eq(tree_size(tree), 100);

    /* Depth of RB tree: should be <= 2*log2(n+1) ~= 14 for n=100 */
    int depth = tree_depth(tree);
    ck_assert(depth > 0);
    ck_assert(depth <= 14);

    /* Verify all elements findable */
    for (int i = 0; i < 100; i++) {
        int *f = (int *)tree_find(tree, i);
        ck_assert_ptr_nonnull(f);
        ck_assert_int_eq(*f, i * 10);
    }

    tree_free(tree);
}
END_TEST_DEFINITION()

RUN_TESTS(RedBlack, test_tree_create_empty, test_tree_insert_find,
          test_tree_delete, test_tree_duplicate_insert,
          test_tree_delete_errors, test_tree_large_insert)
