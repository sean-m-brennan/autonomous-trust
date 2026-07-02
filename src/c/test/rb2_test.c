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
#include <stdlib.h>
#include <sodium.h>

#include "autonomous_trust/structures/redblack_priv.h"

DEFINE_TEST(test_tree_delete_sequential)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    /* Insert sequential keys to create specific tree structure */
    int dummy = 0;
    for (int i = 1; i <= 10; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, i));
    ck_assert_int_eq(tree_size(tree), 10);

    /* Delete from the middle to exercise recoloring */
    ck_assert_ret_ok(tree_delete(tree, 5));
    ck_assert_int_eq(tree_size(tree), 9);
    ck_assert_ptr_null(tree_find(tree, 5));

    /* Delete more to exercise different recoloring paths */
    ck_assert_ret_ok(tree_delete(tree, 3));
    ck_assert_ret_ok(tree_delete(tree, 8));
    ck_assert_int_eq(tree_size(tree), 7);

    /* Remaining elements should still be findable */
    ck_assert_ptr_nonnull(tree_find(tree, 1));
    ck_assert_ptr_nonnull(tree_find(tree, 2));
    ck_assert_ptr_nonnull(tree_find(tree, 10));

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_delete_all)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int keys[] = {50, 25, 75, 12, 37, 62, 87};
    int dummy = 0;
    for (int i = 0; i < 7; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, keys[i]));

    /* Delete all elements one by one */
    for (int i = 0; i < 7; i++) {
        ck_assert_ret_ok(tree_delete(tree, keys[i]));
        ck_assert_int_eq(tree_size(tree), 7 - i - 1);
    }

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_delete_root)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int keys[] = {5, 3, 7, 1, 4, 6, 8};
    int dummy = 0;
    for (int i = 0; i < 7; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, keys[i]));

    /* Delete root value */
    ck_assert_ret_ok(tree_delete(tree, 5));
    ck_assert_int_eq(tree_size(tree), 6);
    ck_assert_ptr_null(tree_find(tree, 5));

    /* All other elements should be findable */
    for (int i = 1; i < 7; i++)
        ck_assert_ptr_nonnull(tree_find(tree, keys[i]));

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_delete_leaves)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    int keys[] = {4, 2, 6, 1, 3, 5, 7};
    int dummy = 0;
    for (int i = 0; i < 7; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, keys[i]));

    /* Delete leaf nodes */
    ck_assert_ret_ok(tree_delete(tree, 1));
    ck_assert_ret_ok(tree_delete(tree, 3));
    ck_assert_ret_ok(tree_delete(tree, 5));
    ck_assert_ret_ok(tree_delete(tree, 7));
    ck_assert_int_eq(tree_size(tree), 3);

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_large_delete)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    /* Insert 50 elements */
    int dummy = 0;
    for (int i = 0; i < 50; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, i * 3 + 1));
    ck_assert_int_eq(tree_size(tree), 50);

    /* Delete every other element */
    for (int i = 0; i < 50; i += 2)
        ck_assert_ret_ok(tree_delete(tree, i * 3 + 1));
    ck_assert_int_eq(tree_size(tree), 25);

    /* Verify remaining elements */
    for (int i = 1; i < 50; i += 2)
        ck_assert_ptr_nonnull(tree_find(tree, i * 3 + 1));

    tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tree_depth_properties)
{
    ck_assert(sodium_init() >= 0);

    tree_t *tree = NULL;
    ck_assert_ret_ok(tree_create(&tree));

    /* Empty tree depth = 0 */
    ck_assert_int_eq(tree_depth(tree), 0);

    int dummy = 0;
    ck_assert_ret_ok(tree_insert(tree, &dummy, 42));
    ck_assert_int_eq(tree_depth(tree), 1);

    /* Insert more - depth should be logarithmic */
    for (int i = 1; i <= 15; i++)
        ck_assert_ret_ok(tree_insert(tree, &dummy, i));
    /* RB tree with 16 elements: depth should be <= 2*log2(16)+1 = 9 */
    ck_assert(tree_depth(tree) <= 9);

    tree_free(tree);
}
END_TEST_DEFINITION()

RUN_TESTS(RedBlack2, test_tree_delete_sequential, test_tree_delete_all,
          test_tree_delete_root, test_tree_delete_leaves,
          test_tree_large_delete, test_tree_depth_properties)
