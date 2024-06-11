/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include <stdlib.h>
#include "autonomous_trust/structures/redblack.h"

#define DEBUG_TESTS 0

#if DEBUG_TESTS
#define ck_assert_int_eq(x, y)
#define ck_assert_int_ne(x, y)
#define ck_assert_str_eq(x, y)
#define ck_assert_ptr_nonnull(x)
#define ck_assert_ret_ok(x) x
#define ck_assert_ret_nonzero(x) x
#else
#include <check.h>
#define ck_assert_ret_ok(x) ck_assert_int_eq(0, x)
#define ck_assert_ret_nonzero(x) ck_assert_int_ne(0, x)
#endif

#if DEBUG_TESTS
void test_red_black_tree()
#else
START_TEST(test_red_black_tree)
#endif
{
    
    /*int ch, data;
    while (1) {
        printf("1. Insertion\t2. Deletion\n");
        printf("\nEnter your choice:");
      scanf("%d", &ch);
      switch (ch) {
        case 1:
          printf("Enter the element to insert:");
          scanf("%d", &data);
          insertion(data);
          break;
        case 2:
          printf("Enter the element to delete:");
          scanf("%d", &data);
          deletion(data);
          break;
        default:
          printf("Not available\n");
          break;
      }
      printf("\n");
    }*/
}
#if !DEBUG_TESTS
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("Red/Black Tree");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_red_black_tree);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
#else
int main()
{
    test_red_black_tree();
    return 0;
}
#endif
