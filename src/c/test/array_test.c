#include <stdlib.h>
#include "autonomous_trust/structures/array_priv.h"
#include "autonomous_trust/config/protobuf_shutdown.h"
#include "autonomous_trust/utilities/util.h"
#include "autonomous_trust/utilities/logger.h"

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
void test_array_data()
#else
START_TEST(test_array_data)
#endif
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    data_t *data1 = integer_data(1);
    ck_assert_ptr_nonnull(data1);
    ck_assert_ret_ok(array_append(&arr, data1));
    data_t *data2 = string_data((char*)"two", 3);
    ck_assert_ptr_nonnull(data2);
    ck_assert_ret_ok(array_append(&arr, data2));
    data_t *data3 = boolean_data(true);
    ck_assert_ptr_nonnull(data3);
    ck_assert_ret_ok(array_append(&arr, data3));
    data_t *data4 = floating_pt_data(4.0);
    ck_assert_ptr_nonnull(data4);
    ck_assert_ret_ok(array_append(&arr, data4));
    data_t *data5 = ul_integer_data(5UL);
    ck_assert_ptr_nonnull(data5);
    ck_assert_ret_ok(array_append(&arr, data5));
    data_t *data6 = bytes_data((unsigned char*)"six", 3);
    ck_assert_ptr_nonnull(data6);
    ck_assert_ret_ok(array_append(&arr, data6));
    int size = array_size(&arr);
    ck_assert_int_eq(6, size);

    data_t *data;
    ck_assert_ret_ok(array_get(&arr, 5, &data));
    unsigned char *bytes;
    ck_assert_ret_ok(data_bytes_ptr(data, &bytes));
    ck_assert_mem_eq(bytes, (unsigned char*)"six", 3);

    ck_assert_ret_ok(array_get(&arr, 4, &data));
    unsigned long l;
    ck_assert_ret_ok(data_ul_integer(data, &l));
    ck_assert_uint_eq(l, 5UL);
    
    ck_assert_ret_ok(array_get(&arr, 3, &data));
    float d;
    ck_assert_ret_ok(data_floating_pt(data, &d));
    ck_assert_double_eq_tol(d, 4.0, 0.0001);
    
    ck_assert_ret_ok(array_get(&arr, 2, &data));
    bool b;
    ck_assert_ret_ok(data_boolean(data, &b));
    ck_assert(b);
    
    ck_assert_ret_ok(array_get(&arr, 1, &data));
    char *str;
    ck_assert_ret_ok(data_string_ptr(data, &str));
    ck_assert_str_eq(str, "two");
    
    ck_assert_ret_ok(array_get(&arr, 0, &data));
    int one;
    ck_assert_ret_ok(data_integer(data, &one));
    ck_assert_int_eq(one, 1);

    data_decr(data1);
    data_decr(data2);
    data_decr(data3);
    data_decr(data4);
    data_decr(data5);
    data_decr(data6);
}
#if !DEBUG_TESTS
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("Array");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_array_data);
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
int main(void)
{
    testArray();
    shutdown_protobuf_library();
    return 0;
}
#endif
