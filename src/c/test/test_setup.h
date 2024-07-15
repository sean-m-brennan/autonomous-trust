#ifndef TEST_SETUP_H
#define TEST_SETUP_H

// FOR_EACH macro from stackoverflow (https://stackoverflow.com/a/11994395)

#define FE_00(WHAT)
#define FE_01(WHAT, X) WHAT(X)
#define FE_02(WHAT, X, ...) WHAT(X) FE_01(WHAT, __VA_ARGS__)
#define FE_03(WHAT, X, ...) WHAT(X) FE_02(WHAT, __VA_ARGS__)
#define FE_04(WHAT, X, ...) WHAT(X) FE_03(WHAT, __VA_ARGS__)
#define FE_05(WHAT, X, ...) WHAT(X) FE_04(WHAT, __VA_ARGS__)
#define FE_06(WHAT, X, ...) WHAT(X) FE_05(WHAT, __VA_ARGS__)
#define FE_07(WHAT, X, ...) WHAT(X) FE_06(WHAT, __VA_ARGS__)
#define FE_08(WHAT, X, ...) WHAT(X) FE_07(WHAT, __VA_ARGS__)
#define FE_09(WHAT, X, ...) WHAT(X) FE_08(WHAT, __VA_ARGS__)
#define FE_10(WHAT, X, ...) WHAT(X) FE_09(WHAT, __VA_ARGS__)
#define FE_11(WHAT, X, ...) WHAT(X) FE_10(WHAT, __VA_ARGS__)
#define FE_12(WHAT, X, ...) WHAT(X) FE_11(WHAT, __VA_ARGS__)
#define FE_13(WHAT, X, ...) WHAT(X) FE_12(WHAT, __VA_ARGS__)
#define FE_14(WHAT, X, ...) WHAT(X) FE_13(WHAT, __VA_ARGS__)
#define FE_15(WHAT, X, ...) WHAT(X) FE_14(WHAT, __VA_ARGS__)
#define FE_16(WHAT, X, ...) WHAT(X) FE_15(WHAT, __VA_ARGS__)
#define FE_17(WHAT, X, ...) WHAT(X) FE_16(WHAT, __VA_ARGS__)
#define FE_18(WHAT, X, ...) WHAT(X) FE_17(WHAT, __VA_ARGS__)
#define FE_19(WHAT, X, ...) WHAT(X) FE_18(WHAT, __VA_ARGS__)
#define FE_20(WHAT, X, ...) WHAT(X) FE_19(WHAT, __VA_ARGS__)

#define GET_MACRO(_00, _01, _02, _03, _04, _05, _06, _07, _08, _09, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, NAME, ...) NAME
#define FOR_EACH(action, ...)                                                                                                                                                     \
    GET_MACRO(_0, __VA_ARGS__, FE_20, FE_19, FE_18, FE_17, FE_16, FE_15, FE_14, FE_13, FE_12, FE_11, FE_10, FE_09, FE_08, FE_07, FE_06, FE_05, FE_04, FE_03, FE_02, FE_01, FE_00) \
    (action, __VA_ARGS__)

//////////

#if DEBUG_TESTS
#define ck_assert_int_eq(x, y)                   \
    do                                           \
    {                                            \
        if (x != y)                              \
            log_error(NULL, "%d != %d\n", x, y); \
    } while (0)

#define ck_assert_int_ne(x, y)                   \
    do                                           \
    {                                            \
        if (x == y)                              \
            log_error(NULL, "%d == %d\n", x, y); \
    } while (0)

#define ck_assert_str_eq(x, y)                   \
    do                                           \
    {                                            \
        if (strcmp(x, y) != 0)                   \
            log_error(NULL, "%s != %s\n", x, y); \
    } while (0)

#define ck_assert_ptr_nonnull(x)               \
    do                                         \
    {                                          \
        if (x == NULL)                         \
            log_error(NULL, "Null pointer\n"); \
    } while (0)

#define ck_assert_ret_ok(x)                                        \
    do                                                             \
    {                                                              \
        int rv = x;                                                \
        if (rv != 0)                                               \
        {                                                          \
            log_error(NULL, "Function returned nonzero %d\n", rv); \
            SYS_EXCEPTION();                                       \
            log_exception(NULL);                                   \
        }                                                          \
    } while (0)

#define ck_assert_ret_nonzero(x)                         \
    do                                                   \
    {                                                    \
        if (x == 0)                                      \
            log_error(NULL, "Function returned zero\n"); \
    } while (0)

#else
#include <check.h>
#define ck_assert_ret_ok(x) ck_assert_int_eq(0, x)
#define ck_assert_ret_nonzero(x) ck_assert_int_ne(0, x)
#endif

#if DEBUG_TESTS // libcheck disabled

#define DEFINE_TEST(test_name) \
    void test_name()

#define END_TEST_DEFINITION()

#define ADD_TEST(x) x();

#define RUN_TESTS(suite_name, ...)      \
                                        \
    int main()                          \
    {                                   \
        FOR_EACH(ADD_TEST, __VA_ARGS__) \
        return 0;                       \
    }

#else // not DEBUG_TESTS

#define DEFINE_TEST(test_name) \
    START_TEST(test_name)

#define END_TEST_DEFINITION() \
    END_TEST

#define ADD_TEST(x) tcase_add_test(tc_core, x);

#define RUN_TESTS(suite_name, ...)                                 \
    END_TEST                                                       \
                                                                   \
    Suite *test_suite(void)                                        \
    {                                                              \
        Suite *s = suite_create(#suite_name);                      \
        TCase *tc_core = tcase_create("Core");                     \
                                                                   \
        FOR_EACH(ADD_TEST, __VA_ARGS__)                            \
        suite_add_tcase(s, tc_core);                               \
                                                                   \
        return s;                                                  \
    }                                                              \
                                                                   \
    int main(void)                                                 \
    {                                                              \
        int number_failed;                                         \
        Suite *s = test_suite();                                   \
        SRunner *sr = srunner_create(s);                           \
                                                                   \
        srunner_run_all(sr, CK_VERBOSE);                           \
        number_failed = srunner_ntests_failed(sr);                 \
        srunner_free(sr);                                          \
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE; \
    }

#endif // DEBUG_TESTS

#endif // TEST_SETUP_H
