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

#ifndef TEST_SETUP_H
#define TEST_SETUP_H

#if DEBUG_TESTS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int _test_failures = 0;
static int _test_count    = 0;

#define _ck_fail(fmt, ...) \
    do { \
        fprintf(stderr, "  FAIL [%s:%d]: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        _test_failures++; \
    } while (0)

#define ck_assert(expr) \
    do { \
        _test_count++; \
        if (!(expr)) { _ck_fail("assertion failed: %s", #expr); } \
    } while (0)

#define ck_assert_ret_ok(expr) \
    do { \
        _test_count++; \
        int _ret = (expr); \
        if (_ret != 0) { _ck_fail("%s returned %d (expected 0)", #expr, _ret); } \
    } while (0)

#define ck_assert_ret_nonzero(expr) \
    do { \
        _test_count++; \
        int _ret = (expr); \
        if (_ret == 0) { _ck_fail("%s returned 0 (expected non-zero)", #expr); } \
    } while (0)

#define ck_assert_int_eq(a, b) \
    do { \
        _test_count++; \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a != _b) { _ck_fail("%s == %s: %lld != %lld", #a, #b, _a, _b); } \
    } while (0)

#define ck_assert_uint_eq(a, b) \
    do { \
        _test_count++; \
        unsigned long long _a = (unsigned long long)(a); \
        unsigned long long _b = (unsigned long long)(b); \
        if (_a != _b) { _ck_fail("%s == %s: %llu != %llu", #a, #b, _a, _b); } \
    } while (0)

#define ck_assert_ptr_nonnull(p) \
    do { \
        _test_count++; \
        if ((p) == NULL) { _ck_fail("%s is NULL (expected non-NULL)", #p); } \
    } while (0)

#define ck_assert_ptr_null(p) \
    do { \
        _test_count++; \
        if ((p) != NULL) { _ck_fail("%s is non-NULL (expected NULL)", #p); } \
    } while (0)

#define ck_assert_ptr_eq(a, b) \
    do { \
        _test_count++; \
        const void *_a = (const void *)(a); \
        const void *_b = (const void *)(b); \
        if (_a != _b) { _ck_fail("%s == %s: %p != %p", #a, #b, _a, _b); } \
    } while (0)

#define ck_assert_str_eq(a, b) \
    do { \
        _test_count++; \
        const char *_a = (a); \
        const char *_b = (b); \
        if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) { \
            _ck_fail("%s == %s: \"%s\" != \"%s\"", #a, #b, \
                     _a ? _a : "(null)", _b ? _b : "(null)"); \
        } \
    } while (0)

#define ck_assert_mem_eq(a, b, n) \
    do { \
        _test_count++; \
        if (memcmp((a), (b), (n)) != 0) { \
            _ck_fail("memcmp(%s, %s, %zu) != 0", #a, #b, (size_t)(n)); \
        } \
    } while (0)

#define ck_assert_double_eq_tol(a, b, tol) \
    do { \
        _test_count++; \
        double _a = (double)(a); \
        double _b = (double)(b); \
        double _t = (double)(tol); \
        if (fabs(_a - _b) > _t) { \
            _ck_fail("%s ~= %s (tol %g): %g != %g", #a, #b, _t, _a, _b); \
        } \
    } while (0)

#define ck_assert_double_lt(a, b) \
    do { \
        _test_count++; \
        double _a = (double)(a); \
        double _b = (double)(b); \
        if (!(_a < _b)) { \
            _ck_fail("%s < %s: %g not < %g", #a, #b, _a, _b); \
        } \
    } while (0)

#define DEFINE_TEST(name) static void name(void)

#define END_TEST_DEFINITION() /* nothing needed in debug mode */

/* --- RUN_TESTS variadic dispatch --- */

#define RUN_TESTS_1(suite, t1) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_2(suite, t1, t2) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_3(suite, t1, t2, t3) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_4(suite, t1, t2, t3, t4) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_5(suite, t1, t2, t3, t4, t5) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_6(suite, t1, t2, t3, t4, t5, t6) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_7(suite, t1, t2, t3, t4, t5, t6, t7) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_8(suite, t1, t2, t3, t4, t5, t6, t7, t8) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_9(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_10(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_11(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_12(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_13(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); t13(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_14(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); t13(); t14(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_15(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); t13(); t14(); t15(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define RUN_TESTS_16(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16) \
    int main(void) { \
        printf("=== %s ===\n", #suite); \
        t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); t13(); t14(); t15(); t16(); \
        printf("=== %d checks, %d failures ===\n", _test_count, _test_failures); \
        return _test_failures > 0 ? 1 : 0; \
    }

#define _GET_RUN_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, NAME, ...) NAME
#define RUN_TESTS(suite, ...) \
    _GET_RUN_MACRO(__VA_ARGS__, RUN_TESTS_16, RUN_TESTS_15, RUN_TESTS_14, RUN_TESTS_13, RUN_TESTS_12, RUN_TESTS_11, RUN_TESTS_10, RUN_TESTS_9, RUN_TESTS_8, RUN_TESTS_7, RUN_TESTS_6, RUN_TESTS_5, RUN_TESTS_4, RUN_TESTS_3, RUN_TESTS_2, RUN_TESTS_1)(suite, __VA_ARGS__)

#else  /* DEBUG_TESTS == 0: use libcheck */

#include <check.h>

#define DEFINE_TEST(name)     START_TEST(name)
#define END_TEST_DEFINITION() END_TEST

#define ck_assert_ret_ok(expr)      ck_assert_int_eq((expr), 0)
#define ck_assert_ret_nonzero(expr) ck_assert_int_ne((expr), 0)
/* ck_assert_double_eq_tol is already defined in check.h */

/* RUN_TESTS with libcheck: build a simple non-forking suite and run it */
#define RUN_TESTS_1(suite, t1) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_2(suite, t1, t2) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_3(suite, t1, t2, t3) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_4(suite, t1, t2, t3, t4) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); \
        tcase_add_test(tc, t3); tcase_add_test(tc, t4); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_5(suite, t1, t2, t3, t4, t5) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_6(suite, t1, t2, t3, t4, t5, t6) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_7(suite, t1, t2, t3, t4, t5, t6, t7) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_8(suite, t1, t2, t3, t4, t5, t6, t7, t8) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_9(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_10(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_11(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_12(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); tcase_add_test(tc, t12); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_13(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); tcase_add_test(tc, t12); \
        tcase_add_test(tc, t13); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_14(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); tcase_add_test(tc, t12); \
        tcase_add_test(tc, t13); tcase_add_test(tc, t14); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_15(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); tcase_add_test(tc, t12); \
        tcase_add_test(tc, t13); tcase_add_test(tc, t14); tcase_add_test(tc, t15); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define RUN_TESTS_16(suite, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16) \
    int main(void) { \
        Suite *s = suite_create(#suite); \
        TCase *tc = tcase_create("core"); \
        tcase_add_test(tc, t1); tcase_add_test(tc, t2); tcase_add_test(tc, t3); \
        tcase_add_test(tc, t4); tcase_add_test(tc, t5); tcase_add_test(tc, t6); \
        tcase_add_test(tc, t7); tcase_add_test(tc, t8); tcase_add_test(tc, t9); \
        tcase_add_test(tc, t10); tcase_add_test(tc, t11); tcase_add_test(tc, t12); \
        tcase_add_test(tc, t13); tcase_add_test(tc, t14); tcase_add_test(tc, t15); \
        tcase_add_test(tc, t16); \
        suite_add_tcase(s, tc); \
        SRunner *sr = srunner_create(s); \
        srunner_set_fork_status(sr, CK_NOFORK); \
        srunner_run_all(sr, CK_NORMAL); \
        int nfail = srunner_ntests_failed(sr); \
        srunner_free(sr); \
        return nfail > 0 ? 1 : 0; \
    }

#define _GET_RUN_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, NAME, ...) NAME
#define RUN_TESTS(suite, ...) \
    _GET_RUN_MACRO(__VA_ARGS__, RUN_TESTS_16, RUN_TESTS_15, RUN_TESTS_14, RUN_TESTS_13, RUN_TESTS_12, RUN_TESTS_11, RUN_TESTS_10, RUN_TESTS_9, RUN_TESTS_8, RUN_TESTS_7, RUN_TESTS_6, RUN_TESTS_5, RUN_TESTS_4, RUN_TESTS_3, RUN_TESTS_2, RUN_TESTS_1)(suite, __VA_ARGS__)

#endif  /* DEBUG_TESTS */

#endif  /* TEST_SETUP_H */
