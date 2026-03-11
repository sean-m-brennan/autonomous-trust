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

#include "autonomous_trust/structures/data_priv.h"

DEFINE_TEST(test_integer_roundtrip)
{
    data_t *d = integer_data(42);
    ck_assert_ptr_nonnull(d);

    int val = 0;
    ck_assert_ret_ok(data_integer(d, &val));
    ck_assert_int_eq(val, 42);

    /* Negative values */
    data_t *d2 = integer_data(-99);
    ck_assert_ptr_nonnull(d2);
    int val2 = 0;
    ck_assert_ret_ok(data_integer(d2, &val2));
    ck_assert_int_eq(val2, -99);

    /* Long integer */
    data_t *d3 = l_integer_data(1234567890L);
    ck_assert_ptr_nonnull(d3);
    long lval = 0;
    ck_assert_ret_ok(data_l_integer(d3, &lval));
    ck_assert(lval == 1234567890L);

    smrt_deref(d);
    smrt_deref(d2);
    smrt_deref(d3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unsigned_roundtrip)
{
    data_t *d = u_integer_data(255);
    ck_assert_ptr_nonnull(d);
    unsigned int uval = 0;
    ck_assert_ret_ok(data_u_integer(d, &uval));
    ck_assert_uint_eq(uval, 255);

    data_t *d2 = ul_integer_data(4000000000UL);
    ck_assert_ptr_nonnull(d2);
    unsigned long ulval = 0;
    ck_assert_ret_ok(data_ul_integer(d2, &ulval));
    ck_assert(ulval == 4000000000UL);

    smrt_deref(d);
    smrt_deref(d2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_float_roundtrip)
{
    data_t *d = floating_pt_data(3.14f);
    ck_assert_ptr_nonnull(d);
    float fval = 0.0f;
    ck_assert_ret_ok(data_floating_pt(d, &fval));
    ck_assert_double_eq_tol(fval, 3.14f, 0.001);

    data_t *d2 = floating_pt_dbl_data(2.718281828);
    ck_assert_ptr_nonnull(d2);
    double dval = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(d2, &dval));
    ck_assert_double_eq_tol(dval, 2.718281828, 1e-9);

    smrt_deref(d);
    smrt_deref(d2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_bool_string_bytes)
{
    /* Boolean */
    data_t *db = boolean_data(true);
    ck_assert_ptr_nonnull(db);
    bool bval = false;
    ck_assert_ret_ok(data_boolean(db, &bval));
    ck_assert(bval == true);

    data_t *dbf = boolean_data(false);
    bool bval2 = true;
    ck_assert_ret_ok(data_boolean(dbf, &bval2));
    ck_assert(bval2 == false);

    /* String */
    char hello[] = "hello";
    data_t *ds = string_data(hello, 5);
    ck_assert_ptr_nonnull(ds);
    char buf[32] = {0};
    ck_assert_ret_ok(data_string(ds, buf, sizeof(buf)));
    ck_assert_str_eq(buf, "hello");

    /* String pointer */
    string_t sptr = NULL;
    ck_assert_ret_ok(data_string_ptr(ds, &sptr));
    ck_assert_ptr_nonnull(sptr);
    ck_assert_str_eq(sptr, "hello");

    /* Bytes */
    unsigned char raw[] = {0xDE, 0xAD, 0xBE, 0xEF};
    data_t *dby = bytes_data(raw, sizeof(raw));
    ck_assert_ptr_nonnull(dby);
    unsigned char out[8] = {0};
    ck_assert_ret_ok(data_bytes(dby, out, sizeof(out)));
    ck_assert_mem_eq(out, raw, sizeof(raw));

    smrt_deref(db);
    smrt_deref(dbf);
    smrt_deref(ds);
    smrt_deref(dby);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_equality)
{
    data_t *a = integer_data(42);
    data_t *b = integer_data(42);
    data_t *c = integer_data(99);
    ck_assert(data_equal(a, b) == true);
    ck_assert(data_equal(a, c) == false);

    char tstr[] = "test";
    char tstr2[] = "test";
    char ostr[] = "other";
    data_t *sa = string_data(tstr, 4);
    data_t *sb = string_data(tstr2, 4);
    data_t *sc = string_data(ostr, 5);
    ck_assert(data_equal(sa, sb) == true);
    ck_assert(data_equal(sa, sc) == false);

    /* Different types are not equal */
    ck_assert(data_equal(a, sa) == false);

    smrt_deref(a);
    smrt_deref(b);
    smrt_deref(c);
    smrt_deref(sa);
    smrt_deref(sb);
    smrt_deref(sc);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_type_mismatch_errors)
{
    data_t *d = integer_data(42);
    float fval = 0.0f;
    /* Extracting float from int data should fail */
    ck_assert_ret_nonzero(data_floating_pt(d, &fval));

    bool bval = false;
    ck_assert_ret_nonzero(data_boolean(d, &bval));

    char buf[32] = {0};
    ck_assert_ret_nonzero(data_string(d, buf, sizeof(buf)));

    smrt_deref(d);
}
END_TEST_DEFINITION()

RUN_TESTS(Data, test_integer_roundtrip, test_unsigned_roundtrip,
          test_float_roundtrip, test_bool_string_bytes,
          test_data_equality, test_type_mismatch_errors)
