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
#include <jansson.h>

#include "autonomous_trust/structures/data_priv.h"

DEFINE_TEST(test_data_int_json_roundtrip)
{
    data_t *d = integer_data(42);
    ck_assert_ptr_nonnull(d);

    json_t *obj = NULL;
    ck_assert_ret_ok(data_to_json(d, &obj));
    ck_assert_ptr_nonnull(obj);

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_from_json(obj, &d2));

    int val = 0;
    ck_assert_ret_ok(data_integer(&d2, &val));
    ck_assert_int_eq(val, 42);

    json_decref(obj);
    smrt_deref(d);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_float_json_roundtrip)
{
    data_t *d = floating_pt_dbl_data(3.14159);
    ck_assert_ptr_nonnull(d);

    json_t *obj = NULL;
    ck_assert_ret_ok(data_to_json(d, &obj));
    ck_assert_ptr_nonnull(obj);

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_from_json(obj, &d2));

    double val = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(&d2, &val));
    ck_assert_double_eq_tol(val, 3.14159, 1e-5);

    json_decref(obj);
    smrt_deref(d);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_bool_json_roundtrip)
{
    data_t *dt = boolean_data(true);
    data_t *df = boolean_data(false);

    json_t *obj_t = NULL;
    json_t *obj_f = NULL;
    ck_assert_ret_ok(data_to_json(dt, &obj_t));
    ck_assert_ret_ok(data_to_json(df, &obj_f));

    data_t d2t, d2f;
    memset(&d2t, 0, sizeof(d2t));
    memset(&d2f, 0, sizeof(d2f));
    ck_assert_ret_ok(data_from_json(obj_t, &d2t));
    ck_assert_ret_ok(data_from_json(obj_f, &d2f));

    bool vt = false, vf = true;
    ck_assert_ret_ok(data_boolean(&d2t, &vt));
    ck_assert_ret_ok(data_boolean(&d2f, &vf));
    ck_assert(vt == true);
    ck_assert(vf == false);

    json_decref(obj_t);
    json_decref(obj_f);
    smrt_deref(dt);
    smrt_deref(df);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_string_json_roundtrip)
{
    char hello[] = "hello world";
    data_t *d = string_data(hello, strlen(hello));
    ck_assert_ptr_nonnull(d);

    json_t *obj = NULL;
    ck_assert_ret_ok(data_to_json(d, &obj));
    ck_assert_ptr_nonnull(obj);

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_from_json(obj, &d2));

    /* Use strncmp since from_json may not null-terminate */
    ck_assert(d2.size == strlen(hello));
    ck_assert_mem_eq(d2.str, "hello world", d2.size);

    json_decref(obj);
    smrt_deref(d);
    free(d2.str);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_bytes_json_roundtrip)
{
    unsigned char raw[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    data_t *d = bytes_data(raw, sizeof(raw));
    ck_assert_ptr_nonnull(d);

    json_t *obj = NULL;
    ck_assert_ret_ok(data_to_json(d, &obj));
    ck_assert_ptr_nonnull(obj);

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_from_json(obj, &d2));

    unsigned char out[16] = {0};
    ck_assert_ret_ok(data_bytes(&d2, out, sizeof(out)));
    ck_assert_mem_eq(out, raw, sizeof(raw));

    json_decref(obj);
    smrt_deref(d);
    free(d2.byt);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_uint_json_roundtrip)
{
    data_t *d = u_integer_data(255);
    ck_assert_ptr_nonnull(d);

    json_t *obj = NULL;
    ck_assert_ret_ok(data_to_json(d, &obj));
    ck_assert_ptr_nonnull(obj);

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_from_json(obj, &d2));

    unsigned int val = 0;
    ck_assert_ret_ok(data_u_integer(&d2, &val));
    ck_assert_uint_eq(val, 255);

    json_decref(obj);
    smrt_deref(d);
}
END_TEST_DEFINITION()

RUN_TESTS(DataJson, test_data_int_json_roundtrip, test_data_float_json_roundtrip,
          test_data_bool_json_roundtrip, test_data_string_json_roundtrip,
          test_data_bytes_json_roundtrip, test_data_uint_json_roundtrip)
