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

#include "structures/data_priv.h"

DEFINE_TEST(test_data_int_proto_roundtrip)
{
    data_t *d = integer_data(12345);

    AutonomousTrust__Core__Protobuf__Structures__Data proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    ck_assert_ret_ok(data_sync_out(d, &proto));

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_sync_in(&proto, &d2));

    int val = 0;
    ck_assert_ret_ok(data_integer(&d2, &val));
    ck_assert_int_eq(val, 12345);

    data_proto_free(&proto);
    smrt_deref(d);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_uint_proto_roundtrip)
{
    data_t *d = u_integer_data(99999);

    AutonomousTrust__Core__Protobuf__Structures__Data proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    ck_assert_ret_ok(data_sync_out(d, &proto));

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_sync_in(&proto, &d2));

    unsigned int val = 0;
    ck_assert_ret_ok(data_u_integer(&d2, &val));
    ck_assert_uint_eq(val, 99999);

    data_proto_free(&proto);
    smrt_deref(d);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_float_proto_roundtrip)
{
    data_t *d = floating_pt_dbl_data(2.71828);

    AutonomousTrust__Core__Protobuf__Structures__Data proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    ck_assert_ret_ok(data_sync_out(d, &proto));

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_sync_in(&proto, &d2));

    double val = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(&d2, &val));
    ck_assert_double_eq_tol(val, 2.71828, 1e-5);

    data_proto_free(&proto);
    smrt_deref(d);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_bool_proto_roundtrip)
{
    data_t *dt = boolean_data(true);
    data_t *df = boolean_data(false);

    AutonomousTrust__Core__Protobuf__Structures__Data pt =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    AutonomousTrust__Core__Protobuf__Structures__Data pf =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;

    ck_assert_ret_ok(data_sync_out(dt, &pt));
    ck_assert_ret_ok(data_sync_out(df, &pf));

    data_t d2t, d2f;
    memset(&d2t, 0, sizeof(d2t));
    memset(&d2f, 0, sizeof(d2f));
    ck_assert_ret_ok(data_sync_in(&pt, &d2t));
    ck_assert_ret_ok(data_sync_in(&pf, &d2f));

    bool vt = false, vf = true;
    ck_assert_ret_ok(data_boolean(&d2t, &vt));
    ck_assert_ret_ok(data_boolean(&d2f, &vf));
    ck_assert(vt == true);
    ck_assert(vf == false);

    data_proto_free(&pt);
    data_proto_free(&pf);
    smrt_deref(dt);
    smrt_deref(df);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_string_proto_roundtrip)
{
    char msg[] = "proto string test";
    data_t *d = string_data(msg, strlen(msg));

    AutonomousTrust__Core__Protobuf__Structures__Data proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    ck_assert_ret_ok(data_sync_out(d, &proto));

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_sync_in(&proto, &d2));

    ck_assert(d2.type == STRING);
    ck_assert_mem_eq(d2.str, "proto string test", d2.size);

    data_proto_free(&proto);
    smrt_deref(d);
    free(d2.str);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_data_bytes_proto_roundtrip)
{
    unsigned char raw[] = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xFF};
    data_t *d = bytes_data(raw, sizeof(raw));

    AutonomousTrust__Core__Protobuf__Structures__Data proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    ck_assert_ret_ok(data_sync_out(d, &proto));

    data_t d2;
    memset(&d2, 0, sizeof(d2));
    ck_assert_ret_ok(data_sync_in(&proto, &d2));

    ck_assert(d2.type == BYTES);
    ck_assert_uint_eq(d2.size, sizeof(raw));
    unsigned char out[16] = {0};
    ck_assert_ret_ok(data_bytes(&d2, out, sizeof(out)));
    ck_assert_mem_eq(out, raw, sizeof(raw));

    data_proto_free(&proto);
    smrt_deref(d);
    free(d2.byt);
}
END_TEST_DEFINITION()

RUN_TESTS(DataProto, test_data_int_proto_roundtrip, test_data_uint_proto_roundtrip,
          test_data_float_proto_roundtrip, test_data_bool_proto_roundtrip,
          test_data_string_proto_roundtrip, test_data_bytes_proto_roundtrip)
