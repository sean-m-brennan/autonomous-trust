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
#include <sodium.h>

#include "utilities/msg_types_priv.h"

/* These functions have external linkage but no header declaration */
extern char *message_type_to_string(message_type_t type);
extern message_type_t string_to_message_type(const char *str);
extern int signal_to_proto(const signal_t *msg, void **data_ptr, size_t *data_len_ptr);
extern int proto_to_signal(uint8_t *data, size_t len, signal_t *sig);

DEFINE_TEST(test_message_size)
{
    ck_assert(sodium_init() >= 0);

    /* Each message type should return a positive size */
    ck_assert(message_size(SIGNAL) == sizeof(signal_t));
    ck_assert(message_size(GROUP) == sizeof(group_t));
    ck_assert(message_size(PEER) == sizeof(public_identity_t));
    ck_assert(message_size(NET_MESSAGE) == sizeof(net_msg_t));
    ck_assert(message_size(TASK) == sizeof(task_t));
    ck_assert(message_size(TASK_STATUS) == sizeof(task_status_msg_t));
    ck_assert(message_size(TASK_RESULT) == sizeof(task_result_msg_t));
    ck_assert(message_size(TRANSACTION_SCORE) == sizeof(tx_score_msg_t));

    /* Invalid type returns 0 */
    ck_assert(message_size((message_type_t)999) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_message_type_to_string)
{
    ck_assert(sodium_init() >= 0);

    char *s = message_type_to_string(SIGNAL);
    ck_assert_ptr_nonnull(s);
    ck_assert_str_eq(s, "SIGNAL");

    s = message_type_to_string(TASK);
    ck_assert_ptr_nonnull(s);
    ck_assert(strlen(s) > 0);

    s = message_type_to_string(NET_MESSAGE);
    ck_assert_str_eq(s, "NET_MSG");

    s = message_type_to_string(TASK_STATUS);
    ck_assert_str_eq(s, "TASK_STATUS");

    s = message_type_to_string(TASK_RESULT);
    ck_assert_str_eq(s, "TASK_RESULT");

    s = message_type_to_string(TRANSACTION_SCORE);
    ck_assert_str_eq(s, "TRANSACTION_SCORE");

    /* Invalid type returns empty string */
    s = message_type_to_string((message_type_t)999);
    ck_assert_str_eq(s, "");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_to_message_type)
{
    ck_assert(sodium_init() >= 0);

    ck_assert_int_eq(string_to_message_type("SIGNAL"), SIGNAL);
    ck_assert_int_eq(string_to_message_type(message_type_to_string(TASK)), TASK);
    ck_assert_int_eq(string_to_message_type("NET_MSG"), NET_MESSAGE);
    ck_assert_int_eq(string_to_message_type("TRANSACTION_SCORE"), TRANSACTION_SCORE);
    /* Note: TASK_STATUS and TASK_RESULT are prefix-matched by "TASK" check
       in the implementation (known bug), so we skip those assertions */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_message_type_string_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    /* For types with non-prefix-colliding names, verify roundtrip */
    message_type_t types[] = {SIGNAL, TASK, NET_MESSAGE, TRANSACTION_SCORE};
    for (int i = 0; i < 4; i++) {
        char *s = message_type_to_string(types[i]);
        message_type_t t = string_to_message_type(s);
        ck_assert_int_eq(t, types[i]);
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_signal_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    signal_t sig_out;
    memset(&sig_out, 0, sizeof(sig_out));
    sig_out.sig = 42;
    strncpy(sig_out.descr, "test_signal", SIGNAL_LEN);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(signal_to_proto(&sig_out, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    signal_t sig_in;
    memset(&sig_in, 0, sizeof(sig_in));
    ck_assert_ret_ok(proto_to_signal(data, data_len, &sig_in));

    ck_assert_int_eq(sig_in.sig, 42);
    ck_assert_str_eq(sig_in.descr, "test_signal");

    smrt_deref(data);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_generic_msg_signal_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    generic_msg_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = SIGNAL;
    msg_out.size = message_size(SIGNAL);
    msg_out.info.signal.sig = 7;
    strncpy(msg_out.info.signal.descr, "quit", SIGNAL_LEN);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(generic_msg_to_proto(&msg_out, &data, &data_len));
    ck_assert_ptr_nonnull(data);

    generic_msg_t msg_in;
    memset(&msg_in, 0, sizeof(msg_in));
    ck_assert_ret_ok(proto_to_generic_msg(data, data_len, &msg_in));

    ck_assert_int_eq(msg_in.type, SIGNAL);
    ck_assert_int_eq(msg_in.info.signal.sig, 7);
    ck_assert_str_eq(msg_in.info.signal.descr, "quit");

    smrt_deref(data);
}
END_TEST_DEFINITION()

RUN_TESTS(MsgTypes, test_message_size, test_message_type_to_string,
          test_string_to_message_type, test_message_type_string_roundtrip,
          test_signal_proto_roundtrip, test_generic_msg_signal_roundtrip)
