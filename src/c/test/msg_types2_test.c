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
#include <sodium.h>

#include "autonomous_trust/utilities/msg_types.h"
#include "autonomous_trust/utilities/msg_types_priv.h"

extern char *message_type_to_string(message_type_t type);
extern message_type_t string_to_message_type(const char *str);
extern int signal_to_proto(const signal_t *msg, void **data_ptr, size_t *data_len_ptr);
extern int proto_to_signal(uint8_t *data, size_t len, signal_t *sig);
extern int wrap_in_any(message_type_t type, void *data_in, size_t data_in_len,
                       void **data_ptr, size_t *data_len_ptr);

DEFINE_TEST(test_generic_msg_signal_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = SIGNAL;
    msg.size = sizeof(signal_t);
    msg.info.signal.sig = 77;
    strncpy(msg.info.signal.descr, "test_proto", SIGNAL_LEN);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(generic_msg_to_proto(&msg, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    /* Deserialize back */
    generic_msg_t msg2;
    memset(&msg2, 0, sizeof(msg2));
    ck_assert_ret_ok(proto_to_generic_msg(data, data_len, &msg2));
    ck_assert_int_eq(msg2.type, SIGNAL);
    ck_assert_int_eq(msg2.info.signal.sig, 77);
    ck_assert_str_eq(msg2.info.signal.descr, "test_proto");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wrap_in_any)
{
    ck_assert(sodium_init() >= 0);

    /* Create simple data to wrap */
    char test_data[] = "hello";
    size_t test_len = strlen(test_data) + 1;
    void *data_in = smrt_create(test_len);
    ck_assert_ptr_nonnull(data_in);
    memcpy(data_in, test_data, test_len);

    void *packed = NULL;
    size_t packed_len = 0;
    ck_assert_ret_ok(wrap_in_any(SIGNAL, data_in, test_len, &packed, &packed_len));
    ck_assert_ptr_nonnull(packed);
    ck_assert(packed_len > 0);
    /* data_in is freed by wrap_in_any (smrt_deref) */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_message_size_all_types)
{
    ck_assert(message_size(SIGNAL) == sizeof(signal_t));
    ck_assert(message_size(NET_MESSAGE) == sizeof(net_msg_t));
    ck_assert(message_size(TRANSACTION_SCORE) > 0);

    /* Unknown type should return 0 */
    ck_assert(message_size((message_type_t)999) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_message_type_to_string_all)
{
    char *s;
    s = message_type_to_string(SIGNAL);
    ck_assert_str_eq(s, "SIGNAL");

    s = message_type_to_string(TASK);
    ck_assert_str_eq(s, "TASK");

    s = message_type_to_string(NET_MESSAGE);
    ck_assert_str_eq(s, "NET_MSG");

    s = message_type_to_string(TASK_STATUS);
    ck_assert_str_eq(s, "TASK_STATUS");

    s = message_type_to_string(TASK_RESULT);
    ck_assert_str_eq(s, "TASK_RESULT");

    s = message_type_to_string(TRANSACTION_SCORE);
    ck_assert_str_eq(s, "TRANSACTION_SCORE");

    /* Unknown type */
    s = message_type_to_string((message_type_t)999);
    ck_assert_str_eq(s, "");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_to_message_type_all)
{
    ck_assert_int_eq(string_to_message_type("SIGNAL"), SIGNAL);
    ck_assert_int_eq(string_to_message_type("NET_MSG"), NET_MESSAGE);
    ck_assert_int_eq(string_to_message_type("TRANSACTION_SCORE"), TRANSACTION_SCORE);

    /* Unknown string returns (message_type_t)-1 */
    ck_assert(string_to_message_type("GARBAGE") == (message_type_t)-1);
    ck_assert(string_to_message_type("") == (message_type_t)-1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_signal_proto_format)
{
    signal_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.sig = 42;
    strncpy(sig.descr, "quit", SIGNAL_LEN);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(signal_to_proto(&sig, &data, &data_len));

    /* Format should be "42-quit" */
    ck_assert_str_eq((char *)data, "42-quit");

    /* Parse back */
    signal_t sig2;
    memset(&sig2, 0, sizeof(sig2));
    ck_assert_ret_ok(proto_to_signal((uint8_t *)data, data_len, &sig2));
    ck_assert_int_eq(sig2.sig, 42);
    ck_assert_str_eq(sig2.descr, "quit");
}
END_TEST_DEFINITION()

RUN_TESTS(MsgTypes2, test_generic_msg_signal_proto_roundtrip, test_wrap_in_any,
          test_message_size_all_types, test_message_type_to_string_all,
          test_string_to_message_type_all, test_signal_proto_format)
