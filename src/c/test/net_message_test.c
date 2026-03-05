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

#include "network/net_message.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

DEFINE_TEST(test_net_message_roundtrip)
{
    net_wire_msg_t msg;
    net_wire_msg_init(&msg);

    strncpy(msg.process, "identity", PROC_NAME_LEN);
    strncpy(msg.function, "request_access", NET_MSG_FUNC_LEN);

    const char *payload = "{\"__type__\":\"Identity\",\"name\":\"Alice\"}";
    msg.data = (uint8_t *)strdup(payload);
    msg.data_len = strlen(payload);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);

    /* Verify wire format is "process|function|data" */
    ck_assert_int_eq(wire_len, strlen("identity") + 1 + strlen("request_access") + 1 + msg.data_len);

    /* Parse back */
    net_wire_msg_t parsed;
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &parsed));
    ck_assert_str_eq(parsed.process, "identity");
    ck_assert_str_eq(parsed.function, "request_access");
    ck_assert_int_eq(parsed.data_len, msg.data_len);
    ck_assert_int_eq(memcmp(parsed.data, payload, msg.data_len), 0);

    free(wire);
    free(msg.data);
    net_wire_msg_free(&parsed);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_message_empty_data)
{
    net_wire_msg_t msg;
    net_wire_msg_init(&msg);

    strncpy(msg.process, "network", PROC_NAME_LEN);
    strncpy(msg.function, "ping", NET_MSG_FUNC_LEN);
    msg.data = NULL;
    msg.data_len = 0;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));

    net_wire_msg_t parsed;
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &parsed));
    ck_assert_str_eq(parsed.process, "network");
    ck_assert_str_eq(parsed.function, "ping");
    ck_assert_int_eq(parsed.data_len, 0);

    free(wire);
    net_wire_msg_free(&parsed);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_message_data_with_pipes)
{
    net_wire_msg_t msg;
    net_wire_msg_init(&msg);

    strncpy(msg.process, "test", PROC_NAME_LEN);
    strncpy(msg.function, "handler", NET_MSG_FUNC_LEN);

    /* Data containing pipe characters */
    const char *payload = "key1|val1|key2|val2";
    msg.data = (uint8_t *)strdup(payload);
    msg.data_len = strlen(payload);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));

    net_wire_msg_t parsed;
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &parsed));
    ck_assert_str_eq(parsed.process, "test");
    ck_assert_str_eq(parsed.function, "handler");
    ck_assert_int_eq(parsed.data_len, strlen(payload));
    ck_assert_int_eq(memcmp(parsed.data, payload, parsed.data_len), 0);

    free(wire);
    free(msg.data);
    net_wire_msg_free(&parsed);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_message_invalid_format)
{
    net_wire_msg_t parsed;
    /* No delimiters */
    const uint8_t bad1[] = "nodelmiter";
    ck_assert_ret_nonzero(net_message_from_wire(bad1, sizeof(bad1) - 1, NULL, &parsed));

    /* Only one delimiter */
    const uint8_t bad2[] = "process|nodelmiter2";
    ck_assert_ret_nonzero(net_message_from_wire(bad2, sizeof(bad2) - 1, NULL, &parsed));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_message_broadcast)
{
    net_wire_msg_t msg;
    net_wire_msg_init(&msg);

    ck_assert_int_eq(msg.encrypt, true);
    ck_assert_int_eq(msg.to_whom.type, RECIPIENT_NONE);

    net_wire_msg_set_broadcast(&msg);
    ck_assert_int_eq(msg.encrypt, false);
    ck_assert_int_eq(msg.to_whom.type, RECIPIENT_BROADCAST);
}

RUN_TESTS(NetMessage, test_net_message_roundtrip, test_net_message_empty_data,
          test_net_message_data_with_pipes, test_net_message_invalid_format,
          test_net_message_broadcast)
