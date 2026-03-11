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
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>

#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

static void setup_test_dir(void)
{
    char tmpl[] = "/tmp/at_msg_test_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (dir != NULL) {
        char var_path[256];
        snprintf(var_path, sizeof(var_path), "%s/var/at", dir);
        mkdir(var_path, 0755);
        /* Need to create intermediate dirs */
        char var1[256];
        snprintf(var1, sizeof(var1), "%s/var", dir);
        mkdir(var1, 0755);
        mkdir(var_path, 0755);
        setenv("AUTONOMOUS_TRUST_ROOT", dir, 1);
    }
}

DEFINE_TEST(test_messaging_init_and_close)
{
    ck_assert(sodium_init() >= 0);
    setup_test_dir();

    queue_t q;
    memset(&q, 0, sizeof(q));
    ck_assert_ret_ok(messaging_init("test_queue", &q));
    ck_assert(q.fd > 0);
    ck_assert_str_eq(q.key, "test_queue");

    messaging_qclose(&q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_assign_recv_no_msg)
{
    ck_assert(sodium_init() >= 0);
    setup_test_dir();

    queue_t q;
    memset(&q, 0, sizeof(q));
    ck_assert_ret_ok(messaging_init("test_assign", &q));

    messaging_assign(&q);

    /* Non-blocking recv with no messages should return ENOMSG */
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int ret = messaging_recv_from(&msg, NULL, false);
    ck_assert_int_eq(ret, ENOMSG);

    messaging_qclose(&q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_send_recv_signal)
{
    ck_assert(sodium_init() >= 0);
    setup_test_dir();

    queue_t sender_q, recv_q;
    memset(&sender_q, 0, sizeof(sender_q));
    memset(&recv_q, 0, sizeof(recv_q));

    ck_assert_ret_ok(messaging_init("msg_sender", &sender_q));
    ck_assert_ret_ok(messaging_init("msg_recv", &recv_q));

    messaging_assign(&sender_q);

    /* Send a signal message to recv_q */
    generic_msg_t send_msg;
    memset(&send_msg, 0, sizeof(send_msg));
    send_msg.type = SIGNAL;
    send_msg.size = sizeof(signal_t);
    send_msg.info.signal.sig = 42;
    strncpy(send_msg.info.signal.descr, "test_sig", SIGNAL_LEN);

    ck_assert_ret_ok(messaging_send("msg_recv", SIGNAL, &send_msg, true));

    /* Receive the message */
    generic_msg_t recv_msg;
    memset(&recv_msg, 0, sizeof(recv_msg));
    ck_assert_ret_ok(messaging_recv_on(&recv_q, &recv_msg, NULL, true));

    ck_assert_int_eq(recv_msg.type, SIGNAL);
    ck_assert_int_eq(recv_msg.info.signal.sig, 42);
    ck_assert_str_eq(recv_msg.info.signal.descr, "test_sig");

    messaging_qclose(&sender_q);
    messaging_qclose(&recv_q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_signal_recv_function)
{
    ck_assert(sodium_init() >= 0);
    setup_test_dir();

    queue_t sender_q, sig_q;
    memset(&sender_q, 0, sizeof(sender_q));
    memset(&sig_q, 0, sizeof(sig_q));

    ck_assert_ret_ok(messaging_init("sig_sender", &sender_q));
    ck_assert_ret_ok(messaging_init("sig_recv", &sig_q));

    messaging_assign(&sender_q);

    /* Send a signal */
    generic_msg_t send_msg;
    memset(&send_msg, 0, sizeof(send_msg));
    send_msg.type = SIGNAL;
    send_msg.size = sizeof(signal_t);
    send_msg.info.signal.sig = 99;
    strncpy(send_msg.info.signal.descr, "quit", SIGNAL_LEN);

    ck_assert_ret_ok(messaging_send("sig_recv", SIGNAL, &send_msg, true));

    /* Receive via signal_recv */
    long msg_type = 0;
    signal_t sig;
    memset(&sig, 0, sizeof(sig));
    ck_assert_ret_ok(signal_recv(&sig_q, &msg_type, &sig));
    ck_assert_int_eq(msg_type, SIGNAL);
    ck_assert_int_eq(sig.sig, 99);
    ck_assert_str_eq(sig.descr, "quit");

    messaging_qclose(&sender_q);
    messaging_qclose(&sig_q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_recv_not_connected)
{
    ck_assert(sodium_init() >= 0);

    /* messaging_recv_from without assign should fail */
    messaging_assign(NULL);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_ret_nonzero(messaging_recv_from(&msg, NULL, false));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_close_null)
{
    ck_assert(sodium_init() >= 0);

    /* Close NULL should not crash */
    messaging_qclose(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(Message, test_messaging_init_and_close, test_messaging_assign_recv_no_msg,
          test_messaging_send_recv_signal, test_signal_recv_function,
          test_messaging_recv_not_connected, test_messaging_close_null)
