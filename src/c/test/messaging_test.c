/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include <stdlib.h>
#include <unistd.h>

#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/utilities/msg_types.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"
#include "autonomous_trust/utilities/util.h"
#include "autonomous_trust/utilities/logger.h"
#include "autonomous_trust/config/configuration.h"
#include "autonomous_trust/identity/identity_priv.h"

#define DEBUG_TESTS 0

#include "test_setup.h"

void msg_test_snd(char *key, config_t *config) {
    queue_t mq;
    ck_assert_ret_ok(messaging_init("msgtest.other", &mq));  // required for unix domain udp to work
    messaging_assign(&mq);

    usleep(100000);
    generic_msg_t sig = {.type = SIGNAL, .info.signal = {.descr = "test", .sig = -1}};
    ck_assert_ret_ok(messaging_send(key, SIGNAL, &sig, false));

    ck_assert_ret_ok(messaging_send(key, SIGNAL, &sig, false));

    generic_msg_t peer = {.type = PEER};
    memcpy(&peer.info.peer, config->data_struct, sizeof(public_identity_t));
    ck_assert_ret_ok(messaging_send(key, PEER, &peer, false));
    messaging_close();
}

void msg_test_rcv(char *key, config_t *config) {
    queue_t mq;
    ck_assert_ret_ok(messaging_init(key, &mq));

    generic_msg_t recvd = {0};
    ck_assert_ret_ok(messaging_recv_on(&mq, &recvd, NULL, true));
    ck_assert_int_eq(SIGNAL, recvd.type);
    ck_assert_int_eq(-1, recvd.info.signal.sig);
    ck_assert_str_eq("test", recvd.info.signal.descr);

    signal_t signal = {0};
    long type = 0;
    ck_assert_ret_ok(signal_recv(&mq, &type, &signal));
    ck_assert_int_eq(SIGNAL, type);
    ck_assert_int_eq(-1, signal.sig);
    ck_assert_str_eq("test", signal.descr);

    messaging_assign(&mq);
    ck_assert_ret_ok(messaging_recv(&recvd));
    ck_assert_int_eq(PEER, recvd.type);
    public_identity_t *pub_ident = config->data_struct;
    ck_assert_str_eq(pub_ident->address, recvd.info.peer.address);
    ck_assert_str_eq(pub_ident->fullname, recvd.info.peer.fullname);
    messaging_close();
}

DEFINE_TEST(test_messages)
{
    logger_t log;
    logger_init(&log, INFO, NULL);

    char *mfile = "msgtest";

    config_t *config;
    ck_assert_ret_ok(load_config("identity.cfg.json", &config, NULL, NULL));

    pid_t pid = fork();
    ck_assert_int_ne(-1, pid);

    if (pid == 0) {
        msg_test_snd(mfile, config);
    }
    else {
        msg_test_rcv(mfile, config);
    }
}
END_TEST_DEFINITION()

RUN_TESTS(IPC, test_messages)
