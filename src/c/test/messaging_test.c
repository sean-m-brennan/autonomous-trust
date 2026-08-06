/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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
#include <sys/wait.h>

#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/utilities/msg_types.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"
#include "autonomous_trust/utilities/util.h"
#include "autonomous_trust/utilities/logger.h"
#include "autonomous_trust/config/configuration.h"
#include "autonomous_trust/identity/identity_priv.h"

#define DEBUG_TESTS 1

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
    ck_assert_str_eq(pub_ident->nickname, recvd.info.peer.nickname);
    messaging_close();
}

DEFINE_TEST(test_messages)
{
    logger_t log;
    logger_init(&log, INFO, NULL);

    char mfile[] = "msgtest";

    config_t *config;
    char cfg_name[] = "identity.cfg.json";
    if (load_config(cfg_name, &config, NULL, NULL) != 0)
    {
        log_warn(&log, "Skipping msg_test: no identity config found\n");
        return;
    }

    queue_t probe;
    if (messaging_init("_msg_test_probe", &probe) != 0)
    {
        log_warn(&log, "Skipping msg_test: messaging unavailable (missing /var/at/)\n");
        return;
    }
    messaging_close();

    pid_t pid = fork();
    ck_assert((int)pid != -1);

    if (pid == 0) {
        msg_test_snd(mfile, config);
        _exit(0);
    }
    else {
        msg_test_rcv(mfile, config);
        int status;
        waitpid(pid, &status, 0);
    }
}
END_TEST_DEFINITION()

/* --- ISSUES.md §2.1.1: the socket path -------------------------------------
 *
 * `unix_addr` built its path in a 108-byte `sun_path`-sized buffer and told
 * `get_data_dir` the buffer held 255, so a long AUTONOMOUS_TRUST_ROOT wrote past
 * the end of the frame — measured as `*** stack smashing detected ***` aborting
 * the caller's own process, with ASan reporting a 115-byte write into 108 bytes.
 *
 * Separately, `path[strlen(path)] = '/'` overwrote the terminating NUL without
 * replacing it, after which `strncat`'s own `strlen` ran off the end. That one is
 * the more instructive defect, because at the lengths just under the crash it did
 * not crash — it silently truncated the queue name and bound a DIFFERENT socket,
 * which is exactly what `at_app_node_build_config` refuses to do one layer up.
 */

/* A root of `len` bytes, under /tmp so the test never depends on where it runs.
 *
 * It also *creates* `<root>/var/at`, and that is not housekeeping — it is what
 * makes the assertions mean anything. A negative control (restoring the
 * NUL-destroying join) initially failed to fire here because the over-long roots
 * had no directory: `messaging_init` was failing with ENOENT, so a test that
 * meant "refused for being too long" passed just as happily when the length
 * check was gone entirely. Every root this test uses is therefore a root where
 * binding would otherwise work. */
static void set_root_of_length(char *buf, size_t buflen, size_t len)
{
    ck_assert(len >= 5 && len < buflen);
    memset(buf, 'r', len);
    memcpy(buf, "/tmp/", 5);
    buf[len] = '\0';
    setenv("AUTONOMOUS_TRUST_ROOT", buf, 1);

    char dir[512];
    snprintf(dir, sizeof(dir), "%s/var/at", buf);
    (void)makedirs(dir, 0755);
}

DEFINE_TEST(test_a_root_too_long_for_a_socket_is_refused_not_truncated)
{
    char root[256];

    /* 90 bytes of root is the most that fits: 90 + "/var/at" (7) + "/" +
     * "at_to_app" (9) + NUL = 108, which is exactly a sun_path. Asserted on both
     * sides rather than assumed, and the success side matters as much as the
     * refusal — a length check that refused everything would pass a test that
     * only ever checked for refusals. */
    set_root_of_length(root, sizeof(root), 90);
    queue_t q;
    ck_assert_ret_ok(messaging_init("at_to_app", &q));
    ck_assert(messaging_bound("at_to_app"));
    messaging_qclose(&q);

    /* One byte more and it needs 109. It must be REFUSED, and refused *for that
     * reason*: before the fix this truncated the queue name and bound a
     * different socket, reporting success. */
    set_root_of_length(root, sizeof(root), 91);
    queue_t q2;
    ck_assert(messaging_init("at_to_app", &q2) != 0);
    ck_assert_int_eq(_exception.errnum, ENAMETOOLONG);
    /* Nothing is listening under any prefix of the name, which is the failure
     * mode truncation produced. */
    ck_assert(!messaging_bound("at_to_app"));

    /* And far past the limit, where the write used to smash the stack. Here the
     * data directory itself does not fit, so the refusal comes one step earlier,
     * in get_data_dir — and must still name the same cause. */
    set_root_of_length(root, sizeof(root), 200);
    queue_t q3;
    ck_assert(messaging_init("at_to_app", &q3) != 0);
    ck_assert_int_eq(_exception.errnum, ENAMETOOLONG);

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_bound_queue_keeps_the_whole_name_it_was_given)
{
    /* The silent-truncation half. With a short root there is plenty of room, so
     * the name must arrive intact — and `messaging_bound` is the honest way to ask
     * whether the socket that exists is the one we asked for. A name that had been
     * shortened would leave `messaging_bound("...")` false for the full name while
     * something was nonetheless listening under a prefix of it. */
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_msg_name_test", 1);
    char d1[] = "/tmp/at_msg_name_test/var/at";
    (void)makedirs(d1, 0755);

    queue_t q;
    if (messaging_init("a_long_but_legal_queue_name", &q) != 0)
    {
        unsetenv("AUTONOMOUS_TRUST_ROOT");
        return;   /* no /var/at in this environment; nothing to assert */
    }
    ck_assert(messaging_bound("a_long_but_legal_queue_name"));
    /* Not bound under a truncation of it. */
    ck_assert(!messaging_bound("a_long_but_legal_queue_nam"));
    ck_assert(!messaging_bound("a"));
    messaging_qclose(&q);

    /* Closed, so no longer bound — and this is what makes `messaging_bound` a
     * readiness signal rather than a "was it ever there" signal. */
    ck_assert(!messaging_bound("a_long_but_legal_queue_name"));

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_bound_ignores_a_stale_socket_file)
{
    /* Why the probe is `connect` and not a `stat`: a daemon that died leaves its
     * socket file behind, and a file check would call that ready. */
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_msg_stale_test", 1);
    char d2[] = "/tmp/at_msg_stale_test/var/at";
    (void)makedirs(d2, 0755);

    const char *name = "_stale_probe";
    queue_t q;
    if (messaging_init(name, &q) != 0)
    {
        unsetenv("AUTONOMOUS_TRUST_ROOT");
        return;
    }
    ck_assert(messaging_bound(name));

    /* Close the socket but leave the filesystem entry, which is precisely what a
     * killed daemon leaves behind. */
    close(q.fd);
    ck_assert(access("/tmp/at_msg_stale_test/var/at/_stale_probe", F_OK) == 0);
    ck_assert(!messaging_bound(name));

    unlink("/tmp/at_msg_stale_test/var/at/_stale_probe");
    ck_assert(!messaging_bound(name));
    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

RUN_TESTS(IPC, test_messages,
          test_a_root_too_long_for_a_socket_is_refused_not_truncated,
          test_a_bound_queue_keeps_the_whole_name_it_was_given,
          test_messaging_bound_ignores_a_stale_socket_file)
