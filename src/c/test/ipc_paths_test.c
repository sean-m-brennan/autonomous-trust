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

/* The two delivery paths an in-process node uses (utilities/message_ipc.h):
 * the in-process queues its subsystem threads talk over, and the stream link
 * the app reaches it by, which is all Windows has. Both are selected here the
 * way a node selects them, by $AT_IN_PROCESS and $AT_IPC_STREAM, set before
 * the first messaging call reads them. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/utilities/msg_types.h"

static char g_root[64];

__attribute__((constructor)) static void _select_paths(void)
{
    setenv("AT_IN_PROCESS", "1", 1);
    setenv("AT_IPC_STREAM", "1", 1);
    /* A short private root: socket paths must fit sun_path. */
    snprintf(g_root, sizeof(g_root), "/tmp/atipcXXXXXX");
    if (mkdtemp(g_root) == NULL)
        return;
    char var[96];
    snprintf(var, sizeof(var), "%s/var", g_root);
    mkdir(var, 0700);
    snprintf(var, sizeof(var), "%s/var/at", g_root);
    mkdir(var, 0700);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
}

static generic_msg_t _sig(int n)
{
    generic_msg_t m = {.type = SIGNAL};
    m.info.signal.sig = n;
    snprintf(m.info.signal.descr, sizeof(m.info.signal.descr), "n%d", n);
    return m;
}

/* ---- in-process ---------------------------------------------------------- */

DEFINE_TEST(test_inproc_fifo_and_full)
{
    ck_assert(messaging_in_process());
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init("ipc_a", &q));
    /* A Linux unix datagram queue admits 11; so does this, by default. */
    for (int i = 0; i < 11; i++)
    {
        generic_msg_t m = _sig(i);
        ck_assert_ret_ok(messaging_send("ipc_a", SIGNAL, &m, false));
    }
    generic_msg_t extra = _sig(99);
    ck_assert_int_eq(messaging_send("ipc_a", SIGNAL, &extra, false), EAGAIN);
    for (int i = 0; i < 11; i++)
    {
        generic_msg_t got = {0};
        ck_assert_ret_ok(messaging_recv_on(&q, &got, NULL, false));
        ck_assert_int_eq(got.type, SIGNAL);
        ck_assert_int_eq(got.info.signal.sig, i);
        messaging_recv_release(&got);
    }
    generic_msg_t none = {0};
    ck_assert_int_eq(messaging_recv_on(&q, &none, NULL, false), ENOMSG);
    messaging_qclose(&q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_inproc_bound_close_reopen)
{
    ck_assert(!messaging_bound("ipc_b"));
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init("ipc_b", &q));
    ck_assert(messaging_bound("ipc_b"));
    generic_msg_t m = _sig(1);
    ck_assert_ret_ok(messaging_send("ipc_b", SIGNAL, &m, false));
    messaging_qclose(&q);
    ck_assert(!messaging_bound("ipc_b"));
    /* A queue nobody holds refuses, as a stale socket file did. */
    ck_assert(messaging_send("ipc_b", SIGNAL, &m, false) != 0);

    /* The next owner starts empty, as a fresh bind does. */
    queue_t q2 = {0};
    ck_assert_ret_ok(messaging_init("ipc_b", &q2));
    generic_msg_t got = {0};
    ck_assert_int_eq(messaging_recv_on(&q2, &got, NULL, false), ENOMSG);
    messaging_qclose(&q2);
}
END_TEST_DEFINITION()

/* The receive side is per thread: each subsystem thread assigns its own. */
static void *_assign_and_recv(void *arg)
{
    queue_t *q = arg;
    messaging_assign(q);
    generic_msg_t got = {0};
    int rc = -1;
    for (int tries = 0; tries < 200 && rc != 0; tries++)
    {
        rc = messaging_recv(&got);
        if (rc != 0)
            usleep(5000);
    }
    long sig = rc == 0 ? got.info.signal.sig : -1;
    messaging_recv_release(&got);
    return (void *)(intptr_t)sig;
}

DEFINE_TEST(test_inproc_assign_is_per_thread)
{
    queue_t qa = {0}, qb = {0};
    ck_assert_ret_ok(messaging_init("ipc_ta", &qa));
    ck_assert_ret_ok(messaging_init("ipc_tb", &qb));
    pthread_t ta, tb;
    ck_assert_ret_ok(pthread_create(&ta, NULL, _assign_and_recv, &qa));
    ck_assert_ret_ok(pthread_create(&tb, NULL, _assign_and_recv, &qb));
    usleep(20000);
    generic_msg_t ma = _sig(10), mb = _sig(20);
    ck_assert_ret_ok(messaging_send("ipc_tb", SIGNAL, &mb, false));
    ck_assert_ret_ok(messaging_send("ipc_ta", SIGNAL, &ma, false));
    void *ra = NULL, *rb = NULL;
    pthread_join(ta, &ra);
    pthread_join(tb, &rb);
    ck_assert_int_eq((intptr_t)ra, 10);
    ck_assert_int_eq((intptr_t)rb, 20);
    messaging_qclose(&qa);
    messaging_qclose(&qb);
}
END_TEST_DEFINITION()

#define BURST 2000

static void *_drain_burst(void *arg)
{
    queue_t *q = arg;
    long bad = 0;
    for (int i = 0; i < BURST; i++)
    {
        generic_msg_t got = {0};
        if (messaging_recv_on(q, &got, NULL, true) != 0 || got.info.signal.sig != i)
            bad++;
        messaging_recv_release(&got);
    }
    return (void *)(intptr_t)bad;
}

DEFINE_TEST(test_inproc_blocking_send_waits_for_room)
{
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init("ipc_burst", &q));
    pthread_t t;
    ck_assert_ret_ok(pthread_create(&t, NULL, _drain_burst, &q));
    for (int i = 0; i < BURST; i++)
    {
        generic_msg_t m = _sig(i);
        ck_assert_ret_ok(messaging_send("ipc_burst", SIGNAL, &m, true));
    }
    void *bad = NULL;
    pthread_join(t, &bad);
    ck_assert_int_eq((intptr_t)bad, 0);   /* every one, in order */
    messaging_qclose(&q);
}
END_TEST_DEFINITION()

/* ---- stream -------------------------------------------------------------- */

DEFINE_TEST(test_stream_roundtrip_and_bound)
{
    ck_assert(!messaging_bound("ipc_s"));
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init_external("ipc_s", &q));
    ck_assert(messaging_bound("ipc_s"));
    for (int i = 0; i < 10; i++)
    {
        generic_msg_t m = _sig(i);
        ck_assert_ret_ok(messaging_send("ipc_s", SIGNAL, &m, false));
    }
    for (int i = 0; i < 10; i++)
    {
        generic_msg_t got = {0};
        ck_assert_ret_ok(messaging_recv_on(&q, &got, NULL, true));
        ck_assert_int_eq(got.info.signal.sig, i);
        messaging_recv_release(&got);
    }
    messaging_qclose(&q);
    ck_assert(!messaging_bound("ipc_s"));
    generic_msg_t m = _sig(0);
    ck_assert(messaging_send("ipc_s", SIGNAL, &m, false) != 0);
}
END_TEST_DEFINITION()

/* A receiver that is not reading pushes back: a non-blocking send answers
 * EAGAIN, as a full datagram queue did, and nothing accepted before that is
 * lost or reordered. */
DEFINE_TEST(test_stream_backpressure)
{
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init_external("ipc_bp", &q));
    int sent = 0, rc = 0;
    while (sent < 100000)
    {
        generic_msg_t m = _sig(sent);
        rc = messaging_send("ipc_bp", SIGNAL, &m, false);
        if (rc != 0)
            break;
        sent++;
    }
    ck_assert_int_eq(rc, EAGAIN);
    ck_assert(sent >= 11);   /* at least what a datagram queue held */
    for (int i = 0; i < sent; i++)
    {
        generic_msg_t got = {0};
        ck_assert_ret_ok(messaging_recv_on(&q, &got, NULL, true));
        ck_assert_int_eq(got.info.signal.sig, i);
        messaging_recv_release(&got);
    }
    generic_msg_t none = {0};
    ck_assert_int_eq(messaging_recv_on(&q, &none, NULL, false), ENOMSG);
    messaging_qclose(&q);
}
END_TEST_DEFINITION()

/* A frame far bigger than one socket read: the receiver reassembles it. */
DEFINE_TEST(test_stream_large_frame)
{
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init_external("ipc_big", &q));
    const size_t n = 150000;
    uint8_t *obj = malloc(n);
    ck_assert(obj != NULL);
    /* Text, as every NET_MESSAGE payload is (the IPC encoding carries it as a
     * JSON string). */
    for (size_t i = 0; i < n; i++)
        obj[i] = (uint8_t)('a' + (i * 31 + 7) % 26);
    generic_msg_t m = {.type = NET_MESSAGE};
    snprintf(m.info.net_msg.process, sizeof(m.info.net_msg.process), "identity");
    char fn[] = "bulk";
    m.info.net_msg.function = fn;
    m.info.net_msg.obj = obj;
    m.info.net_msg.len = n;
    ck_assert_ret_ok(messaging_send("ipc_big", NET_MESSAGE, &m, true));
    generic_msg_t got = {0};
    ck_assert_ret_ok(messaging_recv_on(&q, &got, NULL, true));
    ck_assert_int_eq(got.type, NET_MESSAGE);
    ck_assert_uint_eq(got.info.net_msg.len, n);
    ck_assert(got.info.net_msg.obj != NULL && memcmp(got.info.net_msg.obj, obj, n) == 0);
    ck_assert_str_eq(got.info.net_msg.function, "bulk");
    messaging_recv_release(&got);
    free(obj);
    messaging_qclose(&q);
}
END_TEST_DEFINITION()

/* The app link's whole point: a sender in ANOTHER process. */
DEFINE_TEST(test_stream_other_process)
{
#ifdef _WIN32
    printf("  skipped: needs fork (Windows covers this with agorad and the shim)\n");
#else
    queue_t q = {0};
    ck_assert_ret_ok(messaging_init_external("ipc_x", &q));
    for (int round = 0; round < 2; round++)
    {
        pid_t pid = fork();
        ck_assert(pid >= 0);
        if (pid == 0)
        {
            int failed = 0;
            for (int i = 0; i < 100; i++)
            {
                generic_msg_t m = _sig(round * 1000 + i);
                if (messaging_send("ipc_x", SIGNAL, &m, true) != 0)
                    failed++;
            }
            _exit(failed == 0 ? 0 : 1);
        }
        for (int i = 0; i < 100; i++)
        {
            generic_msg_t got = {0};
            ck_assert_ret_ok(messaging_recv_on(&q, &got, NULL, true));
            ck_assert_int_eq(got.info.signal.sig, round * 1000 + i);
            messaging_recv_release(&got);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        ck_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    messaging_qclose(&q);
#endif
}
END_TEST_DEFINITION()

RUN_TESTS(IpcPaths, test_inproc_fifo_and_full, test_inproc_bound_close_reopen,
          test_inproc_assign_is_per_thread, test_inproc_blocking_send_waits_for_room,
          test_stream_roundtrip_and_bound, test_stream_backpressure,
          test_stream_large_frame,
          test_stream_other_process)
