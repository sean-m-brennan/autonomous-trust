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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "autonomous_trust/utilities/socket_helpers.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

/* ---------- Test 1: send/recv round-trip via socketpair ---------- */

DEFINE_TEST(test_send_recv_roundtrip)
{
    int sv[2];
    ck_assert_ret_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

    const char payload[] = "hello-eintr";
    ssize_t sent = at_send_eintr(sv[0], payload, sizeof(payload), 0);
    ck_assert_int_eq(sent, (ssize_t)sizeof(payload));

    char buf[64] = {0};
    ssize_t got = at_recv_eintr(sv[1], buf, sizeof(buf), 0);
    ck_assert_int_eq(got, (ssize_t)sizeof(payload));
    ck_assert_str_eq(buf, payload);

    close(sv[0]);
    close(sv[1]);
}
END_TEST_DEFINITION()

/* ---------- Test 2: at_set_rcvtimeo causes recv to time out ---------- */

DEFINE_TEST(test_rcvtimeo_returns_eagain)
{
    int sv[2];
    ck_assert_ret_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

    ck_assert_ret_ok(at_set_rcvtimeo(sv[0], 100 /* ms */, NULL));

    char buf[8] = {0};
    errno = 0;
    ssize_t got = at_recv_eintr(sv[0], buf, sizeof(buf), 0);
    /* Timer must fire; recv returns -1 with EAGAIN/EWOULDBLOCK. EINTR
     * must NOT leak through. */
    ck_assert_int_eq(got, -1);
    ck_assert(errno == EAGAIN || errno == EWOULDBLOCK);

    close(sv[0]);
    close(sv[1]);
}
END_TEST_DEFINITION()

/* ---------- Test 3: EINTR retry transparency ---------- */
/* Thread blocks in at_recv_eintr. Main signals it (EINTR injected into
 * the blocked syscall), then writes a payload. The thread must NOT
 * surface EINTR — it must keep waiting and return the payload. */

struct recv_thread_arg {
    int        fd;
    ssize_t    ret;
    int        saved_errno;
    char       buf[32];
};

static volatile sig_atomic_t sig_count;
static void sig_handler(int sig) { (void)sig; sig_count++; }

static void *recv_worker(void *p)
{
    struct recv_thread_arg *a = p;
    a->ret = at_recv_eintr(a->fd, a->buf, sizeof(a->buf) - 1, 0);
    a->saved_errno = errno;
    return NULL;
}

DEFINE_TEST(test_eintr_is_retried_transparently)
{
    /* Install a userland handler for SIGUSR2 so the signal interrupts
     * the syscall instead of terminating the process. No SA_RESTART so
     * the kernel really returns EINTR. */
    struct sigaction sa = {0};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* explicitly no SA_RESTART */
    ck_assert_ret_ok(sigaction(SIGUSR2, &sa, NULL));
    sig_count = 0;

    int sv[2];
    ck_assert_ret_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

    struct recv_thread_arg arg = { .fd = sv[0] };
    memset(arg.buf, 0, sizeof(arg.buf));
    pthread_t tid;
    ck_assert_ret_ok(pthread_create(&tid, NULL, recv_worker, &arg));

    /* Let the worker block in recv. */
    struct timespec rest = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
    nanosleep(&rest, NULL);

    /* Inject EINTR a few times — wrapper must absorb each. */
    for (int i = 0; i < 3; i++) {
        pthread_kill(tid, SIGUSR2);
        nanosleep(&rest, NULL);
    }

    /* Now actually deliver the payload. */
    const char payload[] = "post-eintr";
    ssize_t sent = at_send_eintr(sv[1], payload, sizeof(payload), 0);
    ck_assert_int_eq(sent, (ssize_t)sizeof(payload));

    ck_assert_ret_ok(pthread_join(tid, NULL));

    /* Wrapper must report the payload, not EINTR. */
    ck_assert_int_eq(arg.ret, (ssize_t)sizeof(payload));
    ck_assert_str_eq(arg.buf, payload);
    /* Handler must have actually fired (otherwise the test proves nothing). */
    ck_assert((int)sig_count >= 1);

    close(sv[0]);
    close(sv[1]);
}
END_TEST_DEFINITION()

/* ---------- Test 4: sendto/recvfrom datagram round-trip ---------- */

DEFINE_TEST(test_sendto_recvfrom_udp_roundtrip)
{
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    ck_assert(srv >= 0);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    ck_assert(cli >= 0);

    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port        = 0; /* let kernel pick */
    ck_assert_ret_ok(bind(srv, (struct sockaddr *)&srv_addr, sizeof(srv_addr)));

    socklen_t slen = sizeof(srv_addr);
    ck_assert_ret_ok(getsockname(srv, (struct sockaddr *)&srv_addr, &slen));

    ck_assert_ret_ok(at_set_rcvtimeo(srv, 500, NULL));
    ck_assert_ret_ok(at_set_sndtimeo(cli, 500, NULL));

    const char payload[] = "udp-eintr-test";
    ssize_t sent = at_sendto_eintr(cli, payload, sizeof(payload), 0,
                                   (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    ck_assert_int_eq(sent, (ssize_t)sizeof(payload));

    char buf[64] = {0};
    struct sockaddr_in from = {0};
    socklen_t flen = sizeof(from);
    ssize_t got = at_recvfrom_eintr(srv, buf, sizeof(buf), 0,
                                    (struct sockaddr *)&from, &flen);
    ck_assert_int_eq(got, (ssize_t)sizeof(payload));
    ck_assert_str_eq(buf, payload);

    close(srv);
    close(cli);
}
END_TEST_DEFINITION()

RUN_TESTS(SocketHelpers,
          test_send_recv_roundtrip,
          test_rcvtimeo_returns_eagain,
          test_eintr_is_retried_transparently,
          test_sendto_recvfrom_udp_roundtrip)
