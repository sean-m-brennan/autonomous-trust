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

/**
 * @file net_tcp_multiframe_test.c
 * @brief The TCP receiver must take many frames from ONE connection.
 *
 * A sender with connection pooling on -- Python's AT_NET_POOL, on by default
 * since 2026-08-10 -- connects once per peer and writes every subsequent
 * frame down that connection. This transport used to close after reading the
 * first frame, which does not merely cost a reconnect: the sender's next
 * write lands in a half-closed socket and SUCCEEDS, the RST arrives after
 * send() has returned, and that message is gone with no error raised on
 * either side. One silent loss per reuse (ISSUES.md §3.6).
 *
 * These drive the real vtable with a plain client socket standing in for the
 * pooled sender, so what is pinned is the observable transport contract:
 * frames written back-to-back on one connection all come out, in order, each
 * attributed to the sender.
 *
 * Mirrors the Python twin's receive-side coverage in
 * tests/a_unit/test_network_tcp_pool.py (TestPersistentReader).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "network/network.h"
#include "network/net_transport_priv.h"

static logger_t test_logger;

#define TEST_PORT_BASE 31900
#define LOCAL_ADDR "127.0.0.1"

/* Open a TCP transport bound to loopback, or NULL if it cannot bind here. */
static net_transport_ctx_t *open_tcp(const net_transport_t *t,
                                     network_config_t *net_cfg, int port_base)
{
    memset(net_cfg, 0, sizeof(*net_cfg));
    snprintf(net_cfg->ip4_cidr, sizeof(net_cfg->ip4_cidr), "%s/8", LOCAL_ADDR);
    snprintf(net_cfg->mcast4_addr, sizeof(net_cfg->mcast4_addr), "%s",
             DEFAULT_MCAST4_ADDR);
    net_cfg->port = port_base;
    net_transport_params_t params = {
        .net_cfg   = net_cfg,
        .logger    = &test_logger,
        .port_base = port_base,
        .myself    = NULL,
        .proc      = NULL,
    };
    net_transport_ctx_t *ctx = NULL;
    if (t->open(&ctx, &params) != 0)
        return NULL;
    return ctx;
}

/* A pooled sender: one connection, kept open across sends. */
static int connect_to(int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return -1;
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, LOCAL_ADDR, &dest.sin_addr);
    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* Write one length-prefixed frame, as Python's _write_frame does. */
static int send_frame(int sock, const char *payload)
{
    uint32_t len_be = htonl((uint32_t)strlen(payload));
    if (send(sock, &len_be, sizeof(len_be), 0) != (ssize_t)sizeof(len_be))
        return -1;
    size_t len = strlen(payload);
    if (send(sock, payload, len, 0) != (ssize_t)len)
        return -1;
    return 0;
}

/****************************
 * Many frames, one connection
 ****************************/

DEFINE_TEST(test_two_frames_on_one_connection_both_arrive)
{
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE);
    if (ctx == NULL)
        return;  /* port busy in this environment; nothing to assert */

    int sender = connect_to(TEST_PORT_BASE);
    ck_assert(sender != -1);

    /* Both frames go out before either is read, exactly as a pooled sender
     * pushing back-to-back messages would. */
    ck_assert_ret_ok(send_frame(sender, "first"));
    ck_assert_ret_ok(send_frame(sender, "second"));

    uint8_t *buf = NULL;
    size_t len = 0;
    char peer[IPV6_ADDR_LEN] = {0};

    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, peer,
                             sizeof(peer), 200));
    ck_assert_uint_eq((unsigned int)len, 5u);
    ck_assert_mem_eq(buf, "first", 5);
    ck_assert_str_eq(peer, LOCAL_ADDR);
    free(buf);

    /* The one that used to vanish. */
    buf = NULL;
    len = 0;
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, peer,
                             sizeof(peer), 200));
    ck_assert_uint_eq((unsigned int)len, 6u);
    ck_assert_mem_eq(buf, "second", 6);
    ck_assert_str_eq(peer, LOCAL_ADDR);
    free(buf);

    close(sender);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_frame_sent_after_a_read_still_arrives)
{
    /* The reuse case proper: the sender goes quiet, we drain, and only then
     * does it send again on the SAME connection. */
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE + 10);
    if (ctx == NULL)
        return;
    int sender = connect_to(TEST_PORT_BASE + 10);
    ck_assert(sender != -1);

    uint8_t *buf = NULL;
    size_t len = 0;
    ck_assert_ret_ok(send_frame(sender, "one"));
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
    free(buf);

    /* Nothing pending now. */
    buf = NULL;
    ck_assert(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 10) == ENOMSG);

    ck_assert_ret_ok(send_frame(sender, "two"));
    buf = NULL;
    len = 0;
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
    ck_assert_uint_eq((unsigned int)len, 3u);
    ck_assert_mem_eq(buf, "two", 3);
    free(buf);

    close(sender);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_two_senders_are_served_independently)
{
    /* Holding connections open must not make one peer wait on another. */
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE + 20);
    if (ctx == NULL)
        return;

    int a = connect_to(TEST_PORT_BASE + 20);
    ck_assert(a != -1);
    ck_assert_ret_ok(send_frame(a, "aaa"));
    uint8_t *buf = NULL;
    size_t len = 0;
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
    free(buf);

    int b = connect_to(TEST_PORT_BASE + 20);
    ck_assert(b != -1);
    ck_assert_ret_ok(send_frame(b, "bbb"));
    ck_assert_ret_ok(send_frame(a, "aa2"));

    /* Both are outstanding; two recv calls must produce both, in some order. */
    int seen_a = 0, seen_b = 0;
    for (int i = 0; i < 2; i++) {
        buf = NULL;
        len = 0;
        ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
        ck_assert_uint_eq((unsigned int)len, 3u);
        if (memcmp(buf, "aa2", 3) == 0) seen_a++;
        if (memcmp(buf, "bbb", 3) == 0) seen_b++;
        free(buf);
    }
    ck_assert_int_eq(seen_a, 1);
    ck_assert_int_eq(seen_b, 1);

    close(a);
    close(b);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_hangup_frees_the_slot)
{
    /* An orderly close is a normal protocol event, not an error: the slot has
     * to come back or the cap leaks a connection per peer restart. */
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE + 30);
    if (ctx == NULL)
        return;

    int sender = connect_to(TEST_PORT_BASE + 30);
    ck_assert(sender != -1);
    ck_assert_ret_ok(send_frame(sender, "bye"));
    uint8_t *buf = NULL;
    size_t len = 0;
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
    free(buf);

    int held = 0;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0) held++;
    ck_assert_int_eq(held, 1);

    close(sender);
    /* One drain pass notices the EOF and reclaims the slot. */
    buf = NULL;
    ck_assert(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 10) == ENOMSG);

    held = 0;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0) held++;
    ck_assert_int_eq(held, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_live_connections_are_capped)
{
    /* A peer opening connections without bound must not exhaust our
     * descriptors; the refused one is closed, not queued. */
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE + 40);
    if (ctx == NULL)
        return;
    ctx->max_live_conns = 2;

    int socks[3];
    for (int i = 0; i < 3; i++) {
        socks[i] = connect_to(TEST_PORT_BASE + 40);
        ck_assert(socks[i] != -1);
        ck_assert_ret_ok(send_frame(socks[i], "hi"));
        uint8_t *buf = NULL;
        size_t len = 0;
        /* The third is refused, so its frame never surfaces. */
        int rc = t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200);
        if (rc == 0)
            free(buf);
    }

    int held = 0;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0) held++;
    ck_assert_int_eq(held, 2);

    for (int i = 0; i < 3; i++)
        close(socks[i]);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_idle_connection_is_reaped)
{
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;
    network_config_t net_cfg;
    net_transport_ctx_t *ctx = open_tcp(t, &net_cfg, TEST_PORT_BASE + 50);
    if (ctx == NULL)
        return;

    int sender = connect_to(TEST_PORT_BASE + 50);
    ck_assert(sender != -1);
    ck_assert_ret_ok(send_frame(sender, "hi"));
    uint8_t *buf = NULL;
    size_t len = 0;
    ck_assert_ret_ok(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 200));
    free(buf);

    /* Age it past the TTL rather than sleeping through one. */
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0)
            ctx->live_conns[i].last_used -= (ctx->conn_idle_ttl + 1);

    buf = NULL;
    ck_assert(t->recv(ctx, NET_CHAN_PEER, &buf, &len, NULL, 0, 10) == ENOMSG);

    int held = 0;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0) held++;
    ck_assert_int_eq(held, 0);

    close(sender);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_knob_defaults_match_python)
{
    /* Same values, same env names, both runtimes -- the reason these are
     * knobs at all (ISSUES.md 2.4.4). Python: system.py net_conn_idle_ttl /
     * net_max_live_conns. */
    ck_assert_int_eq(NET_CONN_IDLE_TTL_SEC, 30);
    ck_assert_int_eq(NET_MAX_LIVE_CONNS, 64);
    net_knob_source_t src;
    ck_assert_int_eq(net_conn_idle_ttl_resolve(&src, &test_logger), 30);
    ck_assert_int_eq((int)src, (int)KNOB_SRC_DEFAULT);
    ck_assert_int_eq(net_max_live_conns_resolve(&src, &test_logger), 64);
    ck_assert_int_eq((int)src, (int)KNOB_SRC_DEFAULT);
}
END_TEST_DEFINITION()

RUN_TESTS(NetTcpMultiframe,
          test_two_frames_on_one_connection_both_arrive,
          test_frame_sent_after_a_read_still_arrives,
          test_two_senders_are_served_independently,
          test_peer_hangup_frees_the_slot,
          test_live_connections_are_capped,
          test_idle_connection_is_reaped,
          test_knob_defaults_match_python)
