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
 * @file dtn_transport_test.c
 * @brief Tests for the DTN transport against the no-op stub backend.
 *
 * Scope: verifies the transport's address-resolution, channel dispatch,
 * and lifecycle without requiring any running BP daemon. Only built
 * when AT_NET_DTN=ON and AT_NET_DTN_BACKEND=stub — for the ud3tn / ion
 * backends, send() and recv() would attempt real I/O which this unit
 * test is not set up to cover.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "network/network.h"
#include "network/net_transport.h"
#include "network/dtn/dtn_eid.h"  /* DTN_EID_MAX */

static logger_t test_logger;

/* Helper: open a fresh DTN transport against the stub backend.
 *
 * @p out_ctx receives the opaque context the caller must pass to close().
 * Returns the resolved transport descriptor, or NULL on failure. */
static const net_transport_t *open_dtn(net_transport_ctx_t **out_ctx,
                                       network_config_t *net_cfg)
{
    const net_transport_t *t = net_transport_find("dtn_bp");
    if (t == NULL) return NULL;

    net_transport_params_t params = {
        .net_cfg   = net_cfg,
        .logger    = &test_logger,
        .port_base = 27787,
        .myself    = NULL,  /* transport falls back to placeholder EID */
        .proc      = NULL,  /* no peer registry / group lookup in unit tests */
    };
    if (t->open(out_ctx, &params) != 0)
        return NULL;
    return t;
}

DEFINE_TEST(test_dtn_transport_is_registered)
{
    const net_transport_t *t = net_transport_find("dtn_bp");
    ck_assert(t != NULL);
    ck_assert_str_eq(t->name, "dtn_bp");
    ck_assert(t->open != NULL && t->close != NULL);
    ck_assert(t->send_unicast != NULL && t->send_broadcast != NULL);
    ck_assert(t->recv != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_open_close_lifecycle)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);
    ck_assert(ctx != NULL);
    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_unicast_plain_host)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "hello";
    int rc = t->send_unicast(ctx, payload, sizeof(payload),
                             "192.168.1.5", 27787);
    /* Stub backend always succeeds; unicast resolves "192.168.1.5" into
     * a fallback EID of the form "dtn://at-192.168.1.5/peer". */
    ck_assert_int_eq(rc, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_unicast_dtn_prefix_passthrough)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "hello";
    int rc = t->send_unicast(ctx, payload, sizeof(payload),
                             "dtn://at-abcd/peer", 0);
    ck_assert_int_eq(rc, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_unicast_ipn_prefix_passthrough)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "hello";
    int rc = t->send_unicast(ctx, payload, sizeof(payload),
                             "ipn:42.1", 0);
    ck_assert_int_eq(rc, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_broadcast_peer_channel_rejected)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "nope";
    int rc = t->send_broadcast(ctx, NET_CHAN_PEER,
                               payload, sizeof(payload), 0);
    /* send_broadcast is only valid for BROADCAST/GROUP channels. */
    ck_assert_int_eq(rc, -1);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_broadcast_bcast_channel_ok)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "bcast";
    int rc = t->send_broadcast(ctx, NET_CHAN_BROADCAST,
                               payload, sizeof(payload), 0);
    ck_assert_int_eq(rc, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_send_broadcast_group_channel_ok)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    const uint8_t payload[] = "group";
    int rc = t->send_broadcast(ctx, NET_CHAN_GROUP,
                               payload, sizeof(payload), 0);
    ck_assert_int_eq(rc, 0);

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dtn_recv_times_out_to_enomsg)
{
    network_config_t net_cfg = {0};
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_dtn(&ctx, &net_cfg);
    ck_assert(t != NULL);

    uint8_t *buf = NULL;
    size_t len = 0;
    char peer[DTN_EID_MAX + 1] = {0};
    /* Short timeout — stub's recv always returns ENOMSG after sleeping. */
    int rc = t->recv(ctx, NET_CHAN_PEER, &buf, &len,
                     peer, sizeof(peer), /*timeout_ms=*/ 10);
    ck_assert_int_eq(rc, ENOMSG);
    ck_assert(buf == NULL);

    t->close(ctx);
}
END_TEST_DEFINITION()

/* Bootstrap logger before the test bodies run. */
static void setup_logger(void) { logger_init(&test_logger, WARNING, NULL); }

#define TEST_MAIN_SUITE "DTN_Transport"

/* Wrap each test with logger setup. We use a "first-call" flag rather
 * than editing every macro — this keeps the test source minimal. */
#define WRAP(name) static void name##_wrapped(void) { \
    static int _logger_init_done = 0; \
    if (!_logger_init_done) { setup_logger(); _logger_init_done = 1; } \
    name(); \
}
WRAP(test_dtn_transport_is_registered)
WRAP(test_dtn_open_close_lifecycle)
WRAP(test_dtn_send_unicast_plain_host)
WRAP(test_dtn_send_unicast_dtn_prefix_passthrough)
WRAP(test_dtn_send_unicast_ipn_prefix_passthrough)
WRAP(test_dtn_send_broadcast_peer_channel_rejected)
WRAP(test_dtn_send_broadcast_bcast_channel_ok)
WRAP(test_dtn_send_broadcast_group_channel_ok)
WRAP(test_dtn_recv_times_out_to_enomsg)

RUN_TESTS(DTN_Transport,
          test_dtn_transport_is_registered_wrapped,
          test_dtn_open_close_lifecycle_wrapped,
          test_dtn_send_unicast_plain_host_wrapped,
          test_dtn_send_unicast_dtn_prefix_passthrough_wrapped,
          test_dtn_send_unicast_ipn_prefix_passthrough_wrapped,
          test_dtn_send_broadcast_peer_channel_rejected_wrapped,
          test_dtn_send_broadcast_bcast_channel_ok_wrapped,
          test_dtn_send_broadcast_group_channel_ok_wrapped,
          test_dtn_recv_times_out_to_enomsg_wrapped)
