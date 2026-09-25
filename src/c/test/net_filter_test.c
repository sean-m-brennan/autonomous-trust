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

/* The network filter chain (network/net_filter.h, FEATURE_SPLIT_PLAN Phase 2):
 * ordering, narrowing, verdicts, refusals, the config gate, and the gateway
 * switches in network_config_t's JSON. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "network/network.h"
#include "network/net_filter.h"

/* Network filter chain (network/net_filter.h). Two test filters: each
 * records its inbound call, strips / prepends a one-byte tag, and can be
 * told what verdict to return. */
static char filter_log[16];
static size_t filter_log_len;
static net_filter_verdict_t verdict_a = NET_FILTER_CONTINUE;
static size_t after_len_a, after_len_b;

static net_filter_verdict_t tag_inbound(char tag, net_filter_verdict_t v,
                                        uint8_t *frame, size_t len,
                                        net_inbound_meta_t *meta)
{
    filter_log[filter_log_len++] = tag;
    if (v != NET_FILTER_CONTINUE)
        return v;
    if (len > 0 && frame[0] == (uint8_t)tag) {   /* strip our header */
        meta->inner = frame + 1;
        meta->inner_len = len - 1;
    }
    return NET_FILTER_CONTINUE;
}
static net_filter_verdict_t a_in(const net_thread_ctx_t *c, net_channel_t ch, uint8_t *f,
                                 size_t n, const char *from, net_inbound_meta_t *m)
{
    m->has_src_uuid = true;
    return tag_inbound('A', verdict_a, f, n, m);
}
static net_filter_verdict_t b_in(const net_thread_ctx_t *c, net_channel_t ch, uint8_t *f,
                                 size_t n, const char *from, net_inbound_meta_t *m)
{
    return tag_inbound('B', NET_FILTER_CONTINUE, f, n, m);
}
static int tag_out(char tag, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    uint8_t *b = malloc(in_len + 1);
    if (b == NULL) return -1;
    b[0] = (uint8_t)tag;
    memcpy(b + 1, in, in_len);
    *out = b;
    *out_len = in_len + 1;
    return 0;
}
static int a_out(const net_send_info_t *i, const uint8_t *in, size_t n, uint8_t **o, size_t *on)
{ return tag_out('A', in, n, o, on); }
static int b_out(const net_send_info_t *i, const uint8_t *in, size_t n, uint8_t **o, size_t *on)
{ return tag_out('B', in, n, o, on); }
static int refuse_out(const net_send_info_t *i, const uint8_t *in, size_t n, uint8_t **o, size_t *on)
{ return -1; }
static void a_after(const net_thread_ctx_t *c, net_channel_t ch, uint8_t *f, size_t n,
                    const net_inbound_meta_t *m) { after_len_a = n; }
static void b_after(const net_thread_ctx_t *c, net_channel_t ch, uint8_t *f, size_t n,
                    const net_inbound_meta_t *m) { after_len_b = n; }

static const net_filter_t filter_a = { .name = "a", .order = 0, .inbound = a_in,
                                       .outbound = a_out, .after_deliver = a_after };
static const net_filter_t filter_b = { .name = "b", .order = 10, .inbound = b_in,
                                       .outbound = b_out, .after_deliver = b_after };

static void filters_fresh(void)
{
    net_filters_reset();
    filter_log_len = 0;
    verdict_a = NET_FILTER_CONTINUE;
    after_len_a = after_len_b = 0;
}

DEFINE_TEST(test_filter_chain_empty_is_a_no_op)
{
    filters_fresh();
    uint8_t buf[] = "payload";
    net_inbound_meta_t meta;
    ck_assert_int_eq(net_filters_inbound(NULL, NET_CHAN_PEER, buf, 7, "x", &meta),
                     NET_FILTER_CONTINUE);
    ck_assert(meta.inner == buf);
    ck_assert_int_eq((int)meta.inner_len, 7);
    ck_assert(!meta.has_src_uuid && !meta.forwarded && !meta.keep_reported_addr);

    uint8_t *out = NULL;
    size_t out_len = 0;
    net_send_info_t info = { .channel = NET_CHAN_PEER };
    ck_assert_int_eq(net_filters_outbound(&info, buf, 7, &out, &out_len), 0);
    ck_assert(out == buf);
    ck_assert_int_eq((int)out_len, 7);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_filter_chain_order_and_narrowing)
{
    filters_fresh();
    /* Installed out of order: the chain sorts by .order. */
    ck_assert_int_eq(net_filter_install(&filter_b), 0);
    ck_assert_int_eq(net_filter_install(&filter_a), 0);

    /* Outbound descending: b wraps first, a last -> a's header outermost. */
    uint8_t *out = NULL;
    size_t out_len = 0;
    net_send_info_t info = { .channel = NET_CHAN_BROADCAST };
    ck_assert_int_eq(net_filters_outbound(&info, (const uint8_t *)"xy", 2, &out, &out_len), 0);
    ck_assert_int_eq((int)out_len, 4);
    ck_assert(memcmp(out, "ABxy", 4) == 0);

    /* Inbound ascending: a strips its byte, b sees the narrowed slice. */
    net_inbound_meta_t meta;
    ck_assert_int_eq(net_filters_inbound(NULL, NET_CHAN_BROADCAST, out, out_len, "x", &meta),
                     NET_FILTER_CONTINUE);
    ck_assert(filter_log_len == 2 && filter_log[0] == 'A' && filter_log[1] == 'B');
    ck_assert_int_eq((int)meta.inner_len, 2);
    ck_assert(memcmp(meta.inner, "xy", 2) == 0);
    ck_assert(meta.has_src_uuid);

    /* after_deliver hands each filter the slice it saw. */
    net_filters_after_deliver(NULL, NET_CHAN_BROADCAST, &meta);
    ck_assert_int_eq((int)after_len_a, 4);
    ck_assert_int_eq((int)after_len_b, 3);
    free(out);
    net_filters_reset();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_filter_verdict_stops_the_chain)
{
    for (int v = NET_FILTER_DROP; v <= NET_FILTER_CONSUMED; v++)
    {
        filters_fresh();
        net_filter_install(&filter_a);
        net_filter_install(&filter_b);
        verdict_a = (net_filter_verdict_t)v;
        uint8_t buf[] = "Axy";
        net_inbound_meta_t meta;
        ck_assert_int_eq(net_filters_inbound(NULL, NET_CHAN_PEER, buf, 3, "x", &meta), v);
        ck_assert(filter_log_len == 1 && filter_log[0] == 'A');
        /* A frame that never reached b gives b no after_deliver. */
        net_filters_after_deliver(NULL, NET_CHAN_PEER, &meta);
        ck_assert_int_eq((int)after_len_b, 0);
    }
    /* An outbound refusal refuses the send. */
    filters_fresh();
    static const net_filter_t refuser = { .name = "refuser", .order = 5, .outbound = refuse_out };
    net_filter_install(&filter_a);
    net_filter_install(&refuser);
    net_filter_install(&filter_b);
    uint8_t *out = NULL;
    size_t out_len = 0;
    net_send_info_t info = { .channel = NET_CHAN_PEER };
    ck_assert_int_eq(net_filters_outbound(&info, (const uint8_t *)"xy", 2, &out, &out_len), -1);
    net_filters_reset();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_filter_install_refusals)
{
    filters_fresh();
    static const net_filter_t unnamed = { .name = NULL };
    static const net_filter_t empty = { .name = "" };
    ck_assert_int_eq(net_filter_install(NULL), -1);
    ck_assert_int_eq(net_filter_install(&unnamed), -1);
    ck_assert_int_eq(net_filter_install(&empty), -1);
    ck_assert_int_eq(net_filter_install(&filter_a), 0);
    ck_assert_int_eq(net_filter_install(&filter_a), -1);
    ck_assert(net_filter_installed("a") && !net_filter_installed("b"));

    static net_filter_t fill[NET_FILTER_MAX];
    static char names[NET_FILTER_MAX][16];
    int accepted = 0;
    for (int i = 0; i < NET_FILTER_MAX; i++)
    {
        snprintf(names[i], sizeof(names[i]), "fill_%d", i);
        fill[i].name = names[i];
        if (net_filter_install(&fill[i]) == 0) accepted++;
    }
    ck_assert_int_eq(accepted, NET_FILTER_MAX - 1);
    net_filters_reset();
    ck_assert(!net_filter_installed("a"));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_filter_config_gate)
{
    filters_fresh();
    network_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), 0);
    cfg.group_forward = true;
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), -1);   /* needs envelope */
    cfg.group_forward = false;
    cfg.cross_cluster = true;
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), -1);
    cfg.cross_cluster = false;
    cfg.envelope = true;
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), -1);   /* no library */
    static const net_filter_t env = { .name = NET_FILTER_ENVELOPE };
    net_filter_install(&env);
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), 0);
    cfg.group_forward = cfg.cross_cluster = true;
    ck_assert_int_eq(net_filters_check_config(&cfg, NULL), 0);
    net_filters_reset();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_network_config_writes_gateway_switches_only_when_set)
{
    network_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    json_t *obj = NULL;
    ck_assert_int_eq(network_to_json(&cfg, &obj), 0);
    ck_assert_ptr_null(json_object_get(obj, "envelope"));
    ck_assert_ptr_null(json_object_get(obj, "group_forward"));
    ck_assert_ptr_null(json_object_get(obj, "cross_cluster"));
    json_decref(obj);

    cfg.envelope = cfg.cross_cluster = true;
    ck_assert_int_eq(network_to_json(&cfg, &obj), 0);
    network_config_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_int_eq(network_from_json(obj, &back), 0);
    ck_assert(back.envelope && !back.group_forward && back.cross_cluster);
    json_decref(obj);
}
END_TEST_DEFINITION()

RUN_TESTS(NetFilter, test_filter_chain_empty_is_a_no_op,
          test_filter_chain_order_and_narrowing,
          test_filter_verdict_stops_the_chain,
          test_filter_install_refusals,
          test_filter_config_gate,
          test_network_config_writes_gateway_switches_only_when_set)
