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
 * @file net_leg_address_test.c
 * @brief The sender address a frame names is the address of the leg it
 *        leaves on.
 *
 * A gateway sits on two networks, and each side reaches it only at the address
 * it holds on that side. A frame naming the identity address on every leg gave
 * the far side's receivers an address they cannot reach, which they took for
 * the member having moved. Mirrors the Python tests in test_network_hybrid.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <jansson.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/net_transport_hybrid.h"

/* ---- the pure helpers ---- */

static void set_inner(hybrid_inner_t *in, const char *cidr, const char *own, bool dflt)
{
    memset(in, 0, sizeof(*in));
    snprintf(in->kind, sizeof(in->kind), "%s", "udp_net_4");
    snprintf(in->match_cidr, sizeof(in->match_cidr), "%s", cidr);
    if (own)
        snprintf(in->net_cfg.ip4_cidr, sizeof(in->net_cfg.ip4_cidr), "%s", own);
    in->is_default = dflt;
}

static void two_nets(hybrid_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->n_inners = 2;
    set_inner(&cfg->inners[0], "10.0.0.0/24", "10.0.0.7/24", true);
    set_inner(&cfg->inners[1], "172.20.0.0/16", "172.20.0.7/16", false);
}

DEFINE_TEST(test_leg_address_strips_the_prefix)
{
    hybrid_config_t cfg;
    two_nets(&cfg);
    char out[64];
    ck_assert_int_eq(hybrid_leg_address(&cfg, 1, out, sizeof(out)), 0);
    ck_assert_str_eq(out, "172.20.0.7");
    ck_assert_int_eq(hybrid_leg_address(&cfg, 2, out, sizeof(out)), -1);
    cfg.inners[1].net_cfg.ip4_cidr[0] = '\0';
    ck_assert_int_eq(hybrid_leg_address(&cfg, 1, out, sizeof(out)), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_envelope_address_is_the_routed_legs)
{
    hybrid_config_t cfg;
    two_nets(&cfg);
    char out[64];
    ck_assert_int_eq(hybrid_envelope_address(&cfg, "172.20.4.4", out, sizeof(out)), 0);
    ck_assert_str_eq(out, "172.20.0.7");
    ck_assert_int_eq(hybrid_envelope_address(&cfg, "10.0.0.9", out, sizeof(out)), 0);
    ck_assert_str_eq(out, "10.0.0.7");
    ck_assert_int_eq(hybrid_envelope_address(&cfg, "192.168.1.1", out, sizeof(out)), 0);
    ck_assert_str_eq(out, "10.0.0.7");   /* the default leg */
}
END_TEST_DEFINITION()

/* ---- the send path, through a two-leg fake transport ---- */

static hybrid_config_t g_cfg;
static char g_leg_from[2][64];
static int g_leg_sends[2];
static char g_unicast_from[64];

static void from_address_of(const uint8_t *wire, size_t len, char *out, size_t out_len)
{
    out[0] = '\0';
    json_error_t err;
    json_t *root = json_loadb((const char *)wire, len, 0, &err);
    if (root == NULL)
        return;
    const char *a = json_string_value(json_object_get(root, "from_address"));
    snprintf(out, out_len, "%s", a ? a : "");
    json_decref(root);
}

static int t_send_unicast(net_transport_ctx_t *ctx, const uint8_t *wire, size_t len,
                          const char *target, int port)
{
    (void)ctx; (void)target; (void)port;
    from_address_of(wire, len, g_unicast_from, sizeof(g_unicast_from));
    return 0;
}
static int t_send_broadcast(net_transport_ctx_t *ctx, net_channel_t ch,
                            const uint8_t *wire, size_t len, int port)
{
    (void)ctx; (void)ch; (void)wire; (void)len; (void)port;
    ck_assert(!"a multi-leg send must go leg by leg");
    return -1;
}
static int t_send_on_leg(net_transport_ctx_t *ctx, size_t leg, net_channel_t ch,
                         const uint8_t *wire, size_t len, int port)
{
    (void)ctx; (void)port;
    ck_assert(leg < 2);
    g_leg_sends[leg]++;
    if (ch == NET_CHAN_BROADCAST)
        from_address_of(wire, len, g_leg_from[leg], sizeof(g_leg_from[leg]));
    return 0;
}
static size_t t_leg_count(const net_transport_ctx_t *ctx)
{
    (void)ctx;
    return 2;
}
static int t_leg_address(const net_transport_ctx_t *ctx, size_t leg, char *out, size_t len)
{
    (void)ctx;
    return hybrid_leg_address(&g_cfg, leg, out, len);
}
static int t_address_for_target(const net_transport_ctx_t *ctx, const char *target,
                                char *out, size_t len)
{
    (void)ctx;
    return hybrid_envelope_address(&g_cfg, target, out, len);
}
static const net_transport_t T_TWO_LEGS = {
    .name = "t_two_legs",
    .send_unicast = t_send_unicast,
    .send_broadcast = t_send_broadcast,
    .send_on_leg = t_send_on_leg,
    .leg_count = t_leg_count,
    .leg_address = t_leg_address,
    .address_for_target = t_address_for_target,
};

static identity_t *_mk(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

static void _msg(net_wire_msg_t *w, identity_t *me, recipient_type_t type, const char *fn)
{
    memset(w, 0, sizeof(*w));
    snprintf(w->process, sizeof(w->process), "%s", "identity");
    w->function = strdup(fn);
    w->data = (uint8_t *)strdup("{}");
    w->data_len = 2;
    w->to_whom.type = type;
    w->encrypt = false;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(me, &pub));
    memcpy(&w->from_whom, pub, sizeof(*pub));
    smrt_deref(pub);
}

static void _reset(void)
{
    two_nets(&g_cfg);
    memset(g_leg_from, 0, sizeof(g_leg_from));
    memset(g_leg_sends, 0, sizeof(g_leg_sends));
    g_unicast_from[0] = '\0';
}

DEFINE_TEST(test_broadcast_names_each_legs_own_address)
{
    ck_assert(sodium_init() >= 0);
    _reset();
    identity_t *me = _mk("gw", "10.0.0.7");
    net_wire_msg_t w;
    _msg(&w, me, RECIPIENT_BROADCAST, "request_access");
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, NULL, &w, &T_TWO_LEGS, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_str_eq(g_leg_from[0], "10.0.0.7");
    ck_assert_str_eq(g_leg_from[1], "172.20.0.7");
    ck_assert_str_eq(w.from_whom.address, "10.0.0.7");   /* the caller's message is untouched */
    free(w.function);
    free(w.data);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_frames_go_leg_by_leg)
{
    _reset();
    identity_t *me = _mk("gw", "10.0.0.7");
    group_t grp = {0};
    char gaddr[] = "group-addr";
    ck_assert_int_eq(group_init(NULL, gaddr, &grp), 0);
    net_wire_msg_t w;
    _msg(&w, me, RECIPIENT_GROUP, "presence");
    w.encrypt = true;
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, &grp, &w, &T_TWO_LEGS, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(g_leg_sends[0], 1);
    ck_assert_int_eq(g_leg_sends[1], 1);
    free(w.function);
    free(w.data);
    map_free(&grp.address_map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unicast_names_the_routed_legs_address)
{
    _reset();
    identity_t *me = _mk("gw", "10.0.0.7"), *far = _mk("far", "172.20.4.4");
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(far, &pub));
    net_wire_msg_t w;
    _msg(&w, me, RECIPIENT_PEER, "access_granted");
    memcpy(&w.to_whom.target.peer, pub, sizeof(*pub));
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, NULL, &w, &T_TWO_LEGS, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_str_eq(g_unicast_from, "172.20.0.7");
    ck_assert_str_eq(w.from_whom.address, "10.0.0.7");
    free(w.function);
    free(w.data);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

RUN_TESTS(Net_Leg_Address,
          test_leg_address_strips_the_prefix,
          test_envelope_address_is_the_routed_legs,
          test_broadcast_names_each_legs_own_address,
          test_group_frames_go_leg_by_leg,
          test_unicast_names_the_routed_legs_address)
