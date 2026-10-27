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

/* The Phase 7a core hooks (FEATURE_SPLIT_PLAN Phase 7, C1-C4): a negotiation
 * tier cap only lowers, a network extension carries a unicast only for a peer
 * it reaches (else the transport), the local-verb and reachability dispatch,
 * and exclusions recorded by uuid and by key before the extensions hear of
 * them. Mirrors Python test_extension_hooks.py. First contact's cap and
 * rendezvous's network hooks may be linked in too; neither answers for the
 * peers used here. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "negotiation/neg_ext.h"
#include "network/net_ext.h"
#include "network/net_proc_priv.h"
#include "reputation/rep_ext.h"

static int to_two(const process_t *proc, const unsigned char *peer, int tier)
{
    (void)proc; (void)peer; (void)tier;
    return 2;
}

static int raise_it(const process_t *proc, const unsigned char *peer, int tier)
{
    (void)proc; (void)peer;
    return tier + 5;            /* ignored: a cap never raises */
}

static const neg_tier_cap_t CAP_TWO = { .name = "t.two", .cap = to_two };
static const neg_tier_cap_t CAP_UP = { .name = "t.up", .cap = raise_it };

DEFINE_TEST(test_tier_caps_only_lower)
{
    uuid_t peer;
    uuid_generate(peer);
    int before = neg_ext_capped_tier(NULL, peer, 4);
    ck_assert_int_eq(before, 4);
    ck_assert_int_eq(neg_tier_cap_register(&CAP_UP), 0);
    ck_assert_int_eq(neg_ext_capped_tier(NULL, peer, 4), 4);
    ck_assert_int_eq(neg_tier_cap_register(&CAP_TWO), 0);
    ck_assert_int_eq(neg_ext_capped_tier(NULL, peer, 4), 2);
    ck_assert_int_eq(neg_ext_capped_tier(NULL, peer, 1), 1);
    /* Duplicates and unnamed caps are refused. */
    ck_assert_int_eq(neg_tier_cap_register(&CAP_TWO), -1);
    static const neg_tier_cap_t unnamed = { .name = "", .cap = to_two };
    ck_assert_int_eq(neg_tier_cap_register(&unnamed), -1);
    ck_assert(neg_tier_cap_present("t.two"));
}

static uuid_t carried;
static int sent, verbs_seen, excl_seen;
static bool excl_last, excl_recorded;
static char excl_uuid[UUID_STR_LEN + 1];

static bool t_reachable(const uuid_t peer) { return uuid_compare(peer, carried) == 0; }
static int t_unicast(const uuid_t peer, const uint8_t *buf, size_t len)
{
    (void)buf; (void)len;
    if (uuid_compare(peer, carried) != 0)
        return 1;               /* not mine */
    sent++;
    return 0;
}
static bool t_local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg)
{
    (void)ctx;
    verbs_seen++;
    return nmsg->function != NULL && strcmp(nmsg->function, "t_verb") == 0;
}
static void t_exclusion(const char *uuid, bool excluded)
{
    excl_seen++;
    excl_last = excluded;
    excl_recorded = net_is_excluded(uuid, NULL);
    snprintf(excl_uuid, sizeof(excl_uuid), "%s", uuid);
}

static const net_ext_t T_NET = {
    .name = "t.net",
    .local_verb = t_local_verb,
    .reachable = t_reachable,
    .unicast = t_unicast,
    .exclusion = t_exclusion,
};

DEFINE_TEST(test_network_hooks_dispatch)
{
    uuid_generate(carried);
    uuid_t other;
    uuid_generate(other);
    ck_assert_int_eq(net_ext_register(&T_NET), 0);
    ck_assert_int_eq(net_ext_register(&T_NET), -1);
    ck_assert(net_ext_reachable(carried));
    ck_assert(!net_ext_reachable(other));
    const uint8_t frame[4] = {1, 2, 3, 4};
    ck_assert_int_eq(net_ext_unicast(carried, frame, sizeof(frame)), 0);
    ck_assert_int_eq(sent, 1);
    ck_assert_int_eq(net_ext_unicast(other, frame, sizeof(frame)), 1); /* the transport */
    ck_assert_int_eq(sent, 1);
    char mine_fn[] = "t_verb", theirs_fn[] = "nobody_owns_this";
    net_msg_t mine = {0}, theirs = {0};
    mine.function = mine_fn;
    theirs.function = theirs_fn;
    ck_assert(net_ext_local_verb(NULL, &mine));
    ck_assert(!net_ext_local_verb(NULL, &theirs));
    ck_assert(verbs_seen >= 2);
}

DEFINE_TEST(test_exclusions_by_uuid_and_key)
{
    net_exclusions_reset();
    const char *u = "12345678-0000-4000-8000-0000000000aa";
    const char *fresh = "12345678-0000-4000-8000-0000000000bb";
    char key[65];
    memset(key, 'a', 64);
    key[64] = '\0';
    char upper[65];
    memset(upper, 'A', 64);
    upper[64] = '\0';
    ck_assert(!net_is_excluded(u, key));
    net_note_exclusion("12345678-0000-4000-8000-0000000000AA", key, true);
    /* Recorded (lower-cased) before the extension heard of it. */
    ck_assert(excl_last);
    ck_assert(excl_recorded);
    ck_assert_str_eq(excl_uuid, u);
    ck_assert(net_is_excluded(u, NULL));
    ck_assert(net_is_excluded(fresh, upper));      /* same key, new uuid */
    ck_assert(!net_is_excluded(fresh, NULL));
    net_note_exclusion(u, key, false);
    ck_assert(!excl_last);
    ck_assert(!excl_recorded);
    ck_assert(!net_is_excluded(u, key));
    ck_assert(!net_is_excluded(fresh, key));
    /* An unparseable uuid is ignored, and no extension hears of it. */
    int seen = excl_seen;
    net_note_exclusion("not-a-uuid", key, true);
    ck_assert_int_eq(excl_seen, seen);
    ck_assert(!net_is_excluded(fresh, key));
    net_exclusions_reset();
}

static void t_seeds(const process_t *proc, rep_seed_offer_fn offer, void *arg)
{
    (void)proc; (void)offer; (void)arg;
}

DEFINE_TEST(test_seed_provider_registry)
{
    static const rep_seed_provider_t P = { .name = "t.seeds", .seeds = t_seeds };
    static const rep_seed_provider_t NOFN = { .name = "t.nofn" };
    size_t before = rep_seed_providers((const rep_seed_provider_t *[REP_SEED_PROVIDER_MAX]){0},
                                       REP_SEED_PROVIDER_MAX);
    ck_assert_int_eq(rep_seed_provider_register(&P), 0);
    ck_assert_int_eq(rep_seed_provider_register(&P), -1);
    ck_assert_int_eq(rep_seed_provider_register(&NOFN), -1);
    ck_assert(rep_seed_provider_present("t.seeds"));
    const rep_seed_provider_t *out[REP_SEED_PROVIDER_MAX];
    size_t n = rep_seed_providers(out, REP_SEED_PROVIDER_MAX);
    ck_assert_int_eq((int)n, (int)before + 1);
    ck_assert_ptr_eq(out[n - 1], &P);
}

static const char *const T_WIRE_VERBS[] = {"t_announce", NULL};
static int config_calls;
static int config_answer;
static int t_check_config(logger_t *logger)
{
    (void)logger;
    config_calls++;
    return config_answer;
}
static const net_ext_t T_DECL = {
    .name = "t.decl",
    .wire_verbs = T_WIRE_VERBS,
    .check_config = t_check_config,
};

DEFINE_TEST(test_declared_network_verbs_are_admitted_on_member_paths_only)
{
    ck_assert(!net_wire_verb_admitted("network", "t_announce", NET_PATH_PEER, NULL));
    ck_assert_int_eq(net_ext_register(&T_DECL), 0);
    ck_assert(net_ext_wire_verb_declared("t_announce"));
    ck_assert(!net_ext_wire_verb_declared("t_other"));
    ck_assert(net_wire_verb_admitted("network", "t_announce", NET_PATH_PEER, NULL));
    ck_assert(net_wire_verb_admitted("network", "t_announce", NET_PATH_GROUP, NULL));
    ck_assert(!net_wire_verb_admitted("network", "t_announce", NET_PATH_BROADCAST, NULL));
    ck_assert(!net_wire_verb_admitted("network", "t_announce", NET_PATH_STRANGER, NULL));
    ck_assert(!net_wire_verb_admitted("network", "t_announce", NET_PATH_RELAY_STRANGER, NULL));
    ck_assert(!net_wire_verb_admitted("network", "t_other", NET_PATH_PEER, NULL));
    ck_assert(net_wire_verb_admitted("network", "stats_req", NET_PATH_PEER, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_config_refusal_is_reported)
{
    /* Its own registration, so it does not lean on the test before it; a
     * second registration of the same extension returns -1 and changes
     * nothing. */
    (void)net_ext_register(&T_DECL);
    config_calls = 0;
    config_answer = 0;
    ck_assert_int_eq(net_ext_check_config(NULL), 0);
    ck_assert(config_calls >= 1);
    config_answer = 1;
    ck_assert_int_eq(net_ext_check_config(NULL), -1);
    config_answer = 0;
}
END_TEST_DEFINITION()

/* The checks network_run makes before any receiver starts: an extension
 * that refuses its configuration refuses the start. */
DEFINE_TEST(test_start_checks_refuse_on_a_config_refusal)
{
    (void)net_ext_register(&T_DECL);
    config_answer = 0;
    ck_assert_int_eq(net_proc_test_start_checks(NULL, NULL), 0);
    config_answer = 1;
    ck_assert_int_eq(net_proc_test_start_checks(NULL, NULL), -1);
    config_answer = 0;
}
END_TEST_DEFINITION()

/* A transport that records what network_run asks of it and never delivers. */
static int t_opens, t_closes, t_recvs;
static int t_open(net_transport_ctx_t **out, const net_transport_params_t *params)
{
    (void)params;
    t_opens++;
    *out = (net_transport_ctx_t *)&t_opens;     /* opaque; never dereferenced */
    return 0;
}
static int t_recv(net_transport_ctx_t *ctx, net_channel_t channel, uint8_t **out_buf,
                  size_t *out_len, char *from, size_t from_len, int timeout_ms)
{
    (void)ctx; (void)channel; (void)out_buf; (void)out_len; (void)from; (void)from_len;
    __atomic_add_fetch(&t_recvs, 1, __ATOMIC_SEQ_CST);
    usleep((useconds_t)timeout_ms * 1000);
    return ENOMSG;
}
static void t_close(net_transport_ctx_t *ctx)
{
    (void)ctx;
    t_closes++;
}
static const net_transport_t T_RECORDING = {
    .name = "t_recording",
    .open = t_open,
    .recv = t_recv,
    .close = t_close,
};

/* network_run itself, in-process so process_setup does not fork: a refused
 * extension config closes the opened transport and returns -1 before any
 * receiver thread reads from it. */
DEFINE_TEST(test_network_run_refuses_to_start_on_a_config_refusal)
{
    setenv("AT_IN_PROCESS", "1", 1);
    ck_assert(messaging_in_process());          /* else process_setup would fork */
    (void)net_ext_register(&T_DECL);
    ck_assert_int_eq(net_transport_register(&T_RECORDING), 0);
    network_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    proc->conf.data_struct = &cfg;
    ck_assert_ret_ok(map_create(&proc->configs));
    config_answer = 1;
    config_calls = 0;
    t_opens = t_closes = t_recvs = 0;
    char signal[] = "t_signal";
    ck_assert_int_eq(network_run_by_name("t_recording", proc, NULL, signal, NULL), -1);
    config_answer = 0;
    ck_assert_int_eq(config_calls, 1);          /* refused by the extension's check */
    ck_assert_int_eq(t_opens, 1);
    ck_assert_int_eq(t_closes, 1);
    ck_assert_int_eq(__atomic_load_n(&t_recvs, __ATOMIC_SEQ_CST), 0);
    map_free(proc->configs);
    smrt_deref(proc);
}
END_TEST_DEFINITION()

RUN_TESTS(ExtHooks,
          test_tier_caps_only_lower,
          test_network_hooks_dispatch,
          test_exclusions_by_uuid_and_key,
          test_seed_provider_registry,
          test_declared_network_verbs_are_admitted_on_member_paths_only,
          test_a_config_refusal_is_reported,
          test_start_checks_refuse_on_a_config_refusal,
          test_network_run_refuses_to_start_on_a_config_refusal)
