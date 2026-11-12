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

/** @file Tier hysteresis (doc/architecture/trust-tiers.md, "Hysteresis"):
 *  promotion happens at a tier's floor and demotion at the floor less the
 *  ladder's tier_demotion_epsilon (0.02 by default), so a peer whose score
 *  hovers on a floor holds its tier instead of flapping across it.
 *
 *  Found on the Wi-Fi fleet (2026-11-11): a node failing probes settled at
 *  0.63-0.66 and every observer, the Raspberry Pi included, moved it between
 *  tiers 1 and 2 three to six times in forty minutes. The margin was parsed
 *  from the ladder but never applied. The Python twin is
 *  tests/a_unit/test_tier_hysteresis.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static identity_t *_mk_identity(const char *addr, const char *name)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    return ident;
}

/* Self, with @p peer admitted. */
static process_t *_mk_process(identity_t *self, identity_t *peer)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(public_identity_t));
    smrt_deref(pub);
    proc->protocol.num_peers = 1;
    return proc;
}

static int g_last_tier;

static int _tier_hook(const char *key, const message_type_t type,
                      generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == NET_MESSAGE && key != NULL && strcmp(key, "identity") == 0 &&
        msg->info.net_msg.function != NULL &&
        strcmp(msg->info.net_msg.function, "tier_update") == 0) {
        json_t *arr = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &arr) == 0 && arr != NULL) {
            g_last_tier = (int)json_integer_value(json_array_get(arr, 1));
            json_decref(arr);
        }
    }
    return 0;
}

static char g_root[64];
static identity_t *me, *them;

/* Self and one peer under a fresh root, with @p ladder_json (NULL: none)
 * written as the trust ladder before the state is reset, which reads it. */
static process_t *_begin(const char *ladder_json)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-hyst-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/etc", g_root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/etc/at", g_root);
    mkdir(path, 0700);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    unsetenv("AT_REP_MIN_TENURE_SEC");
    if (ladder_json != NULL) {
        snprintf(path, sizeof(path), "%s/ladder.json", g_root);
        FILE *f = fopen(path, "w");
        ck_assert_ptr_nonnull(f);
        fputs(ladder_json, f);
        fclose(f);
        setenv("AT_TRUST_LADDER", path, 1);
    } else {
        unsetenv("AT_TRUST_LADDER");
    }
    reputation_reset_state(2);
    me = _mk_identity("10.0.0.1", "self");
    them = _mk_identity("10.0.0.2", "peer");
    process_t *proc = _mk_process(me, them);
    g_last_tier = -1;
    messaging_set_test_hook(_tier_hook);
    return proc;
}

/* Publish @p score and return the tier identity now holds for the peer: the
 * last tier_update, since an unchanged tier sends none. */
static int _publish(process_t *proc, double score)
{
    reputation_publish_tier(proc, them->uuid, score);
    return g_last_tier;
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    unsetenv("AT_TRUST_LADDER");
    unsetenv("AT_REP_MIN_TENURE_SEC");
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
#ifndef _WIN32   /* cleanup only; Windows' system() shell has no rm */
    ck_assert_int_eq(system(cmd), 0);
#endif
    reputation_reset_state(2);
}

DEFINE_TEST(test_promotion_happens_at_the_floor)
{
    process_t *proc = _begin(NULL);
    ck_assert_int_eq(_publish(proc, 0.60), 1);
    ck_assert_int_eq(_publish(proc, 0.65), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_demotion_waits_for_the_floor_less_the_margin)
{
    process_t *proc = _begin(NULL);
    ck_assert_int_eq(_publish(proc, 0.70), 2);
    ck_assert_int_eq(_publish(proc, 0.64), 2);
    ck_assert_int_eq(_publish(proc, 0.631), 2);
    ck_assert_int_eq(_publish(proc, 0.629), 1);
    _end();
}
END_TEST_DEFINITION()

/* The Pi's own sequence for the defector, 2026-11-11. */
DEFINE_TEST(test_a_score_hovering_on_a_floor_does_not_flap)
{
    process_t *proc = _begin(NULL);
    static const double scores[] = {0.795, 0.627, 0.660, 0.640, 0.651, 0.647, 0.629};
    static const int tiers[] = {2, 1, 2, 2, 2, 2, 1};
    for (size_t i = 0; i < sizeof(scores) / sizeof(scores[0]); i++)
        ck_assert_int_eq(_publish(proc, scores[i]), tiers[i]);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_margin_spans_several_tiers_only_as_far_as_the_score)
{
    process_t *proc = _begin(NULL);
    ck_assert_int_eq(_publish(proc, 0.95), 4);
    ck_assert_int_eq(_publish(proc, 0.885), 4);
    ck_assert_int_eq(_publish(proc, 0.79), 3);
    ck_assert_int_eq(_publish(proc, 0.70), 2);
    _end();
}
END_TEST_DEFINITION()

/* A young member is capped just under tier 3's floor, which is inside the
 * margin: the hold, not the margin, decides its tier. */
DEFINE_TEST(test_a_tenure_hold_is_not_softened_by_the_margin)
{
    process_t *proc = _begin(NULL);
    reputation_set_min_tenure(600.0);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL) - 1000.0);
    ck_assert_int_eq(_publish(proc, 0.85), 3);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL));
    ck_assert_int_eq(_publish(proc, 0.7999), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_ladder_sets_the_margin)
{
    process_t *proc = _begin("{\"tier_demotion_epsilon\": 0.0}");
    ck_assert_int_eq(_publish(proc, 0.70), 2);
    ck_assert_int_eq(_publish(proc, 0.649), 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_ladder_sets_the_floors)
{
    process_t *proc = _begin("{\"tier_floors\": [0.45, 0.6, 0.75, 0.85], "
                             "\"tier_demotion_epsilon\": 0.0}");
    static const double scores[] = {0.44, 0.46, 0.61, 0.76, 0.86};
    for (size_t i = 0; i < sizeof(scores) / sizeof(scores[0]); i++)
        ck_assert_int_eq(_publish(proc, scores[i]), (int)i);
    _end();
}
END_TEST_DEFINITION()

/* A peer failing probes is held at tier 1's floor less 0.01, wherever the
 * ladder puts that floor. Contrite tit-for-tat's repeat-defection cap belongs
 * to the 0.5 cooperation boundary and stays at 0.49. */
DEFINE_TEST(test_the_probe_hold_follows_tier_one)
{
    process_t *proc = _begin("{\"tier_floors\": [0.45, 0.6, 0.75, 0.85]}");
    (void)proc;
    ck_assert_double_eq_tol(reputation_tier_one_hold(), 0.44, 1e-9);
    ck_assert_double_eq_tol(reputation_persist_threshold(), 0.45, 1e-9);
    /* Six cooperative 0.9s and two defections in a row. */
    ck_assert_double_eq_tol(reputation_ctft_score(5.4, 6, 0.2, 0.2), 0.49, 1e-9);
    _end();
    ck_assert_double_eq_tol(reputation_tier_one_hold(), 0.49, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_malformed_ladder_leaves_the_default_floors)
{
    process_t *proc = _begin("{\"tier_floors\": [0.5, 0.8, 0.65, 0.9], "
                             "\"tier_demotion_epsilon\": 0.0}");
    ck_assert_int_eq(_publish(proc, 0.64), 1);
    ck_assert_int_eq(_publish(proc, 0.66), 2);
    ck_assert_double_eq_tol(reputation_tier_one_hold(), 0.49, 1e-9);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepTierHysteresis,
          test_promotion_happens_at_the_floor,
          test_demotion_waits_for_the_floor_less_the_margin,
          test_a_score_hovering_on_a_floor_does_not_flap,
          test_the_margin_spans_several_tiers_only_as_far_as_the_score,
          test_a_tenure_hold_is_not_softened_by_the_margin,
          test_the_ladder_sets_the_margin,
          test_the_ladder_sets_the_floors,
          test_the_probe_hold_follows_tier_one,
          test_a_malformed_ladder_leaves_the_default_floors)
