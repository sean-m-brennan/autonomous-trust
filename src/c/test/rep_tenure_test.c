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

/** @file Tenure (doc/architecture/reputation.md, "Tenure"): a member this node
 *  has held for less than AT_REP_MIN_TENURE_SEC holds at most tier 2, however
 *  well it has answered.
 *
 *  Found by Stele's red team (rt-3717776, 2026-10-15): the owner's shill
 *  answered four probes honestly, ordered placement committed them in seconds,
 *  and the observer scored it 0.90 (tier 4) fourteen seconds after it joined,
 *  then counted it as a replica. Every assertion here is on the tier the sweep
 *  PUBLISHES, the thing identity's gates read. The Python twin is
 *  tests/a_unit/test_tenure.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>
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

#define TENURE "600"

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
static double g_present;

/* Self and one peer, four bilateral 0.9 tasks between them (a tier-4 record),
 * the gate set to @p tenure ("" leaves it unset), and a fresh root so no
 * roster.cfg.json from elsewhere is read. */
static process_t *_begin(const char *tenure)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-tenure-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    char etc[128];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    mkdir(etc, 0700);
    snprintf(etc, sizeof(etc), "%s/etc/at", g_root);
    mkdir(etc, 0700);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    if (tenure[0] != '\0')
        setenv("AT_REP_MIN_TENURE_SEC", tenure, 1);
    else
        unsetenv("AT_REP_MIN_TENURE_SEC");
    reputation_reset_state(2);
    me = _mk_identity("10.0.0.1", "self");
    them = _mk_identity("10.0.0.2", "peer");
    process_t *proc = _mk_process(me, them);
    for (int i = 0; i < 4; i++)
    {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, me->uuid, 0.9, them->uuid, 0.9);
    }
    g_last_tier = -1;
    g_present = (double)time(NULL);
    messaging_set_test_hook(_tier_hook);
    return proc;
}

static void _sweep(process_t *proc)
{
    g_present += 1000.0;            /* past the rescore throttle */
    (void)reputation_rescore_sweep(proc, g_present, me->uuid);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    unsetenv("AT_REP_MIN_TENURE_SEC");
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
#ifndef _WIN32   /* cleanup only; Windows' system() shell has no rm */
    ck_assert_int_eq(system(cmd), 0);
#endif
}

static void _key_hex(const identity_t *who, char out[crypto_sign_PUBLICKEYBYTES * 2 + 1])
{
    sodium_bin2hex(out, crypto_sign_PUBLICKEYBYTES * 2 + 1, who->signature.public,
                   crypto_sign_PUBLICKEYBYTES);
}

DEFINE_TEST(test_a_young_member_is_held_at_tier_two)
{
    process_t *proc = _begin(TENURE);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL) - 10.0);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 2);
    double score = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &score));
    ck_assert(score < 0.80 && score > 0.79);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_member_past_its_tenure_is_not_held)
{
    process_t *proc = _begin(TENURE);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL) - 1000.0);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_gate_is_off_unless_set)
{
    process_t *proc = _begin("");
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL));
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

/* A member never held before starts its tenure at the sweep that first sees
 * it. */
DEFINE_TEST(test_a_member_first_seen_now_is_held)
{
    process_t *proc = _begin(TENURE);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 2);
    _end();
}
END_TEST_DEFINITION()

/* Served tenure lifts the hold at the next sweep, with no new commit to make
 * the peer due. */
DEFINE_TEST(test_the_hold_lifts_once_tenure_is_served)
{
    process_t *proc = _begin(TENURE);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL) - 10.0);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 2);
    reputation_set_member_since(them->uuid, NULL, (double)time(NULL) - 1000.0);
    g_last_tier = -1;
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

/* A restart keeps the clock: first_seen in roster.cfg.json, for the same key,
 * seeds it. */
DEFINE_TEST(test_first_seen_in_the_roster_survives_a_restart)
{
    process_t *proc = _begin(TENURE);
    char u[UUID_STRING_LEN + 1], k[crypto_sign_PUBLICKEYBYTES * 2 + 1], path[160];
    uuid_unparse_lower(them->uuid, u);
    _key_hex(them, k);
    json_t *doc = json_pack("{s:{s:{s:I, s:s}}}", "members", u, "first_seen",
                            (json_int_t)time(NULL) - 1000, "pubkey", k);
    snprintf(path, sizeof(path), "%s/etc/at/roster.cfg.json", g_root);
    ck_assert_int_eq(json_dump_file(doc, path, 0), 0);
    json_decref(doc);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

/* A new key is a new identity: the clock started for the old one does not
 * carry over. */
DEFINE_TEST(test_a_changed_key_restarts_the_clock)
{
    process_t *proc = _begin(TENURE);
    char other[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    memset(other, 'a', sizeof(other) - 1);
    other[sizeof(other) - 1] = '\0';
    reputation_set_member_since(them->uuid, other, (double)time(NULL) - 1000.0);
    _sweep(proc);
    ck_assert_int_eq(g_last_tier, 2);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepTenure,
          test_a_young_member_is_held_at_tier_two,
          test_a_member_past_its_tenure_is_not_held,
          test_the_gate_is_off_unless_set,
          test_a_member_first_seen_now_is_held,
          test_the_hold_lifts_once_tenure_is_served,
          test_first_seen_in_the_roster_survives_a_restart,
          test_a_changed_key_restarts_the_clock)
