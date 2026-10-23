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

/** @file A half has no round of its own (doc/architecture/reputation.md,
 *  "Agreeing on an order").
 *
 *  Where its entry lands is decided by placement, so the proposer sends its
 *  `transaction` at once, naming the group and asking to be certified, and an
 *  acceptor signs it without a grant. A proposal that does neither is from a
 *  build that still ran the half round, and so are the half round's own verbs
 *  (retired 2026-10-16): nothing answers them. Mirrors
 *  tests/a_unit/test_placement_halves.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char TX_FN[] = "transaction";

/* What this node sent: how many of each (g_sent: anything at all), and the
 * last transaction and acceptance. */
static int g_asks, g_txs, g_accepts, g_sent;
static json_t *g_tx, *g_accepted;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || msg->info.net_msg.obj == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    json_t **slot = NULL;
    g_sent++;
    if (strcmp(fn, "ask permission") == 0)   /* a retired verb */
        g_asks++;
    else if (strcmp(fn, "transaction") == 0)
    {
        g_txs++;
        slot = &g_tx;
    }
    else if (strcmp(fn, "tx accepted") == 0)
    {
        g_accepts++;
        slot = &g_accepted;
    }
    if (slot != NULL)
    {
        json_decref(*slot);
        *slot = json_loads((const char *)msg->info.net_msg.obj, 0, NULL);
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

static identity_t *me, *p[3];

/* This node, rostered with p[0..2]. */
static process_t *_begin(void)
{
    reputation_reset_state(3);
    messaging_set_test_hook(_capture_hook);
    g_asks = g_txs = g_accepts = g_sent = 0;
    g_tx = g_accepted = NULL;
    me = _mk_identity("me", "10.0.0.1");
    p[0] = _mk_identity("p0", "10.0.0.2");
    p[1] = _mk_identity("p1", "10.0.0.3");
    p[2] = _mk_identity("p2", "10.0.0.4");
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    uuid_generate(proc->protocol.group.uuid);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = me;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    for (int i = 0; i < 3; i++)
    {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish(p[i], &pub));
        memcpy(&proc->protocol.peers[i], pub, sizeof(public_identity_t));
        smrt_deref(pub);
    }
    proc->protocol.num_peers = 3;
    return proc;
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    json_decref(g_tx);
    json_decref(g_accepted);
    g_tx = g_accepted = NULL;
}

/* p[0] proposes a half of its own to us, ungranted. */
static void _offer(process_t *proc, bool certify, bool name_group)
{
    char by[UUID_STRING_LEN + 1], task[UUID_STRING_LEN + 1];
    uuid_t t;
    uuid_generate(t);
    uuid_unparse_lower(t, task);
    uuid_unparse_lower(p[0]->uuid, by);
    json_t *tx = json_pack("{s:I, s:I, s:s, s:f, s:s}", "id1", (json_int_t)7000,
                           "id2", (json_int_t)1, "peer_uuid", by, "score", 0.9,
                           "task_uuid", task);
    if (certify)
        json_object_set_new(tx, "certify", json_true());
    if (name_group)
    {
        char g[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.group.uuid, g);
        json_object_set_new(tx, "group", json_string(g));
    }
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(p[0], &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = TX_FN;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, tx));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
    json_decref(tx);
}

static void _propose(process_t *proc)
{
    uuid_t task, other;
    uuid_generate(task);
    /* Our half names whom it scores (R+D.md §14.2); which peer does not
     * matter here. */
    uuid_generate(other);
    _forward_transaction(proc, task, me->uuid, 0.9, NULL, NULL, other, 0.0);
}

DEFINE_TEST(test_a_placing_proposer_sends_its_half_without_asking)
{
    process_t *proc = _begin();
    _propose(proc);
    ck_assert_int_eq(g_asks, 0);
    ck_assert_int_eq(g_txs, 3);                  /* one to each member */
    ck_assert_ptr_nonnull(g_tx);
    ck_assert(json_is_true(json_object_get(g_tx, "certify")));
    char g[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, g);
    ck_assert_str_eq(json_string_value(json_object_get(g_tx, "group")), g);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_placing_acceptor_signs_a_half_it_never_granted)
{
    process_t *proc = _begin();
    _offer(proc, true, true);
    ck_assert_int_eq(g_accepts, 1);
    ck_assert_ptr_nonnull(g_accepted);
    ck_assert_ptr_nonnull(json_string_value(json_object_get(g_accepted, "sig")));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unless_it_asks_to_be_certified_or_names_no_group)
{
    process_t *proc = _begin();
    _offer(proc, false, true);
    _offer(proc, true, false);
    ck_assert_int_eq(g_accepts, 0);
    _end();
}
END_TEST_DEFINITION()

/* A node on a build from before every group placed its order asks for the
 * floor: nothing answers it, whichever of the retired verbs it sends. */
DEFINE_TEST(test_a_retired_verb_gets_no_answer)
{
    process_t *proc = _begin();
    static char retired[][24] = { "ask permission", "permission granted",
                                  "try again", "out of date" };
    char by[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p[0]->uuid, by);
    for (size_t i = 0; i < sizeof(retired) / sizeof(retired[0]); i++)
    {
        json_t *ask = json_pack("{s:I, s:I, s:s}", "id1", (json_int_t)1,
                                "id2", (json_int_t)1, "peer_uuid", by);
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish(p[0], &pub));
        generic_msg_t msg = {0};
        msg.type = NET_MESSAGE;
        strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
        msg.info.net_msg.function = retired[i];
        msg.info.net_msg.verified = true;
        memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
        ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, ask));
        ck_assert(run_message_handlers(proc, NULL, NET_MESSAGE, &msg));
        smrt_deref(pub);
        json_decref(ask);
    }
    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlaceHalves,
          test_a_placing_proposer_sends_its_half_without_asking,
          test_a_placing_acceptor_signs_a_half_it_never_granted,
          test_unless_it_asks_to_be_certified_or_names_no_group,
          test_a_retired_verb_gets_no_answer)
