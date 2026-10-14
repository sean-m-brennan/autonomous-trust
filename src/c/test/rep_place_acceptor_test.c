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

/** @file The acceptor of ordered placement keeps its promises across a
 *  restart (doc/architecture/reputation.md, "Agreeing on an order").
 *
 *  A node that promised a ballot, restarted, and then promised or accepted a
 *  lower one could let two values be decided at one index. So the promise is
 *  written before the grant goes out, and read back on first use. The
 *  conformance corpus pins the rest of the acceptor and learner in both
 *  runtimes; this is the part it cannot reach, since its C harness starts every
 *  step from empty state. Mirrors tests/a_unit/test_placement_acceptor.py
 *  test_a_promise_survives_a_restart.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
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

static char PLACE_REQUEST_FN[] = "place request";

static size_t g_grants;
static size_t g_nacks;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    if (strcmp(msg->info.net_msg.function, "place grant") == 0)
        g_grants++;
    else if (strcmp(msg->info.net_msg.function, "place nack") == 0)
        g_nacks++;
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

static process_t *_mk_process(identity_t *self, identity_t *peer)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    proc->protocol.group.ordered_placement = true;
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
    proc->protocol.num_peers = 1;
    smrt_deref(pub);
    return proc;
}

/* `sender` asks for instance 0 of the primary chain under (n, sender). */
static void _ask(process_t *proc, identity_t *sender, int64_t n)
{
    char by[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender->uuid, by);
    json_t *p = json_pack("{s:s, s:i, s:{s:I, s:s}, s:s}", "group", "", "k", 0,
                          "ballot", "n", (json_int_t)n, "by", by, "head", "");
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = PLACE_REQUEST_FN;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
    json_decref(p);
}

DEFINE_TEST(test_a_promise_survives_a_restart)
{
    char dir[] = "/tmp/at-place-test-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    reputation_set_placement_dir(dir);
    reputation_reset_state(1);
    messaging_set_test_hook(_capture_hook);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *peer = _mk_identity("peer", "10.0.0.2");
    process_t *proc = _mk_process(me, peer);

    g_grants = g_nacks = 0;
    _ask(proc, peer, 9);
    ck_assert_uint_eq(g_grants, 1);

    reputation_reset_state(1);           /* the restart: memory is gone */
    g_grants = g_nacks = 0;
    _ask(proc, peer, 8);
    ck_assert_uint_eq(g_grants, 0);
    ck_assert_uint_eq(g_nacks, 1);
    _ask(proc, peer, 10);
    ck_assert_uint_eq(g_grants, 1);

    messaging_set_test_hook(NULL);
    reputation_set_placement_dir(NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/reputation-placement.cfg.json", dir);
    unlink(path);
    rmdir(dir);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unreadable_state_promises_nothing)
{
    char dir[] = "/tmp/at-place-test-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/reputation-placement.cfg.json", dir);
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs("{not json", f);
    fclose(f);
    reputation_set_placement_dir(dir);
    reputation_reset_state(1);
    messaging_set_test_hook(_capture_hook);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *peer = _mk_identity("peer", "10.0.0.2");
    process_t *proc = _mk_process(me, peer);

    g_grants = g_nacks = 0;
    _ask(proc, peer, 9);
    ck_assert_uint_eq(g_grants, 0);

    messaging_set_test_hook(NULL);
    reputation_set_placement_dir(NULL);
    unlink(path);
    rmdir(dir);
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlaceAcceptor,
          test_a_promise_survives_a_restart,
          test_an_unreadable_state_promises_nothing)
