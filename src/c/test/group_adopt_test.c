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


/** @file A group adopted from a welcomer's history reaches the NETWORK process.
 *
 *  net_proc decrypts group frames with its OWN protocol.group, which only a
 *  GROUP message updates. choose_group's history adoption, the path a member
 *  rejoining after a restart takes, copied the mesh group into identity alone.
 *  moderation_cohort.sh's restart phase showed the result: the restarted node
 *  heard no group traffic ever again, with no error logged anywhere, because
 *  its network still held the group it had bootstrapped for itself.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "identity/id_proc_priv.h"
#include "structures/array.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
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

static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 2;
    proc->protocol.num_peers = 0;

    /* What a node holds before it adopts: its own self-seeded group. */
    group_init(NULL, (char *)self->address, &proc->protocol.group);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    return proc;
}

/* Every GROUP message sent to the network queue, the last one kept. */
static int g_group_to_net;
static group_t g_last_group;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == GROUP && key != NULL && strcmp(key, "network") == 0) {
        g_last_group = msg->info.group;
        g_group_to_net++;
    }
    return 0;
}

DEFINE_TEST(test_a_group_adopted_from_history_reaches_the_network)
{
    identity_t *me = _mk_identity("10.0.0.1", "rejoiner");
    process_t *proc = _mk_process(me);
    identity_reset_state();
    g_group_to_net = 0;
    memset(&g_last_group, 0, sizeof(g_last_group));

    /* The welcomer's mesh group, with its shared private key, as the first
     * slot of a full_history [group, steps]. */
    group_t mesh = {0};
    ck_assert_ret_ok(group_init(NULL, (char *)"10.0.0.2", &mesh));
    mesh.key_epoch = 2;
    json_t *g_json = NULL;
    ck_assert_ret_ok(group_to_json(&mesh, &g_json));
    json_t *hist = json_array();
    json_array_append_new(hist, g_json);
    json_array_append_new(hist, json_array());
    identity_stash_history(hist);

    directory_t queues;
    ck_assert_ret_ok(array_init(&queues));
    ck_assert_ret_ok(array_append(&queues, string_data(strdup("identity"), 8)));
    ck_assert_ret_ok(array_append(&queues, string_data(strdup("network"), 7)));
    messaging_set_test_hook(_hook);

    ck_assert(identity_adopt_group_from_histories(proc, &queues));

    /* identity adopted it... */
    ck_assert_int_eq(uuid_compare(proc->protocol.group.uuid, mesh.uuid), 0);
    /* ...and so did the network, with the KEY: this is what was missing. */
    ck_assert_int_eq(g_group_to_net, 1);
    ck_assert_int_eq(uuid_compare(g_last_group.uuid, mesh.uuid), 0);
    ck_assert_int_eq((int)g_last_group.key_epoch, 2);
    ck_assert(!sodium_is_zero(g_last_group.encryptor.private,
                              crypto_box_SECRETKEYBYTES));
    ck_assert_int_eq(memcmp(g_last_group.encryptor.private,
                            mesh.encryptor.private,
                            crypto_box_SECRETKEYBYTES), 0);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(GroupAdopt,
          test_a_group_adopted_from_history_reaches_the_network)
