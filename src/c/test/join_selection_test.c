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

/** @file Anchor-first join selection and provisional marking
 *  (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 3, D1 (c) + (d)). Under an enabled
 *  join policy a history OFFERED BY an anchor beats a longer one; the members
 *  the adopted group introduced, unanchored and not held, are provisional and
 *  persisted to provisional_members.cfg.json. Inert, nothing changes. Twin of
 *  test_join_selection.py; the merge rule is pinned by conformance
 *  (merge-to-mesh-*). */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "identity/id_ext.h"
#include "identity/id_proc_priv.h"
#include "identity/identity_priv.h"
#include "identity/join_policy.h"
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
    group_init(NULL, (char *)self->address, &proc->protocol.group);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    return proc;
}

/* The one identity the fake extension anchors, as a verified contact. */
static uuid_t g_anchor;

static uint32_t _anchor_classes(const process_t *proc, const public_identity_t *ident)
{
    (void)proc;
    return uuid_compare(ident->uuid, g_anchor) == 0 ? AT_ANCHOR_VERIFIED_CONTACT : 0;
}

static const identity_ext_t g_ext = {
    .name = "join_selection_test",
    .anchor_classes = _anchor_classes,
};

static char g_root[] = "/tmp/at-join-selection-XXXXXX";

static void _setup(bool enabled)
{
    static bool registered = false;
    identity_reset_state();
    if (!registered)
        ck_assert_ret_ok(identity_ext_register(&g_ext));
    registered = true;
    at_join_policy_t policy = { enabled, AT_ANCHOR_VERIFIED_CONTACT };
    identity_set_join_policy(&policy);
    if (g_root[strlen(g_root) - 1] == 'X') {
        ck_assert_ptr_nonnull(mkdtemp(g_root));
        char cfg[sizeof(g_root) + 16];
        snprintf(cfg, sizeof(cfg), "%s/etc", g_root);
        mkdir(cfg, 0700);
        snprintf(cfg, sizeof(cfg), "%s/etc/at", g_root);
        mkdir(cfg, 0700);
        setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    }
    char path[sizeof(g_root) + 64];
    snprintf(path, sizeof(path), "%s/etc/at/" ID_PROVISIONAL_FILE ".cfg.json", g_root);
    unlink(path);
}

/* [group, steps] with @p n made-up steps, as a welcomer sends it. */
static json_t *_history(const group_t *g, int n)
{
    json_t *g_json = NULL;
    ck_assert_ret_ok(group_to_json(g, &g_json));
    json_t *steps = json_array();
    for (int i = 0; i < n; i++) {
        uuid_t u;
        char us[UUID_STRING_LEN + 1];
        uuid_generate(u);
        uuid_unparse_lower(u, us);
        json_array_append_new(steps, json_pack(
            "{s:s, s:s, s:s}", "uuid", us,
            "timestamp", "2026-10-23T02:04:43.067288+00:00",
            "payload", "abababababababababababababababababababababababababababababababab"));
    }
    json_t *hist = json_array();
    json_array_append_new(hist, g_json);
    json_array_append_new(hist, steps);
    return hist;
}

/* A welcomer's public identity and a one-member group of its own. */
static void _welcomer(const char *addr, const char *name, public_identity_t *pub,
                      group_t *g)
{
    identity_t *w = _mk_identity(addr, name);
    public_identity_t *p = NULL;
    ck_assert_ret_ok(identity_publish(w, &p));
    memcpy(pub, p, sizeof(*pub));
    ck_assert_ret_ok(group_init(NULL, (char *)addr, g));
    char us[UUID_STRING_LEN + 1];
    uuid_unparse_lower(pub->uuid, us);
    group_add_address(g, us, (char *)addr);
}

static directory_t *_queues(void)
{
    static directory_t q;
    ck_assert_ret_ok(array_init(&q));
    ck_assert_ret_ok(array_append(&q, string_data(strdup("identity"), 8)));
    return &q;
}

DEFINE_TEST(test_an_offer_from_an_anchor_beats_a_longer_one)
{
    process_t *proc = _mk_process(_mk_identity("10.0.1.1", "joiner"));
    _setup(true);
    public_identity_t horde, friend;
    group_t hg = {0}, fg = {0};
    _welcomer("10.0.1.2", "horde", &horde, &hg);
    _welcomer("10.0.1.3", "friend", &friend, &fg);
    uuid_copy(g_anchor, friend.uuid);
    identity_stash_history_from(_history(&hg, 3), &horde);
    identity_stash_history_from(_history(&fg, 1), &friend);
    ck_assert(identity_adopt_group_from_histories(proc, _queues()));
    ck_assert_int_eq(uuid_compare(proc->protocol.group.uuid, fg.uuid), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_inert_policy_ignores_the_sender)
{
    process_t *proc = _mk_process(_mk_identity("10.0.2.1", "joiner"));
    _setup(false);
    public_identity_t horde, friend;
    group_t hg = {0}, fg = {0};
    _welcomer("10.0.2.2", "horde", &horde, &hg);
    _welcomer("10.0.2.3", "friend", &friend, &fg);
    uuid_copy(g_anchor, friend.uuid);
    identity_stash_history_from(_history(&hg, 3), &horde);
    identity_stash_history_from(_history(&fg, 1), &friend);
    ck_assert(identity_adopt_group_from_histories(proc, _queues()));
    ck_assert_int_eq(uuid_compare(proc->protocol.group.uuid, hg.uuid), 0);
    json_t *prov = identity_provisional_members();
    ck_assert_int_eq((int)json_array_size(prov), 0);
    json_decref(prov);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_history_stashed_without_a_sender_ranks_unanchored)
{
    process_t *proc = _mk_process(_mk_identity("10.0.3.1", "joiner"));
    _setup(true);
    public_identity_t horde, friend;
    group_t hg = {0}, fg = {0};
    _welcomer("10.0.3.2", "horde", &horde, &hg);
    _welcomer("10.0.3.3", "friend", &friend, &fg);
    uuid_copy(g_anchor, friend.uuid);
    identity_stash_history(_history(&fg, 1));          /* no sender noted */
    identity_stash_history_from(_history(&hg, 3), &horde);
    ck_assert(identity_adopt_group_from_histories(proc, _queues()));
    ck_assert_int_eq(uuid_compare(proc->protocol.group.uuid, hg.uuid), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_adopted_members_are_provisional_unless_anchored_and_persisted)
{
    process_t *proc = _mk_process(_mk_identity("10.0.4.1", "joiner"));
    _setup(true);
    public_identity_t friend;
    group_t fg = {0};
    _welcomer("10.0.4.3", "friend", &friend, &fg);
    uuid_copy(g_anchor, friend.uuid);
    group_add_address(&fg, "f1110000-0000-4000-8000-000000000001", (char *)"10.0.4.9");
    identity_stash_history_from(_history(&fg, 1), &friend);
    ck_assert(identity_adopt_group_from_histories(proc, _queues()));
    json_t *prov = identity_provisional_members();
    ck_assert_int_eq((int)json_array_size(prov), 1);
    ck_assert_str_eq(json_string_value(json_array_get(prov, 0)),
                     "f1110000-0000-4000-8000-000000000001");
    json_decref(prov);
    char path[sizeof(g_root) + 64];
    snprintf(path, sizeof(path), "%s/etc/at/" ID_PROVISIONAL_FILE ".cfg.json", g_root);
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    ck_assert_ptr_nonnull(doc);
    ck_assert_int_eq((int)json_array_size(doc), 1);
    ck_assert_str_eq(json_string_value(json_array_get(doc, 0)),
                     "f1110000-0000-4000-8000-000000000001");
    json_decref(doc);
}
END_TEST_DEFINITION()

RUN_TESTS(JoinSelection,
          test_an_offer_from_an_anchor_beats_a_longer_one,
          test_an_inert_policy_ignores_the_sender,
          test_a_history_stashed_without_a_sender_ranks_unanchored,
          test_adopted_members_are_provisional_unless_anchored_and_persisted)
