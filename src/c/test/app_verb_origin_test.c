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

/** @file An app verb is local-only: a peer must not drive one over the wire.
 *
 *  WHERE THIS CAME FROM. Traced while planning Phase 4 P4.1 (moderation). An
 *  app verb and a peer's message are the same kind of object — both are
 *  NET_MESSAGEs dispatched on `net_msg.function` by run_message_handlers —
 *  and route_to_process (net_proc.c) forwards to the named process by name
 *  with NO function allowlist. Nothing in id_proc.c inspected `from_whom`.
 *
 *  HOW BIG THE HOLE ACTUALLY IS, measured rather than assumed. The plaintext
 *  receive policy (ID_UNENCRYPTED_VERBS, enforced at net_proc.c:1799) refuses
 *  an app_* verb in the clear, so this was never open to a stranger. It was
 *  open to an ADMITTED peer, whose encrypted frame decrypts and routes like
 *  any other. That is not a small set to dismiss: admitted peers are exactly
 *  who the tier and reputation machinery exists to constrain, so "already
 *  admitted" is not a trust argument. P4.1 also adds a verb that can FLOOR
 *  ANY PEER'S REPUTATION, which is what turned a latent gap into a blocker.
 *
 *  THE SIGNATURE. The app builds its request as `generic_msg_t req = {0}` and
 *  never populates from_whom (at_app_events_block, app_events.c), so a local
 *  app verb carries a NULL uuid; anything off the wire carries the sender's
 *  identity, copied whole by route_to_process.
 *
 *  BOTH HALVES ARE ASSERTED. A guard that refused everything would pass a
 *  test that only checked the refusal, so the local verb is driven first and
 *  its effect observed. The observable is the tier clamp, since that is the
 *  whole of what a block does today (identity_get_peer_tier).
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
#include "identity/id_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

#define SEEDED_TIER 3

static char BLOCK_FN[] = "app_block";
static char TIER_FN[]  = "tier_update";

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
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    char self_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid);
    group_add_address(&proc->protocol.group, self_uuid, self->address);

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

/* Drive a verb with a chosen origin. @p from is NULL for a local app verb
 * (from_whom left zeroed, exactly as the shim leaves it) or a peer identity
 * for one arriving off the wire (from_whom populated, exactly as
 * route_to_process leaves it). */
static void _drive(process_t *proc, char *function, json_t *payload,
                   const identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = true;
    if (from != NULL) {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
        ck_assert_ptr_nonnull(pub);
        memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
        smrt_deref(pub);
    }
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* Give the peer a tier worth clamping. Without this every assertion below
 * reads 0 whether or not the block landed. */
static void _seed_tier(process_t *proc, const identity_t *peer)
{
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer->uuid, peer_str);
    /* [peer_uuid, tier] — an ARRAY, as handle_tier_update reads it. */
    json_t *p = json_array();
    json_array_append_new(p, json_string(peer_str));
    json_array_append_new(p, json_integer(SEEDED_TIER));
    _drive(proc, TIER_FN, p, NULL);
    json_decref(p);
    ck_assert_int_eq(identity_get_peer_tier(peer->uuid), SEEDED_TIER);
}

static void _block(process_t *proc, const identity_t *target,
                   const identity_t *from)
{
    char target_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(target->uuid, target_str);
    json_t *p = json_object();
    json_object_set_new(p, "peer", json_string(target_str));
    _drive(proc, BLOCK_FN, p, from);
    json_decref(p);
}

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_the_local_app_may_block)
{
    /* The control. A guard that refused everything would satisfy the refusal
     * test below while breaking the feature outright. */
    identity_reset_state();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *target = _mk_identity("10.0.0.2", "target");

    _seed_tier(proc, target);
    _block(proc, target, NULL);

    ck_assert_int_eq(identity_get_peer_tier(target->uuid), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_peer_may_not_block_a_third_party_on_our_node)
{
    /* The same verb, the same payload, one difference: it arrives carrying a
     * peer's identity. An admitted peer's encrypted frame routes exactly like
     * this, so before P4.1 a peer could reach into this node and clamp a
     * third party's tier. */
    identity_reset_state();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *target = _mk_identity("10.0.0.2", "target");
    identity_t *meddler = _mk_identity("10.0.0.3", "meddler");

    _seed_tier(proc, target);
    _block(proc, target, meddler);

    ck_assert_int_eq(identity_get_peer_tier(target->uuid), SEEDED_TIER);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_verb_looped_back_through_our_own_queue_is_local)
{
    /* Self is accepted: a few paths send a verb back through this node's own
     * queue, and those carry our identity rather than a zeroed from_whom.
     * Refusing them would be a self-inflicted outage. */
    identity_reset_state();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *target = _mk_identity("10.0.0.2", "target");

    _seed_tier(proc, target);
    _block(proc, target, me);

    ck_assert_int_eq(identity_get_peer_tier(target->uuid), 0);
}
END_TEST_DEFINITION()

RUN_TESTS(AppVerbOrigin,
          test_the_local_app_may_block,
          test_a_peer_may_not_block_a_third_party_on_our_node,
          test_a_verb_looped_back_through_our_own_queue_is_local)
