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

/** @file The app hands the core an authority finding, and it becomes a bound.
 *
 *  Phase 4 P4.1, the expulsion half of the moderation box: "revocation as a
 *  reputation event, not a hard cut" (SOCIAL_APP_PLAN.md:481).
 *
 *  WHAT IS BEING PINNED. An Ethne expulsion is decided in the app — the core
 *  holds no Ethne and cannot parse a charter record — so the finding arrives
 *  over the local app queue as AT_APP_PEER_STANDING. Identity validates its
 *  SHAPE, never its truth, and republishes it to reputation as a
 *  PEER_STANDING, where it becomes a CEILING.
 *
 *  WHY A CEILING AND NOT A SCORE, restated because it is the whole design:
 *  rep_proc.c records that this mechanism's predecessor expressed an authority
 *  finding as `score = -0.8` on a TRANSACTION_SCORE, which was discarded at the
 *  boundary twice over, so a revoked peer paid exactly nothing. A bound is the
 *  representation AT's [0, 1] scale actually has.
 *
 *  THE EMITTED MESSAGE IS THE OBSERVABLE. Identity and reputation are separate
 *  processes, so this suite captures the PEER_STANDING through
 *  messaging_set_test_hook and asserts on what crossed — the same seam
 *  social_send_test.c uses. That a ceiling then binds a score is
 *  peer_standing_test.c's job, and is not re-proved here.
 *
 *  Every guard gets a negative case, and the positive case comes first: a
 *  handler that refused everything would satisfy all four refusals.
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
#include "reputation/reputation.h"   /* COMM_CUTOFF */

static char STANDING_FN[] = AT_APP_PEER_STANDING;

/* What crossed to the reputation process, captured by the send hook. */
static int   g_sent;
static peer_standing_msg_t g_last;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (key != NULL && strcmp(key, "reputation") == 0
        && type == PEER_STANDING && msg != NULL) {
        g_sent++;
        memcpy(&g_last, &msg->info.peer_standing, sizeof(g_last));
    }
    return 0;
}

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

/* Admit a peer, so guard 4 (must be a known peer) has something to find. */
static void _admit(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

/* Drive the verb. @p from is NULL for the local app, or a peer for a frame
 * arriving off the wire. @p peer_str is passed raw so a malformed uuid can be
 * exercised. */
static void _standing(process_t *proc, const char *peer_str,
                      const char *standing, json_t *ceiling,
                      const char *source, const identity_t *from)
{
    json_t *p = json_object();
    if (peer_str != NULL)
        json_object_set_new(p, "peer", json_string(peer_str));
    if (standing != NULL)
        json_object_set_new(p, "standing", json_string(standing));
    if (ceiling != NULL)
        json_object_set_new(p, "ceiling", ceiling);
    if (source != NULL)
        json_object_set_new(p, "source", json_string(source));
    json_object_set_new(p, "reason", json_string("expelled from the polity"));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = STANDING_FN;
    msg.info.net_msg.verified = true;
    if (from != NULL) {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
        memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
        smrt_deref(pub);
    }
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

static void _begin(void)
{
    identity_reset_state();
    g_sent = 0;
    memset(&g_last, 0, sizeof(g_last));
    messaging_set_test_hook(_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_an_expulsion_becomes_a_ceiling)
{
    /* The control, and the increment's headline claim. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    _admit(proc, rogue);

    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);
    _standing(proc, rogue_str, "failed",
              json_real(AT_ETHNE_EXPEL_CEILING), PEER_STANDING_SOURCE_ETHNE,
              NULL);

    ck_assert_int_eq(g_sent, 1);
    ck_assert_int_eq(uuid_compare(g_last.peer_uuid, rogue->uuid), 0);
    ck_assert_int_eq(g_last.standing, (int32_t)PEER_STANDING_FAILED);
    ck_assert_double_eq_tol(g_last.ceiling, AT_ETHNE_EXPEL_CEILING, 1e-9);
    ck_assert_str_eq(g_last.source, PEER_STANDING_SOURCE_ETHNE);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_expulsion_ceiling_closes_tiers_without_cutting_the_peer_off)
{
    /* The number itself carries the plan line's meaning, so it is asserted
     * rather than left to a comment: below the tier-1 floor, so every
     * tier-gated capability and feed closes; above COMM_CUTOFF, so the peer is
     * NOT severed at the network layer and can still re-earn. */
    ck_assert(AT_ETHNE_EXPEL_CEILING < 0.50);
    ck_assert(AT_ETHNE_EXPEL_CEILING > COMM_CUTOFF);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_reinstatement_lifts_the_bound)
{
    /* "Not a hard cut" has to be true in both directions: the authority that
     * levied a bound can lift it. `proved` from the app means reinstated. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    _admit(proc, rogue);

    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);
    _standing(proc, rogue_str, "proved", NULL, PEER_STANDING_SOURCE_ETHNE,
              NULL);

    ck_assert_int_eq(g_sent, 1);
    ck_assert_int_eq(g_last.standing, (int32_t)PEER_STANDING_PROVED);
    /* No ceiling field at all means "no bound" — the sentinel, not 0.0, which
     * would floor the peer instead of freeing it. */
    ck_assert(g_last.ceiling < 0.0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_peer_may_not_hand_us_a_finding)
{
    /* GUARD 1. Without this the verb is a remote reputation-floor primitive. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    identity_t *meddler = _mk_identity("10.0.0.3", "meddler");
    _admit(proc, rogue);
    _admit(proc, meddler);

    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);
    _standing(proc, rogue_str, "failed",
              json_real(AT_ETHNE_EXPEL_CEILING), PEER_STANDING_SOURCE_ETHNE,
              meddler);

    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_app_may_not_speak_as_the_credential_authority)
{
    /* GUARD 2. An app cannot know what ZTA proved, so letting it claim a ZTA
     * standing would let it forge a `proved` and clear a real certificate
     * ceiling. Per-source keying makes that a total bypass, not a nuisance. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    _admit(proc, rogue);

    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);
    _standing(proc, rogue_str, "proved", NULL, PEER_STANDING_SOURCE_ZTA, NULL);
    ck_assert_int_eq(g_sent, 0);

    /* An authority nobody has heard of is refused for the same reason a
     * channel spelling is: the set is closed or it is not a set. */
    _standing(proc, rogue_str, "failed", json_real(0.2), "nonsense", NULL);
    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_off_scale_ceiling_is_refused)
{
    /* GUARD 3. A ceiling above 1.0 is not a bound on AT's scale. Below zero is
     * NOT an error — it is the "no bound" sentinel — so only the high side is
     * refused, and the low side is covered by the reinstatement test. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    _admit(proc, rogue);

    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);
    _standing(proc, rogue_str, "failed", json_real(1.5),
              PEER_STANDING_SOURCE_ETHNE, NULL);

    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_finding_about_a_stranger_is_refused)
{
    /* GUARD 4. A bound on somebody this node never admitted bounds nothing,
     * and is far likelier a mistake than a decision. */
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *stranger = _mk_identity("10.0.0.9", "stranger");
    /* deliberately NOT admitted */

    char stranger_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(stranger->uuid, stranger_str);
    _standing(proc, stranger_str, "failed",
              json_real(AT_ETHNE_EXPEL_CEILING), PEER_STANDING_SOURCE_ETHNE,
              NULL);

    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_malformed_finding_is_refused)
{
    _begin();
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    identity_t *rogue = _mk_identity("10.0.0.2", "rogue");
    _admit(proc, rogue);
    char rogue_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(rogue->uuid, rogue_str);

    _standing(proc, "not-a-uuid", "failed", json_real(0.2),
              PEER_STANDING_SOURCE_ETHNE, NULL);
    ck_assert_int_eq(g_sent, 0);

    _standing(proc, NULL, "failed", json_real(0.2),
              PEER_STANDING_SOURCE_ETHNE, NULL);
    ck_assert_int_eq(g_sent, 0);

    _standing(proc, rogue_str, "banished", json_real(0.2),
              PEER_STANDING_SOURCE_ETHNE, NULL);
    ck_assert_int_eq(g_sent, 0);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(PeerStandingVerb,
          test_an_expulsion_becomes_a_ceiling,
          test_the_expulsion_ceiling_closes_tiers_without_cutting_the_peer_off,
          test_a_reinstatement_lifts_the_bound,
          test_a_peer_may_not_hand_us_a_finding,
          test_the_app_may_not_speak_as_the_credential_authority,
          test_an_off_scale_ceiling_is_refused,
          test_a_finding_about_a_stranger_is_refused,
          test_a_malformed_finding_is_refused)
