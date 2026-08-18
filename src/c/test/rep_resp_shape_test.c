/*
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
 *
 *  What a `reputation response` looks like on the wire, and where it is
 *  addressed.
 *
 *  Both were wrong in the same way at all three reply sites. The payload was
 *  `{peer_uuid, score, requesting_process}` with no `__type__` tag, which a
 *  Python requestor deserialises to a bare dict and then raises on; and the
 *  envelope named the "reputation" process rather than the process that asked,
 *  so even a readable reply was delivered to a process with no handler for it.
 *  Together that meant a C peer's view of the cohort reached nothing — the
 *  inspector's trust graph had no C opinions in it, and nothing said so.
 *
 *  Handlers are static, so they are driven through run_message_handlers with a
 *  crafted NET_MESSAGE and the emission captured with the messaging test hook,
 *  following the rep_quorum_test precedent. Python twin:
 *  tests/a_unit/test_rep_resp_interop.py. See doc/architecture/reputation.md.
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
#include "identity/identity_priv.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "structures/data.h"

#define REP_TYPE_TAG "autonomous_trust.core._python.reputation.reputation.Reputation"

/* Last captured rep_resp: its payload and the process it was addressed to. */
static json_t *g_last_body = NULL;
static char    g_last_process[PROC_NAME_LEN + 1];
static int     g_resp_count = 0;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    if (strcmp(msg->info.net_msg.function, REP_PROTO_REP_RESP) != 0)
        return 0;
    g_resp_count++;
    strncpy(g_last_process, msg->info.net_msg.process, PROC_NAME_LEN);
    g_last_process[PROC_NAME_LEN] = '\0';
    if (g_last_body != NULL) {
        json_decref(g_last_body);
        g_last_body = NULL;
    }
    if (msg->info.net_msg.obj != NULL) {
        json_error_t err;
        g_last_body = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
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
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    proc->protocol.num_peers = 0;

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    return proc;
}

static void _uuid_str(const uuid_t u, char *out)
{
    uuid_unparse_lower(u, out);
}

static void _dispatch(process_t *proc, identity_t *sender, char *function,
                      json_t *payload)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
}

static void _begin(int num_peers)
{
    reputation_reset_state(num_peers);
    g_resp_count = 0;
    g_last_process[0] = '\0';
    if (g_last_body != NULL) {
        json_decref(g_last_body);
        g_last_body = NULL;
    }
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    if (g_last_body != NULL) {
        json_decref(g_last_body);
        g_last_body = NULL;
    }
}

/* The one reply entry, whether the body is a bare object or a one-element
 * roster, so the shape assertions read the same for both verbs. */
static json_t *_entry(json_t *body)
{
    ck_assert_ptr_nonnull(body);
    if (json_is_array(body)) {
        ck_assert(json_array_size(body) >= 1);
        return json_array_get(body, 0);
    }
    return body;
}

static void _assert_reputation_shape(json_t *entry, const char *expect_uuid)
{
    ck_assert_ptr_nonnull(entry);
    ck_assert(json_is_object(entry));
    /* The tag is what makes a Python requestor build a Reputation rather than
     * hand its caller a dict. */
    ck_assert_str_eq(json_string_value(json_object_get(entry, "__type__")),
                     REP_TYPE_TAG);
    ck_assert_str_eq(json_string_value(json_object_get(entry, "peer_id")),
                     expect_uuid);
    ck_assert(json_is_number(json_object_get(entry, "score")));
    /* Exactly three keys: the requestor reconstructs the object by keyword, so
     * a stray field is a TypeError there, not a value it ignores. The old
     * `requesting_process` field lived here and belongs in the envelope. */
    ck_assert_uint_eq(json_object_size(entry), 3);
    ck_assert_ptr_null(json_object_get(entry, "requesting_process"));
    ck_assert_ptr_null(json_object_get(entry, "peer_uuid"));
}

/* ------------------------------------------------------------------ */
/* Single-subject reputation request                                    */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_rep_req_reply_is_a_reputation_addressed_to_the_asker)
{
    _begin(2);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *subject = _mk_identity("charlie", "10.0.0.3");
    process_t *proc = _mk_process(me);

    char subject_u[UUID_STRING_LEN + 1];
    _uuid_str(subject->uuid, subject_u);

    json_t *p = json_object();
    json_object_set_new(p, "peer_uuid", json_string(subject_u));
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_REP_REQ, p);
    json_decref(p);

    ck_assert_int_eq(g_resp_count, 1);
    _assert_reputation_shape(_entry(g_last_body), subject_u);
    /* Addressed to the process that asked, not to ours: a requestor routes an
     * inbound message by this field. */
    ck_assert_str_eq(g_last_process, "monitor");
    _end();
}

DEFINE_TEST(test_consensus_req_reply_is_a_reputation_addressed_to_the_asker)
{
    _begin(2);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *subject = _mk_identity("charlie", "10.0.0.3");
    process_t *proc = _mk_process(me);

    char subject_u[UUID_STRING_LEN + 1];
    _uuid_str(subject->uuid, subject_u);

    json_t *p = json_object();
    json_object_set_new(p, "peer_uuid", json_string(subject_u));
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_REQ, p);
    json_decref(p);

    ck_assert_int_eq(g_resp_count, 1);
    _assert_reputation_shape(_entry(g_last_body), subject_u);
    ck_assert_str_eq(g_last_process, "monitor");
    _end();
}

/* ------------------------------------------------------------------ */
/* Batched consensus request                                            */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_batch_reply_is_a_roster_of_reputations)
{
    _begin(3);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *c = _mk_identity("charlie", "10.0.0.3");
    identity_t *d = _mk_identity("dave", "10.0.0.4");
    process_t *proc = _mk_process(me);

    char c_u[UUID_STRING_LEN + 1], d_u[UUID_STRING_LEN + 1];
    _uuid_str(c->uuid, c_u);
    _uuid_str(d->uuid, d_u);

    json_t *uuids = json_array();
    json_array_append_new(uuids, json_string(c_u));
    json_array_append_new(uuids, json_string(d_u));
    json_t *p = json_object();
    json_object_set_new(p, "peer_uuids", uuids);
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_BATCH_REQ, p);
    json_decref(p);

    /* ONE reply for both subjects — that is the whole point of the verb. */
    ck_assert_int_eq(g_resp_count, 1);
    ck_assert_ptr_nonnull(g_last_body);
    ck_assert(json_is_array(g_last_body));
    ck_assert_uint_eq(json_array_size(g_last_body), 2);
    _assert_reputation_shape(json_array_get(g_last_body, 0), c_u);
    _assert_reputation_shape(json_array_get(g_last_body, 1), d_u);
    ck_assert_str_eq(g_last_process, "monitor");
    _end();
}

DEFINE_TEST(test_batch_reply_skips_the_responder_itself)
{
    _begin(3);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *c = _mk_identity("charlie", "10.0.0.3");
    process_t *proc = _mk_process(me);

    char me_u[UUID_STRING_LEN + 1], c_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);
    _uuid_str(c->uuid, c_u);

    json_t *uuids = json_array();
    json_array_append_new(uuids, json_string(me_u));
    json_array_append_new(uuids, json_string(c_u));
    json_t *p = json_object();
    json_object_set_new(p, "peer_uuids", uuids);
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_BATCH_REQ, p);
    json_decref(p);

    ck_assert_int_eq(g_resp_count, 1);
    ck_assert_uint_eq(json_array_size(g_last_body), 1);
    _assert_reputation_shape(json_array_get(g_last_body, 0), c_u);
    _end();
}

DEFINE_TEST(test_batch_reply_collapses_a_repeated_subject)
{
    _begin(3);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *c = _mk_identity("charlie", "10.0.0.3");
    process_t *proc = _mk_process(me);

    char c_u[UUID_STRING_LEN + 1];
    _uuid_str(c->uuid, c_u);

    json_t *uuids = json_array();
    json_array_append_new(uuids, json_string(c_u));
    json_array_append_new(uuids, json_string(c_u));
    json_t *p = json_object();
    json_object_set_new(p, "peer_uuids", uuids);
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_BATCH_REQ, p);
    json_decref(p);

    /* A repeated entry would be read as two observations of one pair. */
    ck_assert_int_eq(g_resp_count, 1);
    ck_assert_uint_eq(json_array_size(g_last_body), 1);
    _end();
}

DEFINE_TEST(test_batch_with_only_our_own_uuid_answers_nothing)
{
    _begin(2);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    process_t *proc = _mk_process(me);

    char me_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);

    json_t *uuids = json_array();
    json_array_append_new(uuids, json_string(me_u));
    json_t *p = json_object();
    json_object_set_new(p, "peer_uuids", uuids);
    json_object_set_new(p, "requesting_process", json_string("monitor"));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_BATCH_REQ, p);
    json_decref(p);

    /* An empty roster would cost a round trip to convey nothing. */
    ck_assert_int_eq(g_resp_count, 0);
    _end();
}

DEFINE_TEST(test_absent_requesting_process_still_addresses_something)
{
    /* A reply addressed to "" would be undeliverable and would look like a lost
     * message rather than a malformed request. */
    _begin(2);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *asker = _mk_identity("alice", "10.0.0.1");
    identity_t *subject = _mk_identity("charlie", "10.0.0.3");
    process_t *proc = _mk_process(me);

    char subject_u[UUID_STRING_LEN + 1];
    _uuid_str(subject->uuid, subject_u);

    json_t *p = json_object();
    json_object_set_new(p, "peer_uuid", json_string(subject_u));
    json_object_set_new(p, "requesting_process", json_string(""));
    _dispatch(proc, asker, REP_PROTO_CONSENSUS_REP_REQ, p);
    json_decref(p);

    ck_assert_int_eq(g_resp_count, 1);
    ck_assert_str_eq(g_last_process, "reputation");
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepRespShape,
          test_rep_req_reply_is_a_reputation_addressed_to_the_asker,
          test_consensus_req_reply_is_a_reputation_addressed_to_the_asker,
          test_batch_reply_is_a_roster_of_reputations,
          test_batch_reply_skips_the_responder_itself,
          test_batch_reply_collapses_a_repeated_subject,
          test_batch_with_only_our_own_uuid_answers_nothing,
          test_absent_requesting_process_still_addresses_something)
