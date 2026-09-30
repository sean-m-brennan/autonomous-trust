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

/* Finding someone by handle and asking to be their contact
 * (identity/directory_contact.c), FIRST_CONTACT_PLAN Phase 3. Mirrors Python
 * tests/a_unit/test_directory_contact.py.
 *
 * Stub identity processes, each under its own root, with the network played
 * by hand: what one node sends (captured by the messaging test hook) is handed
 * to the other node's handler, and registry answers come from a real
 * net_registry. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "at_first_contact.h"
#include "config/configuration.h"
#include "contacts/contacts.h"
#include "contacts/directory.h"
#include "identity/directory_contact.h"
#include "identity/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_registry.h"
#include "network/network.h"
#include "processes/processes.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

#define REGISTRY_EP "127.0.0.1:27790"

/* ------------------------------------------------------------------ */
/* Capture                                                             */
/* ------------------------------------------------------------------ */

#define MAX_CAP 64
typedef struct {
    char fn[64];
    char *obj;
    uuid_t to;
} sent_t;
static sent_t g_sent[MAX_CAP];
static size_t g_n_sent;
static fc_directory_msg_t g_dir[MAX_CAP];
static size_t g_n_dir;
static fc_event_msg_t g_fc[MAX_CAP];
static size_t g_n_fc;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)key; (void)blocking;
    if (type == FIRST_CONTACT_DIRECTORY_EVENT && g_n_dir < MAX_CAP) {
        g_dir[g_n_dir++] = *AT_MSG_EXT(msg, fc_directory_msg_t);
    } else if (type == FIRST_CONTACT_EVENT && g_n_fc < MAX_CAP) {
        g_fc[g_n_fc++] = *AT_MSG_EXT(msg, fc_event_msg_t);
    } else if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
               && g_n_sent < MAX_CAP) {
        const net_msg_t *n = &msg->info.net_msg;
        sent_t *s = &g_sent[g_n_sent++];
        at_strlcpy(s->fn, n->function, sizeof(s->fn));
        s->obj = calloc(1, n->len + 1);
        if (n->obj != NULL)
            memcpy(s->obj, n->obj, n->len);
        memcpy(s->to, n->to_whom.uuid, sizeof(uuid_t));
    }
    return 0;
}

static void _clear(void)
{
    for (size_t i = 0; i < g_n_sent; i++)
        free(g_sent[i].obj);
    g_n_sent = g_n_dir = g_n_fc = 0;
}

/* The last message sent under @p fn (NULL if none). */
static const sent_t *_sent(const char *fn)
{
    for (size_t i = g_n_sent; i-- > 0;)
        if (strcmp(g_sent[i].fn, fn) == 0)
            return &g_sent[i];
    return NULL;
}

static const fc_directory_msg_t *_dir_kind(int32_t kind)
{
    for (size_t i = 0; i < g_n_dir; i++)
        if (g_dir[i].kind == kind)
            return &g_dir[i];
    return NULL;
}

static const fc_event_msg_t *_fc_kind(int32_t kind)
{
    for (size_t i = 0; i < g_n_fc; i++)
        if (g_fc[i].kind == kind)
            return &g_fc[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Nodes                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    identity_t *id;
    process_t *proc;
    char root[128];
    char uuid[UUID_STRING_LEN + 1];
} node_t;

static char g_base[] = "/tmp/dir_contact_test.XXXXXX";
static int g_n_roots;
static unsigned char g_issuer_sk[crypto_sign_SECRETKEYBYTES];
static char g_issuer_hex[65];
static net_registry_t *g_reg;

static void _as(const node_t *n)
{
    setenv("AUTONOMOUS_TRUST_ROOT", n->root, 1);
}

static node_t *_node(const char *name, const char *addr)
{
    node_t *n = calloc(1, sizeof(*n));
    snprintf(n->root, sizeof(n->root), "%s/r%d-%s", g_base, g_n_roots++, name);
    ck_assert_ret_ok(makedirs(n->root, 0755));
    _as(n);
    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &n->id));
    uuid_unparse_lower(u, n->uuid);
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    id_cfg->name = "identity";
    id_cfg->data_struct = n->id;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    n->proc = proc;
    return n;
}

typedef bool (*handler_t)(const process_t *, directory_t *, generic_msg_t *);

/* A local request (no sender): the app's, or the network process's. */
static void _local(node_t *n, handler_t h, const char *verb, json_t *body)
{
    _as(n);
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)verb;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    h(n->proc, NULL, &msg);
    net_msg_free_obj(&msg.info.net_msg);
}

/* @p text arriving from the wire, sent by @p from. */
static void _wire(node_t *n, const node_t *from, handler_t h, const char *verb,
                  const char *text)
{
    _as(n);
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)verb;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(from->id, &pub));
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    msg.info.net_msg.from_whom.petname[0] = '\0';
    size_t len = strlen(text);
    msg.info.net_msg.obj = malloc(len + 1);
    memcpy(msg.info.net_msg.obj, text, len + 1);
    msg.info.net_msg.len = len;
    h(n->proc, NULL, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    smrt_deref(pub);
}

static void _begin(void)
{
    static bool rooted = false;
    if (!rooted) {
        ck_assert_ptr_nonnull(mkdtemp(g_base));
        rooted = true;
        unsigned char seed[32], pk[32];
        memset(seed, 0x44, sizeof(seed));
        crypto_sign_seed_keypair(pk, g_issuer_sk, seed);
        sodium_bin2hex(g_issuer_hex, sizeof(g_issuer_hex), pk, sizeof(pk));
    }
    setenv(AT_FIRST_CONTACT_ENV, "1", 1);
    unsetenv("AT_USE_RELAY");
    at_first_contact_reset();
    at_dir_contact_reset();
    const char *iss[] = {g_issuer_hex};
    net_registry_free(g_reg);
    g_reg = net_registry_new(iss, 1, 10);
    _clear();
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    _clear();
}

/* ------------------------------------------------------------------ */
/* Steps (as test_directory_contact.py's helpers)                      */
/* ------------------------------------------------------------------ */

/* Alice publishes @p handle; the registry files it; its answer comes back.
 * Returns the entry's wire (new reference). */
static json_t *_publish(node_t *alice, net_registry_t *reg, const char *handle,
                        const char *visibility)
{
    at_dir_signed_t att;
    ck_assert_int_eq(at_dir_attest(g_issuer_sk, handle, (const char *)alice->id->signature.public_hex,
                                   (long)time(NULL) + 3600, &att), AT_DIR_OK);
    json_t *body = json_pack("{s:s, s:o, s:s}", "ref", "pub1",
                             "attestation", at_dir_to_wire(&att), "visibility", visibility);
    at_dir_free(&att);
    _clear();
    _local(alice, handle_dir_app_publish, AT_APP_DIR_PUBLISH, body);
    const sent_t *s = _sent(NET_FN_DIR_PUBLISH);
    ck_assert_ptr_nonnull(s);
    json_t *msg = json_loads(s->obj, 0, NULL);
    json_t *entry = json_incref(json_object_get(msg, "entry"));
    json_decref(msg);
    json_t *reply = net_registry_publish(reg, alice->uuid,
                                         (const char *)alice->id->signature.public_hex, entry);
    json_object_set_new(reply, "relay", json_string(REGISTRY_EP));
    _local(alice, handle_dir_status, "dir_status", reply);
    return entry;
}

static void _lookup(node_t *bob, net_registry_t *reg, const char *handle)
{
    _clear();
    _local(bob, handle_dir_app_lookup, AT_APP_DIR_LOOKUP,
           json_pack("{s:s, s:s}", "ref", "look1", "handle", handle));
    const sent_t *s = _sent(NET_FN_DIR_LOOKUP);
    ck_assert_ptr_nonnull(s);
    json_t *asked = json_loads(s->obj, 0, NULL);
    json_t *ans = net_registry_lookup(reg, bob->uuid,
                                      json_string_value(json_object_get(asked, "handle")));
    json_decref(asked);
    _local(bob, handle_dir_result, "dir_result",
           json_pack("{s:O, s:O, s:s, s:b}", "handle", json_object_get(ans, "handle"),
                     "entry", json_object_get(ans, "entry"), "relay", REGISTRY_EP,
                     "limited", 0));
    json_decref(ans);
}

/* Bob asks; returns the request's text (caller frees). */
static char *_request(node_t *alice, node_t *bob)
{
    _clear();
    _local(bob, handle_dir_app_request, AT_APP_FC_REQUEST,
           json_pack("{s:s, s:s}", "ref", "req1", "handle", "alice@example.org"));
    const sent_t *route = _sent("relay_route");
    ck_assert_ptr_nonnull(route);
    json_t *r = json_loads(route->obj, 0, NULL);
    ck_assert_str_eq(json_string_value(json_object_get(r, "uuid")), alice->uuid);
    ck_assert_uint_eq(json_array_size(json_object_get(r, "relays")), 1);
    ck_assert_str_eq(json_string_value(json_array_get(json_object_get(r, "relays"), 0)),
                     REGISTRY_EP);
    json_decref(r);
    const sent_t *s = _sent(ID_FC_REQUEST);
    ck_assert_ptr_nonnull(s);
    ck_assert_ptr_nonnull(_dir_kind(AT_APP_EVENT_DIR_REQUEST_SENT));
    return strdup(s->obj);
}

static bool _contact_is_directory(node_t *me, const node_t *them)
{
    _as(me);
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    contacts_t store;
    contacts_init(&store);
    contacts_load(dir, &store);
    contact_t *c = contacts_get(&store, them->uuid);
    bool ok = c != NULL && !c->verified && c->provenance == AT_PROV_DIRECTORY;
    contacts_free(&store);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_find_ask_accept_and_both_hold_an_unverified_directory_contact)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2");
    json_decref(_publish(alice, g_reg, "alice@example.org", "anyone"));
    const fc_directory_msg_t *pub = _dir_kind(AT_APP_EVENT_DIR_PUBLISHED);
    ck_assert_ptr_nonnull(pub);
    ck_assert_str_eq(pub->data.ref, "pub1");
    ck_assert_str_eq(pub->data.handle, "alice@example.org");
    ck_assert_int_eq(pub->data.seq, 1);

    _lookup(bob, g_reg, "Alice@Example.org");
    const fc_directory_msg_t *found = _dir_kind(AT_APP_EVENT_DIR_FOUND);
    ck_assert_ptr_nonnull(found);
    ck_assert_str_eq(found->data.ref, "look1");
    ck_assert_str_eq(found->data.nickname, "alice");
    ck_assert(uuid_compare(found->data.peer_uuid, alice->id->uuid) == 0);

    char *request = _request(alice, bob);
    _clear();
    _wire(alice, bob, handle_dir_contact_request, ID_FC_REQUEST, request);
    free(request);
    const fc_directory_msg_t *asked = _dir_kind(AT_APP_EVENT_DIR_CONTACT_REQUEST);
    ck_assert_ptr_nonnull(asked);
    ck_assert_str_eq(asked->data.handle, "alice@example.org");
    ck_assert(uuid_compare(asked->data.peer_uuid, bob->id->uuid) == 0);
    ck_assert_uint_eq(g_n_sent, 0);             /* a request waits for the app */
    char req_ref[AT_FC_REF_LEN];
    at_strlcpy(req_ref, asked->data.ref, sizeof(req_ref));

    _clear();
    _local(alice, handle_dir_app_accept, AT_APP_FC_ACCEPT, json_pack("{s:s}", "ref", req_ref));
    ck_assert_ptr_nonnull(_dir_kind(AT_APP_EVENT_DIR_ACCEPTED));
    const sent_t *acc = _sent(ID_FC_ACCEPT);
    ck_assert_ptr_nonnull(acc);
    char *accept = strdup(acc->obj);

    _clear();
    _wire(bob, alice, handle_dir_contact_accept, ID_FC_ACCEPT, accept);
    free(accept);
    ck_assert_ptr_nonnull(_fc_kind(AT_APP_EVENT_FC_HELLO_SENT));
    const sent_t *hs = _sent(ID_FC_HELLO);
    ck_assert_ptr_nonnull(hs);
    char *hello = strdup(hs->obj);

    _clear();
    _wire(alice, bob, handle_first_contact_hello, ID_FC_HELLO, hello);
    free(hello);
    const fc_event_msg_t *est_a = _fc_kind(AT_APP_EVENT_FC_ESTABLISHED);
    ck_assert_ptr_nonnull(est_a);
    ck_assert_str_eq(est_a->data.ref, req_ref);  /* reported under the request's ref */
    const sent_t *as = _sent(ID_FC_HELLO_ACK);
    ck_assert_ptr_nonnull(as);
    char *ack = strdup(as->obj);

    _clear();
    _wire(bob, alice, handle_first_contact_hello_ack, ID_FC_HELLO_ACK, ack);
    free(ack);
    const fc_event_msg_t *est_b = _fc_kind(AT_APP_EVENT_FC_ESTABLISHED);
    ck_assert_ptr_nonnull(est_b);
    ck_assert_str_eq(est_b->data.ref, "req1");

    ck_assert(_contact_is_directory(alice, bob));
    ck_assert(_contact_is_directory(bob, alice));
    _as(alice);
    ck_assert_int_eq(at_first_contact_capped_tier(alice->proc, bob->id->uuid, 3),
                     AT_FC_UNVERIFIED_TIER_CAP);
    _as(bob);
    ck_assert_int_eq(at_first_contact_capped_tier(bob->proc, alice->id->uuid, 3),
                     AT_FC_UNVERIFIED_TIER_CAP);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_decline_sends_nothing_and_the_request_is_gone)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2");
    json_decref(_publish(alice, g_reg, "alice@example.org", "anyone"));
    _lookup(bob, g_reg, "alice@example.org");
    char *request = _request(alice, bob);
    _clear();
    _wire(alice, bob, handle_dir_contact_request, ID_FC_REQUEST, request);
    free(request);
    char ref[AT_FC_REF_LEN];
    at_strlcpy(ref, _dir_kind(AT_APP_EVENT_DIR_CONTACT_REQUEST)->data.ref, sizeof(ref));
    _clear();
    _local(alice, handle_dir_app_decline, AT_APP_FC_DECLINE, json_pack("{s:s}", "ref", ref));
    ck_assert_uint_eq(g_n_sent, 0);
    ck_assert_ptr_nonnull(_dir_kind(AT_APP_EVENT_DIR_DECLINED));
    _clear();
    _local(alice, handle_dir_app_accept, AT_APP_FC_ACCEPT, json_pack("{s:s}", "ref", ref));
    ck_assert_str_eq(_dir_kind(AT_APP_EVENT_DIR_REFUSED)->data.reason, "unknown_request");
    ck_assert_uint_eq(g_n_sent, 0);
    _end();
}
END_TEST_DEFINITION()

/* A request from @p by to the holder of @p entry, for @p handle, as text. */
static char *_forged_request(const node_t *by, const json_t *entry_wire, const char *handle)
{
    at_dir_signed_t e, r;
    ck_assert_int_eq(at_dir_from_wire(entry_wire, &e), AT_DIR_OK);
    if (handle != NULL)
        json_object_set_new(e.body, "handle", json_string(handle));
    ck_assert_int_eq(at_dir_request_create(by->id, &e, NULL, 0, NULL, 0, (double)time(NULL),
                                           &r), AT_DIR_OK);
    json_t *w = at_dir_to_wire(&r);
    char *text = json_dumps(w, JSON_COMPACT);
    json_decref(w);
    at_dir_free(&e);
    at_dir_free(&r);
    return text;
}

DEFINE_TEST(test_a_request_for_a_handle_we_do_not_publish_is_ignored)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2");
    json_t *entry = _publish(alice, g_reg, "alice@example.org", "anyone");
    char *req = _forged_request(bob, entry, "someone@else.org");
    _clear();
    _wire(alice, bob, handle_dir_contact_request, ID_FC_REQUEST, req);
    ck_assert_uint_eq(g_n_dir, 0);
    free(req);
    json_decref(entry);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_request_not_signed_by_its_sender_is_ignored)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2"),
           *mallory = _node("mallory", "10.0.0.66");
    json_t *entry = _publish(alice, g_reg, "alice@example.org", "anyone");
    char *req = _forged_request(mallory, entry, NULL);     /* signed by Mallory... */
    _clear();
    _wire(alice, bob, handle_dir_contact_request, ID_FC_REQUEST, req);   /* ...sent as Bob */
    ck_assert_uint_eq(g_n_dir, 0);
    free(req);
    json_decref(entry);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_request_addressed_to_someone_else_is_ignored)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2"),
           *carol = _node("carol", "10.0.0.3");
    json_t *entry = _publish(alice, g_reg, "alice@example.org", "anyone");
    /* Carol holds the same handle (an issuer attested it twice), so only the
     * request's `to` tells her it was meant for Alice. */
    const char *iss[] = {g_issuer_hex};
    net_registry_t *other = net_registry_new(iss, 1, 10);
    json_decref(_publish(carol, other, "alice@example.org", "anyone"));
    net_registry_free(other);
    char *req = _forged_request(bob, entry, NULL);
    _clear();
    _wire(carol, bob, handle_dir_contact_request, ID_FC_REQUEST, req);
    ck_assert_uint_eq(g_n_dir, 0);
    free(req);
    json_decref(entry);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_accept_nobody_asked_for_is_ignored)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2"),
           *mallory = _node("mallory", "10.0.0.66");
    json_decref(_publish(alice, g_reg, "alice@example.org", "anyone"));
    _lookup(bob, g_reg, "alice@example.org");
    char *request = _request(alice, bob);
    _clear();
    _wire(alice, bob, handle_dir_contact_request, ID_FC_REQUEST, request);
    free(request);
    char ref[AT_FC_REF_LEN];
    at_strlcpy(ref, _dir_kind(AT_APP_EVENT_DIR_CONTACT_REQUEST)->data.ref, sizeof(ref));
    _clear();
    _local(alice, handle_dir_app_accept, AT_APP_FC_ACCEPT, json_pack("{s:s}", "ref", ref));
    char *accept = strdup(_sent(ID_FC_ACCEPT)->obj);
    /* From someone we never asked... */
    _clear();
    _wire(bob, mallory, handle_dir_contact_accept, ID_FC_ACCEPT, accept);
    ck_assert_ptr_null(_sent(ID_FC_HELLO));
    /* ...answering another nonce... */
    json_t *payload = json_loads(accept, 0, NULL);
    json_object_set_new(payload, "nonce", json_string("00000000000000000000000000000000"));
    char *wrong = json_dumps(payload, JSON_COMPACT);
    _clear();
    _wire(bob, alice, handle_dir_contact_accept, ID_FC_ACCEPT, wrong);
    ck_assert_ptr_null(_sent(ID_FC_HELLO));
    free(wrong);
    /* ...or carrying someone else's invitation. */
    char *theirs = NULL;
    ck_assert_ret_ok(at_create_invitation(mallory->id, NULL, 0, (long)time(NULL) + 60,
                                          "ABABABABABABABABABABABABABABABAB", &theirs));
    json_object_set_new(payload, "nonce", json_string(ref));
    json_object_set_new(payload, "invitation", json_string(theirs));
    free(theirs);
    char *swapped = json_dumps(payload, JSON_COMPACT);
    _clear();
    _wire(bob, alice, handle_dir_contact_accept, ID_FC_ACCEPT, swapped);
    ck_assert_ptr_null(_sent(ID_FC_HELLO));
    free(swapped);
    json_decref(payload);
    /* The real one still works. */
    _clear();
    _wire(bob, alice, handle_dir_contact_accept, ID_FC_ACCEPT, accept);
    ck_assert_ptr_nonnull(_sent(ID_FC_HELLO));
    free(accept);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_lookup_checks_the_entry_itself)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2");
    json_t *entry = _publish(alice, g_reg, "alice@example.org", "anyone");
    /* A registry answering another handle than the one asked... */
    _clear();
    _local(bob, handle_dir_app_lookup, AT_APP_DIR_LOOKUP,
           json_pack("{s:s, s:s}", "ref", "x", "handle", "bob@example.org"));
    _local(bob, handle_dir_result, "dir_result",
           json_pack("{s:s, s:O, s:s, s:b}", "handle", "bob@example.org", "entry", entry,
                     "relay", REGISTRY_EP, "limited", 0));
    const fc_directory_msg_t *ev = _dir_kind(AT_APP_EVENT_DIR_NOT_FOUND);
    ck_assert_ptr_nonnull(ev);
    ck_assert_str_eq(ev->data.reason, "invalid");
    /* ...and one whose signature does not hold. */
    json_t *bad = json_deep_copy(entry);
    char *body = strdup(json_string_value(json_object_get(bad, "body")));
    char *seq = strstr(body, "\"seq\":1");
    ck_assert_ptr_nonnull(seq);
    seq[6] = '9';
    json_object_set_new(bad, "body", json_string(body));
    free(body);
    _clear();
    _local(bob, handle_dir_app_lookup, AT_APP_DIR_LOOKUP,
           json_pack("{s:s, s:s}", "ref", "y", "handle", "alice@example.org"));
    _local(bob, handle_dir_result, "dir_result",
           json_pack("{s:s, s:o, s:s, s:b}", "handle", "alice@example.org", "entry", bad,
                     "relay", REGISTRY_EP, "limited", 0));
    ck_assert_str_eq(_dir_kind(AT_APP_EVENT_DIR_NOT_FOUND)->data.reason, "invalid");
    json_decref(entry);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_limited_or_empty_lookup_says_so)
{
    _begin();
    node_t *bob = _node("bob", "10.0.0.2");
    _local(bob, handle_dir_app_lookup, AT_APP_DIR_LOOKUP,
           json_pack("{s:s, s:s}", "ref", "x", "handle", "nobody@example.org"));
    _clear();
    _local(bob, handle_dir_result, "dir_result",
           json_pack("{s:s, s:n, s:s, s:b}", "handle", "nobody@example.org", "entry",
                     "relay", "", "limited", 1));
    ck_assert_uint_eq(g_n_dir, 1);
    ck_assert_int_eq(g_dir[0].kind, AT_APP_EVENT_DIR_NOT_FOUND);
    ck_assert_str_eq(g_dir[0].data.reason, "limited");
    ck_assert_str_eq(g_dir[0].data.ref, "x");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_asking_without_a_lookup_is_refused)
{
    _begin();
    node_t *bob = _node("bob", "10.0.0.2");
    _local(bob, handle_dir_app_request, AT_APP_FC_REQUEST,
           json_pack("{s:s, s:s}", "ref", "r", "handle", "alice@example.org"));
    ck_assert_str_eq(_dir_kind(AT_APP_EVENT_DIR_REFUSED)->data.reason, "unknown_handle");
    ck_assert_uint_eq(g_n_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_republishing_raises_the_seq_and_survives_a_restart)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1");
    json_decref(_publish(alice, g_reg, "alice@example.org", "anyone"));
    json_t *second = _publish(alice, g_reg, "alice@example.org", "published");
    at_dir_signed_t e;
    ck_assert_int_eq(at_dir_from_wire(second, &e), AT_DIR_OK);
    ck_assert_int_eq(at_dir_seq(&e), 2);
    at_dir_free(&e);
    json_decref(second);
    _clear();
    _as(alice);
    ck_assert_int_eq(at_dir_contact_restore_entries(alice->proc), 1);
    json_t *msg = json_loads(_sent(NET_FN_DIR_PUBLISH)->obj, 0, NULL);
    ck_assert_int_eq(at_dir_from_wire(json_object_get(msg, "entry"), &e), AT_DIR_OK);
    ck_assert_int_eq(at_dir_seq(&e), 2);
    at_dir_free(&e);
    json_decref(msg);
    /* Withdrawn, it is not refiled -- and its seq is kept. */
    _local(alice, handle_dir_app_withdraw, AT_APP_DIR_WITHDRAW,
           json_pack("{s:s, s:s}", "ref", "w", "handle", "alice@example.org"));
    _clear();
    _as(alice);
    ck_assert_int_eq(at_dir_contact_restore_entries(alice->proc), 0);
    json_t *third = _publish(alice, g_reg, "alice@example.org", "anyone");
    ck_assert_int_eq(at_dir_from_wire(third, &e), AT_DIR_OK);
    ck_assert_int_eq(at_dir_seq(&e), 3);
    at_dir_free(&e);
    json_decref(third);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_app_verbs_are_local_only)
{
    _begin();
    node_t *alice = _node("alice", "10.0.0.1"), *bob = _node("bob", "10.0.0.2");
    struct { handler_t h; const char *verb; } verbs[] = {
        {handle_dir_app_publish, AT_APP_DIR_PUBLISH},
        {handle_dir_app_withdraw, AT_APP_DIR_WITHDRAW},
        {handle_dir_app_lookup, AT_APP_DIR_LOOKUP},
        {handle_dir_app_request, AT_APP_FC_REQUEST},
        {handle_dir_app_accept, AT_APP_FC_ACCEPT},
        {handle_dir_app_decline, AT_APP_FC_DECLINE},
        {handle_dir_result, "dir_result"},
        {handle_dir_status, "dir_status"},
    };
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
        _wire(alice, bob, verbs[i].h, verbs[i].verb, "{\"ref\":\"x\",\"handle\":\"a@x\"}");
    ck_assert_uint_eq(g_n_sent, 0);
    ck_assert_uint_eq(g_n_dir, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_app_verbs_are_declared_to_the_identity_process)
{
    const char *verbs[] = {AT_APP_DIR_PUBLISH, AT_APP_DIR_WITHDRAW, AT_APP_DIR_LOOKUP,
                           AT_APP_FC_REQUEST, AT_APP_FC_ACCEPT, AT_APP_FC_DECLINE};
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
        const char *target = at_app_verb_target(verbs[i]);
        ck_assert_ptr_nonnull(target);
        ck_assert_str_eq(target, "identity");
    }
}
END_TEST_DEFINITION()

RUN_TESTS(DirectoryContact,
          test_find_ask_accept_and_both_hold_an_unverified_directory_contact,
          test_a_decline_sends_nothing_and_the_request_is_gone,
          test_a_request_for_a_handle_we_do_not_publish_is_ignored,
          test_a_request_not_signed_by_its_sender_is_ignored,
          test_a_request_addressed_to_someone_else_is_ignored,
          test_an_accept_nobody_asked_for_is_ignored,
          test_a_lookup_checks_the_entry_itself,
          test_a_limited_or_empty_lookup_says_so,
          test_asking_without_a_lookup_is_refused,
          test_republishing_raises_the_seq_and_survives_a_restart,
          test_the_app_verbs_are_local_only,
          test_the_app_verbs_are_declared_to_the_identity_process)
