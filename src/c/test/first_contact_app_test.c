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

/* How an application adds a friend: the two first-contact app verbs, the
 * FIRST_CONTACT_EVENT answers, and the ack gate (identity/first_contact.c,
 * at_first_contact.h). The C twin of Python's test_first_contact_app_verbs.py
 * and of the ack-gate cases in test_first_contact_handshake.py.
 *
 * Handlers are called directly on a minimal identity process; every emission
 * is captured through the messaging test hook, so no socket is opened. The
 * cross-runtime halves (unsolicited ack, wrong nonce) are also pinned in the
 * conformance corpus; the SIGNING-KEY half is pinned only here and in Python,
 * because a corpus fixture cannot mint a second key for a participant's uuid. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "at_first_contact.h"
#include "app_events_registry.h"
#include "config/configuration.h"
#include "contacts/contacts.h"
#include "identity/identity.h"
#include "identity/first_contact.h"
#include "identity/id_proc_priv.h"
#include "processes/processes.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "network/network.h"
#include "network/net_relay.h"
#include "contacts/reach.h"

/* ------------------------------------------------------------------ */
/* Capture                                                             */
/* ------------------------------------------------------------------ */

#define MAX_EVENTS 16
static fc_event_msg_t g_events[MAX_EVENTS];
static size_t g_n_events;
static size_t g_n_hellos;
static size_t g_n_acks;
static char g_last_hello[AT_FC_BLOB_LEN];
static char g_last_ack_nonce[AT_CONTACT_NONCE_MAX + 1];
static fc_contact_msg_t g_book[MAX_EVENTS];
static size_t g_n_book;
static size_t g_n_removed_sent;
static size_t g_n_caps_queries;
static size_t g_n_routes;
static char g_last_route[512];
static char g_removed_to[64];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == FIRST_CONTACT_EVENT) {
        if (g_n_events < MAX_EVENTS)
            g_events[g_n_events++] = *AT_MSG_EXT(msg, fc_event_msg_t);
        return 0;
    }
    if (type == FIRST_CONTACT_CONTACT_EVENT) {
        if (g_n_book < MAX_EVENTS)
            g_book[g_n_book++] = *AT_MSG_EXT(msg, fc_contact_msg_t);
        return 0;
    }
    if (type == PEER_REMOVED) {
        g_n_removed_sent++;
        at_strlcpy(g_removed_to, key, sizeof(g_removed_to));
        return 0;
    }
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const net_msg_t *n = &msg->info.net_msg;
    if (strcmp(n->function, ID_FC_HELLO) == 0) {
        g_n_hellos++;
        size_t len = n->len < sizeof(g_last_hello) - 1 ? n->len
                                                       : sizeof(g_last_hello) - 1;
        memcpy(g_last_hello, n->obj, len);
        g_last_hello[len] = '\0';
    } else if (strcmp(n->function, "peer_caps_query") == 0) {
        g_n_caps_queries++;
    } else if (strcmp(n->function, "relay_route") == 0) {
        g_n_routes++;
        size_t len = n->len < sizeof(g_last_route) - 1 ? n->len
                                                       : sizeof(g_last_route) - 1;
        memcpy(g_last_route, n->obj, len);
        g_last_route[len] = '\0';
    } else if (strcmp(n->function, ID_FC_HELLO_ACK) == 0) {
        g_n_acks++;
        json_t *p = NULL;
        if (net_msg_unpack_json((net_msg_t *)n, &p) == 0 && p != NULL) {
            const char *nonce = json_string_value(json_object_get(p, "nonce"));
            at_strlcpy(g_last_ack_nonce, nonce != NULL ? nonce : "",
                       sizeof(g_last_ack_nonce));
            json_decref(p);
        }
    }
    return 0;
}

static char g_root[] = "/tmp/fc_app_test.XXXXXX";

static void _begin(void)
{
    static bool rooted = false;
    if (!rooted) {
        ck_assert_ptr_nonnull(mkdtemp(g_root));
        rooted = true;
    }
    /* A fresh data dir per test: contacts and spent nonces must not leak. */
    char dir[sizeof(g_root) + 32];
    static int n = 0;
    snprintf(dir, sizeof(dir), "%s/t%d", g_root, n++);
    ck_assert_ret_ok(makedirs(dir, 0755));
    setenv("AUTONOMOUS_TRUST_ROOT", dir, 1);
    setenv(AT_FIRST_CONTACT_ENV, "1", 1);
    at_first_contact_reset();
    g_n_events = g_n_hellos = g_n_acks = g_n_book = g_n_removed_sent = 0;
    g_n_caps_queries = 0;
    g_n_routes = 0;
    g_last_route[0] = '\0';
    g_removed_to[0] = '\0';
    g_last_hello[0] = g_last_ack_nonce[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
}

/* ------------------------------------------------------------------ */
/* Construction                                                        */
/* ------------------------------------------------------------------ */

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;

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

static bool _is_peer(const process_t *proc, const identity_t *who)
{
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (uuid_compare(proc->protocol.peers[i].uuid, who->uuid) == 0)
            return true;
    return false;
}

static char *_mint(const identity_t *by, long expiry, const char *nonce)
{
    char *blob = NULL;
    const char *hint = "10.0.0.1";
    ck_assert_ret_ok(at_create_invitation(by, &hint, 1, expiry, nonce, &blob));
    return blob;
}

/* A local app request: no sender, JSON payload. */
static void _app(process_t *proc, const char *verb, json_t *body)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)verb;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    if (strcmp(verb, AT_APP_FC_INVITE) == 0)
        handle_first_contact_app_invite(proc, NULL, &msg);
    else
        handle_first_contact_app_initiate(proc, NULL, &msg);
}

/* An address-book request, local, with a queue directory naming `network`
 * so a PEER_REMOVED fan-out is observable. */
static void _book(process_t *proc, const char *verb, json_t *body)
{
    array_t *dir = NULL;
    ck_assert_ret_ok(array_create(&dir));
    array_append(dir, string_data((char *)"identity", 8));
    array_append(dir, string_data((char *)"network", 7));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)verb;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    bool (*h)(const process_t *, directory_t *, generic_msg_t *) =
        strcmp(verb, AT_APP_FC_SAFETY_NUMBER) == 0 ? handle_first_contact_app_safety_number
      : strcmp(verb, AT_APP_FC_VERIFY) == 0 ? handle_first_contact_app_verify
      : strcmp(verb, AT_APP_FC_LIST) == 0 ? handle_first_contact_app_list
      : strcmp(verb, AT_APP_FC_RENAME) == 0 ? handle_first_contact_app_rename
      : handle_first_contact_app_remove;
    h(proc, dir, &msg);
    array_free(dir);
}

static json_t *_peer_body(const char *ref, const identity_t *who)
{
    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string(ref));
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    json_object_set_new(b, "peer", json_string(u));
    return b;
}

/* Put `who` in the address book, optionally also in peers[]. */
static void _know(process_t *proc, const identity_t *who, double added_at,
                  bool as_peer)
{
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    contacts_t store;
    contacts_init(&store);
    contacts_load(dir, &store);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)who, &pub));
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *pub;
    char name[NAME_LEN + 8];
    snprintf(name, sizeof(name), "%s-pet", who->nickname);
    at_strlcpy(c.petname, name, sizeof(c.petname));
    c.provenance = AT_PROV_TOKEN;
    c.added_at = added_at;
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_ret_ok(contacts_save(&store, dir));
    contacts_free(&store);
    if (as_peer)
        identity_admit_direct_peer(proc, NULL, pub);
    smrt_deref(pub);
}

/* The same request arriving from the wire, signed by `from`. */
static void _wire_app(process_t *proc, const char *verb, json_t *body,
                      const identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)verb;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    if (strcmp(verb, AT_APP_FC_INVITE) == 0)
        handle_first_contact_app_invite(proc, NULL, &msg);
    else if (strcmp(verb, AT_APP_FC_VERIFY) == 0)
        handle_first_contact_app_verify(proc, NULL, &msg);
    else
        handle_first_contact_app_initiate(proc, NULL, &msg);
    smrt_deref(pub);
}

static void _hello(process_t *proc, const identity_t *from, const char *blob)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = ID_FC_HELLO;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    /* As the wire delivers it: a petname never crosses, so an unknown
     * sender's identity arrives without one (net_message.c flat from_*). */
    msg.info.net_msg.from_whom.petname[0] = '\0';
    size_t len = strlen(blob);
    msg.info.net_msg.obj = smrt_create(len + 1);
    memcpy(msg.info.net_msg.obj, blob, len + 1);
    msg.info.net_msg.len = len;
    handle_first_contact_hello(proc, NULL, &msg);
    smrt_deref(pub);
}

static void _ack(process_t *proc, const identity_t *from, const char *nonce)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = ID_FC_HELLO_ACK;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    json_t *body = json_object();
    json_object_set_new(body, "nonce", json_string(nonce));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    handle_first_contact_hello_ack(proc, NULL, &msg);
    smrt_deref(pub);
}

static json_t *_initiate_body(const char *ref, const char *blob)
{
    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string(ref));
    if (blob != NULL)
        json_object_set_new(b, "invitation", json_string(blob));
    return b;
}

static bool _stored(const identity_t *who, contact_t *out)
{
    char dir[CFG_PATH_LEN + 1];
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return false;
    contacts_t store;
    contacts_init(&store);
    contacts_load(dir, &store);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse(who->uuid, u);
    contact_t *c = contacts_get(&store, u);
    bool found = c != NULL;
    if (found && out != NULL) {
        out->verified = c->verified;
        out->provenance = c->provenance;
        at_strlcpy(out->petname, c->petname, sizeof(out->petname));
    }
    contacts_free(&store);
    return found;
}

/* ------------------------------------------------------------------ */
/* APP_INVITE                                                          */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_invite_mints_a_link_signed_by_this_node)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    process_t *proc = _mk_process(alice);
    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string("r1"));
    json_object_set_new(b, "ttl_seconds", json_integer(600));
    _app(proc, AT_APP_FC_INVITE, b);

    ck_assert_int_eq(g_n_events, 1);
    const fc_event_msg_t *ev = &g_events[0];
    ck_assert_int_eq(ev->kind, AT_APP_EVENT_FC_INVITATION);
    ck_assert_str_eq(ev->data.ref, "r1");
    ck_assert(strncmp(ev->data.blob, "at+contact:", 11) == 0);
    ck_assert(ev->data.expiry > (int64_t)time(NULL));

    at_invitation_t inv;
    ck_assert_int_eq(at_invitation_decode(ev->data.blob, &inv), AT_INVITE_OK);
    public_identity_t who;
    memset(&who, 0, sizeof(who));
    ck_assert_int_eq(at_invitation_verify(&inv, &who), AT_INVITE_OK);
    ck_assert(uuid_compare(who.uuid, alice->uuid) == 0);
    /* A real nonce, not the empty one at_create_invitation writes for NULL. */
    const char *nonce = json_string_value(json_object_get(inv.body, "nonce"));
    ck_assert_int_eq(strlen(nonce), 32);
    free(who.operator_key_binding);
    at_invitation_free(&inv);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_invite_from_the_wire_is_refused)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string("r1"));
    _wire_app(proc, AT_APP_FC_INVITE, b, bob);
    ck_assert_int_eq(g_n_events, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_invite_with_an_unusable_payload_says_so)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    process_t *proc = _mk_process(alice);

    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string("r1"));
    json_object_set_new(b, "ttl_seconds", json_string("soon"));
    _app(proc, AT_APP_FC_INVITE, b);
    ck_assert_int_eq(g_n_events, 1);
    ck_assert_int_eq(g_events[0].kind, AT_APP_EVENT_FC_REFUSED);
    ck_assert_int_eq(g_events[0].data.reason, AT_FC_REASON_BAD_REQUEST);
    ck_assert_str_eq(g_events[0].data.ref, "r1");

    /* A ref too long to echo intact is refused with an empty ref. */
    char longref[AT_FC_REF_LEN + 8];
    memset(longref, 'x', sizeof(longref) - 1);
    longref[sizeof(longref) - 1] = '\0';
    b = json_object();
    json_object_set_new(b, "ref", json_string(longref));
    _app(proc, AT_APP_FC_INVITE, b);
    ck_assert_int_eq(g_n_events, 2);
    ck_assert_int_eq(g_events[1].data.reason, AT_FC_REASON_BAD_REQUEST);
    ck_assert_str_eq(g_events[1].data.ref, "");
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* APP_INITIATE                                                        */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_initiate_sends_the_hello_and_records_the_contact)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);
    char *blob = _mint(alice, (long)time(NULL) + 600, "n1");
    _app(proc, AT_APP_FC_INITIATE, _initiate_body("r2", blob));

    ck_assert_int_eq(g_n_hellos, 1);
    ck_assert_int_eq(g_n_events, 1);
    ck_assert_int_eq(g_events[0].kind, AT_APP_EVENT_FC_HELLO_SENT);
    ck_assert_str_eq(g_events[0].data.ref, "r2");
    ck_assert(memcmp(g_events[0].data.peer_uuid, alice->uuid, 16) == 0);
    contact_t c;
    memset(&c, 0, sizeof(c));
    ck_assert(_stored(alice, &c));
    ck_assert(!c.verified);
    free(blob);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_initiate_in_person_is_verified_at_once)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);
    char *blob = _mint(alice, (long)time(NULL) + 600, "n1");
    json_t *b = _initiate_body("", blob);
    json_object_set_new(b, "in_person", json_true());
    json_object_set_new(b, "petname", json_string("Al"));
    _app(proc, AT_APP_FC_INITIATE, b);
    contact_t c;
    memset(&c, 0, sizeof(c));
    ck_assert(_stored(alice, &c));
    ck_assert(c.verified);
    ck_assert_int_eq(c.provenance, AT_PROV_IN_PERSON);
    ck_assert_str_eq(c.petname, "Al");
    free(blob);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_initiate_from_the_wire_is_refused)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.66");
    process_t *proc = _mk_process(bob);
    char *blob = _mint(alice, 0, "n1");
    _wire_app(proc, AT_APP_FC_INITIATE, _initiate_body("", blob), mallory);
    ck_assert_int_eq(g_n_hellos, 0);
    ck_assert_int_eq(g_n_events, 0);
    free(blob);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_initiate_names_what_was_wrong)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);

    char *good = _mint(alice, 0, "n1");
    /* Flip one signature hex digit: re-encode {"body","sig"} with a bad sig. */
    at_invitation_t inv;
    ck_assert_int_eq(at_invitation_decode(good, &inv), AT_INVITE_OK);
    char sig[160];
    at_strlcpy(sig, inv.sig_hex, sizeof(sig));
    sig[0] = sig[0] == '0' ? '1' : '0';
    json_t *env = json_object();
    json_object_set_new(env, "body", json_string(inv.body_str));
    json_object_set_new(env, "sig", json_string(sig));
    at_invitation_free(&inv);
    char *env_s = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    char tampered[4096];
    sodium_bin2base64(tampered, sizeof(tampered), (unsigned char *)env_s,
                      strlen(env_s), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    free(env_s);
    char *expired = _mint(alice, 100, "n2");
    char *own = _mint(bob, 0, "n3");

    struct { const char *blob; int reason; } cases[] = {
        { NULL, AT_FC_REASON_BAD_REQUEST },
        { "at+contact:not-base64!!", AT_FC_REASON_MALFORMED },
        { tampered, AT_FC_REASON_BAD_SIGNATURE },
        { expired, AT_FC_REASON_EXPIRED },
        { own, AT_FC_REASON_BAD_REQUEST },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        g_n_events = 0;
        _app(proc, AT_APP_FC_INITIATE, _initiate_body("r3", cases[i].blob));
        ck_assert_int_eq(g_n_events, 1);
        ck_assert_int_eq(g_events[0].kind, AT_APP_EVENT_FC_REFUSED);
        ck_assert_int_eq(g_events[0].data.reason, cases[i].reason);
        ck_assert_str_eq(g_events[0].data.ref, "r3");
    }
    ck_assert_int_eq(g_n_hellos, 0);
    free(good);
    free(expired);
    free(own);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The ack gate                                                        */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_an_unsolicited_ack_admits_nobody)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);
    _ack(proc, alice, "x");
    ck_assert(!_is_peer(proc, alice));
    ck_assert(!_stored(alice, NULL));
    ck_assert_int_eq(g_n_events, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_ack_must_match_the_pending_hello)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.66");
    /* Alice's uuid, somebody else's keys: the envelope would verify against
     * the identity it carries, so only the key comparison stops this. */
    identity_t *forged = NULL;
    uuid_t au;
    uuid_copy(au, alice->uuid);
    ck_assert_ret_ok(identity_create(&au, "10.0.0.66", "alice", "alice", &forged));
    process_t *proc = _mk_process(bob);
    char *blob = _mint(alice, 0, "x");
    ck_assert_int_eq(at_first_contact_initiate_ref(proc, NULL, blob, NULL,
                                                   "r4", NULL), 0);

    _ack(proc, mallory, "x");
    ck_assert(!_is_peer(proc, mallory));
    _ack(proc, forged, "x");
    ck_assert(!_is_peer(proc, alice));
    _ack(proc, alice, "y");
    ck_assert(!_is_peer(proc, alice));
    ck_assert_int_eq(g_n_events, 0);

    /* None of those burned the entry: the real ack still lands, once. */
    _ack(proc, alice, "x");
    ck_assert(_is_peer(proc, alice));
    ck_assert_int_eq(g_n_events, 1);
    ck_assert_int_eq(g_events[0].kind, AT_APP_EVENT_FC_ESTABLISHED);
    ck_assert_int_eq(g_events[0].data.role, AT_FC_ROLE_INITIATOR);
    ck_assert_str_eq(g_events[0].data.ref, "r4");
    _ack(proc, alice, "x");
    ck_assert_int_eq(g_n_events, 1);
    free(blob);
    identity_free(forged);
    _end();
}
END_TEST_DEFINITION()


DEFINE_TEST(test_the_ack_records_every_relay_the_link_named)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);
    const char *hints[] = {"relay://203.0.113.7:27790", "10.0.0.1",
                           "relay://198.51.100.2:27790"};
    char *blob = NULL;
    ck_assert_ret_ok(at_create_invitation(alice, hints, 3, 0, "rx", &blob));
    ck_assert_int_eq(at_first_contact_initiate_ref(proc, NULL, blob, NULL,
                                                   "r", NULL), 0);
    /* One route, every relay the link names, in its order. */
    ck_assert_uint_eq(g_n_routes, 1);
    json_t *r = json_loads(g_last_route, 0, NULL);
    json_t *list = json_object_get(r, "relays");
    ck_assert_uint_eq(json_array_size(list), 2);
    ck_assert_str_eq(json_string_value(json_array_get(list, 0)), "203.0.113.7:27790");
    ck_assert_str_eq(json_string_value(json_array_get(list, 1)), "198.51.100.2:27790");
    json_decref(r);
    _ack(proc, alice, "rx");
    ck_assert(_is_peer(proc, alice));
    /* ...and the contact keeps them, relays first, for the next restart. */
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    contacts_t store;
    contacts_init(&store);
    ck_assert_ret_ok(contacts_load(dir, &store));
    char u[UUID_STRING_LEN + 1];
    uuid_unparse(alice->uuid, u);
    contact_t *c = contacts_get(&store, u);
    ck_assert_ptr_nonnull(c);
    ck_assert(c->rendezvous_count >= 2);
    ck_assert_str_eq(c->rendezvous[0], "relay://203.0.113.7:27790");
    ck_assert_str_eq(c->rendezvous[1], "relay://198.51.100.2:27790");
    contacts_free(&store);
    free(blob);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The whole flow, as two apps see it                                  */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_two_apps_add_each_other)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *ap = _mk_process(alice);
    process_t *bp = _mk_process(bob);

    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string("alice-link"));
    _app(ap, AT_APP_FC_INVITE, b);
    ck_assert_int_eq(g_n_events, 1);
    char link[AT_FC_BLOB_LEN];
    at_strlcpy(link, g_events[0].data.blob, sizeof(link));

    _app(bp, AT_APP_FC_INITIATE, _initiate_body("bob-add", link));
    ck_assert_int_eq(g_n_hellos, 1);
    ck_assert_int_eq(g_events[1].kind, AT_APP_EVENT_FC_HELLO_SENT);

    _hello(ap, bob, g_last_hello);
    ck_assert_int_eq(g_n_acks, 1);
    ck_assert_int_eq(g_events[2].kind, AT_APP_EVENT_FC_ESTABLISHED);
    ck_assert_int_eq(g_events[2].data.role, AT_FC_ROLE_INVITER);
    /* Alice recorded Bob from the envelope, which carries no petname; the
     * record still gets a name to show (derived, as Python's Contact does). */
    {
        contact_t rec;
        memset(&rec, 0, sizeof(rec));
        ck_assert(_stored(bob, &rec));
        ck_assert(rec.petname[0] != '\0');
    }
    ck_assert_str_eq(g_events[2].data.ref, "alice-link");
    ck_assert(memcmp(g_events[2].data.peer_uuid, bob->uuid, 16) == 0);

    _ack(bp, alice, g_last_ack_nonce);
    ck_assert(_is_peer(bp, alice));
    ck_assert_int_eq(g_n_events, 4);
    ck_assert_int_eq(g_events[3].kind, AT_APP_EVENT_FC_ESTABLISHED);
    ck_assert_int_eq(g_events[3].data.role, AT_FC_ROLE_INITIATOR);
    ck_assert_str_eq(g_events[3].data.ref, "bob-add");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_inviter_hears_about_its_own_expired_or_spent_link)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(alice);

    char *expired = _mint(alice, 100, "e1");
    _hello(proc, bob, expired);
    ck_assert_int_eq(g_n_events, 1);
    ck_assert_int_eq(g_events[0].kind, AT_APP_EVENT_FC_REFUSED);
    ck_assert_int_eq(g_events[0].data.reason, AT_FC_REASON_EXPIRED);
    ck_assert_int_eq(g_events[0].data.role, AT_FC_ROLE_INVITER);

    char *fresh = _mint(alice, 0, "f1");
    _hello(proc, bob, fresh);                  /* established */
    _hello(proc, bob, fresh);                  /* replay */
    ck_assert_int_eq(g_n_events, 3);
    ck_assert_int_eq(g_events[2].data.reason, AT_FC_REASON_SPENT);

    /* Not ours, or not an invitation: not the app's business. */
    char *foreign = _mint(carol, 0, "c1");
    _hello(proc, bob, foreign);
    _hello(proc, bob, "at+contact:garbage");
    ck_assert_int_eq(g_n_events, 3);
    free(expired);
    free(fresh);
    free(foreign);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The flat ABI half                                                   */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_the_event_decodes_through_the_registry)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_EVENT;
    fc_event_msg_t *m = AT_MSG_EXT(&msg, fc_event_msg_t);
    m->kind = AT_APP_EVENT_FC_ESTABLISHED;
    at_strlcpy(m->data.ref, "r9", sizeof(m->data.ref));
    m->data.role = AT_FC_ROLE_INVITER;

    const at_msg_vtable_t *vt = at_msg_type_lookup(FIRST_CONTACT_EVENT);
    ck_assert_ptr_nonnull(vt);
    ck_assert(vt->app_bound);
    ck_assert_int_eq(at_msg_type_by_name("FIRST_CONTACT_EVENT"),
                     FIRST_CONTACT_EVENT);

    at_app_event_decoder_t dec = at_app_event_decoder_lookup(FIRST_CONTACT_EVENT);
    ck_assert_ptr_nonnull(dec);
    at_app_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ck_assert_ret_ok(dec(&msg, &ev));
    ck_assert_int_eq(ev.kind, AT_APP_EVENT_FC_ESTABLISHED);
    const at_app_first_contact_t *fc = at_first_contact_event(&ev);
    ck_assert_ptr_nonnull(fc);
    ck_assert_str_eq(fc->ref, "r9");
    ck_assert_int_eq(fc->role, AT_FC_ROLE_INVITER);

    /* The accessor is kind-checked: never one payload read as another. */
    ev.kind = AT_APP_EVENT_PEER_RTT;
    ck_assert_ptr_null(at_first_contact_event(&ev));
    ck_assert_ptr_null(at_first_contact_event(NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_senders_refuse_before_they_send)
{
    at_app_events_t *h = at_app_events_open_existing();
    ck_assert_ptr_nonnull(h);
    char longref[AT_FC_REF_LEN + 8];
    memset(longref, 'x', sizeof(longref) - 1);
    longref[sizeof(longref) - 1] = '\0';

    ck_assert_int_eq(at_app_first_contact_invite(NULL, "q", "r", -1, NULL, 0), -1);
    ck_assert_int_eq(at_app_first_contact_invite(h, "q", longref, -1, NULL, 0), -1);
    ck_assert_int_eq(at_app_first_contact_invite(h, "q", "r", -1, NULL, 2), -1);
    ck_assert_int_eq(at_app_first_contact_initiate(h, "q", "r", NULL, NULL,
                                                   false, NULL), -1);
    /* Well-formed, but nobody has bound the queue: retry, not an error. */
    ck_assert_int_eq(at_app_first_contact_invite(h, "fc_app_test_nobody", "r",
                                                 -1, NULL, 0), AT_APP_NOT_READY);
    ck_assert_int_eq(at_app_first_contact_initiate(h, "fc_app_test_nobody", "r",
                                                   "at+contact:x", NULL, false,
                                                   NULL), AT_APP_NOT_READY);
    at_app_events_close(h);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The address book, through the node                                  */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_book_verbs_are_local_only_and_name_a_contact)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    /* Bob is not in the book: every verb that names a peer says so. */
    const char *verbs[] = { AT_APP_FC_SAFETY_NUMBER, AT_APP_FC_VERIFY,
                            AT_APP_FC_RENAME, AT_APP_FC_REMOVE };
    for (size_t i = 0; i < 4; i++) {
        g_n_events = 0;
        json_t *b = _peer_body("r", bob);
        json_object_set_new(b, "confirmed", json_true());
        json_object_set_new(b, "petname", json_string("x"));
        _book(proc, verbs[i], b);
        ck_assert_int_eq(g_n_events, 1);
        ck_assert_int_eq(g_events[0].data.reason, AT_FC_REASON_UNKNOWN_CONTACT);
    }
    /* From the wire: nothing at all, even for a known contact. */
    _know(proc, bob, 100.0, false);
    g_n_events = g_n_book = 0;
    json_t *b = _peer_body("r", bob);
    json_object_set_new(b, "confirmed", json_true());
    _wire_app(proc, AT_APP_FC_VERIFY, b, bob);
    ck_assert_int_eq(g_n_events + g_n_book, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_safety_number_and_both_ways_to_verify)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    _know(proc, bob, 100.0, false);

    _book(proc, AT_APP_FC_SAFETY_NUMBER, _peer_body("s", bob));
    ck_assert_int_eq(g_n_book, 1);
    ck_assert_int_eq(g_book[0].kind, AT_APP_EVENT_FC_SAFETY_NUMBER);
    char number[AT_FC_SAFETY_NUMBER_LEN];
    at_strlcpy(number, g_book[0].data.safety_number, sizeof(number));
    ck_assert_int_eq(strlen(number), AT_FC_SAFETY_NUMBER_LEN - 1);

    /* A wrong digit: refused, still unverified. */
    char wrong[AT_FC_SAFETY_NUMBER_LEN];
    at_strlcpy(wrong, number, sizeof(wrong));
    wrong[0] = wrong[0] == '1' ? '2' : '1';
    json_t *b = _peer_body("v", bob);
    json_object_set_new(b, "presented", json_string(wrong));
    _book(proc, AT_APP_FC_VERIFY, b);
    ck_assert_int_eq(g_events[g_n_events - 1].data.reason, AT_FC_REASON_MISMATCH);
    contact_t c;
    memset(&c, 0, sizeof(c));
    ck_assert(_stored(bob, &c));
    ck_assert(!c.verified);

    /* Neither digits nor a confirmation: a bad request. */
    b = _peer_body("v", bob);
    json_object_set_new(b, "presented", json_string("   "));
    _book(proc, AT_APP_FC_VERIFY, b);
    ck_assert_int_eq(g_events[g_n_events - 1].data.reason, AT_FC_REASON_BAD_REQUEST);

    /* The right digits, typed. */
    b = _peer_body("v", bob);
    json_object_set_new(b, "presented", json_string(number));
    _book(proc, AT_APP_FC_VERIFY, b);
    ck_assert_int_eq(g_book[g_n_book - 1].kind, AT_APP_EVENT_FC_VERIFIED);
    ck_assert_int_eq(g_book[g_n_book - 1].data.method, AT_FC_METHOD_PRESENTED);
    ck_assert(_stored(bob, &c));
    ck_assert(c.verified);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_by_confirmation)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    _know(proc, bob, 100.0, false);
    json_t *b = _peer_body("v", bob);
    json_object_set_new(b, "confirmed", json_true());
    _book(proc, AT_APP_FC_VERIFY, b);
    ck_assert_int_eq(g_n_book, 1);
    ck_assert_int_eq(g_book[0].data.method, AT_FC_METHOD_CONFIRMED);
    ck_assert(g_book[0].data.verified);
    contact_t c;
    memset(&c, 0, sizeof(c));
    ck_assert(_stored(bob, &c));
    ck_assert(c.verified);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_list_answers_even_when_empty_and_in_order)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(alice);
    json_t *b = json_object();
    json_object_set_new(b, "ref", json_string("l"));
    _book(proc, AT_APP_FC_LIST, b);
    ck_assert_int_eq(g_n_book, 1);
    ck_assert_int_eq(g_book[0].kind, AT_APP_EVENT_FC_CONTACTS_DONE);
    ck_assert_int_eq(g_book[0].data.count, 0);

    _know(proc, carol, 200.0, false);
    _know(proc, bob, 100.0, false);
    g_n_book = 0;
    b = json_object();
    json_object_set_new(b, "ref", json_string("l"));
    _book(proc, AT_APP_FC_LIST, b);
    ck_assert_int_eq(g_n_book, 3);
    ck_assert(memcmp(g_book[0].data.peer_uuid, bob->uuid, 16) == 0);
    ck_assert(memcmp(g_book[1].data.peer_uuid, carol->uuid, 16) == 0);
    ck_assert_int_eq(g_book[1].data.provenance, AT_PROV_TOKEN);
    ck_assert_int_eq(g_book[2].kind, AT_APP_EVENT_FC_CONTACTS_DONE);
    ck_assert_int_eq(g_book[2].data.count, 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rename)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    _know(proc, bob, 100.0, false);
    json_t *b = _peer_body("n", bob);
    json_object_set_new(b, "petname", json_string("Bobby"));
    _book(proc, AT_APP_FC_RENAME, b);
    ck_assert_int_eq(g_book[0].kind, AT_APP_EVENT_FC_CONTACT);
    ck_assert_str_eq(g_book[0].data.petname, "Bobby");
    contact_t c;
    memset(&c, 0, sizeof(c));
    ck_assert(_stored(bob, &c));
    ck_assert_str_eq(c.petname, "Bobby");

    b = _peer_body("n", bob);
    json_object_set_new(b, "petname", json_string("   "));
    _book(proc, AT_APP_FC_RENAME, b);
    ck_assert_int_eq(g_events[g_n_events - 1].data.reason, AT_FC_REASON_BAD_REQUEST);
    _end();
}
END_TEST_DEFINITION()

static bool _has_peer(const process_t *proc, const identity_t *who)
{
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (uuid_compare(proc->protocol.peers[i].uuid, who->uuid) == 0)
            return true;
    return false;
}

DEFINE_TEST(test_remove_drops_a_direct_peer_everywhere)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(alice);
    _know(proc, carol, 50.0, true);
    _know(proc, bob, 100.0, true);
    proc->protocol.peer_rtt_ms[1] = 42;           /* bob's slot */

    _book(proc, AT_APP_FC_REMOVE, _peer_body("x", carol));
    ck_assert_int_eq(g_book[0].kind, AT_APP_EVENT_FC_REMOVED);
    ck_assert(g_book[0].data.peer_dropped);
    ck_assert(!_stored(carol, NULL));
    ck_assert(!_has_peer(proc, carol));
    ck_assert(_has_peer(proc, bob));
    /* The parallel RTT slot moved with its peer. */
    ck_assert_int_eq(proc->protocol.num_peers, 1);
    ck_assert_int_eq(proc->protocol.peer_rtt_ms[0], 42);
    /* The siblings are told, and a sibling applying it forgets the peer too. */
    ck_assert_int_eq(g_n_removed_sent, 1);
    ck_assert_str_eq(g_removed_to, "network");
    process_t *net = _mk_process(bob);
    _know(net, carol, 50.0, true);
    generic_msg_t gone = {0};
    gone.type = PEER_REMOVED;
    memcpy(gone.info.peer_removed.peer_uuid, carol->uuid, 16);
    run_message_handlers(net, NULL, PEER_REMOVED, &gone);
    ck_assert(!_has_peer(net, carol));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_remove_keeps_a_cohort_members_peer_entry)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(alice);
    _know(proc, bob, 100.0, true);
    uuid_t g;
    uuid_generate(g);
    group_init(&g, (char *)alice->address, &proc->protocol.group);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(bob->uuid, u);
    group_add_address(&proc->protocol.group, u, bob->address);

    _book(proc, AT_APP_FC_REMOVE, _peer_body("x", bob));
    ck_assert_int_eq(g_book[0].kind, AT_APP_EVENT_FC_REMOVED);
    ck_assert(!g_book[0].data.peer_dropped);
    ck_assert(!_stored(bob, NULL));
    ck_assert(_has_peer(proc, bob));
    ck_assert_int_eq(g_n_removed_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_contact_event_decodes_through_the_registry)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_CONTACT_EVENT;
    fc_contact_msg_t *m = AT_MSG_EXT(&msg, fc_contact_msg_t);
    m->kind = AT_APP_EVENT_FC_VERIFIED;
    m->data.method = AT_FC_METHOD_CONFIRMED;
    ck_assert(at_msg_type_lookup(FIRST_CONTACT_CONTACT_EVENT)->app_bound);
    at_app_event_decoder_t dec =
        at_app_event_decoder_lookup(FIRST_CONTACT_CONTACT_EVENT);
    ck_assert_ptr_nonnull(dec);
    at_app_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ck_assert_ret_ok(dec(&msg, &ev));
    const at_app_contact_t *c = at_first_contact_contact_event(&ev);
    ck_assert_ptr_nonnull(c);
    ck_assert_int_eq(c->method, AT_FC_METHOD_CONFIRMED);
    /* Each accessor reads only its own kinds. */
    ck_assert_ptr_null(at_first_contact_event(&ev));
    ev.kind = AT_APP_EVENT_FC_ESTABLISHED;
    ck_assert_ptr_null(at_first_contact_contact_event(&ev));

    at_app_events_t *h = at_app_events_open_existing();
    uint8_t peer[16] = {1};
    ck_assert_int_eq(at_app_first_contact_verify(h, "q", "r", peer, NULL, false), -1);
    ck_assert_int_eq(at_app_first_contact_verify(h, "q", "r", peer, "1", true), -1);
    ck_assert_int_eq(at_app_first_contact_rename(h, "q", "r", peer, ""), -1);
    ck_assert_int_eq(at_app_first_contact_remove(h, "q", "r", NULL), -1);
    ck_assert_int_eq(at_app_first_contact_list(h, "fc_app_test_nobody", "r"),
                     AT_APP_NOT_READY);
    at_app_events_close(h);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Capabilities, and the §10.3 tier cap                                */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_direct_peer_is_asked_for_its_capabilities_on_admission)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(bob);
    char *blob = _mint(alice, 0, "x");
    ck_assert_int_eq(at_first_contact_initiate_ref(proc, NULL, blob, NULL, "",
                                                   NULL), 0);
    _ack(proc, alice, "x");
    ck_assert(_is_peer(proc, alice));
    ck_assert_int_eq(g_n_caps_queries, 1);
    free(blob);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unverified_contact_is_held_at_communication)
{
    _begin();
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(bob);

    /* No record at all, then an unverified one: capped either way. */
    ck_assert_int_eq(at_first_contact_capped_tier(proc, alice->uuid, 4),
                     AT_FC_UNVERIFIED_TIER_CAP);
    _know(proc, alice, 100.0, false);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, alice->uuid, 4), 1);
    /* Low tiers are left alone. */
    ck_assert_int_eq(at_first_contact_capped_tier(proc, alice->uuid, 0), 0);

    /* Verified through the node: the cap lifts on the next ask. */
    usleep(20 * 1000);          /* a distinct mtime for the store */
    json_t *b = _peer_body("v", alice);
    json_object_set_new(b, "confirmed", json_true());
    _book(proc, AT_APP_FC_VERIFY, b);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, alice->uuid, 4), 4);

    /* A member of our own group is never capped. */
    uuid_t g;
    uuid_generate(g);
    group_init(&g, (char *)bob->address, &proc->protocol.group);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(carol->uuid, u);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, carol->uuid, 3), 1);
    group_add_address(&proc->protocol.group, u, carol->address);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, carol->uuid, 3), 3);

    identity_t *dave = _mk_identity("dave", "10.0.0.4");
    group_t *child = calloc(1, sizeof(group_t));
    uuid_t cg;
    uuid_generate(cg);
    group_init(&cg, (char *)bob->address, child);
    char du[UUID_STRING_LEN + 1], cgs[UUID_STRING_LEN + 1];
    uuid_unparse_lower(dave->uuid, du);
    uuid_unparse_lower(cg, cgs);
    group_add_address(child, du, dave->address);
    ck_assert_ret_ok(map_create(&proc->protocol.child_groups));
    map_set(proc->protocol.child_groups, (map_key_t)cgs,
            object_ptr_data(child, sizeof(group_t)));
    /* A child-group member with no contact record: not capped. */
    ck_assert_int_eq(at_first_contact_capped_tier(proc, dave->uuid, 3), 3);
    /* ...but on record as an UNVERIFIED contact it is: the child's vote does
     * not vouch for what first contact introduced. */
    usleep(20 * 1000);          /* a distinct mtime for the store */
    _know(proc, dave, 101.0, false);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, dave->uuid, 3), 1);
    usleep(20 * 1000);
    json_t *dv = _peer_body("v", dave);
    json_object_set_new(dv, "confirmed", json_true());
    _book(proc, AT_APP_FC_VERIFY, dv);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, dave->uuid, 3), 3);
    /* An own-group member stays exempt even as an unverified contact. */
    usleep(20 * 1000);
    _know(proc, carol, 102.0, false);
    ck_assert_int_eq(at_first_contact_capped_tier(proc, carol->uuid, 3), 3);

    /* Nothing is capped while first contact is off. */
    unsetenv(AT_FIRST_CONTACT_ENV);
    identity_t *erin = _mk_identity("erin", "10.0.0.5");
    ck_assert_int_eq(at_first_contact_capped_tier(proc, erin->uuid, 4), 4);
    _end();
}
END_TEST_DEFINITION()



/* The first rendezvous hint of the last minted link, into @p out. */
static void _minted_first_hint(char *out, size_t out_len)
{
    ck_assert(g_n_events >= 1);
    const fc_event_msg_t *ev = &g_events[g_n_events - 1];
    ck_assert_int_eq(ev->kind, AT_APP_EVENT_FC_INVITATION);
    at_invitation_t inv;
    ck_assert_int_eq(at_invitation_decode(ev->data.blob, &inv), AT_INVITE_OK);
    json_t *rv = json_object_get(inv.body, "rendezvous");
    ck_assert(json_array_size(rv) >= 1);
    at_strlcpy(out, json_string_value(json_array_get(rv, 0)), out_len);
    at_invitation_free(&inv);
}

static void _relay_identity(process_t *proc, const identity_t *from,
                            const char *uuid, const char *fp)
{
    json_t *b = json_object();
    json_object_set_new(b, "relay", json_string("203.0.113.7:27790"));
    json_object_set_new(b, "uuid", json_string(uuid));
    json_object_set_new(b, "fp", json_string(fp));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = NET_FN_RELAY_IDENTITY;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, b));
    json_decref(b);
    if (from != NULL)
        uuid_copy(msg.info.net_msg.from_whom.uuid, from->uuid);
    handle_first_contact_relay_identity(proc, NULL, &msg);
    smrt_deref(msg.info.net_msg.obj);
}

DEFINE_TEST(test_links_pin_our_relay_once_it_proves_itself)
{
    _begin();
    setenv("AT_USE_RELAY", "203.0.113.7:27790", 1);
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.66");
    process_t *proc = _mk_process(alice);
    char hint[256];
    _app(proc, AT_APP_FC_INVITE, json_object());
    _minted_first_hint(hint, sizeof(hint));
    ck_assert_str_eq(hint, "relay://203.0.113.7:27790");

    char cu[UUID_STRING_LEN + 1], fp[AT_RELAY_FP_BYTES * 2 + 1], want[256];
    uuid_unparse_lower(carol->uuid, cu);
    ck_assert_ret_ok(net_relay_key_fingerprint((const char *)carol->signature.public_hex,
                                               fp, sizeof(fp)));
    _relay_identity(proc, NULL, cu, fp);
    _app(proc, AT_APP_FC_INVITE, json_object());
    _minted_first_hint(hint, sizeof(hint));
    snprintf(want, sizeof(want), "relay://%s:%s@203.0.113.7:27790", cu, fp);
    ck_assert_str_eq(hint, want);
    /* Nobody on the wire chooses our pin. */
    _relay_identity(proc, mallory, cu, "00000000000000000000000000000000");
    _app(proc, AT_APP_FC_INVITE, json_object());
    _minted_first_hint(hint, sizeof(hint));
    ck_assert_str_eq(hint, want);
    unsetenv("AT_USE_RELAY");
    _end();
}
END_TEST_DEFINITION()


/* Deliver @p wire as a reach_record, from @p sender (NULL = local, from the
 * network process's relay lookup). */
static void _reach_msg(process_t *proc, const identity_t *sender, json_t *wire)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)"reach_record";
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, wire));
    if (sender != NULL)
        uuid_copy(msg.info.net_msg.from_whom.uuid, sender->uuid);
    handle_first_contact_reach_record(proc, NULL, &msg);
    smrt_deref(msg.info.net_msg.obj);
}

static contact_t *_contact_of(contacts_t *store, const identity_t *who)
{
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    contacts_init(store);
    ck_assert_ret_ok(contacts_load(dir, store));
    char u[UUID_STRING_LEN + 1];
    uuid_unparse(who->uuid, u);
    return contacts_get(store, u);
}

static json_t *_signed(const identity_t *who, int64_t seq, const char *relay)
{
    const char *relays[1] = { relay };
    at_reach_record_t rec;
    ck_assert_int_eq(at_reach_create(who, seq, relays, 1, NULL, 0, 0, &rec),
                     AT_REACH_OK);
    json_t *w = at_reach_to_wire(&rec);
    at_reach_free(&rec);
    return w;
}

DEFINE_TEST(test_a_contacts_newer_record_is_applied_and_others_refused)
{
    _begin();
    identity_t *me = _mk_identity("me", "10.0.0.5");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.66");
    process_t *proc = _mk_process(me);
    _know(proc, alice, 100.0, false);

    json_t *w = _signed(alice, 7, "relay://203.0.113.7:27790");
    _reach_msg(proc, alice, w);
    json_decref(w);
    contacts_t store;
    contact_t *c = _contact_of(&store, alice);
    ck_assert_ptr_nonnull(c);
    ck_assert_int_eq(c->reach_seq, 7);
    ck_assert_str_eq(c->rendezvous[0], "relay://203.0.113.7:27790");
    contacts_free(&store);
    ck_assert_uint_eq(g_n_routes, 1);

    /* Stale, pushed by someone else, and not a contact: all refused. */
    w = _signed(alice, 7, "relay://1.1.1.1:1");
    _reach_msg(proc, NULL, w);
    json_decref(w);
    w = _signed(alice, 9, "relay://1.1.1.1:1");
    _reach_msg(proc, mallory, w);
    json_decref(w);
    w = _signed(mallory, 9, "relay://1.1.1.1:1");
    _reach_msg(proc, NULL, w);
    json_decref(w);
    c = _contact_of(&store, alice);
    ck_assert_int_eq(c->reach_seq, 7);
    for (size_t i = 0; i < c->rendezvous_count; i++)
        ck_assert(strstr(c->rendezvous[i], "1.1.1.1") == NULL);
    contacts_free(&store);
    ck_assert_uint_eq(g_n_routes, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_our_record_seq_rises_only_on_change_and_persists)
{
    _begin();
    setenv("AT_USE_RELAY", "203.0.113.7:27790", 1);
    identity_t *me = _mk_identity("me", "10.0.0.5");
    process_t *proc = _mk_process(me);
    char dir[CFG_PATH_LEN + 1], path[CFG_PATH_LEN + 64];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    snprintf(path, sizeof(path), "%s/reach.cfg.json", dir);

    at_first_contact_refresh_own_record(proc);
    json_t *st = json_load_file(path, 0, NULL);
    ck_assert_ptr_nonnull(st);
    ck_assert_int_eq(json_integer_value(json_object_get(st, "seq")), 1);
    json_decref(st);
    at_first_contact_refresh_own_record(proc);          /* nothing changed */
    st = json_load_file(path, 0, NULL);
    ck_assert_int_eq(json_integer_value(json_object_get(st, "seq")), 1);
    json_decref(st);
    setenv("AT_USE_RELAY", "198.51.100.2:27790", 1);    /* moved relays */
    at_first_contact_refresh_own_record(proc);
    st = json_load_file(path, 0, NULL);
    ck_assert_int_eq(json_integer_value(json_object_get(st, "seq")), 2);
    at_reach_record_t rec;
    ck_assert_int_eq(at_reach_from_wire(json_object_get(st, "record"), &rec),
                     AT_REACH_OK);
    ck_assert_int_eq(at_reach_verify(&rec, (double)time(NULL)), AT_REACH_OK);
    ck_assert_str_eq(json_string_value(json_array_get(at_reach_relays(&rec), 0)),
                     "relay://198.51.100.2:27790");
    at_reach_free(&rec);
    json_decref(st);
    unsetenv("AT_USE_RELAY");
    _end();
}
END_TEST_DEFINITION()

/* A saved contact holding a relay hint, written straight into the store. */
static void _know_via_relay(const identity_t *who, const char *hint)
{
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    contacts_t store;
    contacts_init(&store);
    contacts_load(dir, &store);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)who, &pub));
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *pub;
    at_strlcpy(c.petname, "relayed-pet", sizeof(c.petname));
    c.provenance = AT_PROV_TOKEN;
    c.added_at = 1.0;
    char *hints[1] = {(char *)hint};
    c.rendezvous = hints;
    c.rendezvous_count = 1;
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_ret_ok(contacts_save(&store, dir));
    contacts_free(&store);
    smrt_deref(pub);
}

DEFINE_TEST(test_saved_contacts_are_readmitted_and_routed_at_startup)
{
    _begin();
    setenv("AT_USE_RELAY", "198.51.100.9:27790", 1);
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(bob);
    _know_via_relay(carol, "relay://203.0.113.7:27790");
    ck_assert(!_is_peer(proc, carol));
    ck_assert_int_eq(at_first_contact_restore_contacts(proc), 1);
    ck_assert(_is_peer(proc, carol));
    ck_assert_uint_eq(g_n_routes, 1);
    /* Its own relay first, then ours, where it registered to reach us. */
    json_t *r = json_loads(g_last_route, 0, NULL);
    ck_assert_ptr_nonnull(r);
    json_t *list = json_object_get(r, "relays");
    ck_assert_uint_eq(json_array_size(list), 2);
    ck_assert_str_eq(json_string_value(json_array_get(list, 0)), "203.0.113.7:27790");
    ck_assert_str_eq(json_string_value(json_array_get(list, 1)), "198.51.100.9:27790");
    json_decref(r);
    /* Nothing is restored while first contact is off. */
    unsetenv(AT_FIRST_CONTACT_ENV);
    ck_assert_int_eq(at_first_contact_restore_contacts(proc), 0);
    unsetenv("AT_USE_RELAY");
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(FirstContactApp,
          test_saved_contacts_are_readmitted_and_routed_at_startup,
          test_a_contacts_newer_record_is_applied_and_others_refused,
          test_our_record_seq_rises_only_on_change_and_persists,
          test_links_pin_our_relay_once_it_proves_itself,
          test_the_ack_records_every_relay_the_link_named,
          test_invite_mints_a_link_signed_by_this_node,
          test_invite_from_the_wire_is_refused,
          test_invite_with_an_unusable_payload_says_so,
          test_initiate_sends_the_hello_and_records_the_contact,
          test_initiate_in_person_is_verified_at_once,
          test_initiate_from_the_wire_is_refused,
          test_initiate_names_what_was_wrong,
          test_an_unsolicited_ack_admits_nobody,
          test_an_ack_must_match_the_pending_hello,
          test_two_apps_add_each_other,
          test_the_inviter_hears_about_its_own_expired_or_spent_link,
          test_the_event_decodes_through_the_registry,
          test_the_senders_refuse_before_they_send,
          test_book_verbs_are_local_only_and_name_a_contact,
          test_safety_number_and_both_ways_to_verify,
          test_verify_by_confirmation,
          test_list_answers_even_when_empty_and_in_order,
          test_rename,
          test_remove_drops_a_direct_peer_everywhere,
          test_remove_keeps_a_cohort_members_peer_entry,
          test_the_contact_event_decodes_through_the_registry,
          test_a_direct_peer_is_asked_for_its_capabilities_on_admission,
          test_an_unverified_contact_is_held_at_communication)
