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

/* Phase 4 live pairing, the wire half (identity/sibling_sync.c): a pairing
 * invitation, two devices becoming siblings, and their address books kept
 * the same. Mirrors Python tests/a_unit/test_sibling_sync.py.
 *
 * Stub identity processes, each under its own root, as device_contact_test
 * does. What a node sends is captured by the messaging test hook under the
 * node that was running, and _route hands it to the recipient's handler. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <errno.h>
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
#include "contacts/device.h"
#include "contacts/reach.h"
#include "contacts/siblings.h"
#include "contacts/sync.h"
#include "identity/device_contact.h"
#include "identity/directory_contact.h"
#include "identity/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/sibling_sync.h"
#include "processes/processes.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

#define PUB(id) ((const public_identity_t *)(id))

typedef struct {
    identity_t *id;
    process_t *proc;
    char root[128];
    char uuid[UUID_STRING_LEN + 1];
    const char *name;
} node_t;

/* ------------------------------------------------------------------ */
/* Capture                                                             */
/* ------------------------------------------------------------------ */

#define MAX_CAP 256
typedef struct {
    const node_t *from;
    char fn[64];
    char *obj;
    size_t len;
    uuid_t to;
    bool encrypt;
} sent_t;
typedef struct {
    const node_t *on;
    bool contact;               /* FIRST_CONTACT_CONTACT_EVENT, else EVENT */
    int32_t kind;
    fc_event_msg_t fc;
    fc_contact_msg_t c;
} ev_t;
static sent_t g_sent[MAX_CAP];
static size_t g_n_sent;
static ev_t g_ev[MAX_CAP];
static size_t g_n_ev;
static const node_t *g_cur;
/* EAGAIN this many contacts_sync sends first: a network queue held full, as
 * net.unix.max_dgram_qlen (10 in every fresh namespace) and a Paxos burst make
 * it (device_cohort dev-4050177). */
static size_t g_refuse_sync;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)key; (void)blocking;
    if (type == FIRST_CONTACT_CONTACT_EVENT && g_n_ev < MAX_CAP) {
        ev_t *e = &g_ev[g_n_ev++];
        memset(e, 0, sizeof(*e));
        e->on = g_cur;
        e->contact = true;
        e->c = *AT_MSG_EXT(msg, fc_contact_msg_t);
        e->kind = e->c.kind;
    } else if (type == FIRST_CONTACT_EVENT && g_n_ev < MAX_CAP) {
        ev_t *e = &g_ev[g_n_ev++];
        memset(e, 0, sizeof(*e));
        e->on = g_cur;
        e->fc = *AT_MSG_EXT(msg, fc_event_msg_t);
        e->kind = e->fc.kind;
    } else if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
               && g_n_sent < MAX_CAP) {
        const net_msg_t *n = &msg->info.net_msg;
        if (g_refuse_sync > 0 && strcmp(n->function, "contacts_sync") == 0) {
            g_refuse_sync--;
            return EAGAIN;
        }
        sent_t *s = &g_sent[g_n_sent++];
        s->from = g_cur;
        at_strlcpy(s->fn, n->function, sizeof(s->fn));
        s->obj = calloc(1, n->len + 1);
        if (n->obj != NULL)
            memcpy(s->obj, n->obj, n->len);
        s->len = n->len;
        memcpy(s->to, n->to_whom.uuid, sizeof(uuid_t));
        s->encrypt = n->encrypt;
    }
    return 0;
}

static void _clear(void)
{
    for (size_t i = 0; i < g_n_sent; i++)
        free(g_sent[i].obj);
    g_n_sent = g_n_ev = 0;
}

/* The last event of @p kind @p on emitted, or NULL. */
static const ev_t *_event(const node_t *on, int32_t kind)
{
    for (size_t i = g_n_ev; i-- > 0;)
        if (g_ev[i].on == on && g_ev[i].kind == kind)
            return &g_ev[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Nodes                                                               */
/* ------------------------------------------------------------------ */

static char g_base[] = "/tmp/sibling_sync_test.XXXXXX";
static int g_n_roots;
static unsigned char g_op[crypto_sign_SECRETKEYBYTES];
static unsigned char g_op2[crypto_sign_SECRETKEYBYTES];

static void _as(const node_t *n)
{
    g_cur = n;
    setenv("AUTONOMOUS_TRUST_ROOT", n->root, 1);
}

static node_t *_node(const char *name, const char *addr)
{
    node_t *n = calloc(1, sizeof(*n));
    n->name = name;
    snprintf(n->root, sizeof(n->root), "%s/r%d-%s", g_base, g_n_roots++, name);
    ck_assert_ret_ok(makedirs(n->root, 0755));
    _as(n);
    char cfg[CFG_PATH_LEN + 1];
    ck_assert(get_cfg_dir(cfg, sizeof(cfg)) > 0);
    ck_assert_ret_ok(makedirs(cfg, 0755));
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

/* A local app request: no sender. */
static void _app(node_t *n, handler_t h, const char *verb, json_t *body)
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

/* @p text (len bytes) arriving from the wire, sent by @p from. */
static void _wire(node_t *n, const node_t *from, handler_t h, const char *verb,
                  const char *text, size_t len)
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
    msg.info.net_msg.obj = malloc(len + 1);
    memcpy(msg.info.net_msg.obj, text, len);
    msg.info.net_msg.obj[len] = '\0';
    msg.info.net_msg.len = len;
    h(n->proc, NULL, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    smrt_deref(pub);
}

static handler_t _handler_for(const char *fn)
{
    if (strcmp(fn, ID_FC_HELLO) == 0)
        return handle_first_contact_hello;
    if (strcmp(fn, ID_FC_HELLO_ACK) == 0)
        return handle_first_contact_hello_ack;
    if (strcmp(fn, ID_FC_DEVICE_CERT) == 0)
        return handle_device_cert;
    if (strcmp(fn, ID_FC_DEVICE_ANNOUNCE) == 0)
        return handle_device_announce;
    if (strcmp(fn, "reach_record") == 0)
        return handle_first_contact_reach_record;
    if (strcmp(fn, "contacts_sync") == 0)
        return handle_contacts_sync;
    return NULL;
}

/* A log of what _route carried: "from>to:fn" lines. */
static char g_route_log[16384];

/* Deliver everything the nodes sent to one another until quiet; @p drop
 * (may be NULL) is lost on the way. */
static void _route(node_t **nodes, size_t n_nodes, const char *drop)
{
    g_route_log[0] = '\0';
    size_t next = 0;
    for (int round = 0; round < 50 && next < g_n_sent; round++) {
        size_t end = g_n_sent;
        for (size_t i = next; i < end; i++) {
            sent_t s = g_sent[i];
            handler_t h = _handler_for(s.fn);
            node_t *dest = NULL;
            for (size_t k = 0; k < n_nodes; k++)
                if (uuid_compare(nodes[k]->id->uuid, s.to) == 0)
                    dest = nodes[k];
            if (h == NULL || s.from == NULL)
                continue;
            char line[160];
            snprintf(line, sizeof(line), "%s>%s:%s\n", s.from->name,
                     dest != NULL ? dest->name : "?", s.fn);
            strncat(g_route_log, line, sizeof(g_route_log) - strlen(g_route_log) - 1);
            if (dest == NULL || (drop != NULL && strcmp(drop, s.fn) == 0))
                continue;
            char *obj = strndup(s.obj, s.len);
            _wire(dest, s.from, h, s.fn, obj, s.len);
            free(obj);
        }
        next = end;
    }
}

static bool _routed(const char *line)
{
    return strstr(g_route_log, line) != NULL;
}

static void _begin(void)
{
    static bool rooted = false;
    if (!rooted) {
        ck_assert_ptr_nonnull(mkdtemp(g_base));
        rooted = true;
        unsigned char seed[32], pk[32];
        memset(seed, 0x61, sizeof(seed));
        crypto_sign_seed_keypair(pk, g_op, seed);
        memset(seed, 0x62, sizeof(seed));
        crypto_sign_seed_keypair(pk, g_op2, seed);
    }
    setenv(AT_FIRST_CONTACT_ENV, "1", 1);
    unsetenv("AT_USE_RELAY");
    at_first_contact_reset();
    at_dir_contact_reset();
    _clear();
    g_refuse_sync = 0;
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    _clear();
}

static void _install_cert(const node_t *n, const unsigned char *sk)
{
    _as(n);
    char cfg[CFG_PATH_LEN + 1], path[CFG_PATH_LEN + 64];
    ck_assert(get_cfg_dir(cfg, sizeof(cfg)) > 0);
    snprintf(path, sizeof(path), "%s/%s", cfg, AT_DEVICE_CERT_FILENAME);
    at_dir_signed_t cert;
    ck_assert_int_eq(at_device_cert_create(sk, PUB(n->id), 1000, &cert), AT_DEVICE_OK);
    json_t *wire = at_dir_to_wire(&cert);
    at_dir_free(&cert);
    ck_assert_ret_ok(json_dump_file(wire, path, JSON_COMPACT));
    json_decref(wire);
}

static void _remove_cert(const node_t *n)
{
    _as(n);
    char cfg[CFG_PATH_LEN + 1], path[CFG_PATH_LEN + 64];
    ck_assert(get_cfg_dir(cfg, sizeof(cfg)) > 0);
    snprintf(path, sizeof(path), "%s/%s", cfg, AT_DEVICE_CERT_FILENAME);
    unlink(path);
}

static void _load(const node_t *me, contacts_t *store, char *dir)
{
    _as(me);
    ck_assert(get_data_dir(dir, CFG_PATH_LEN + 1) > 0);
    contacts_init(store);
    (void)contacts_load(dir, store);
}

static void _siblings(const node_t *me, at_siblings_t *sib)
{
    _as(me);
    char dir[CFG_PATH_LEN + 1];
    ck_assert(get_data_dir(dir, sizeof(dir)) > 0);
    at_siblings_load(dir, sib);
}

static size_t _n_siblings(const node_t *me)
{
    at_siblings_t sib;
    _siblings(me, &sib);
    size_t n = sib.count;
    at_siblings_free(&sib);
    return n;
}

static size_t _n_contacts(const node_t *me)
{
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(me, &store, dir);
    size_t n = store.count;
    contacts_free(&store);
    return n;
}

/* @p me holds @p them: verified, and with their operator key when @p sk. */
static void _befriend(const node_t *me, const node_t *them, const unsigned char *sk)
{
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(me, &store, dir);
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(them->id);
    c.identity.operator_key_binding = NULL;
    snprintf(c.petname, sizeof(c.petname), "%.100s-pet", them->name);
    c.added_at = 1000.0;
    contact_mark_verified(&c, 0.3);
    if (sk != NULL) {
        at_dir_signed_t cert;
        ck_assert_int_eq(at_device_cert_create(sk, PUB(them->id), 1000, &cert), AT_DEVICE_OK);
        ck_assert_int_eq(at_adopt_operator(&c, &cert, &store), AT_DEVICE_OK);
        at_dir_free(&cert);
    }
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_ret_ok(contacts_save(&store, dir));
    contacts_free(&store);
}

static bool _is_peer(const node_t *me, const node_t *them)
{
    for (size_t j = 0; j < me->proc->protocol.num_peers; j++)
        if (uuid_compare(me->proc->protocol.peers[j].uuid, them->id->uuid) == 0)
            return true;
    return false;
}

/* The link @p n mints (pair or not); caller frees. */
static char *_link(node_t *n, bool pair)
{
    json_t *body = json_pack("{s:s}", "ref", "p");
    if (pair)
        json_object_set_new(body, "pair", json_true());
    _app(n, handle_first_contact_app_invite, AT_APP_FC_INVITE, body);
    const ev_t *e = _event(n, AT_APP_EVENT_FC_INVITATION);
    ck_assert_ptr_nonnull(e);
    return strdup(e->fc.data.blob);
}

static void _initiate(node_t *n, const char *link)
{
    _app(n, handle_first_contact_app_initiate, AT_APP_FC_INITIATE,
         json_pack("{s:s, s:s}", "ref", "n", "invitation", link));
}

static void _pair(node_t *old, node_t *fresh, node_t *third)
{
    char *link = _link(old, true);
    _initiate(fresh, link);
    free(link);
    node_t *nodes[3] = {old, fresh, third};
    _route(nodes, third != NULL ? 3 : 2, NULL);
}

static node_t *g_phone, *g_laptop, *g_bob;

static void _nodes(void)
{
    g_phone = _node("phone", "10.0.0.1");
    g_laptop = _node("laptop", "10.0.0.3");
    g_bob = _node("bob", "10.0.0.2");
}

/* ------------------------------------------------------------------ */
/* The invitation                                                      */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_pair_link_carries_a_signed_purpose)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    char *link = _link(g_phone, true);
    at_invitation_t inv;
    ck_assert_int_eq(at_invitation_decode(link, &inv), AT_INVITE_OK);
    ck_assert_str_eq(at_invitation_purpose(&inv), AT_INVITATION_PURPOSE_PAIR);
    ck_assert_ptr_nonnull(strstr(inv.body_str, "\"purpose\":\"pair\""));
    public_identity_t who;
    ck_assert_int_eq(at_invitation_verify(&inv, &who), AT_INVITE_OK);
    free(who.operator_key_binding);
    at_invitation_free(&inv);
    free(link);
    link = _link(g_phone, false);
    ck_assert_int_eq(at_invitation_decode(link, &inv), AT_INVITE_OK);
    ck_assert_str_eq(at_invitation_purpose(&inv), "");
    ck_assert_ptr_null(json_object_get(inv.body, "purpose"));
    at_invitation_free(&inv);
    free(link);
    ck_assert(!identity_verb_is_unencrypted("contacts_sync"));
    _end();
}
END_TEST_DEFINITION()

/* Python: create_invitation(Identity('py-old'), rendezvous=['10.0.0.1'],
 * expiry=0, nonce='00112233445566778899AABBCCDDEEFF', purpose='pair'). */
#define PY_PAIR_LINK "at+contact:eyJib2R5Ijoie1wiZXhwaXJ5XCI6MCxcImlkZW50aXR5XCI6e1wiYWRkcmVzc1wiOlwiMTAuMC4wLjFcIixcImVuY3J5cHRvclwiOntcImhleF9zZWVkXCI6XCI3NjdiZTdlNGI4ZGFlZDY3MjZhNzIwMWQyNmRmZTI4ZjBmMzgxZDQ4YjRlMjFhMjU0MzkzOTViMWQ1ZWRiNTc5XCJ9LFwibmlja25hbWVcIjpcInB5LW9sZFwiLFwic2lnbmF0dXJlXCI6e1wiaGV4X3NlZWRcIjpcIjIyY2ZkMTk3OGU2ZjY5NDkwNWFlYzE0YmNhYmQ5ZWY2YjhmNDBkZTA4ZDYyZDg1ZjdhMjZlMTEwN2QzODIzOTFcIn0sXCJ0eXBlbmFtZVwiOlwiaWRlbnRpdHlcIixcInV1aWRcIjpcImNjMjk3N2E5LTE4NjctNDI4NS04OWM1LTM4MTlkNTJlNGZkZVwifSxcIm5vbmNlXCI6XCIwMDExMjIzMzQ0NTU2Njc3ODg5OUFBQkJDQ0RERUVGRlwiLFwicHVycG9zZVwiOlwicGFpclwiLFwicmVuZGV6dm91c1wiOltcIjEwLjAuMC4xXCJdLFwidHlwZW5hbWVcIjpcImF0LWludml0YXRpb25cIixcInZcIjoxfSIsInNpZyI6IjVkMzQwMWZjMzNlNTAzMGQxYjcyYzhlOWNmZDVhNDlhNzkxNjY5ZTlkNmVkNzIwYzM3YjU2YTBjMzdhY2I3MDMyMTE4Y2M3M2U5ZDYwZGVlOGNkZjJlYmJkNjdkMWQxNDMyOTYyZWVkODIwYzcxOWVlN2JmZDllYzVlYjgwYTA0In0"

DEFINE_TEST(test_a_python_pair_link_verifies_here)
{
    at_invitation_t inv;
    ck_assert_int_eq(at_invitation_decode(PY_PAIR_LINK, &inv), AT_INVITE_OK);
    public_identity_t who;
    ck_assert_int_eq(at_invitation_verify(&inv, &who), AT_INVITE_OK);
    ck_assert_str_eq(who.nickname, "py-old");
    free(who.operator_key_binding);
    ck_assert_str_eq(at_invitation_purpose(&inv), AT_INVITATION_PURPOSE_PAIR);
    at_invitation_free(&inv);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_cert_no_pair_link_and_pair_must_be_a_boolean)
{
    _begin();
    _nodes();
    _app(g_phone, handle_first_contact_app_invite, AT_APP_FC_INVITE,
         json_pack("{s:s, s:b}", "ref", "p", "pair", 1));
    const ev_t *e = _event(g_phone, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_NOT_SIBLING);
    ck_assert_ptr_null(_event(g_phone, AT_APP_EVENT_FC_INVITATION));
    _install_cert(g_phone, g_op);
    _clear();
    _app(g_phone, handle_first_contact_app_invite, AT_APP_FC_INVITE,
         json_pack("{s:s, s:s}", "ref", "p", "pair", "yes"));
    e = _event(g_phone, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_BAD_REQUEST);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Pairing                                                             */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_two_devices_under_one_operator_pair)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _pair(g_phone, g_laptop, NULL);
    ck_assert(_routed("phone>laptop:device_cert"));
    ck_assert(_routed("laptop>phone:device_cert"));
    at_siblings_t sib;
    _siblings(g_phone, &sib);
    ck_assert_uint_eq(sib.count, 1);
    ck_assert_str_eq(sib.devices[0].uuid, g_laptop->uuid);
    at_siblings_free(&sib);
    _siblings(g_laptop, &sib);
    ck_assert_uint_eq(sib.count, 1);
    ck_assert_str_eq(sib.devices[0].uuid, g_phone->uuid);
    at_siblings_free(&sib);
    ck_assert_uint_eq(_n_contacts(g_phone), 0);
    ck_assert_uint_eq(_n_contacts(g_laptop), 0);
    ck_assert_ptr_nonnull(_event(g_phone, AT_APP_EVENT_FC_SIBLING_PAIRED));
    const ev_t *e = _event(g_laptop, AT_APP_EVENT_FC_SIBLING_PAIRED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.role, AT_FC_ROLE_INITIATOR);
    ck_assert_str_eq(e->fc.data.ref, "n");
    ck_assert_ptr_null(_event(g_phone, AT_APP_EVENT_FC_ESTABLISHED));
    ck_assert_ptr_null(_event(g_laptop, AT_APP_EVENT_FC_ESTABLISHED));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_new_device_gets_the_book_and_bob_links_it)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _befriend(g_phone, g_bob, NULL);
    _befriend(g_bob, g_phone, g_op);
    _pair(g_phone, g_laptop, g_bob);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_laptop, &store, dir);
    contact_t *got = contacts_get(&store, g_bob->uuid);
    ck_assert_ptr_nonnull(got);
    ck_assert(got->verified);
    ck_assert_int_eq(got->provenance, AT_PROV_SIBLING);
    contacts_free(&store);
    const ev_t *e = _event(g_laptop, AT_APP_EVENT_FC_CONTACT);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->c.data.origin, AT_FC_ORIGIN_SIBLING);
    ck_assert(_routed("laptop>bob:device_announce"));
    _load(g_bob, &store, dir);
    contact_t *alice = contacts_get(&store, g_phone->uuid);
    ck_assert_ptr_nonnull(alice);
    ck_assert_uint_eq(alice->devices_count, 1);
    ck_assert_str_eq(alice->devices[0].uuid, g_laptop->uuid);
    contacts_free(&store);
    ck_assert_ptr_nonnull(_event(g_bob, AT_APP_EVENT_FC_DEVICE_LINKED));
    _end();
}
END_TEST_DEFINITION()

/* THE REGRESSION (device_cohort dev-4050177): the old device's network queue
 * was full when pairing completed, the full book was handed over once, the
 * send returned EAGAIN unread, and the new device paired with an empty book.
 * The book now goes through identity_send_to_network's bounded retry. */
DEFINE_TEST(test_a_full_network_queue_does_not_lose_the_book)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _befriend(g_phone, g_bob, NULL);
    _befriend(g_bob, g_phone, g_op);
    g_refuse_sync = 3;
    _pair(g_phone, g_laptop, g_bob);
    ck_assert_uint_eq(g_refuse_sync, 0);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_laptop, &store, dir);
    contact_t *got = contacts_get(&store, g_bob->uuid);
    ck_assert_ptr_nonnull(got);
    ck_assert(got->verified);
    contacts_free(&store);
    ck_assert_ptr_nonnull(_event(g_bob, AT_APP_EVENT_FC_DEVICE_LINKED));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_another_operators_device_is_refused)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op2);
    _pair(g_phone, g_laptop, NULL);
    ck_assert_uint_eq(_n_siblings(g_phone), 0);
    ck_assert_uint_eq(_n_siblings(g_laptop), 0);
    ck_assert_uint_eq(_n_contacts(g_phone), 0);
    ck_assert_uint_eq(_n_contacts(g_laptop), 0);
    node_t *both[2] = {g_phone, g_laptop};
    for (int i = 0; i < 2; i++) {
        const ev_t *e = _event(both[i], AT_APP_EVENT_FC_REFUSED);
        ck_assert_ptr_nonnull(e);
        ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_NOT_SIBLING);
    }
    ck_assert(!_is_peer(g_phone, g_laptop));
    ck_assert(!_is_peer(g_laptop, g_phone));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_new_device_without_a_cert_sends_no_hello)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    char *link = _link(g_phone, true);
    size_t before = g_n_sent;
    _initiate(g_laptop, link);
    free(link);
    const ev_t *e = _event(g_laptop, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_NOT_SIBLING);
    for (size_t i = before; i < g_n_sent; i++)
        ck_assert(strcmp(g_sent[i].fn, ID_FC_HELLO) != 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_old_device_that_lost_its_cert_does_not_ack)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    char *link = _link(g_phone, true);
    _remove_cert(g_phone);
    _initiate(g_laptop, link);
    free(link);
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, NULL);
    ck_assert(!_routed("phone>laptop:first_contact_hello_ack"));
    const ev_t *e = _event(g_phone, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_NOT_SIBLING);
    ck_assert(!_is_peer(g_phone, g_laptop));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_cert_that_never_comes_times_out)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    char *link = _link(g_phone, true);
    _initiate(g_laptop, link);
    free(link);
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, ID_FC_DEVICE_CERT);
    ck_assert(_is_peer(g_phone, g_laptop));
    _as(g_phone);
    ck_assert_int_eq(at_sibling_expire(g_phone->proc, NULL, 0.0), 0);
    ck_assert_int_eq(at_sibling_expire(g_phone->proc, NULL,
                                       (double)time(NULL) + AT_SIBLING_PAIR_WAIT_SECONDS + 5),
                     2);   /* both pairings live in this one test process */
    const ev_t *e = _event(g_phone, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_NOT_SIBLING);
    ck_assert(!_is_peer(g_phone, g_laptop));
    ck_assert_uint_eq(_n_siblings(g_phone), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_ordinary_link_still_makes_a_contact)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    char *link = _link(g_phone, false);
    _initiate(g_laptop, link);
    free(link);
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, NULL);
    ck_assert_uint_eq(_n_siblings(g_phone), 0);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_phone, &store, dir);
    ck_assert_ptr_nonnull(contacts_get(&store, g_laptop->uuid));
    contacts_free(&store);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Sync                                                                */
/* ------------------------------------------------------------------ */

static void _paired(void)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _befriend(g_phone, g_bob, NULL);
    _pair(g_phone, g_laptop, NULL);
    ck_assert_uint_eq(_n_siblings(g_phone), 1);
    _clear();
}

DEFINE_TEST(test_a_rename_reaches_the_sibling)
{
    _paired();
    _app(g_phone, handle_first_contact_app_rename, AT_APP_FC_RENAME,
         json_pack("{s:s, s:s, s:s}", "ref", "r", "peer", g_bob->uuid,
                   "petname", "Bobby"));
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, NULL);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_laptop, &store, dir);
    ck_assert_str_eq(contacts_get(&store, g_bob->uuid)->petname, "Bobby");
    contacts_free(&store);
    const ev_t *e = _event(g_laptop, AT_APP_EVENT_FC_CONTACT);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->c.data.origin, AT_FC_ORIGIN_SIBLING);
    ck_assert_str_eq(e->c.data.petname, "Bobby");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_removal_reaches_the_sibling_and_drops_the_peer)
{
    _paired();
    ck_assert(_is_peer(g_laptop, g_bob));
    _app(g_phone, handle_first_contact_app_remove, AT_APP_FC_REMOVE,
         json_pack("{s:s, s:s}", "ref", "r", "peer", g_bob->uuid));
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, NULL);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_laptop, &store, dir);
    ck_assert_ptr_null(contacts_get(&store, g_bob->uuid));
    ck_assert(contacts_tombstone(&store, g_bob->uuid) >= 0.0);
    contacts_free(&store);
    ck_assert(!_is_peer(g_laptop, g_bob));
    const ev_t *e = _event(g_laptop, AT_APP_EVENT_FC_REMOVED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->c.data.origin, AT_FC_ORIGIN_SIBLING);
    ck_assert(e->c.data.peer_dropped);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_nothing_changed_nothing_sent_and_only_a_sibling_is_heard)
{
    _paired();
    _as(g_phone);
    ck_assert_int_eq(at_sibling_push_changes(g_phone->proc), 0);
    /* A stranger's book is not taken. */
    node_t *mallory = _node("mallory", "10.0.0.66");
    _befriend(mallory, _node("eve", "10.0.0.7"), NULL);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(mallory, &store, dir);
    json_t *p = at_sync_build(&store, NULL, 0);
    contacts_free(&store);
    char *text = json_dumps(p, JSON_COMPACT);
    json_decref(p);
    size_t before = _n_contacts(g_laptop);
    _wire(g_laptop, mallory, handle_contacts_sync, "contacts_sync", text, strlen(text));
    free(text);
    ck_assert_uint_eq(_n_contacts(g_laptop), before);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_startup_swaps_books_once_each_way)
{
    _paired();
    _as(g_laptop);
    ck_assert_int_eq(at_sibling_restore(g_laptop->proc), 1);
    node_t *nodes[2] = {g_phone, g_laptop};
    _route(nodes, 2, NULL);
    const char *a = strstr(g_route_log, "laptop>phone:contacts_sync");
    const char *b = strstr(g_route_log, "phone>laptop:contacts_sync");
    ck_assert_ptr_nonnull(a);
    ck_assert_ptr_nonnull(b);
    ck_assert(a < b);
    ck_assert_ptr_null(strstr(a + 1, "laptop>phone:contacts_sync"));
    ck_assert_ptr_null(strstr(b + 1, "phone>laptop:contacts_sync"));
    _end();
}
END_TEST_DEFINITION()

static void _push_record(node_t *to, node_t *from, int64_t seq, const char *relay)
{
    _as(from);
    const char *relays[1] = {relay};
    const char *eps[1] = {"10.0.0.33"};
    at_reach_record_t rec;
    ck_assert_int_eq(at_reach_create(from->id, seq, relays, 1, eps, 1,
                                     (long)time(NULL) + 3600, &rec), AT_REACH_OK);
    json_t *wire = at_reach_to_wire(&rec);
    at_reach_free(&rec);
    char *text = json_dumps(wire, JSON_COMPACT);
    json_decref(wire);
    _wire(to, from, handle_first_contact_reach_record, "reach_record", text, strlen(text));
    free(text);
}

DEFINE_TEST(test_a_siblings_reach_record_moves_its_hints)
{
    _paired();
    _push_record(g_phone, g_laptop, 7, "relay://203.0.113.9:27790");
    at_siblings_t sib;
    _siblings(g_phone, &sib);
    at_sibling_reach_t *r = at_siblings_reach(&sib, g_laptop->uuid);
    ck_assert_ptr_nonnull(r);
    ck_assert_int_eq(r->reach_seq, 7);
    ck_assert_str_eq(r->hints[0], "relay://203.0.113.9:27790");
    at_siblings_free(&sib);
    /* An older record is a replay: nothing moves. */
    _push_record(g_phone, g_laptop, 6, "relay://198.51.100.1:27790");
    _siblings(g_phone, &sib);
    r = at_siblings_reach(&sib, g_laptop->uuid);
    ck_assert_int_eq(r->reach_seq, 7);
    for (size_t i = 0; i < r->n_hints; i++)
        ck_assert(strcmp(r->hints[i], "relay://198.51.100.1:27790") != 0);
    at_siblings_free(&sib);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_sibling_is_never_tier_capped)
{
    _paired();
    _as(g_phone);
    ck_assert_int_eq(at_first_contact_capped_tier(g_phone->proc, g_laptop->id->uuid, 3), 3);
    node_t *x = _node("x", "10.0.0.8");
    _as(g_phone);
    ck_assert_int_eq(at_first_contact_capped_tier(g_phone->proc, x->id->uuid, 3),
                     AT_FC_UNVERIFIED_TIER_CAP);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_list_and_unpair)
{
    _paired();
    _app(g_phone, handle_app_sibling_list, AT_APP_SIBLING_LIST, json_pack("{s:s}", "ref", "l"));
    const ev_t *one = _event(g_phone, AT_APP_EVENT_FC_SIBLING);
    const ev_t *done = _event(g_phone, AT_APP_EVENT_FC_SIBLINGS_DONE);
    ck_assert_ptr_nonnull(one);
    ck_assert_ptr_nonnull(done);
    ck_assert(one < done);
    ck_assert_int_eq(uuid_compare(one->c.data.peer_uuid, g_laptop->id->uuid), 0);
    ck_assert_int_eq(done->c.data.count, 1);
    _app(g_phone, handle_app_sibling_remove, AT_APP_SIBLING_REMOVE,
         json_pack("{s:s, s:s}", "ref", "u", "peer", g_laptop->uuid));
    const ev_t *e = _event(g_phone, AT_APP_EVENT_FC_SIBLING_REMOVED);
    ck_assert_ptr_nonnull(e);
    ck_assert(e->c.data.peer_dropped);
    ck_assert_uint_eq(_n_siblings(g_phone), 0);
    ck_assert(!_is_peer(g_phone, g_laptop));
    /* Unpairing is not synced. */
    ck_assert_uint_eq(_n_siblings(g_laptop), 1);
    _app(g_phone, handle_app_sibling_remove, AT_APP_SIBLING_REMOVE,
         json_pack("{s:s, s:s}", "ref", "u", "peer", g_laptop->uuid));
    e = _event(g_phone, AT_APP_EVENT_FC_REFUSED);
    ck_assert_ptr_nonnull(e);
    ck_assert_int_eq(e->fc.data.reason, AT_FC_REASON_UNKNOWN_CONTACT);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_sibling_verbs_are_local_only)
{
    _paired();
    char *text = NULL;
    json_t *body = json_pack("{s:s, s:s}", "ref", "u", "peer", g_laptop->uuid);
    text = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    _wire(g_phone, g_laptop, handle_app_sibling_remove, AT_APP_SIBLING_REMOVE, text,
          strlen(text));
    free(text);
    ck_assert_uint_eq(_n_siblings(g_phone), 1);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(SiblingSync,
          test_a_pair_link_carries_a_signed_purpose,
          test_a_python_pair_link_verifies_here,
          test_no_cert_no_pair_link_and_pair_must_be_a_boolean,
          test_two_devices_under_one_operator_pair,
          test_the_new_device_gets_the_book_and_bob_links_it,
          test_a_full_network_queue_does_not_lose_the_book,
          test_another_operators_device_is_refused,
          test_a_new_device_without_a_cert_sends_no_hello,
          test_an_old_device_that_lost_its_cert_does_not_ack,
          test_a_cert_that_never_comes_times_out,
          test_an_ordinary_link_still_makes_a_contact,
          test_a_rename_reaches_the_sibling,
          test_a_removal_reaches_the_sibling_and_drops_the_peer,
          test_nothing_changed_nothing_sent_and_only_a_sibling_is_heard,
          test_startup_swaps_books_once_each_way,
          test_a_siblings_reach_record_moves_its_hints,
          test_a_sibling_is_never_tier_capped,
          test_list_and_unpair,
          test_sibling_verbs_are_local_only)
