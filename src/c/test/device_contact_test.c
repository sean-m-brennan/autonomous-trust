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
/* Phase 4 slice 1b: the device cert pushed to contacts, and a new device
 * announcing itself (identity/device_contact.c). Mirrors Python
 * tests/a_unit/test_first_contact_device_wire.py.
 *
 * Stub identity processes, each under its own root, as directory_contact_test
 * does: what a node sends is captured by the messaging test hook, and handed
 * to the other node's handler by hand. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "at_first_contact.h"
#include "config/configuration.h"
#include "contacts/contacts.h"
#include "contacts/device.h"
#include "identity/device_contact.h"
#include "identity/directory_contact.h"
#include "identity/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "processes/processes.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/util.h"

#define PUB(id) ((const public_identity_t *)(id))

/* ------------------------------------------------------------------ */
/* Capture                                                             */
/* ------------------------------------------------------------------ */

#define MAX_CAP 64
typedef struct {
    char fn[64];
    char *obj;
    uuid_t to;
    bool encrypt;
} sent_t;
static sent_t g_sent[MAX_CAP];
static size_t g_n_sent;
static fc_contact_msg_t g_ev[MAX_CAP];
static size_t g_n_ev;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)key; (void)blocking;
    if (type == FIRST_CONTACT_CONTACT_EVENT && g_n_ev < MAX_CAP) {
        g_ev[g_n_ev++] = *AT_MSG_EXT(msg, fc_contact_msg_t);
    } else if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
               && g_n_sent < MAX_CAP) {
        const net_msg_t *n = &msg->info.net_msg;
        sent_t *s = &g_sent[g_n_sent++];
        at_strlcpy(s->fn, n->function, sizeof(s->fn));
        s->obj = calloc(1, n->len + 1);
        if (n->obj != NULL)
            memcpy(s->obj, n->obj, n->len);
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

static size_t _count(const char *fn)
{
    size_t n = 0;
    for (size_t i = 0; i < g_n_sent; i++)
        if (strcmp(g_sent[i].fn, fn) == 0)
            n++;
    return n;
}

static const sent_t *_sent(const char *fn)
{
    for (size_t i = g_n_sent; i-- > 0;)
        if (strcmp(g_sent[i].fn, fn) == 0)
            return &g_sent[i];
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

static char g_base[] = "/tmp/device_contact_test.XXXXXX";
static int g_n_roots;
static unsigned char g_operator_sk[crypto_sign_SECRETKEYBYTES];
static unsigned char g_stranger_sk[crypto_sign_SECRETKEYBYTES];

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
    msg.info.net_msg.obj = smrt_create(len + 1);
    memcpy(msg.info.net_msg.obj, text, len + 1);
    msg.info.net_msg.len = len;
    h(n->proc, NULL, &msg);
    smrt_deref(pub);
}

static void _begin(void)
{
    static bool rooted = false;
    if (!rooted) {
        ck_assert_ptr_nonnull(mkdtemp(g_base));
        rooted = true;
        unsigned char seed[32], pk[32];
        memset(seed, 0x33, sizeof(seed));
        crypto_sign_seed_keypair(pk, g_operator_sk, seed);
        memset(seed, 0x66, sizeof(seed));
        crypto_sign_seed_keypair(pk, g_stranger_sk, seed);
    }
    setenv(AT_FIRST_CONTACT_ENV, "1", 1);
    unsetenv("AT_USE_RELAY");
    at_first_contact_reset();
    at_dir_contact_reset();
    _clear();
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    _clear();
}

/* ------------------------------------------------------------------ */
/* Steps (as test_first_contact_device_wire.py's helpers)              */
/* ------------------------------------------------------------------ */

/* @p sk's cert for @p device, as wire text (caller frees). */
static char *_cert_text(const unsigned char *sk, const node_t *device)
{
    at_dir_signed_t cert;
    ck_assert_int_eq(at_device_cert_create(sk, PUB(device->id), 1000, &cert), AT_DEVICE_OK);
    json_t *wire = at_dir_to_wire(&cert);
    at_dir_free(&cert);
    char *text = json_dumps(wire, JSON_COMPACT);
    json_decref(wire);
    return text;
}

/* The operator's cert for @p device, installed in @p on's config dir. */
static void _install_cert(const node_t *on, const node_t *device)
{
    _as(on);
    char cfg[CFG_PATH_LEN + 1], path[CFG_PATH_LEN + 64];
    ck_assert(get_cfg_dir(cfg, sizeof(cfg)) > 0);
    snprintf(path, sizeof(path), "%s/%s", cfg, AT_DEVICE_CERT_FILENAME);
    char *text = _cert_text(g_operator_sk, device);
    FILE *fh = fopen(path, "w");
    ck_assert_ptr_nonnull(fh);
    fputs(text, fh);
    fclose(fh);
    free(text);
}

static void _load(const node_t *me, contacts_t *store, char *dir)
{
    _as(me);
    ck_assert(get_data_dir(dir, CFG_PATH_LEN + 1) > 0);
    contacts_init(store);
    (void)contacts_load(dir, store);
}

/* @p them, filed in @p me's store as a contact (unverified, no operator). */
static void _knows(const node_t *me, const node_t *them)
{
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(me, &store, dir);
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(them->id);
    c.identity.operator_key_binding = NULL;
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_ret_ok(contacts_save(&store, dir));
    contacts_free(&store);
}

/* Bob's record of Alice's first device @p phone: operator learned, and
 * verified unless @p verified is false. */
static void _bob_knows_alice(const node_t *bob, const node_t *phone, bool verified)
{
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(bob, &store, dir);
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(phone->id);
    c.identity.operator_key_binding = NULL;
    if (verified)
        contact_mark_verified(&c, 0.3);
    at_dir_signed_t cert;
    ck_assert_int_eq(at_device_cert_create(g_operator_sk, PUB(phone->id), 1000, &cert),
                     AT_DEVICE_OK);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, &store), AT_DEVICE_OK);
    at_dir_free(&cert);
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_ret_ok(contacts_save(&store, dir));
    contacts_free(&store);
}

static void _make_peer(node_t *me, const node_t *them)
{
    _as(me);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(them->id, &pub));
    (void)identity_admit_direct_peer(me->proc, NULL, pub);
    smrt_deref(pub);
}

static bool _is_peer(const node_t *me, const node_t *them)
{
    for (size_t j = 0; j < me->proc->protocol.num_peers; j++)
        if (uuid_compare(me->proc->protocol.peers[j].uuid, them->id->uuid) == 0)
            return true;
    return false;
}

/* The operator key @p me holds for @p them ("" when none). */
static void _operator_of(const node_t *me, const node_t *them, char *out, size_t len)
{
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(me, &store, dir);
    contact_t *c = contacts_get(&store, them->uuid);
    at_strlcpy(out, c != NULL ? c->operator_key : "", len);
    contacts_free(&store);
}

static char *_announce_text(const unsigned char *sk, const node_t *device)
{
    char *cert = _cert_text(sk, device);
    json_t *body = json_pack("{s:o, s:[]}", "cert", json_loads(cert, 0, NULL), "relays");
    free(cert);
    char *text = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    return text;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_announce_is_plaintext_and_cert_is_not)
{
    ck_assert(identity_verb_is_unencrypted(ID_FC_DEVICE_ANNOUNCE));
    ck_assert(!identity_verb_is_unencrypted(ID_FC_DEVICE_CERT));
}

DEFINE_TEST(test_own_cert_must_name_this_node)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    at_dir_signed_t cert;
    _as(phone);
    ck_assert_int_eq(at_device_own_cert(phone->proc, &cert), -1);
    _install_cert(phone, laptop);
    ck_assert_int_eq(at_device_own_cert(phone->proc, &cert), -1);
    _install_cert(phone, phone);
    ck_assert_int_eq(at_device_own_cert(phone->proc, &cert), 0);
    ck_assert(at_device_cert_names(&cert, PUB(phone->id)));
    at_dir_free(&cert);
    _end();
}

DEFINE_TEST(test_cert_is_pushed_sealed_to_contact_peers)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *bob = _node("bob", "10.0.0.2");
    _install_cert(phone, phone);
    _knows(phone, bob);
    _make_peer(phone, bob);
    _clear();
    _as(phone);
    ck_assert_int_eq(at_device_push_own_cert(phone->proc, NULL), 1);
    const sent_t *s = _sent(ID_FC_DEVICE_CERT);
    ck_assert_ptr_nonnull(s);
    ck_assert(s->encrypt);
    ck_assert_int_eq(uuid_compare(s->to, bob->id->uuid), 0);
    _end();
}

DEFINE_TEST(test_no_cert_nothing_pushed_or_announced)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *bob = _node("bob", "10.0.0.2");
    _knows(phone, bob);
    _make_peer(phone, bob);
    _clear();
    _as(phone);
    ck_assert_int_eq(at_device_push_own_cert(phone->proc, NULL), 0);
    ck_assert_int_eq(at_device_announce(phone->proc), 0);
    ck_assert_uint_eq(_count(ID_FC_DEVICE_CERT) + _count(ID_FC_DEVICE_ANNOUNCE), 0);
    _end();
}

DEFINE_TEST(test_contact_cert_teaches_the_operator_key)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *bob = _node("bob", "10.0.0.2");
    _knows(bob, phone);
    char *cert = _cert_text(g_operator_sk, phone);
    _wire(bob, phone, handle_device_cert, ID_FC_DEVICE_CERT, cert);
    free(cert);
    char key[AT_OPERATOR_KEY_HEX_LEN + 1], want[AT_OPERATOR_KEY_HEX_LEN + 1];
    _operator_of(bob, phone, key, sizeof(key));
    sodium_bin2hex(want, sizeof(want), g_operator_sk + 32, 32);
    ck_assert_str_eq(key, want);
    _end();
}

DEFINE_TEST(test_cert_from_a_stranger_is_ignored)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *bob = _node("bob", "10.0.0.2");
    char *cert = _cert_text(g_operator_sk, phone);
    _wire(bob, phone, handle_device_cert, ID_FC_DEVICE_CERT, cert);
    free(cert);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(bob, &store, dir);
    ck_assert_ptr_null(contacts_get(&store, phone->uuid));
    contacts_free(&store);
    _end();
}

DEFINE_TEST(test_cert_naming_another_node_teaches_nothing)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    node_t *bob = _node("bob", "10.0.0.2");
    _knows(bob, phone);
    char *cert = _cert_text(g_operator_sk, laptop);
    _wire(bob, phone, handle_device_cert, ID_FC_DEVICE_CERT, cert);
    free(cert);
    char key[AT_OPERATOR_KEY_HEX_LEN + 1];
    _operator_of(bob, phone, key, sizeof(key));
    ck_assert_str_eq(key, "");
    _end();
}

DEFINE_TEST(test_announce_goes_to_every_contact_node_in_plaintext)
{
    _begin();
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    node_t *bob = _node("bob", "10.0.0.2");
    node_t *phone = _node("alice-phone", "10.0.0.1");
    _install_cert(laptop, laptop);
    _knows(laptop, bob);
    _knows(laptop, phone);
    _clear();
    _as(laptop);
    ck_assert_int_eq(at_device_announce(laptop->proc), 2);
    ck_assert_uint_eq(_count(ID_FC_DEVICE_ANNOUNCE), 2);
    bool to_bob = false, to_phone = false;
    for (size_t i = 0; i < g_n_sent; i++) {
        if (strcmp(g_sent[i].fn, ID_FC_DEVICE_ANNOUNCE) != 0)
            continue;
        ck_assert(!g_sent[i].encrypt);
        to_bob |= uuid_compare(g_sent[i].to, bob->id->uuid) == 0;
        to_phone |= uuid_compare(g_sent[i].to, phone->id->uuid) == 0;
    }
    ck_assert(to_bob && to_phone);
    json_t *body = json_loads(_sent(ID_FC_DEVICE_ANNOUNCE)->obj, 0, NULL);
    ck_assert_ptr_nonnull(body);
    ck_assert(json_is_string(json_object_get(json_object_get(body, "cert"), "sig")));
    ck_assert(json_is_array(json_object_get(body, "relays")));
    json_decref(body);
    _end();
}

DEFINE_TEST(test_announce_links_admits_and_tells_the_app)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    node_t *bob = _node("bob", "10.0.0.2");
    _bob_knows_alice(bob, phone, true);
    _clear();
    char *text = _announce_text(g_operator_sk, laptop);
    _wire(bob, laptop, handle_device_announce, ID_FC_DEVICE_ANNOUNCE, text);
    free(text);

    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(bob, &store, dir);
    contact_t *c = contacts_get(&store, laptop->uuid);
    ck_assert_ptr_nonnull(c);
    ck_assert_int_eq(uuid_compare(c->identity.uuid, phone->id->uuid), 0);
    ck_assert_uint_eq(c->devices_count, 1);
    contacts_free(&store);

    ck_assert(_is_peer(bob, laptop));
    ck_assert_uint_eq(g_n_ev, 1);
    ck_assert_int_eq(g_ev[0].kind, AT_APP_EVENT_FC_DEVICE_LINKED);
    ck_assert_int_eq(uuid_compare(g_ev[0].data.peer_uuid, phone->id->uuid), 0);
    ck_assert_int_eq(uuid_compare(g_ev[0].data.device_uuid, laptop->id->uuid), 0);
    /* Nothing is sent back to the device by way of an answer. */
    ck_assert_uint_eq(_count(ID_FC_DEVICE_ANNOUNCE) + _count(ID_FC_HELLO_ACK), 0);
    _end();
}

DEFINE_TEST(test_a_second_announce_is_quiet)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    node_t *bob = _node("bob", "10.0.0.2");
    _bob_knows_alice(bob, phone, true);
    char *text = _announce_text(g_operator_sk, laptop);
    _wire(bob, laptop, handle_device_announce, ID_FC_DEVICE_ANNOUNCE, text);
    _clear();
    _wire(bob, laptop, handle_device_announce, ID_FC_DEVICE_ANNOUNCE, text);
    free(text);
    ck_assert_uint_eq(g_n_ev, 0);
    _end();
}

/* unverified contact, a stranger operator, a lifted cert: each refused, and
 * nothing filed, admitted, told or sent. */
static void _refused(int which)
{
    _begin();
    node_t *phone = _node("alice-phone", "10.0.0.1");
    node_t *laptop = _node("alice-laptop", "10.0.0.3");
    node_t *bob = _node("bob", "10.0.0.2");
    node_t *mallory = _node("mallory", "10.0.0.9");
    _bob_knows_alice(bob, phone, which != 0);
    _clear();
    char *text = _announce_text(which == 1 ? g_stranger_sk : g_operator_sk, laptop);
    _wire(bob, which == 2 ? mallory : laptop, handle_device_announce,
          ID_FC_DEVICE_ANNOUNCE, text);
    free(text);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(bob, &store, dir);
    contact_t *c = contacts_get(&store, phone->uuid);
    ck_assert_ptr_nonnull(c);
    ck_assert_uint_eq(c->devices_count, 0);
    contacts_free(&store);
    ck_assert_uint_eq(bob->proc->protocol.num_peers, 0);
    ck_assert_uint_eq(g_n_ev, 0);
    ck_assert_uint_eq(g_n_sent, 0);
    _end();
}

DEFINE_TEST(test_refused_announce_unverified_is_silent) { _refused(0); }
DEFINE_TEST(test_refused_announce_stranger_operator_is_silent) { _refused(1); }
DEFINE_TEST(test_refused_announce_lifted_is_silent) { _refused(2); }

RUN_TESTS(DeviceContact,
          test_announce_is_plaintext_and_cert_is_not,
          test_own_cert_must_name_this_node,
          test_cert_is_pushed_sealed_to_contact_peers,
          test_no_cert_nothing_pushed_or_announced,
          test_contact_cert_teaches_the_operator_key,
          test_cert_from_a_stranger_is_ignored,
          test_cert_naming_another_node_teaches_nothing,
          test_announce_goes_to_every_contact_node_in_plaintext,
          test_announce_links_admits_and_tells_the_app,
          test_a_second_announce_is_quiet,
          test_refused_announce_unverified_is_silent,
          test_refused_announce_stranger_operator_is_silent,
          test_refused_announce_lifted_is_silent)
