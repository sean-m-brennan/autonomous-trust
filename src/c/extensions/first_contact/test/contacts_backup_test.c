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

/* Phase 4 recovery: the encrypted backup (first_contact/backup.c) and its app
 * verbs (first_contact/backup_contact.c). Mirrors Python tests/a_unit/test_backup.py:
 * the format and its refusals, the vector both runtimes pin, a backup Python
 * made opened here, and the lost-phone case end to end on sibling_sync_test's
 * stub identity processes. Argon2id runs at libsodium's minimum except where
 * the defaults themselves are under test. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "first_contact/at_first_contact.h"
#include "config/configuration.h"
#include "first_contact/backup.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "rendezvous/reach.h"
#include "first_contact/siblings.h"
#include "first_contact/sync.h"
#include "first_contact/backup_contact.h"
#include "first_contact/device_contact.h"
#include "first_contact/directory_contact.h"
#include "first_contact/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "first_contact/sibling_sync.h"
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
    fc_backup_msg_t b;
} ev_t;
static sent_t g_sent[MAX_CAP];
static size_t g_n_sent;
static ev_t g_ev[MAX_CAP];
static size_t g_n_ev;
static const node_t *g_cur;

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
    } else if (type == FIRST_CONTACT_BACKUP_EVENT && g_n_ev < MAX_CAP) {
        ev_t *e = &g_ev[g_n_ev++];
        memset(e, 0, sizeof(*e));
        e->on = g_cur;
        e->b = *AT_MSG_EXT(msg, fc_backup_msg_t);
        e->kind = e->b.kind;
    } else if (type == FIRST_CONTACT_EVENT && g_n_ev < MAX_CAP) {
        ev_t *e = &g_ev[g_n_ev++];
        memset(e, 0, sizeof(*e));
        e->on = g_cur;
        e->fc = *AT_MSG_EXT(msg, fc_event_msg_t);
        e->kind = e->fc.kind;
    } else if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
               && g_n_sent < MAX_CAP) {
        const net_msg_t *n = &msg->info.net_msg;
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

static char g_base[] = "/tmp/contacts_backup_test.XXXXXX";
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

#define PASS "correct horse battery staple"
#define FAST_OPS 1ULL
#define FAST_MEM ((size_t)8192)

static node_t *g_phone, *g_laptop, *g_bob, *g_new;

static void _nodes(void)
{
    g_phone = _node("phone", "10.0.0.1");
    g_laptop = _node("laptop", "10.0.0.3");
    g_bob = _node("bob", "10.0.0.2");
    g_new = _node("new-phone", "10.0.0.4");
    at_backup_set_default_params(FAST_OPS, FAST_MEM);
}

static void _path(char *out, size_t len, const char *name)
{
    snprintf(out, len, "%s/%s", g_base, name);
}

/* app_backup_export with @p pass (NULL: generate). */
static const ev_t *_export(node_t *n, const char *path, const char *pass)
{
    json_t *body = json_pack("{s:s, s:s}", "ref", "b", "path", path);
    if (pass != NULL)
        json_object_set_new(body, "passphrase", json_string(pass));
    else
        json_object_set_new(body, "generate", json_true());
    _app(n, handle_app_backup_export, AT_APP_BACKUP_EXPORT, body);
    return &g_ev[g_n_ev - 1];
}

static const ev_t *_import(node_t *n, const char *path, const char *pass)
{
    json_t *body = json_pack("{s:s, s:s}", "ref", "r", "path", path);
    if (pass != NULL)
        json_object_set_new(body, "passphrase", json_string(pass));
    _app(n, handle_app_backup_import, AT_APP_BACKUP_IMPORT, body);
    return &g_ev[g_n_ev - 1];
}

static json_t *_seal_fast(const char *pt, const char *pass)
{
    json_t *blob = NULL;
    ck_assert_int_eq(at_backup_seal_bytes((const uint8_t *)pt, strlen(pt), pass, FAST_OPS,
                                          FAST_MEM, NULL, NULL, &blob), AT_BACKUP_OK);
    return blob;
}

static int _open_reason(const json_t *blob, const char *pass)
{
    uint8_t *pt = NULL;
    size_t n = 0;
    int rc = at_backup_open_bytes(blob, pass, &pt, &n);
    free(pt);
    return rc;
}

/* ------------------------------------------------------------------ */
/* The format                                                          */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_seal_and_open)
{
    json_t *blob = _seal_fast("the book", PASS);
    ck_assert_str_eq(json_string_value(json_object_get(blob, "typename")), "at-backup");
    ck_assert_int_eq(json_integer_value(json_object_get(blob, "v")), 1);
    ck_assert_str_eq(json_string_value(json_object_get(blob, "kdf")), "argon2id13");
    ck_assert_str_eq(json_string_value(json_object_get(blob, "aead")),
                     "xchacha20poly1305-ietf");
    ck_assert_uint_eq(strlen(json_string_value(json_object_get(blob, "salt"))), 32);
    ck_assert_uint_eq(strlen(json_string_value(json_object_get(blob, "nonce"))), 48);
    uint8_t *pt = NULL;
    size_t n = 0;
    ck_assert_int_eq(at_backup_open_bytes(blob, PASS, &pt, &n), AT_BACKUP_OK);
    ck_assert_uint_eq(n, 8);
    ck_assert_mem_eq(pt, "the book", 8);
    free(pt);
    json_t *again = _seal_fast("the book", PASS);
    ck_assert(strcmp(json_string_value(json_object_get(blob, "salt")),
                     json_string_value(json_object_get(again, "salt"))) != 0);
    json_decref(again);
    json_decref(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_default_is_moderate_argon2id)
{
    at_backup_set_default_params(0, 0);
    json_t *blob = NULL;
    ck_assert_int_eq(at_backup_seal_bytes((const uint8_t *)"x", 1, PASS, 0, 0, NULL, NULL,
                                          &blob), AT_BACKUP_OK);
    ck_assert_int_eq(json_integer_value(json_object_get(blob, "ops")), 3);
    ck_assert_int_eq(json_integer_value(json_object_get(blob, "mem")), 256 << 20);
    ck_assert_int_eq(_open_reason(blob, PASS), AT_BACKUP_OK);
    json_decref(blob);
}
END_TEST_DEFINITION()

/* Python test_backup.py pins the same: salt 00..0f, nonce 10..27. */
#define VECTOR_CT_B64 "4l6LixkmgAPxRgX5dYgekx/XCaGKa/K6vivH8Albd3g="

DEFINE_TEST(test_the_vector_python_pins)
{
    uint8_t salt[16], nonce[24];
    for (int i = 0; i < 16; i++)
        salt[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++)
        nonce[i] = (uint8_t)(16 + i);
    json_t *blob = NULL;
    const char *pt = "at backup vector";
    ck_assert_int_eq(at_backup_seal_bytes((const uint8_t *)pt, strlen(pt), PASS, FAST_OPS,
                                          FAST_MEM, salt, nonce, &blob), AT_BACKUP_OK);
    ck_assert_str_eq(json_string_value(json_object_get(blob, "ct")), VECTOR_CT_B64);
    char ad[200];
    ck_assert(at_backup_header_ad(1, 8192, json_string_value(json_object_get(blob, "salt")),
                                  json_string_value(json_object_get(blob, "nonce")), ad,
                                  sizeof(ad)) > 0);
    ck_assert_str_eq(ad, "at-backup-v1|argon2id13|1|8192|000102030405060708090a0b0c0d0e0f|"
                         "xchacha20poly1305-ietf|"
                         "101112131415161718191a1b1c1d1e1f2021222324252627");
    json_decref(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_wrong_passphrase_or_any_change_fails_alike)
{
    json_t *blob = _seal_fast("the book", PASS);
    ck_assert_int_eq(_open_reason(blob, PASS "!"), AT_BACKUP_BAD_PASSPHRASE);
    ck_assert_int_eq(_open_reason(blob, ""), AT_BACKUP_BAD_PASSPHRASE);
    const char *fields[] = {"ops", "mem", "salt", "nonce"};
    for (size_t i = 0; i < 4; i++) {
        json_t *c = json_deep_copy(blob);
        if (i == 0)
            json_object_set_new(c, "ops", json_integer(2));
        else if (i == 1)
            json_object_set_new(c, "mem", json_integer(16384));
        else if (i == 2)
            json_object_set_new(c, "salt", json_string("00000000000000000000000000000000"));
        else
            json_object_set_new(c, "nonce", json_string(
                "000000000000000000000000000000000000000000000000"));
        if (_open_reason(c, PASS) != AT_BACKUP_BAD_PASSPHRASE)
            _ck_fail("changing %s did not fail the open", fields[i]);
        json_decref(c);
    }
    /* One bit of the ciphertext. */
    const char *b64 = json_string_value(json_object_get(blob, "ct"));
    uint8_t ct[64];
    size_t ct_len = 0;
    ck_assert_ret_ok(sodium_base642bin(ct, sizeof(ct), b64, strlen(b64), NULL, &ct_len, NULL,
                                       sodium_base64_VARIANT_ORIGINAL));
    ct[0] ^= 1;
    char again[128];
    sodium_bin2base64(again, sizeof(again), ct, ct_len, sodium_base64_VARIANT_ORIGINAL);
    json_t *c = json_deep_copy(blob);
    json_object_set_new(c, "ct", json_string(again));
    ck_assert_int_eq(_open_reason(c, PASS), AT_BACKUP_BAD_PASSPHRASE);
    json_decref(c);
    json_decref(blob);
}
END_TEST_DEFINITION()

/* Python test_what_an_open_refuses, case by case. */
DEFINE_TEST(test_what_an_open_refuses)
{
    struct {
        const char *key;
        json_t *value;
        int reason;
    } cases[] = {
        {"typename", json_string("at-contacts-sync"), AT_BACKUP_MALFORMED},
        {"v", json_integer(2), AT_BACKUP_UNSUPPORTED},
        {"v", json_true(), AT_BACKUP_UNSUPPORTED},
        {"kdf", json_string("scrypt"), AT_BACKUP_UNSUPPORTED},
        {"aead", json_string("aes256gcm"), AT_BACKUP_UNSUPPORTED},
        {"ops", json_integer(0), AT_BACKUP_UNSUPPORTED},
        {"ops", json_integer(11), AT_BACKUP_UNSUPPORTED},
        {"mem", json_integer(4096), AT_BACKUP_UNSUPPORTED},
        {"mem", json_integer((1LL << 30) + 1), AT_BACKUP_UNSUPPORTED},
        {"ops", json_true(), AT_BACKUP_MALFORMED},
        {"mem", json_real(8192.0), AT_BACKUP_MALFORMED},
        {"salt", json_string("000000000000000000000000000000"), AT_BACKUP_MALFORMED},
        {"salt", json_string("ABABABABABABABABABABABABABABABAB"), AT_BACKUP_MALFORMED},
        {"nonce", json_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
         AT_BACKUP_MALFORMED},
        {"ct", json_string("not base64!"), AT_BACKUP_MALFORMED},
        {"ct", json_string("c2hvcnQ="), AT_BACKUP_MALFORMED},
        {"ct", json_integer(7), AT_BACKUP_MALFORMED},
    };
    json_t *blob = _seal_fast("the book", PASS);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        json_t *c = json_deep_copy(blob);
        json_object_set_new(c, cases[i].key, cases[i].value);
        int got = _open_reason(c, PASS);
        if (got != cases[i].reason)
            _ck_fail("case %zu (%s): got %s want %s", i, cases[i].key,
                     at_backup_reason_str(got), at_backup_reason_str(cases[i].reason));
        json_decref(c);
    }
    json_decref(blob);
    const char *texts[] = {"", "nope", "[]", "{\"typename\": \"at-backup\""};
    for (size_t i = 0; i < 4; i++) {
        uint8_t *pt = NULL;
        size_t n = 0;
        int rc = at_backup_open_text(texts[i], PASS, &pt, &n);
        ck_assert(rc == AT_BACKUP_MALFORMED || rc == AT_BACKUP_UNSUPPORTED);
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_passphrase_floor_counts_characters)
{
    json_t *blob = NULL;
    ck_assert_int_eq(at_backup_seal_bytes((const uint8_t *)"x", 1, "aaaaaaaaaaa", FAST_OPS,
                                          FAST_MEM, NULL, NULL, &blob),
                     AT_BACKUP_WEAK_PASSPHRASE);
    ck_assert_ptr_null(blob);
    /* Twelve characters, 24 bytes of UTF-8; eleven of them is too few. */
    const char *e12 = "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                      "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9";
    blob = _seal_fast("x", e12);
    ck_assert_int_eq(_open_reason(blob, e12), AT_BACKUP_OK);
    json_decref(blob);
    ck_assert_int_eq(at_backup_check_passphrase(e12 + 2), AT_BACKUP_WEAK_PASSPHRASE);
    ck_assert_int_eq(at_backup_check_passphrase(NULL), AT_BACKUP_WEAK_PASSPHRASE);
    ck_assert_int_eq(at_backup_seal_bytes((const uint8_t *)"x", 1, PASS, 11, FAST_MEM, NULL,
                                          NULL, &blob), AT_BACKUP_UNSUPPORTED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_generated_code_and_its_typing)
{
    char code[AT_BACKUP_CODE_LEN + 1], other[AT_BACKUP_CODE_LEN + 1];
    at_backup_generate_passphrase(code);
    at_backup_generate_passphrase(other);
    ck_assert_uint_eq(strlen(code), 29);
    ck_assert(strcmp(code, other) != 0);
    for (size_t i = 0; i < 29; i++) {
        if (i % 5 == 4)
            ck_assert(code[i] == '-');
        else
            ck_assert(strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", code[i]) != NULL);
    }
    json_t *blob = _seal_fast("x", code);
    char typed[32];
    for (int variant = 0; variant < 3; variant++) {
        at_strlcpy(typed, code, sizeof(typed));
        for (size_t i = 0; typed[i] != '\0'; i++) {
            if (variant != 1 && typed[i] >= 'A' && typed[i] <= 'Z')
                typed[i] = (char)(typed[i] - 'A' + 'a');
            if (variant != 0 && typed[i] == '-')
                typed[i] = ' ';
        }
        ck_assert_int_eq(_open_reason(blob, typed), AT_BACKUP_OK);
    }
    json_decref(blob);
    char out[64];
    at_backup_normalize_passphrase("abcd-efgh", out, sizeof(out));
    ck_assert_str_eq(out, "abcd-efgh");
    at_backup_normalize_passphrase("abcd  efgh-ijkl-mnop-qrst-uvwx", out, sizeof(out));
    ck_assert_str_eq(out, "abcd  efgh-ijkl-mnop-qrst-uvwx");
    at_backup_normalize_passphrase("abc1-efgh-ijkl-mnop-qrst-uvwx", out, sizeof(out));
    ck_assert_str_eq(out, "abc1-efgh-ijkl-mnop-qrst-uvwx");
    at_backup_normalize_passphrase("abcd-efgh-ijkl-mnop-qrst-uvwx\n", out, sizeof(out));
    ck_assert_str_eq(out, "abcd-efgh-ijkl-mnop-qrst-uvwx\n");
    blob = _seal_fast("x", PASS);
    ck_assert_int_eq(_open_reason(blob, "CORRECT HORSE BATTERY STAPLE"),
                     AT_BACKUP_BAD_PASSPHRASE);
    json_decref(blob);
}
END_TEST_DEFINITION()

/* Made by Python's contacts/backup.seal (ops 1, mem 8192, PASS): py-carol
 * verified with petname Carol, py-gone removed, created_at 1800000000. */
static const char PY_BACKUP[] =
    "{\"aead\":\"xchacha20poly1305-ietf\",\"ct\":\"g20I03ncVIbI33QSJMP4IVLU"
    "CPi4KLev6/PKcKFTPFH6n4RPVrs6bBRFmgnmfdKeg7tAQmK5zYgfVirZOhtGAqii6rmqrI"
    "L+CA/YZFdiyh7DBHMtEByFM2fAJ6LUUe4O/VANlBrWeHZUz3gt1WyhIDsO9QGSyXXB9IXl"
    "m52r5DVCL6JnCyp00N6I5eD2jpp3qzUOmylblRoS32Ya/jr5CBOM/dtx3J6wJlcNFzp2TW"
    "6Txo3J8hec8qRd0730nmb3YAAUufjoVv/e66Dt6rlPQSxUuDHkqaT40w6L+YD4EEEfXheW"
    "oz1TPdsf4GFccX4TJXRl5VXRdCYqKL8OJETrtjFBV/HZOy3mb2xbUW1mJmGIstG8JOuEP5"
    "PqYvxuiIjevbVo2JCA1bQ4l3uzBbftolQY8QN+mh+y/3sNS7o2tgtKhRG5+mBJSMC6XLU4"
    "ech5wFJbbdkQ+ntkFO7FNQf1RBC/ambeIgl6wAhc+hjsDykIcyZIMJtN/s1BG7E0zLObXe"
    "0Vp5wqOjz1BAxSZI+fWgr5NAe0RlM4BmCY34r2Ijt5pOiOAh9Yf2+PiZTSOvOEyMrbgvj1"
    "RviWoqoO1xBJ7VV5o5Is77GNhuuFdOyTVHNKq08+0oQQZKVFAxseJJBpFLSCerqqP7jyPm"
    "Np5cmpCgQ9ynnJi7SrGEBvoViCtxqXt8nMFK5b0R2sbQ3ltnwBApmYZD6SzknNP2CqLI8J"
    "orGd1Rli1+ngPdooT9OFahA2zoxNMQ2IpT5da7tqojfpi7o0cvY/yPBnu+pXN+TSYrKrXi"
    "4FiOP47vhKqkbv+INXIXE8Xi31QR+xR/bZrqf0iMe4oCAU48939IpXr3aIUkhnYvN8I7dU"
    "i4IHs4B4y0cULRGAvcUx9S1oRfBPvtLV07a6UBfyre6A40Mt3zmHJjaiCrT0nMSzlHs5Dw"
    "ghrIr06KMrhAadSSC8fkSeQkDo9aH67zbZlw==\",\"kdf\":\"argon2id13\",\"mem\""
    ":8192,\"nonce\":\"abbf2f24b4d349891e63b1bc332ad7c75ad89062a751189f\",\""
    "ops\":1,\"salt\":\"151d216aa8e2b6545cc3312c43ca1af6\",\"typename\":\"a"
    "t-backup\",\"v\":1}";
#define PY_CAROL "c2b52234-5053-4f77-a042-df9521888af1"

DEFINE_TEST(test_a_python_backup_opens_and_restores_here)
{
    json_t *contents = NULL;
    ck_assert_int_eq(at_backup_open_contents(PY_BACKUP, PASS, &contents), AT_BACKUP_OK);
    ck_assert_double_eq_tol(json_real_value(json_object_get(contents, "created_at")),
                            1800000000.0, 1e-6);
    contacts_t store;
    contacts_init(&store);
    at_sync_change_t *ch = NULL;
    size_t n = 0, n_paired = 0;
    char (*paired)[UUID_STRING_LEN + 1] = NULL;
    ck_assert_int_eq(at_backup_restore(&store, NULL, contents, NULL, NULL, 1800000100.0,
                                       &ch, &n, &paired, &n_paired), AT_BACKUP_OK);
    ck_assert_uint_eq(n, 2);
    ck_assert_uint_eq(n_paired, 0);
    contact_t *carol = contacts_get_first(&store, PY_CAROL);
    ck_assert_ptr_nonnull(carol);
    ck_assert(carol->verified);
    ck_assert_str_eq(carol->petname, "Carol");
    ck_assert_int_eq(carol->provenance, AT_PROV_BACKUP);
    ck_assert_str_eq(at_provenance_str(carol->provenance), "backup");
    ck_assert_uint_eq(store.tombstones_count, 1);
    free(ch);
    /* Again: nothing changes. */
    ck_assert_int_eq(at_backup_restore(&store, NULL, contents, NULL, NULL, 1800000100.0,
                                       &ch, &n, &paired, &n_paired), AT_BACKUP_OK);
    ck_assert_uint_eq(n, 0);
    free(ch);
    contacts_free(&store);
    json_decref(contents);
    ck_assert_int_eq(at_backup_open_contents(PY_BACKUP, PASS "x", &contents),
                     AT_BACKUP_BAD_PASSPHRASE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_contents_that_are_not_contents_are_malformed)
{
    const char *pts[] = {"\xff", "[]", "{\"typename\":\"at-backup-contents\",\"v\":1}",
                         "{\"typename\":\"x\",\"v\":1,\"contacts\":{}}"};
    for (size_t i = 0; i < 4; i++) {
        json_t *blob = _seal_fast(pts[i], PASS);
        char *text = json_dumps(blob, JSON_COMPACT);
        json_t *contents = NULL;
        ck_assert_int_eq(at_backup_open_contents(text, PASS, &contents), AT_BACKUP_MALFORMED);
        free(text);
        json_decref(blob);
    }
    contacts_t store;
    contacts_init(&store);
    json_t *bad = json_pack("{s:{s:s}}", "contacts", "typename", "x");
    ck_assert_int_eq(at_backup_restore(&store, NULL, bad, NULL, NULL, 0.0, NULL, NULL, NULL,
                                       NULL), AT_BACKUP_MALFORMED);
    json_decref(bad);
    contacts_free(&store);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The app verbs                                                       */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_export_writes_a_private_file)
{
    _begin();
    _nodes();
    _befriend(g_phone, g_bob, NULL);
    char path[256];
    _path(path, sizeof(path), "alice.atbackup");
    const ev_t *e = _export(g_phone, path, PASS);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    ck_assert_str_eq(e->b.data.ref, "b");
    ck_assert_str_eq(e->b.data.path, path);
    ck_assert_str_eq(e->b.data.passphrase, "");
    ck_assert_int_eq(e->b.data.contacts, 1);
    ck_assert_int_eq(e->b.data.siblings, 0);
    struct stat st;
    ck_assert_ret_ok(stat(path, &st));
    ck_assert_int_eq(st.st_mode & 0777, 0600);
    bool big = false;
    FILE *fp = fopen(path, "r");
    char text[65536];
    size_t got = fread(text, 1, sizeof(text) - 1, fp);
    fclose(fp);
    text[got] = '\0';
    (void)big;
    ck_assert(strstr(text, PASS) == NULL);
    json_t *contents = NULL;
    ck_assert_int_eq(at_backup_open_contents(text, PASS, &contents), AT_BACKUP_OK);
    ck_assert_ptr_nonnull(json_object_get(json_object_get(json_object_get(contents,
                                          "contacts"), "contacts"), g_bob->uuid));
    json_decref(contents);
    /* Generated. */
    _path(path, sizeof(path), "generated.atbackup");
    e = _export(g_phone, path, NULL);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    ck_assert_uint_eq(strlen(e->b.data.passphrase), 29);
    char code[32];
    at_strlcpy(code, e->b.data.passphrase, sizeof(code));
    fp = fopen(path, "r");
    got = fread(text, 1, sizeof(text) - 1, fp);
    fclose(fp);
    text[got] = '\0';
    ck_assert_int_eq(at_backup_open_contents(text, code, &contents), AT_BACKUP_OK);
    json_decref(contents);
    /* A null passphrase is no passphrase, as Python's req.get(). */
    _app(g_phone, handle_app_backup_export, AT_APP_BACKUP_EXPORT,
         json_pack("{s:s, s:s, s:b, s:n}", "ref", "n", "path", path, "generate", 1,
                   "passphrase"));
    ck_assert_int_eq(g_ev[g_n_ev - 1].kind, AT_APP_EVENT_BACKUP_WRITTEN);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_what_export_refuses)
{
    _begin();
    _nodes();
    char ok[256], long_path[4200];
    _path(ok, sizeof(ok), "f");
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[4097] = '\0';
    char long_ref[70];
    memset(long_ref, 'r', 64);
    long_ref[64] = '\0';
    struct {
        json_t *body;
        int reason;
        bool ref_echoed;
    } cases[] = {
        {json_pack("{s:s, s:s}", "ref", "x", "passphrase", PASS), AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:s}", "ref", "x", "path", "relative/file", "passphrase", PASS),
         AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:s}", "ref", "x", "path", long_path, "passphrase", PASS),
         AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s}", "ref", "x", "path", ok), AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:s, s:b}", "ref", "x", "path", ok, "passphrase", PASS,
                   "generate", 1), AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:s}", "ref", "x", "path", ok, "generate", "yes"),
         AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:I}", "ref", "x", "path", ok, "passphrase",
                   (json_int_t)12345678901234LL), AT_BACKUP_BAD_REQUEST, true},
        {json_pack("{s:s, s:s, s:s}", "ref", "x", "path", ok, "passphrase", "short"),
         AT_BACKUP_WEAK_PASSPHRASE, true},
        {json_pack("{s:s, s:s, s:s}", "ref", "x", "path", "/nonexistent-dir/f",
                   "passphrase", PASS), AT_BACKUP_IO, true},
        {json_pack("{s:s, s:s, s:s}", "ref", long_ref, "path", ok, "passphrase", PASS),
         AT_BACKUP_BAD_REQUEST, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        _app(g_phone, handle_app_backup_export, AT_APP_BACKUP_EXPORT, cases[i].body);
        const ev_t *e = &g_ev[g_n_ev - 1];
        if (e->kind != AT_APP_EVENT_BACKUP_REFUSED ||
            strcmp(e->b.data.reason, at_backup_reason_str(cases[i].reason)) != 0)
            _ck_fail("case %zu: kind %d reason %s", i, e->kind, e->b.data.reason);
        ck_assert_str_eq(e->b.data.ref, cases[i].ref_echoed ? "x" : "");
        ck_assert(access(ok, F_OK) != 0);
    }
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_new_phone_keeps_contacts_and_verified_edges)
{
    /* The exit criterion, end to end: the phone is lost; the new phone
     * restores the backup, keeps Bob verified, announces itself, and Bob
     * files it under Alice -- with no old device in the room. */
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _befriend(g_phone, g_bob, NULL);
    _befriend(g_bob, g_phone, g_op);
    _pair(g_phone, g_laptop, NULL);
    char path[256];
    _path(path, sizeof(path), "lost.atbackup");
    const ev_t *e = _export(g_phone, path, PASS);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    ck_assert_int_eq(e->b.data.siblings, 1);

    _install_cert(g_new, g_op);
    _clear();
    e = _import(g_new, path, PASS);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_RESTORED);
    ck_assert_str_eq(e->b.data.ref, "r");
    ck_assert_int_eq(e->b.data.added, 1);
    ck_assert_int_eq(e->b.data.updated, 0);
    ck_assert_int_eq(e->b.data.removed, 0);
    ck_assert_int_eq(e->b.data.siblings, 1);
    ck_assert_int_eq(e->b.data.contacts, 1);
    const ev_t *c = _event(g_new, AT_APP_EVENT_FC_CONTACT);
    ck_assert_ptr_nonnull(c);
    ck_assert_int_eq(c->c.data.origin, AT_FC_ORIGIN_BACKUP);
    ck_assert(c->c.data.verified);
    ck_assert_int_eq(c->c.data.provenance, AT_PROV_BACKUP);

    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_new, &store, dir);
    contact_t *bob = contacts_get_first(&store, g_bob->uuid);
    ck_assert_ptr_nonnull(bob);
    ck_assert(bob->verified);
    ck_assert_int_eq(bob->provenance, AT_PROV_BACKUP);
    contacts_free(&store);
    at_siblings_t sib;
    _siblings(g_new, &sib);
    ck_assert_uint_eq(sib.count, 1);
    ck_assert_str_eq(sib.devices[0].uuid, g_laptop->uuid);
    at_siblings_free(&sib);
    ck_assert(_is_peer(g_new, g_bob));

    node_t *nodes[2] = {g_new, g_bob};
    _route(nodes, 2, NULL);
    ck_assert(_routed("new-phone>bob:device_announce"));
    _load(g_bob, &store, dir);
    contact_t *alice = contacts_get_first(&store, g_phone->uuid);
    ck_assert_ptr_nonnull(alice);
    bool linked = false;
    for (size_t d = 0; d < alice->devices_count; d++)
        linked = linked || strcmp(alice->devices[d].uuid, g_new->uuid) == 0;
    ck_assert(linked);
    contacts_free(&store);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_cert_or_another_operator_gets_no_siblings)
{
    _begin();
    _nodes();
    _install_cert(g_phone, g_op);
    _install_cert(g_laptop, g_op);
    _befriend(g_phone, g_bob, NULL);
    _pair(g_phone, g_laptop, NULL);
    char path[256];
    _path(path, sizeof(path), "nocert.atbackup");
    ck_assert_int_eq(_export(g_phone, path, PASS)->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    const ev_t *e = _import(g_new, path, PASS);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_RESTORED);
    ck_assert_int_eq(e->b.data.added, 1);
    ck_assert_int_eq(e->b.data.siblings, 0);
    ck_assert_uint_eq(_n_siblings(g_new), 0);
    char dir[CFG_PATH_LEN + 1];
    contacts_t store;
    _load(g_new, &store, dir);
    ck_assert_ptr_null(contacts_get_first(&store, g_laptop->uuid));
    contacts_free(&store);
    _install_cert(g_new, g_op2);
    e = _import(g_new, path, PASS);
    ck_assert_int_eq(e->kind, AT_APP_EVENT_BACKUP_RESTORED);
    ck_assert_int_eq(e->b.data.siblings, 0);
    ck_assert_uint_eq(_n_siblings(g_new), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_restore_reaches_the_current_sibling)
{
    _begin();
    _nodes();
    _befriend(g_phone, g_bob, NULL);
    char path[256];
    _path(path, sizeof(path), "sib.atbackup");
    ck_assert_int_eq(_export(g_phone, path, PASS)->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    _install_cert(g_new, g_op);
    _install_cert(g_laptop, g_op);
    _pair(g_new, g_laptop, NULL);
    _clear();
    ck_assert_int_eq(_import(g_new, path, PASS)->kind, AT_APP_EVENT_BACKUP_RESTORED);
    node_t *nodes[2] = {g_new, g_laptop};
    _route(nodes, 2, NULL);
    ck_assert(_routed("new-phone>laptop:contacts_sync"));
    ck_assert_uint_eq(_n_contacts(g_laptop), 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_import_refusals_leave_the_book_alone)
{
    _begin();
    _nodes();
    _befriend(g_phone, g_bob, NULL);
    char path[256], junk[256], missing[256];
    _path(path, sizeof(path), "refuse.atbackup");
    _path(junk, sizeof(junk), "junk");
    _path(missing, sizeof(missing), "missing");
    ck_assert_int_eq(_export(g_phone, path, PASS)->kind, AT_APP_EVENT_BACKUP_WRITTEN);
    FILE *fp = fopen(junk, "w");
    fputs("{\"typename\": \"at-backup\", \"v\": 9}", fp);
    fclose(fp);
    struct {
        const char *path, *pass;
        int reason;
    } cases[] = {
        {path, "not the passphrase", AT_BACKUP_BAD_PASSPHRASE},
        {path, NULL, AT_BACKUP_BAD_REQUEST},
        {"b", PASS, AT_BACKUP_BAD_REQUEST},
        {missing, PASS, AT_BACKUP_IO},
        {junk, PASS, AT_BACKUP_UNSUPPORTED},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const ev_t *e = _import(g_new, cases[i].path, cases[i].pass);
        if (e->kind != AT_APP_EVENT_BACKUP_REFUSED ||
            strcmp(e->b.data.reason, at_backup_reason_str(cases[i].reason)) != 0)
            _ck_fail("case %zu: kind %d reason %s", i, e->kind, e->b.data.reason);
        ck_assert_str_eq(e->b.data.ref, "r");
    }
    ck_assert_uint_eq(_n_contacts(g_new), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_verbs_are_local_only)
{
    _begin();
    _nodes();
    char path[256];
    _path(path, sizeof(path), "remote.atbackup");
    json_t *body = json_pack("{s:s, s:s, s:s}", "ref", "x", "path", path, "passphrase", PASS);
    char *text = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    _wire(g_phone, g_bob, handle_app_backup_export, AT_APP_BACKUP_EXPORT, text, strlen(text));
    _wire(g_phone, g_bob, handle_app_backup_import, AT_APP_BACKUP_IMPORT, text, strlen(text));
    free(text);
    ck_assert(access(path, F_OK) != 0);
    ck_assert_ptr_null(_event(g_phone, AT_APP_EVENT_BACKUP_WRITTEN));
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(ContactsBackup,
          test_seal_and_open,
          test_the_default_is_moderate_argon2id,
          test_the_vector_python_pins,
          test_a_wrong_passphrase_or_any_change_fails_alike,
          test_what_an_open_refuses,
          test_the_passphrase_floor_counts_characters,
          test_a_generated_code_and_its_typing,
          test_a_python_backup_opens_and_restores_here,
          test_contents_that_are_not_contents_are_malformed,
          test_export_writes_a_private_file,
          test_what_export_refuses,
          test_a_new_phone_keeps_contacts_and_verified_edges,
          test_no_cert_or_another_operator_gets_no_siblings,
          test_a_restore_reaches_the_current_sibling,
          test_import_refusals_leave_the_book_alone,
          test_the_verbs_are_local_only)
