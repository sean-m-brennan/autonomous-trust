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

/** @file The proposer of ordered placement (doc/architecture/reputation.md,
 *  "Agreeing on an order"), on real keys.
 *
 *  One node of four, with a ready task in its pool, runs a round: it asks,
 *  and on two grants (with its own, a majority) sends its batch; on two
 *  signed acceptances it broadcasts the placement and writes it. A grant that
 *  reports a value accepted under an earlier ballot makes it carry that value
 *  instead of its own. A nack ends the round, and the next one outranks what
 *  the nack named. Mirrors the proposer cases of
 *  tests/a_unit/test_placement_sim.py, which run whole cohorts.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"
#include "utilities/util.h"

static char GRANT_FN[]    = "place grant";
static char ACCEPTED_FN[] = "place accepted";
static char NACK_FN[]     = "place nack";

/* The last payload of each kind this node sent. */
static json_t *g_request, *g_place, *g_placed, *g_grant;
/* Who each round request went to. */
static uuid_t g_asked[8];
static int g_n_asked;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || msg->info.net_msg.obj == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    json_t **slot = strcmp(fn, "place request") == 0 ? &g_request
                  : strcmp(fn, "place") == 0 ? &g_place
                  : strcmp(fn, "placed") == 0 ? &g_placed
                  : strcmp(fn, "place grant") == 0 ? &g_grant : NULL;
    if (slot == &g_request && g_n_asked < 8)
        uuid_copy(g_asked[g_n_asked++], msg->info.net_msg.to_whom.uuid);
    if (slot != NULL)
    {
        json_decref(*slot);
        *slot = json_loads((const char *)msg->info.net_msg.obj, 0, NULL);
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

static process_t *_mk_process(identity_t *self, identity_t **peers, int n)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    for (int i = 0; i < n; i++)
    {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish(peers[i], &pub));
        memcpy(&proc->protocol.peers[i], pub, sizeof(public_identity_t));
        smrt_deref(pub);
    }
    proc->protocol.num_peers = (size_t)n;
    return proc;
}

static void _send(process_t *proc, identity_t *from, char *fn, json_t *payload)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(from, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = fn;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
}

static void _hex_sig(identity_t *who, const uint8_t *desig, size_t dlen, char *out)
{
    unsigned char sig[crypto_sign_BYTES];
    ck_assert(crypto_sign_detached(sig, NULL, desig, dlen, who->signature.private) == 0);
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)out);
}

/* {voter: sig} over the commit designation of `scorer`'s half, by `signers`. */
static char *_cert(identity_t **signers, int n, const uuid_t scorer,
                   const uuid_t task, double score)
{
    uint8_t desig[512];
    size_t dlen = commit_designation(scorer, task, score, NULL, desig, sizeof(desig));
    json_t *sigs = json_object();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], sig[crypto_sign_BYTES * 2 + 1] = {0};
        uuid_unparse_lower(signers[i]->uuid, u);
        _hex_sig(signers[i], desig, dlen, sig);
        json_object_set_new(sigs, u, json_string(sig));
    }
    char *text = json_dumps(sigs, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(sigs);
    return text;
}

/* @p scorer's own signature over its half of @p task naming @p other
 * (R+D.md §14.2), hex into @p out. */
static void _half_sig(identity_t *scorer, identity_t *other, const uuid_t task,
                      double score, char *out)
{
    uint8_t desig[HALF_DESIG_MAX];
    size_t dlen = half_designation(task, scorer->uuid, other->uuid, score, NULL,
                                   desig, sizeof(desig));
    ck_assert(dlen > 0);
    _hex_sig(scorer, desig, dlen, out);
}

/* A task between a and b, both halves in our pool, certified by c and d and
 * each signed by its scorer naming the other. */
static void _ready_task(identity_t *a, identity_t *b, identity_t *c,
                        identity_t *d, uuid_t task)
{
    uuid_generate(task);
    identity_t *signers[2] = {c, d};
    char *ca = _cert(signers, 2, a->uuid, task, 0.9);
    char *cb = _cert(signers, 2, b->uuid, task, 0.6);
    char sa[crypto_sign_BYTES * 2 + 1] = {0}, sb[crypto_sign_BYTES * 2 + 1] = {0};
    _half_sig(a, b, task, 0.9, sa);
    _half_sig(b, a, task, 0.6, sb);
    reputation_record_named_half_on("", task, a->uuid, 0.9, NULL, ca, b->uuid, sa);
    ck_assert_int_eq(reputation_record_named_half_on("", task, b->uuid, 0.6, NULL,
                                                     cb, a->uuid, sb),
                     TX_HALF_READY);
    free(ca);
    free(cb);
}

static json_t *_reply(json_t *round, json_t *extra)
{
    json_t *r = json_pack("{s:s, s:O, s:O}", "group", "",
                          "k", json_object_get(round, "k"),
                          "ballot", json_object_get(round, "ballot"));
    if (extra != NULL)
        json_object_update(r, extra);
    return r;
}

/* The digest of the value in `place`, at its k. */
static void _digest_of(json_t *place, char out[TX_HASH_HEX_LEN + 1])
{
    json_t *value = json_object_get(place, "value");
    transaction_t entries[PLACE_BATCH_MAX];
    int n = (int)json_array_size(value);
    for (int i = 0; i < n; i++)
    {
        json_t *d = json_array_get(value, (size_t)i);
        memset(&entries[i], 0, sizeof(entries[i]));
        entries[i].index = -1;
        uuid_parse(json_string_value(json_object_get(d, "task")), entries[i].task_uuid);
        uuid_parse(json_string_value(json_object_get(d, "p1")), entries[i].p1_uuid);
        uuid_parse(json_string_value(json_object_get(d, "p2")), entries[i].p2_uuid);
        entries[i].p1_score = json_number_value(json_object_get(d, "p1_score"));
        entries[i].p2_score = json_number_value(json_object_get(d, "p2_score"));
        entries[i].p1_set = entries[i].p2_set = true;
    }
    place_value_digest(entries, n, (int)json_integer_value(json_object_get(place, "k")), out);
}

static void _accept(process_t *proc, identity_t *who)
{
    char digest[TX_HASH_HEX_LEN + 1];
    _digest_of(g_place, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(
        (int)json_integer_value(json_object_get(g_place, "k")),
        json_string_value(json_object_get(g_place, "head")), digest, desig, sizeof(desig));
    char sig[crypto_sign_BYTES * 2 + 1] = {0};
    _hex_sig(who, desig, dlen, sig);
    json_t *extra = json_pack("{s:s, s:s}", "digest", digest, "sig", sig);
    json_t *r = _reply(g_place, extra);
    _send(proc, who, ACCEPTED_FN, r);
    json_decref(r);
    json_decref(extra);
}

static char g_dir[64];
static identity_t *me, *p[3];

static process_t *_begin_with(int in_roster);

static process_t *_begin(void)
{
    return _begin_with(4);
}

/* me and p[0..2]; the first @p in_roster of {me, p0, p1, p2} as the roster in
 * force (an anchor), or none at all for 0. */
static process_t *_begin_with(int in_roster)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/at-place-prop-XXXXXX");
    ck_assert(mkdtemp(g_dir) != NULL);
    reputation_set_placement_dir(g_dir);
    reputation_reset_state(3);
    messaging_set_test_hook(_capture_hook);
    g_request = g_place = g_placed = g_grant = NULL;
    g_n_asked = 0;
    me = _mk_identity("me", "10.0.0.1");
    p[0] = _mk_identity("p0", "10.0.0.2");
    p[1] = _mk_identity("p1", "10.0.0.3");
    p[2] = _mk_identity("p2", "10.0.0.4");
    process_t *proc = _mk_process(me, p, 3);
    /* The roster in force (an anchor): most cases are about placing
     * entries, not founding the group. */
    if (in_roster == 0)
        return proc;
    json_t *members = json_array();
    identity_t *all[4] = { me, p[0], p[1], p[2] };
    for (int i = 0; i < in_roster; i++)
    {
        char u[UUID_STRING_LEN + 1], k[2 * crypto_sign_PUBLICKEYBYTES + 1];
        uuid_unparse_lower(all[i]->uuid, u);
        sodium_bin2hex(k, sizeof(k), all[i]->signature.public, crypto_sign_PUBLICKEYBYTES);
        json_array_append_new(members, json_pack("[s, s]", u, k));
    }
    ck_assert_int_eq(reputation_set_roster_anchor(members), 0);
    json_decref(members);
    return proc;
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    reputation_set_placement_dir(NULL);
    json_decref(g_request);
    json_decref(g_place);
    json_decref(g_placed);
    json_decref(g_grant);
    DIR *d = opendir(g_dir);
    struct dirent *ent;
    while (d != NULL && (ent = readdir(d)) != NULL)
    {
        char path[512];
        if (ent->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", g_dir, ent->d_name);
        unlink(path);
    }
    if (d != NULL)
        closedir(d);
    rmdir(g_dir);
}

DEFINE_TEST(test_a_round_places_our_ready_items)
{
    process_t *proc = _begin();
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);
    ck_assert_ptr_nonnull(g_request);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    ck_assert_ptr_null(g_place);              /* one grant is not a majority */
    _send(proc, p[1], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_int_eq((int)json_array_size(json_object_get(g_place, "value")), 1);
    _accept(proc, p[0]);
    ck_assert_ptr_null(g_placed);
    _accept(proc, p[1]);
    ck_assert_ptr_nonnull(g_placed);
    uuid_t tasks[4];
    ck_assert_int_eq(reputation_get_chain_tasks(tasks, 4), 1);
    ck_assert(uuid_compare(tasks[0], task) == 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_reported_value_is_carried_instead_of_ours)
{
    process_t *proc = _begin();
    uuid_t ours, theirs;
    _ready_task(p[0], p[1], p[2], me, ours);
    _ready_task(p[1], p[2], p[0], me, theirs);
    reputation_place_start(proc);
    /* p0 accepted a value holding only `theirs` under an earlier ballot. */
    char by[UUID_STRING_LEN + 1], t[UUID_STRING_LEN + 1];
    char a[UUID_STRING_LEN + 1], b[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p[2]->uuid, by);
    uuid_unparse_lower(theirs, t);
    identity_t *lo = strcmp((uuid_unparse_lower(p[1]->uuid, a), a),
                            (uuid_unparse_lower(p[2]->uuid, b), b)) < 0 ? p[1] : p[2];
    identity_t *hi = lo == p[1] ? p[2] : p[1];
    uuid_unparse_lower(lo->uuid, a);
    uuid_unparse_lower(hi->uuid, b);
    identity_t *signers[2] = {p[0], me};
    char *ca = _cert(signers, 2, lo->uuid, theirs, lo == p[1] ? 0.9 : 0.6);
    char *cb = _cert(signers, 2, hi->uuid, theirs, hi == p[1] ? 0.9 : 0.6);
    /* Each scorer signs its own half (R+D.md §14.2). */
    char sl[crypto_sign_BYTES * 2 + 1] = {0}, sh[crypto_sign_BYTES * 2 + 1] = {0};
    _half_sig(lo, hi, theirs, lo == p[1] ? 0.9 : 0.6, sl);
    _half_sig(hi, lo, theirs, hi == p[1] ? 0.9 : 0.6, sh);
    json_t *entry = json_pack("{s:s, s:s, s:f, s:s, s:f, s:o, s:o, s:s, s:s}", "task", t,
                              "p1", a, "p1_score", lo == p[1] ? 0.9 : 0.6,
                              "p2", b, "p2_score", hi == p[1] ? 0.9 : 0.6,
                              "p1_cert", json_loads(ca, 0, NULL),
                              "p2_cert", json_loads(cb, 0, NULL),
                              "p1_sig", sl, "p2_sig", sh);
    free(ca);
    free(cb);
    json_t *extra = json_pack("{s:{s:{s:i, s:s}, s:[o]}}", "accepted", "ballot",
                              "n", 1, "by", by, "value", entry);
    json_t *g0 = _reply(g_request, extra);
    json_t *g1 = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, g0);
    _send(proc, p[1], GRANT_FN, g1);
    json_decref(g0);
    json_decref(g1);
    json_decref(extra);
    ck_assert_ptr_nonnull(g_place);
    json_t *value = json_object_get(g_place, "value");
    ck_assert_int_eq((int)json_array_size(value), 1);
    ck_assert_str_eq(json_string_value(json_object_get(json_array_get(value, 0), "task")), t);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_nack_ends_the_round_and_the_next_outranks_it)
{
    process_t *proc = _begin();
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);
    json_int_t n1 = json_integer_value(json_object_get(json_object_get(g_request, "ballot"), "n"));
    char by[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p[2]->uuid, by);
    json_int_t big = n1 + 1000000;
    json_t *extra = json_pack("{s:i, s:{s:I, s:s}}", "next", 0, "promised", "n", big, "by", by);
    json_t *nack = _reply(g_request, extra);
    _send(proc, p[0], NACK_FN, nack);
    json_decref(nack);
    json_decref(extra);
    /* A late grant for the dead round changes nothing. */
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[1], GRANT_FN, grant);
    _send(proc, p[2], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_null(g_place);
    reputation_place_start(proc);
    ck_assert(json_integer_value(json_object_get(json_object_get(g_request, "ballot"), "n")) > big);
    _end();
}
END_TEST_DEFINITION()

/* blake2b(uuid|k), 16 bytes, hex: where a member stands in instance k's
 * takeover order. */
static void _rank_hash(const identity_t *who, int k, char out[33])
{
    char in[UUID_STRING_LEN + 24], u[UUID_STRING_LEN + 1];
    unsigned char h[16];
    uuid_unparse_lower(who->uuid, u);
    snprintf(in, sizeof(in), "%s|%d", u, k);
    crypto_generichash(h, sizeof(h), (const unsigned char *)in, strlen(in), NULL, 0);
    sodium_bin2hex(out, 33, h, sizeof(h));
}

static bool _asked(const identity_t *who)
{
    for (int i = 0; i < g_n_asked; i++)
        if (uuid_compare(g_asked[i], who->uuid) == 0)
            return true;
    return false;
}

/* A gateway proposes on a child chain as on its own: ranked among that
 * group's members alone, and asking only them. Here the gateway leads its
 * child group {me, p0, p1} at instance 0 although p2, outside it, outranks it
 * on the whole roster; so it opens the child round at once, and p2 never
 * hears of it. The pool is persisted first, twice, as the loop does: that
 * once emptied the index of child chains, and the proposer then saw none. */
DEFINE_TEST(test_a_child_chain_round_goes_to_that_group_alone)
{
    process_t *proc = _begin();
    for (int tries = 0;; tries++)
    {
        ck_assert(tries < 2000);
        if (tries >= 2000)
            break;
        char hm[33], h0[33], h1[33], h2[33];
        _rank_hash(me, 0, hm);
        _rank_hash(p[0], 0, h0);
        _rank_hash(p[1], 0, h1);
        _rank_hash(p[2], 0, h2);
        if (strcmp(h2, hm) < 0 && strcmp(hm, h0) < 0 && strcmp(hm, h1) < 0)
            break;
        /* Re-roll every uuid (the roster holds copies of the peers'): one
         * draw in twelve orders the four this way. */
        uuid_generate(me->uuid);
        for (int i = 0; i < 3; i++)
        {
            uuid_generate(p[i]->uuid);
            uuid_copy(proc->protocol.peers[i].uuid, p[i]->uuid);
        }
    }
    static group_t child;
    memset(&child, 0, sizeof(child));
    uuid_t cg;
    uuid_generate(cg);
    ck_assert_ret_ok(group_init(&cg, (char *)me->address, &child));
    for (int i = 0; i < 2; i++)
    {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(p[i]->uuid, u);
        ck_assert_ret_ok(group_add_address(&child, u, p[i]->address));
    }
    ck_assert_ret_ok(identity_add_child_group(proc, &child, NULL));
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(cg, key);

    uuid_t task;
    uuid_generate(task);
    identity_t *signers[2] = {me, p[2]};
    char *ca = _cert(signers, 2, p[0]->uuid, task, 0.9);
    char *cb = _cert(signers, 2, p[1]->uuid, task, 0.6);
    char sa[crypto_sign_BYTES * 2 + 1] = {0}, sb[crypto_sign_BYTES * 2 + 1] = {0};
    _half_sig(p[0], p[1], task, 0.9, sa);
    _half_sig(p[1], p[0], task, 0.6, sb);
    reputation_record_named_half_on(key, task, p[0]->uuid, 0.9, NULL, ca,
                                    p[1]->uuid, sa);
    ck_assert_int_eq(reputation_record_named_half_on(key, task, p[1]->uuid, 0.6,
                                                     NULL, cb, p[0]->uuid, sb),
                     TX_HALF_READY);
    free(ca);
    free(cb);

    reputation_persist_pools(proc);
    reputation_persist_pools(proc);
    reputation_maybe_place(proc);
    ck_assert_ptr_nonnull(g_request);
    ck_assert_str_eq(json_string_value(json_object_get(g_request, "group")), key);
    ck_assert_int_eq(g_n_asked, 2);
    ck_assert(_asked(p[0]) && _asked(p[1]));
    ck_assert(!_asked(p[2]));
    _end();
}
END_TEST_DEFINITION()

/* `from` sends `fn` for instance 0 of the primary chain under (n, from). */
static void _at_zero(process_t *proc, identity_t *from, char *fn, json_int_t n,
                     json_t *value)
{
    char by[UUID_STRING_LEN + 1];
    uuid_unparse_lower(from->uuid, by);
    json_t *m = json_pack("{s:s, s:i, s:{s:I, s:s}, s:s}", "group", "", "k", 0,
                          "ballot", "n", n, "by", by, "head", "");
    if (value != NULL)
        json_object_set(m, "value", value);
    _send(proc, from, fn, m);
    json_decref(m);
}

/* An acceptor that accepts twice at one instance still reports what it
 * accepted after a restart. Pruning the instances below one used to free the
 * accepted map's key index, so the second acceptance was persisted without
 * the first's key -- and with it the value: a grant after the restart named
 * nothing, and a new proposer was free to carry its own value where one may
 * already have been chosen. */
DEFINE_TEST(test_an_acceptance_survives_a_second_and_a_restart)
{
    static char PLACE_FN[] = "place", REQUEST_FN[] = "place request";
    process_t *proc = _begin();
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);          /* only to have a well-formed value */
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    _send(proc, p[1], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    json_t *value = json_deep_copy(json_object_get(g_place, "value"));
    json_int_t n = json_integer_value(
        json_object_get(json_object_get(g_place, "ballot"), "n"));

    _at_zero(proc, p[0], PLACE_FN, n + 10, value);
    _at_zero(proc, p[0], PLACE_FN, n + 11, value);
    reputation_reset_state(3);             /* the restart */
    json_decref(g_grant);
    g_grant = NULL;
    _at_zero(proc, p[1], REQUEST_FN, n + 20, NULL);
    ck_assert_ptr_nonnull(g_grant);
    json_t *held = json_object_get(g_grant, "accepted");
    ck_assert_ptr_nonnull(held);
    ck_assert_int_eq(json_integer_value(json_object_get(
                         json_object_get(held, "ballot"), "n")), n + 11);
    ck_assert(json_equal(json_object_get(held, "value"), value));
    json_decref(value);
    _end();
}
END_TEST_DEFINITION()

/* Run one round on our ready items to its placement; return its ballot n. */
static json_int_t _place_one(process_t *proc)
{
    reputation_place_start(proc);
    ck_assert_ptr_nonnull(g_request);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    _send(proc, p[1], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    _accept(proc, p[0]);
    _accept(proc, p[1]);
    ck_assert_ptr_nonnull(g_placed);
    json_int_t n = json_integer_value(
        json_object_get(json_object_get(g_place, "ballot"), "n"));
    json_decref(g_request);
    json_decref(g_place);
    json_decref(g_placed);
    g_request = g_place = g_placed = NULL;
    return n;
}

/* The leader skips the first phase: the ballot a majority promised it for
 * the instance it placed still carries the next one, so it sends `place`
 * straight away. Mirrors test_placement_sim.py
 * test_the_leader_places_the_next_instance_without_asking. */
DEFINE_TEST(test_the_leader_places_the_next_instance_without_asking)
{
    process_t *proc = _begin();
    uuid_t t1, t2;
    _ready_task(p[0], p[1], p[2], me, t1);
    json_int_t n = _place_one(proc);
    _ready_task(p[0], p[1], p[2], me, t2);
    reputation_maybe_place(proc);
    ck_assert_ptr_null(g_request);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_int_eq(json_integer_value(json_object_get(g_place, "k")), 1);
    ck_assert_int_eq(json_integer_value(
        json_object_get(json_object_get(g_place, "ballot"), "n")), n);
    _accept(proc, p[0]);
    _accept(proc, p[1]);
    ck_assert_ptr_nonnull(g_placed);
    uuid_t tasks[4];
    ck_assert_int_eq(reputation_get_chain_tasks(tasks, 4), 2);
    _end();
}
END_TEST_DEFINITION()

/* ...but not once it has promised another ballot: then it asks again. */
DEFINE_TEST(test_a_leader_that_promised_another_ballot_asks_again)
{
    process_t *proc = _begin();
    uuid_t t1, t2;
    _ready_task(p[0], p[1], p[2], me, t1);
    json_int_t n = _place_one(proc);
    reputation_install_place_promise(n + 5, p[2]->uuid);
    _ready_task(p[0], p[1], p[2], me, t2);
    reputation_maybe_place(proc);
    ck_assert_ptr_null(g_place);
    ck_assert_ptr_nonnull(g_request);
    ck_assert_int_eq(json_integer_value(json_object_get(g_request, "k")), 1);
    ck_assert(json_integer_value(json_object_get(
        json_object_get(g_request, "ballot"), "n")) > n + 5);
    _end();
}
END_TEST_DEFINITION()

/* --- Judged by the logged roster (doc/architecture/reputation.md, "Who is
 * in the group"). Mirrors test_placement_roster.py TestJudgedByRoster. --- */

/* Seed the primary chain with a genesis roster of @p who (n of them). */
static void _seed_roster(identity_t **who, int n)
{
    json_t *members = json_array();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], k[2 * crypto_sign_PUBLICKEYBYTES + 1];
        uuid_unparse_lower(who[i]->uuid, u);
        sodium_bin2hex(k, sizeof(k), who[i]->signature.public,
                       crypto_sign_PUBLICKEYBYTES);
        json_array_append_new(members, json_pack("[s, s]", u, k));
    }
    char digest[TX_HASH_HEX_LEN + 1], task[UUID_STRING_LEN + 1];
    ck_assert_int_eq(roster_digest(members, digest, NULL), 0);
    uuid_t t;
    tx_roster_task_uuid(NULL, "genesis", NULL, digest, t);
    uuid_unparse_lower(t, task);
    json_t *arr = json_pack("[{s:s, s:s, s:b, s:s, s:b, s:i, s:s, s:s, s:n, s:s, s:o}]",
        "task", task, "p1", "00000000-0000-0000-0000-000000000000", "p1_set", 0,
        "p2", "00000000-0000-0000-0000-000000000000", "p2_set", 0, "index", 0,
        "prev_hash", "", "roster_op", "genesis", "roster_uuid",
        "roster_digest", digest, "roster_members", members);
    ck_assert_int_eq(reputation_install_chain_json(arr), 0);
    json_decref(arr);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 1);
}

/* `placed` at 1 from @p from, for one entry between p0 and p1, signed by
 * @p signers. */
static void _placed_at_one(process_t *proc, identity_t *from,
                           identity_t **signers, int n)
{
    transaction_t e;
    memset(&e, 0, sizeof(e));
    e.index = -1;
    uuid_generate(e.task_uuid);
    identity_t *a = p[0], *b = p[1];
    char ua[UUID_STRING_LEN + 1], ub[UUID_STRING_LEN + 1];
    uuid_unparse_lower(a->uuid, ua);
    uuid_unparse_lower(b->uuid, ub);
    if (strcmp(ub, ua) < 0)
    {
        identity_t *t = a; a = b; b = t;
        char tmp[UUID_STRING_LEN + 1];
        strcpy(tmp, ua); strcpy(ua, ub); strcpy(ub, tmp);
    }
    uuid_copy(e.p1_uuid, a->uuid);
    uuid_copy(e.p2_uuid, b->uuid);
    e.p1_set = e.p2_set = true;
    e.p1_score = 0.9;
    e.p2_score = 0.6;
    char head[TX_HASH_HEX_LEN + 1], digest[TX_HASH_HEX_LEN + 1], task[UUID_STRING_LEN + 1];
    reputation_get_head_hash(head);
    place_value_digest(&e, 1, 1, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(1, head, digest, desig, sizeof(desig));
    json_t *sigs = json_object();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], sig[crypto_sign_BYTES * 2 + 1] = {0};
        uuid_unparse_lower(signers[i]->uuid, u);
        _hex_sig(signers[i], desig, dlen, sig);
        json_object_set_new(sigs, u, json_string(sig));
    }
    uuid_unparse_lower(e.task_uuid, task);
    /* Each scorer signs its own half (R+D.md §14.2). */
    char sa[crypto_sign_BYTES * 2 + 1] = {0}, sb[crypto_sign_BYTES * 2 + 1] = {0};
    _half_sig(a, b, e.task_uuid, 0.9, sa);
    _half_sig(b, a, e.task_uuid, 0.6, sb);
    json_t *value = json_pack("[{s:s, s:s, s:f, s:s, s:f, s:s, s:s}]", "task", task,
                              "p1", ua, "p1_score", 0.9, "p2", ub, "p2_score", 0.6,
                              "p1_sig", sa, "p2_sig", sb);
    json_t *msg = json_pack("{s:s, s:i, s:o, s:o}", "group", "", "k", 1,
                            "value", value, "sigs", sigs);
    static char PLACED_FN[] = "placed";
    _send(proc, from, PLACED_FN, msg);
    json_decref(msg);
}

/* me learns p0's placement at 1 after adding p2: the live view {p0, p1, p2}
 * needs three of four, but instance 1 belongs to the roster logged at 0,
 * {me, p0, p1}, so p0's and p1's signatures carry it (part-3546034). */
DEFINE_TEST(test_a_majority_of_the_logged_roster_carries_a_placement)
{
    process_t *proc = _begin();
    identity_t *roster[3] = { me, p[0], p[1] };
    _seed_roster(roster, 3);
    identity_t *signers[2] = { p[0], p[1] };
    _placed_at_one(proc, p[0], signers, 2);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_signer_outside_the_roster_is_not_counted)
{
    process_t *proc = _begin();
    identity_t *roster[3] = { me, p[0], p[1] };
    _seed_roster(roster, 3);
    identity_t *signers[2] = { p[0], p[2] };
    _placed_at_one(proc, p[0], signers, 2);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_departed_members_signature_still_counts)
{
    process_t *proc = _begin();
    identity_t *gone = _mk_identity("gone", "10.0.0.9");
    identity_t *roster[3] = { me, p[0], gone };
    _seed_roster(roster, 3);
    identity_t *signers[2] = { p[0], gone };
    _placed_at_one(proc, p[0], signers, 2);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 2);
    _end();
}
END_TEST_DEFINITION()

/* Placement completes an attested entry, so it logs the line a commit logs
 * in a chain that does not place; cohorts watch for it (Stele rt-3700990
 * waited on it and failed). Mirrors test_placement_acceptor.py
 * test_a_placed_attestation_is_logged_and_brings_a_checkpoint_forward. */
DEFINE_TEST(test_a_placed_attestation_is_logged_as_committed)
{
    process_t *proc = _begin();
    identity_t *roster[3] = { me, p[0], p[1] };
    _seed_roster(roster, 3);
    char log_path[128];
    snprintf(log_path, sizeof(log_path), "%s/rep.log", g_dir);
    logger_t lg;
    ck_assert_int_eq(logger_init(&lg, INFO, log_path), 0);
    proc->logger = &lg;

    transaction_t e;
    memset(&e, 0, sizeof(e));
    e.index = -1;
    e.attested = true;
    e.p1_set = true;
    uuid_copy(e.p1_uuid, p[0]->uuid);
    uuid_copy(e.subject_uuid, p[2]->uuid);
    e.p1_score = 0.3;
    at_strlcpy(e.p1_channel, "probe", sizeof(e.p1_channel));
    memset(e.evidence_digest, 'a', TX_ATTEST_DIGEST_HEX_LEN);
    tx_attest_task_uuid(e.p1_uuid, e.subject_uuid, e.evidence_digest, e.task_uuid);
    char head[TX_HASH_HEX_LEN + 1], digest[TX_HASH_HEX_LEN + 1];
    reputation_get_head_hash(head);
    place_value_digest(&e, 1, 1, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(1, head, digest, desig, sizeof(desig));
    json_t *sigs = json_object();
    identity_t *signers[2] = { p[0], p[1] };
    for (int i = 0; i < 2; i++)
    {
        char u[UUID_STRING_LEN + 1], sig[crypto_sign_BYTES * 2 + 1] = {0};
        uuid_unparse_lower(signers[i]->uuid, u);
        _hex_sig(signers[i], desig, dlen, sig);
        json_object_set_new(sigs, u, json_string(sig));
    }
    char task[UUID_STRING_LEN + 1], ver[UUID_STRING_LEN + 1], subj[UUID_STRING_LEN + 1];
    uuid_unparse_lower(e.task_uuid, task);
    uuid_unparse_lower(e.p1_uuid, ver);
    uuid_unparse_lower(e.subject_uuid, subj);
    /* The learner takes the attestation's own certificate on the placement's
     * word, so placeholder signatures stand in for it here. */
    json_t *value = json_pack("[{s:s, s:b, s:s, s:f, s:s, s:s, s:s, s:{s:s, s:s, s:s}}]",
                              "task", task, "attested", 1, "p1", ver, "p1_score", 0.3,
                              "p1_channel", "probe", "subject", subj,
                              "evidence_digest", e.evidence_digest, "attest_sigs",
                              "x", "00", "y", "01", "z", "02");
    json_t *msg = json_pack("{s:s, s:i, s:o, s:o}", "group", "", "k", 1,
                            "value", value, "sigs", sigs);
    static char PLACED_FN[] = "placed";
    _send(proc, p[0], PLACED_FN, msg);
    json_decref(msg);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 2);

    proc->logger = NULL;
    if (lg.file != NULL)
        fclose(lg.file);
    FILE *f = fopen(log_path, "r");
    ck_assert_ptr_nonnull(f);
    char line[1024], want[256];
    snprintf(want, sizeof(want), "Reputation: attested score committed: verifier=%.8s "
             "subject=%.8s score=0.30 channel=probe signers=3 (index 1)", ver, subj);
    int seen = 0;
    while (fgets(line, sizeof(line), f) != NULL)
        if (strstr(line, want) != NULL)
            seen++;
    fclose(f);
    ck_assert_int_eq(seen, 1);
    _end();
}
END_TEST_DEFINITION()

/* --- Proposing who is in the group (doc/architecture/reputation.md). --- */

static const char *_value_op(json_t *place)
{
    json_t *v = json_object_get(place, "value");
    if (json_array_size(v) != 1)
        return NULL;
    return json_string_value(json_object_get(json_object_get(json_array_get(v, 0),
                                                             "roster"), "op"));
}

DEFINE_TEST(test_an_unfounded_chain_places_its_genesis_first)
{
    process_t *proc = _begin_with(0);
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);    /* as _maybe_place does on our turn */
    ck_assert_ptr_nonnull(g_request);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    _send(proc, p[1], GRANT_FN, grant);
    ck_assert_ptr_null(g_place);          /* a genesis needs every member */
    _send(proc, p[2], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_str_eq(_value_op(g_place), "genesis");
    json_t *members = json_object_get(json_object_get(json_array_get(
        json_object_get(g_place, "value"), 0), "roster"), "members");
    ck_assert_int_eq((int)json_array_size(members), 4);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_member_the_roster_lacks_is_added_first)
{
    process_t *proc = _begin_with(3);       /* p2 is not on the roster */
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);    /* as _maybe_place does on our turn */
    ck_assert_ptr_nonnull(g_request);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[2], GRANT_FN, grant);     /* not a member: not counted */
    ck_assert_ptr_null(g_place);
    _send(proc, p[0], GRANT_FN, grant);     /* with ours, two of three */
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_str_eq(_value_op(g_place), "add");
    char who[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p[2]->uuid, who);
    ck_assert_str_eq(json_string_value(json_object_get(json_object_get(json_array_get(
        json_object_get(g_place, "value"), 0), "roster"), "uuid")), who);
    _end();
}
END_TEST_DEFINITION()

/* The node being added is still behind and refuses the instance: its nack
 * must not end the round that adds it (Python sim founders-one-at-a-time). */
DEFINE_TEST(test_a_newcomers_nack_does_not_end_the_round)
{
    process_t *proc = _begin_with(3);
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);    /* as _maybe_place does on our turn */
    ck_assert_ptr_nonnull(g_request);
    json_t *extra = json_pack("{s:i}", "next", 0);
    json_t *nack = _reply(g_request, extra);
    _send(proc, p[2], NACK_FN, nack);
    json_decref(nack);
    json_decref(extra);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    _end();
}
END_TEST_DEFINITION()

/* --- The newcomer's anchor (doc/architecture/reputation.md, "Who is in the
 * group"). Mirrors test_placement_roster.py TestAnchor. --- */

/* A roster entry over @p who (n of them), op "genesis", or "add" of @p added
 * onto the roster in force on @p h; its member list kept in @p h. */
static void _roster_tx(tx_history_t *h, identity_t **who, int n, identity_t *added,
                       transaction_t *out)
{
    json_t *members = json_array();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], k[2 * crypto_sign_PUBLICKEYBYTES + 1];
        uuid_unparse_lower(who[i]->uuid, u);
        sodium_bin2hex(k, sizeof(k), who[i]->signature.public, crypto_sign_PUBLICKEYBYTES);
        json_array_append_new(members, json_pack("[s, s]", u, k));
    }
    char d[TX_HASH_HEX_LEN + 1];
    ck_assert_int_eq(tx_history_roster_put(h, members, d), 0);
    json_decref(members);
    memset(out, 0, sizeof(*out));
    out->index = -1;
    out->roster = true;
    at_strlcpy(out->roster_digest, d, sizeof(out->roster_digest));
    if (added == NULL)
    {
        strcpy(out->roster_op, "genesis");
        tx_roster_task_uuid(NULL, "genesis", NULL, d, out->task_uuid);
    }
    else
    {
        transaction_t r;
        ck_assert_int_eq(tx_history_roster_at(h, h->next_index, &r), 0);
        strcpy(out->roster_op, "add");
        uuid_copy(out->roster_uuid, added->uuid);
        tx_roster_task_uuid(r.task_uuid, "add", added->uuid, d, out->task_uuid);
    }
}

/* Write @p e at k on @p h with a placement certificate by @p signers. */
static void _src_place(tx_history_t *h, int k, transaction_t *e,
                       identity_t **signers, int n)
{
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(e, 1, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, h->head_hash, digest, desig, sizeof(desig));
    json_t *sigs = json_object();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], sig[crypto_sign_BYTES * 2 + 1] = {0};
        uuid_unparse_lower(signers[i]->uuid, u);
        _hex_sig(signers[i], desig, dlen, sig);
        json_object_set_new(sigs, u, json_string(sig));
    }
    char *text = json_dumps(sigs, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(sigs);
    ck_assert_int_eq(tx_history_apply_placed(h, k, e, 1, text), TX_PLACE_APPLIED);
    free(text);
}

/* The group {p0, p1, p2} founded, a task placed, then me added -- the add
 * signed by @p add_signers -- served to me as catch-up. */
static int _catch_up(process_t *proc, identity_t **add_signers, int n_add,
                     identity_t **founders, int n_founders)
{
    tx_history_t src;
    ck_assert_ret_ok(tx_history_init(&src));
    transaction_t g, t, add;
    _roster_tx(&src, founders, n_founders, NULL, &g);
    _src_place(&src, 0, &g, founders, n_founders);
    memset(&t, 0, sizeof(t));
    t.index = -1;
    uuid_generate(t.task_uuid);
    identity_t *a = p[0], *b = p[1];
    char ua[UUID_STRING_LEN + 1], ub[UUID_STRING_LEN + 1];
    uuid_unparse_lower(a->uuid, ua);
    uuid_unparse_lower(b->uuid, ub);
    if (strcmp(ub, ua) < 0) { identity_t *x = a; a = b; b = x; }
    uuid_copy(t.p1_uuid, a->uuid);
    uuid_copy(t.p2_uuid, b->uuid);
    t.p1_set = t.p2_set = true;
    t.p1_score = 0.9;
    t.p2_score = 0.8;
    identity_t *two[2] = { p[0], p[1] };
    _src_place(&src, 1, &t, two, 2);
    /* Each scorer signs its own half (R+D.md §14.2): placement cover does not
     * excuse a missing one. */
    char sa[crypto_sign_BYTES * 2 + 1] = {0}, sb[crypto_sign_BYTES * 2 + 1] = {0};
    _half_sig(a, b, t.task_uuid, 0.9, sa);
    _half_sig(b, a, t.task_uuid, 0.8, sb);
    ck_assert_int_eq(tx_history_attach_half_sig(&src, t.task_uuid, a->uuid, sa), 0);
    ck_assert_int_eq(tx_history_attach_half_sig(&src, t.task_uuid, b->uuid, sb), 0);
    identity_t *grown[5];
    for (int i = 0; i < n_founders; i++)
        grown[i] = founders[i];
    grown[n_founders] = me;
    _roster_tx(&src, grown, n_founders + 1, me, &add);
    _src_place(&src, 2, &add, add_signers, n_add);
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&src, 0, tx_history_len(&src), &arr));
    static char UPDATE_FN[] = "latest update";
    _send(proc, p[0], UPDATE_FN, arr);
    json_decref(arr);
    tx_history_free(&src);
    return reputation_get_committed_tx_count();
}

DEFINE_TEST(test_a_newcomer_adopts_the_history_its_group_signed)
{
    process_t *proc = _begin_with(0);
    identity_t *founders[3] = { p[0], p[1], p[2] };
    identity_t *signers[2] = { p[0], p[1] };
    ck_assert_int_eq(_catch_up(proc, signers, 2, founders, 3), 3);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_history_only_an_insider_signed_is_refused)
{
    process_t *proc = _begin_with(0);
    identity_t *founders[3] = { p[0], p[1], p[2] };
    identity_t *signers[1] = { p[0] };          /* p0 alone: no majority */
    ck_assert_int_eq(_catch_up(proc, signers, 1, founders, 3), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_roster_two_members_from_our_view_is_refused)
{
    process_t *proc = _begin_with(0);
    identity_t *x = _mk_identity("x", "10.0.0.8"), *y = _mk_identity("y", "10.0.0.9");
    identity_t *founders[4] = { p[0], p[1], x, y };
    identity_t *signers[3] = { p[0], p[1], x };
    ck_assert_int_eq(_catch_up(proc, signers, 3, founders, 4), 0);
    _end();
}
END_TEST_DEFINITION()

/* A placing chain from before rosters is reset at boot; one with a roster in
 * force is kept. Mirrors test_placement_roster.py TestBeforeTheRoster. */
DEFINE_TEST(test_a_chain_from_before_rosters_is_reset)
{
    process_t *proc = _begin_with(0);
    uuid_t t;
    uuid_generate(t);
    reputation_install_tx_single(t, p[0]->uuid, 0.9);
    reputation_install_tx_single(t, p[1]->uuid, 0.8);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 1);
    ck_assert(reputation_reset_pre_roster(proc));
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    _end();

    proc = _begin();                          /* a roster in force */
    uuid_generate(t);
    reputation_install_tx_single(t, p[0]->uuid, 0.9);
    reputation_install_tx_single(t, p[1]->uuid, 0.8);
    ck_assert(!reputation_reset_pre_roster(proc));
    ck_assert_int_eq(reputation_get_committed_tx_count(), 1);
    _end();
}
END_TEST_DEFINITION()

/* ---- The declared N_min (RD_13.2 plan section 0.4) ---------------------- */

/* An acceptance of g_place from @p who reporting @p n_min (0 for none). */
static void _accept_n(process_t *proc, identity_t *who, int n_min)
{
    char digest[TX_HASH_HEX_LEN + 1];
    _digest_of(g_place, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(
        (int)json_integer_value(json_object_get(g_place, "k")),
        json_string_value(json_object_get(g_place, "head")), digest, desig, sizeof(desig));
    char sig[crypto_sign_BYTES * 2 + 1] = {0};
    _hex_sig(who, desig, dlen, sig);
    json_t *extra = json_pack("{s:s, s:s}", "digest", digest, "sig", sig);
    if (n_min > 0)
        json_object_set_new(extra, "n_min", json_integer(n_min));
    json_t *r = _reply(g_place, extra);
    _send(proc, who, ACCEPTED_FN, r);
    json_decref(r);
    json_decref(extra);
}

/* Place one task with p0 and p1 accepting, then p2's late acceptance; each
 * reports reported[i]. Leaves nothing captured. */
static void _place_reporting(process_t *proc, const int reported[3])
{
    uuid_t task;
    _ready_task(p[0], p[1], p[2], me, task);
    reputation_place_start(proc);
    ck_assert_ptr_nonnull(g_request);
    json_t *grant = _reply(g_request, NULL);
    _send(proc, p[0], GRANT_FN, grant);
    _send(proc, p[1], GRANT_FN, grant);
    json_decref(grant);
    ck_assert_ptr_nonnull(g_place);
    _accept_n(proc, p[0], reported[0]);
    _accept_n(proc, p[1], reported[1]);
    ck_assert_ptr_nonnull(g_placed);
    _accept_n(proc, p[2], reported[2]);      /* after the round closed */
    json_decref(g_request);
    json_decref(g_place);
    json_decref(g_placed);
    g_request = g_place = g_placed = NULL;
}

static int _value_n_min(json_t *place)
{
    return (int)json_integer_value(json_object_get(json_object_get(json_array_get(
        json_object_get(place, "value"), 0), "roster"), "n_min"));
}

/* Three of the four report 7 and this node is configured for none: the
 * leader restates the roster declaring the majority's value, not its own.
 * Mirrors test_placement_n_min.py
 * test_a_leader_configured_otherwise_still_declares_the_majoritys. */
DEFINE_TEST(test_the_leader_restates_the_roster_a_majority_reports)
{
    unsetenv("AT_REP_N_MIN");
    process_t *proc = _begin();
    const int reported[3] = {7, 7, 7};
    _place_reporting(proc, reported);
    reputation_maybe_place(proc);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_str_eq(_value_op(g_place), "restate");
    ck_assert_int_eq(_value_n_min(g_place), 7);
    _end();
}
END_TEST_DEFINITION()

/* This node and one other are configured for 7, two of four: no majority,
 * so the leader proposes no change (a minority leader proposing its own value
 * could stall the instance; RD_13.2 plan section 0.4, call 9). */
DEFINE_TEST(test_a_minority_including_the_leader_restates_nothing)
{
    setenv("AT_REP_N_MIN", "7", 1);
    process_t *proc = _begin();
    const int reported[3] = {7, 0, 0};
    _place_reporting(proc, reported);
    reputation_maybe_place(proc);
    ck_assert_ptr_null(g_place);
    unsetenv("AT_REP_N_MIN");
    _end();
}
END_TEST_DEFINITION()

/* With this node's own configuration, three of four is a majority. */
DEFINE_TEST(test_a_majority_counting_the_leader_restates_the_roster)
{
    setenv("AT_REP_N_MIN", "7", 1);
    process_t *proc = _begin();
    const int reported[3] = {7, 7, 0};
    _place_reporting(proc, reported);
    reputation_maybe_place(proc);
    ck_assert_ptr_nonnull(g_place);
    ck_assert_str_eq(_value_op(g_place), "restate");
    ck_assert_int_eq(_value_n_min(g_place), 7);
    unsetenv("AT_REP_N_MIN");
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlaceProposer,
          test_a_chain_from_before_rosters_is_reset,
          test_a_newcomer_adopts_the_history_its_group_signed,
          test_a_history_only_an_insider_signed_is_refused,
          test_a_roster_two_members_from_our_view_is_refused,
          test_an_unfounded_chain_places_its_genesis_first,
          test_a_member_the_roster_lacks_is_added_first,
          test_a_newcomers_nack_does_not_end_the_round,
          test_a_majority_of_the_logged_roster_carries_a_placement,
          test_a_signer_outside_the_roster_is_not_counted,
          test_a_departed_members_signature_still_counts,
          test_a_placed_attestation_is_logged_as_committed,
          test_the_leader_places_the_next_instance_without_asking,
          test_a_leader_that_promised_another_ballot_asks_again,
          test_an_acceptance_survives_a_second_and_a_restart,
          test_a_child_chain_round_goes_to_that_group_alone,
          test_a_round_places_our_ready_items,
          test_a_reported_value_is_carried_instead_of_ours,
          test_a_nack_ends_the_round_and_the_next_outranks_it,
          test_the_leader_restates_the_roster_a_majority_reports,
          test_a_minority_including_the_leader_restates_nothing,
          test_a_majority_counting_the_leader_restates_the_roster)
