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

/** @file A commit certificate names the roster it was collected under.
 *
 *  Hostile-join run, 2026-11-04: while the roster grew from 4 to 10 members,
 *  a proposer one roster behind its receivers sent certificates that met its
 *  own bar and fell short of theirs ("4 of 4 signature(s) verify, 5 needed,
 *  roster of 10"), and every such half was lost. A commit now carries the
 *  digest of the roster its certificate met, unsigned, and a receiver judges
 *  against that roster while it was in force within the last
 *  REP_CERT_ROSTER_WINDOW instances of its own chain. A digest it does not
 *  hold, or one older than that, is judged on its own roster in force, as
 *  before. The Python twin is tests/a_unit/test_cert_roster.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
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
#include "utilities/logger.h"

static char COMMITTED_FN[] = "tx committed";

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

/* [[uuid, signing key], ...] of @p who (n of them), a new reference. */
static json_t *_members(identity_t **who, int n)
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
    return members;
}

/* A roster entry over the first @p n of @p who: a genesis when @p prev is
 * NULL, else an add of who[n - 1] after @p prev, or (with @p restate) a
 * restatement of @p prev declaring @p n_min. Its member list kept in @p h. */
static void _roster_tx(tx_history_t *h, identity_t **who, int n,
                       const transaction_t *prev, bool restate, int n_min,
                       transaction_t *out)
{
    json_t *members = _members(who, n);
    char d[TX_HASH_HEX_LEN + 1];
    ck_assert_int_eq(tx_history_roster_put(h, members, d), 0);
    json_decref(members);
    memset(out, 0, sizeof(*out));
    out->index = -1;
    out->roster = true;
    at_strlcpy(out->roster_digest, d, sizeof(out->roster_digest));
    if (prev == NULL)
    {
        strcpy(out->roster_op, "genesis");
        tx_roster_task_uuid(NULL, "genesis", NULL, d, out->task_uuid);
    }
    else if (restate)
    {
        strcpy(out->roster_op, "restate");
        out->roster_n_min = n_min;
        tx_roster_task_uuid_n(prev->task_uuid, "restate", NULL, d, n_min,
                              out->task_uuid);
    }
    else
    {
        strcpy(out->roster_op, "add");
        uuid_copy(out->roster_uuid, who[n - 1]->uuid);
        tx_roster_task_uuid(prev->task_uuid, "add", who[n - 1]->uuid, d,
                            out->task_uuid);
    }
}

static identity_t *p[6];

/* A chain whose roster grew 4 -> 5 -> 6 at instances 0, 1 and 2 (next 3),
 * with the three roster entries in @p r. */
static void _grown(tx_history_t *h, transaction_t r[3])
{
    ck_assert_ret_ok(tx_history_init(h));
    _roster_tx(h, p, 4, NULL, false, 0, &r[0]);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, &r[0], 1, NULL), TX_PLACE_APPLIED);
    _roster_tx(h, p, 5, &r[0], false, 0, &r[1]);
    ck_assert_int_eq(tx_history_apply_placed(h, 1, &r[1], 1, NULL), TX_PLACE_APPLIED);
    _roster_tx(h, p, 6, &r[1], false, 0, &r[2]);
    ck_assert_int_eq(tx_history_apply_placed(h, 2, &r[2], 1, NULL), TX_PLACE_APPLIED);
}

static void _people(void)
{
    ck_assert(sodium_init() >= 0);
    for (int i = 0; i < 6; i++)
    {
        char name[8], addr[16];
        snprintf(name, sizeof(name), "p%d", i);
        snprintf(addr, sizeof(addr), "10.0.9.%d", i + 1);
        p[i] = _mk_identity(name, addr);
    }
}

/* ------------------------------------------------------------------ */
/* The lookup                                                          */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_superseded_roster_is_found_inside_the_window)
{
    _people();
    tx_history_t h;
    transaction_t r[3], got;
    _grown(&h, r);
    ck_assert_int_eq(tx_history_roster_named(&h, r[0].roster_digest, 32, &got), 0);
    ck_assert_int_eq(got.index, 0);
    ck_assert_int_eq(tx_history_roster_named(&h, r[2].roster_digest, 32, &got), 0);
    ck_assert_int_eq(got.index, 2);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_roster_superseded_before_the_window_is_not)
{
    _people();
    tx_history_t h;
    transaction_t r[3], got;
    _grown(&h, r);                       /* next 3; a window of 1 reaches 2 */
    ck_assert_int_eq(tx_history_roster_named(&h, r[0].roster_digest, 1, &got), -1);
    ck_assert_int_eq(tx_history_roster_named(&h, r[1].roster_digest, 1, &got), 0);
    ck_assert_int_eq(got.index, 1);
    ck_assert_int_eq(tx_history_roster_named(&h, r[2].roster_digest, 1, &got), 0);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_digest_never_held_is_not_found)
{
    _people();
    tx_history_t h;
    transaction_t r[3], got;
    _grown(&h, r);
    char other[TX_HASH_HEX_LEN + 1];
    memset(other, 'a', TX_HASH_HEX_LEN);
    other[TX_HASH_HEX_LEN] = '\0';
    ck_assert_int_eq(tx_history_roster_named(&h, other, 32, &got), -1);
    ck_assert_int_eq(tx_history_roster_named(&h, NULL, 32, &got), -1);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_restated_roster_is_its_newest_declaration)
{
    _people();
    tx_history_t h;
    transaction_t r[3], re, got;
    _grown(&h, r);
    _roster_tx(&h, p, 6, &r[2], true, 7, &re);
    ck_assert_int_eq(tx_history_apply_placed(&h, 3, &re, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_int_eq(tx_history_roster_named(&h, r[2].roster_digest, 32, &got), 0);
    ck_assert_int_eq(got.index, 3);
    ck_assert_int_eq(got.roster_n_min, 7);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_anchor_is_found_while_in_force)
{
    _people();
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    json_t *members = _members(p, 3);
    char d[TX_HASH_HEX_LEN + 1];
    ck_assert_int_eq(tx_history_roster_put(&h, members, d), 0);
    json_decref(members);
    at_strlcpy(h.roster_anchor, d, sizeof(h.roster_anchor));
    transaction_t got;
    ck_assert_int_eq(tx_history_roster_named(&h, d, 32, &got), 0);
    ck_assert_int_eq(got.index, -1);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The roster travels with the half                                    */
/* ------------------------------------------------------------------ */

/* A pooled half names its roster, and the name moves beside the certificate
 * when the entry is placed. */
DEFINE_TEST(test_the_name_moves_with_the_certificate_when_placed)
{
    _people();
    tx_history_t h;
    transaction_t r[3];
    _grown(&h, r);
    uuid_t task;
    uuid_generate(task);
    const char *d = r[0].roster_digest;
    ck_assert_int_eq(tx_history_record_signed_half(&h, task, p[2]->uuid, 900, NULL,
                                                   "{\"x\":\"aa\"}", p[3]->uuid,
                                                   NULL), TX_HALF_PENDING);
    ck_assert_int_eq(tx_history_pool_set_cert_roster(&h, task, p[2]->uuid, d), 0);
    ck_assert_int_eq(tx_history_record_signed_half(&h, task, p[3]->uuid, 700, NULL,
                                                   "{\"y\":\"bb\"}", p[2]->uuid,
                                                   NULL), TX_HALF_READY);
    ck_assert_str_eq(tx_history_pool_cert_roster(&h, task, p[2]->uuid), d);
    ck_assert_ptr_null(tx_history_pool_cert_roster(&h, task, p[3]->uuid));
    /* Only beside a pooled half. */
    uuid_t stranger;
    uuid_generate(stranger);
    ck_assert_int_eq(tx_history_pool_set_cert_roster(&h, task, stranger, d), -1);

    transaction_t ready[1];
    ck_assert_int_eq(tx_history_ready_items(&h, ready, 1), 1);
    ck_assert_int_eq(tx_history_apply_placed(&h, 3, ready, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_str_eq(tx_history_commit_cert_roster(&h, task, p[2]->uuid), d);
    ck_assert_ptr_null(tx_history_pool_cert_roster(&h, task, p[2]->uuid));
    tx_history_free(&h);
}
END_TEST_DEFINITION()

/* The catch-up wire and the evidence document carry it. */
DEFINE_TEST(test_the_catchup_wire_keeps_it)
{
    _people();
    tx_history_t h, back;
    transaction_t r[3];
    _grown(&h, r);
    uuid_t task;
    uuid_generate(task);
    const char *d = r[0].roster_digest;
    tx_history_record_signed_half(&h, task, p[2]->uuid, 900, NULL, "{\"x\":\"aa\"}",
                                  p[3]->uuid, NULL);
    tx_history_pool_set_cert_roster(&h, task, p[2]->uuid, d);
    tx_history_record_signed_half(&h, task, p[3]->uuid, 700, NULL, "{\"y\":\"bb\"}",
                                  p[2]->uuid, NULL);
    transaction_t ready[1];
    ck_assert_int_eq(tx_history_ready_items(&h, ready, 1), 1);
    ck_assert_int_eq(tx_history_apply_placed(&h, 3, ready, 1, NULL), TX_PLACE_APPLIED);

    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 3, 4, &arr));
    char *text = json_dumps(arr, JSON_COMPACT);
    ck_assert_ptr_nonnull(strstr(text, "\"cert_rosters\""));
    free(text);
    ck_assert_ret_ok(tx_history_init(&back));
    tx_reconcile_result_t res;
    tx_history_reconcile(&back, arr, -1, &res);
    tx_reconcile_result_free(&res);
    ck_assert_str_eq(tx_history_commit_cert_roster(&back, task, p[2]->uuid), d);
    json_decref(arr);
    tx_history_free(&back);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Judged by the roster it names (a receiver, end to end)              */
/* ------------------------------------------------------------------ */

static process_t *g_proc;
static char g_digest[3][TX_HASH_HEX_LEN + 1];

/* p0 receives, the other five are peers, and the primary chain's roster grew
 * 4 -> 5 -> 6 at instances 0..2: the roster of six needs three signatures
 * besides a scorer's, the first roster two. */
static void _receiver(void)
{
    _people();
    reputation_reset_state(5);
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    id_cfg->name = "identity";
    id_cfg->data_struct = p[0];
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    for (int i = 1; i < 6; i++)
    {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish(p[i], &pub));
        proc->protocol.peers[proc->protocol.num_peers++] = *pub;
        smrt_deref(pub);
    }
    g_proc = proc;

    /* The same three roster entries, as the chain's catch-up form. */
    tx_history_t h;
    transaction_t r[3];
    _grown(&h, r);
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, 3, &arr));
    ck_assert_int_eq(reputation_install_chain_json(arr), 0);
    json_decref(arr);
    for (int i = 0; i < 3; i++)
        at_strlcpy(g_digest[i], r[i].roster_digest, sizeof(g_digest[i]));
    tx_history_free(&h);
}

static json_t *_sig_json(identity_t *signer, const uuid_t scorer, const uuid_t task,
                         int milli)
{
    uint8_t desig[512];
    size_t dlen = commit_designation(scorer, task, milli, NULL, desig, sizeof(desig));
    ck_assert(dlen > 0);
    unsigned char sig[crypto_sign_BYTES];
    ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                   signer->signature.private) == 0);
    char hex[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex);
    return json_string(hex);
}

/* p3's committed half naming p2, certified by @p signers, naming roster
 * @p roster (NULL: none); dispatched to the receiver, logging to @p log. */
static void _commit(uuid_t task, identity_t **signers, int n, const char *roster,
                    const char *log)
{
    uuid_generate(task);
    identity_t *scorer = p[3], *other = p[2];
    json_t *cert = json_object();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(signers[i]->uuid, u);
        json_object_set_new(cert, u, _sig_json(signers[i], scorer->uuid, task, 900));
    }
    uint8_t desig[HALF_DESIG_MAX];
    size_t dlen = half_designation(task, scorer->uuid, other->uuid, 900, NULL,
                                   desig, sizeof(desig));
    unsigned char sig[crypto_sign_BYTES];
    ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                   scorer->signature.private) == 0);
    char hs[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hs);
    char t[UUID_STRING_LEN + 1], s[UUID_STRING_LEN + 1], o[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, t);
    uuid_unparse_lower(scorer->uuid, s);
    uuid_unparse_lower(other->uuid, o);
    json_t *payload = json_pack("{s:s, s:s, s:i, s:o, s:s, s:s}", "task_uuid", t,
                                "peer_uuid", s, "score_milli", 900,
                                "certificate", cert, "names", o, "half_sig", hs);
    if (roster != NULL)
        json_object_set_new(payload, "roster", json_string(roster));

    logger_t lg;
    if (log != NULL)
    {
        ck_assert_int_eq(logger_init(&lg, INFO, log), 0);
        g_proc->logger = &lg;
    }
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(scorer, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = COMMITTED_FN;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(g_proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
    json_decref(payload);
    if (log != NULL)
    {
        g_proc->logger = NULL;
        if (lg.file != NULL)
            fclose(lg.file);
    }
}

/* Does the file at @p path hold a line containing @p needle? */
static bool _logged(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    ck_assert_ptr_nonnull(f);
    char line[1024];
    bool seen = false;
    while (fgets(line, sizeof(line), f) != NULL)
        if (strstr(line, needle) != NULL)
            seen = true;
    fclose(f);
    return seen;
}

static char *_pool(void)
{
    char *text = reputation_pool_json();
    ck_assert_ptr_nonnull(text);
    return text;
}

DEFINE_TEST(test_a_receiver_ahead_pools_a_half_its_commit_names_the_roster_of)
{
    _receiver();
    uuid_t task;
    identity_t *signers[2] = { p[0], p[1] };
    _commit(task, signers, 2, g_digest[0], NULL);
    char t[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, t);
    char *pool = _pool();
    ck_assert_ptr_nonnull(strstr(pool, t));
    ck_assert_ptr_nonnull(strstr(pool, g_digest[0]));
    free(pool);
    reputation_reset_state(2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_name_the_same_half_is_refused)
{
    _receiver();
    char log_path[] = "/tmp/rep_cert_roster_XXXXXX";
    int fd = mkstemp(log_path);
    ck_assert(fd >= 0);
    close(fd);
    uuid_t task;
    identity_t *signers[2] = { p[0], p[1] };
    _commit(task, signers, 2, NULL, log_path);
    char t[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, t);
    char *pool = _pool();
    ck_assert_ptr_null(strstr(pool, t));
    free(pool);
    ck_assert(_logged(log_path, "(2 of 2 signature(s) verify, 3 needed, "
                                "roster of 6, group primary)"));
    unlink(log_path);
    reputation_reset_state(2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_refusal_says_when_the_named_roster_decided)
{
    _receiver();
    char log_path[] = "/tmp/rep_cert_roster_XXXXXX";
    int fd = mkstemp(log_path);
    ck_assert(fd >= 0);
    close(fd);
    uuid_t task;
    identity_t *signers[1] = { p[0] };
    _commit(task, signers, 1, g_digest[0], log_path);
    ck_assert(_logged(log_path, "(1 of 1 signature(s) verify, 2 needed, "
                                "named roster of 4, group primary)"));
    unlink(log_path);
    reputation_reset_state(2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_signer_outside_the_named_roster_is_not_counted)
{
    _receiver();
    uuid_t task;
    identity_t *signers[2] = { p[0], p[4] };     /* p4 joined later */
    _commit(task, signers, 2, g_digest[0], NULL);
    char t[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, t);
    char *pool = _pool();
    ck_assert_ptr_null(strstr(pool, t));
    free(pool);
    reputation_reset_state(2);
}
END_TEST_DEFINITION()

RUN_TESTS(RepCertRoster,
          test_a_superseded_roster_is_found_inside_the_window,
          test_a_roster_superseded_before_the_window_is_not,
          test_a_digest_never_held_is_not_found,
          test_a_restated_roster_is_its_newest_declaration,
          test_the_anchor_is_found_while_in_force,
          test_the_name_moves_with_the_certificate_when_placed,
          test_the_catchup_wire_keeps_it,
          test_a_receiver_ahead_pools_a_half_its_commit_names_the_roster_of,
          test_without_the_name_the_same_half_is_refused,
          test_the_refusal_says_when_the_named_roster_decided,
          test_a_signer_outside_the_named_roster_is_not_counted)
