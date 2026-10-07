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

/**
 * @file rep_archive_test.c
 * @brief Durable attested records (doc/architecture/reputation.md,
 *        "Verifier-attested scores").
 *
 * A quorum-signed checkpoint over an attested entry writes
 * etc/at/attested/<task>.json once: the entry and its certificate, the
 * checkpoint and its signatures, the inclusion proof, the signers' public keys
 * and the group sizes. Python's verify_attested_record checks it; the record
 * this test writes is the C half of that cross-runtime check (set
 * AT_ARCHIVE_TEST_KEEP to a directory to keep it). Mirrors
 * tests/a_unit/test_attested_scores.py TestArchive.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
#include "utilities/allocation.h"

static const char DIGEST[] =
    "abababababababababababababababababababababababababababababababab";

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

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

/* @p who's detached Ed25519 signature over @p msg, as lowercase hex. */
static void _sign(const identity_t *who, const char *msg, size_t len,
                  char out[crypto_sign_BYTES * 2 + 1])
{
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (const unsigned char *)msg, len,
                         who->signature.private);
    sodium_bin2hex(out, crypto_sign_BYTES * 2 + 1, sig, sizeof(sig));
}

static char g_root_dir[256];

/* The observer archives: it holds the verifier and the subject on its roster.
 * The attestation is certified by the verifier and the observer, the
 * checkpoint over the one-entry window by the observer and the verifier. */
DEFINE_TEST(test_a_checkpoint_archives_its_attested_entries)
{
    ck_assert(sodium_init() >= 0);
    const char *keep = getenv("AT_ARCHIVE_TEST_KEEP");
    if (keep != NULL && keep[0] != '\0')
        snprintf(g_root_dir, sizeof(g_root_dir), "%s", keep);
    else
    {
        snprintf(g_root_dir, sizeof(g_root_dir), "/tmp/at-archive-XXXXXX");
        ck_assert_ptr_nonnull(mkdtemp(g_root_dir));
    }
    char etc[300];
    snprintf(etc, sizeof(etc), "%s/etc", g_root_dir);
    mkdir(etc, 0755);
    snprintf(etc, sizeof(etc), "%s/etc/at", g_root_dir);
    mkdir(etc, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root_dir, 1);

    reputation_reset_state(2);
    identity_t *ver = _mk_identity("ver", "10.0.9.1");
    identity_t *subj = _mk_identity("subj", "10.0.9.2");
    identity_t *obs = _mk_identity("obs", "10.0.9.3");
    process_t *proc = _mk_process(obs);
    _add_peer(proc, ver);
    _add_peer(proc, subj);

    char v_str[UUID_STRING_LEN + 1], s_str[UUID_STRING_LEN + 1];
    char o_str[UUID_STRING_LEN + 1], t_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(ver->uuid, v_str);
    uuid_unparse_lower(subj->uuid, s_str);
    uuid_unparse_lower(obs->uuid, o_str);
    uuid_t task;
    tx_attest_task_uuid(ver->uuid, subj->uuid, DIGEST, task);
    uuid_unparse_lower(task, t_str);

    /* The attestation's designation, as AttestedScore.designation spells it. */
    char desig[512];
    int n = snprintf(desig + 10, sizeof(desig) - 10, "%s|%s|%s|%.17g|probe|%s",
                     v_str, s_str, t_str, 0.3, DIGEST);
    memcpy(desig, "AT-ATTEST", 10);
    size_t dlen = 10 + (size_t)n;
    char sig_v[crypto_sign_BYTES * 2 + 1], sig_o[crypto_sign_BYTES * 2 + 1];
    _sign(ver, desig, dlen, sig_v);
    _sign(obs, desig, dlen, sig_o);
    json_t *cert = json_pack("{s:s, s:s}", v_str, sig_v, o_str, sig_o);
    char *cert_txt = json_dumps(cert, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(cert);
    ck_assert_ret_ok(reputation_install_tx_attested_scoped(
        ver->uuid, 0.3, "probe", subj->uuid, DIGEST, NULL, cert_txt));
    free(cert_txt);

    char root[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_window_root(root);
    ck_assert_int_eq((int)strlen(root), TX_HASH_HEX_LEN);
    char ck_desig[512];
    n = snprintf(ck_desig + 8, sizeof(ck_desig) - 8, "%s|%s|%d|%d|%d",
                 o_str, root, 1, 0, 1);
    memcpy(ck_desig, "AT-CKPT", 8);
    size_t cklen = 8 + (size_t)n;
    char ck_o[crypto_sign_BYTES * 2 + 1], ck_v[crypto_sign_BYTES * 2 + 1];
    _sign(obs, ck_desig, cklen, ck_o);
    _sign(ver, ck_desig, cklen, ck_v);
    json_t *sigs = json_pack("{s:s, s:s}", o_str, ck_o, v_str, ck_v);
    reputation_test_store_checkpoint(proc, o_str, root, 1, 0, 1, "", sigs);

    char path[400];
    snprintf(path, sizeof(path), "%s/etc/at/attested/%s.json", g_root_dir, t_str);
    json_error_t jerr;
    json_t *rec = json_load_file(path, 0, &jerr);
    ck_assert_ptr_nonnull(rec);
    ck_assert_str_eq(json_string_value(json_object_get(rec, "schema")), "1");
    json_t *entry = json_object_get(rec, "entry");
    ck_assert_str_eq(json_string_value(json_object_get(entry, "task_id")), t_str);
    ck_assert(json_is_object(json_object_get(entry, "attest_sigs")));
    ck_assert_int_eq((int)json_integer_value(json_object_get(rec, "group_size")), 3);
    ck_assert_int_eq((int)json_integer_value(json_object_get(rec, "ckpt_group_size")), 3);
    ck_assert(json_is_true(json_object_get(rec, "subject_member")));
    json_t *signers = json_object_get(rec, "signers");
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), ver->signature.public,
                   crypto_sign_PUBLICKEYBYTES);
    ck_assert_str_eq(json_string_value(json_object_get(signers, v_str)), pk_hex);
    ck_assert_ptr_nonnull(json_object_get(signers, o_str));
    ck_assert_str_eq(json_string_value(json_object_get(
        json_object_get(rec, "checkpoint"), "root")), root);
    ck_assert_int_eq((int)json_array_size(json_object_get(rec, "proof")), 0);
    json_decref(rec);

    /* The roster a reader verifies the record against, written beside it:
     * every member's key (this node's included) and the checkpoint it stored.
     * Mirrors TestAnchor.test_the_roster_is_written_beside_the_archive. */
    char rpath[400];
    snprintf(rpath, sizeof(rpath), "%s/etc/at/roster.cfg.json", g_root_dir);
    json_t *roster = json_load_file(rpath, 0, &jerr);
    ck_assert_ptr_nonnull(roster);
    json_t *members = json_object_get(roster, "members");
    ck_assert_int_eq((int)json_object_size(members), 3);
    ck_assert_str_eq(json_string_value(json_object_get(
        json_object_get(members, v_str), "pubkey")), pk_hex);
    ck_assert(json_is_true(json_object_get(json_object_get(members, s_str),
                                           "member")));
    ck_assert_ptr_nonnull(json_object_get(members, o_str));
    ck_assert_str_eq(json_string_value(json_object_get(roster, "self")), o_str);
    json_t *cks = json_object_get(roster, "checkpoints");
    ck_assert_int_eq((int)json_array_size(cks), 1);
    ck_assert_str_eq(json_string_value(json_object_get(
        json_array_get(cks, 0), "root")), root);
    ck_assert_int_eq((int)json_integer_value(json_object_get(
        json_array_get(cks, 0), "epoch")), 1);
    json_decref(roster);

    /* Written once: a fuller signature set re-stores the checkpoint but does
     * not rewrite the record. */
    struct stat before, after;
    ck_assert_int_eq(stat(path, &before), 0);
    sleep(1);
    char ck_s[crypto_sign_BYTES * 2 + 1];
    _sign(subj, ck_desig, cklen, ck_s);
    json_object_set_new(sigs, s_str, json_string(ck_s));
    reputation_test_store_checkpoint(proc, o_str, root, 1, 0, 1, "", sigs);
    ck_assert_int_eq(stat(path, &after), 0);
    ck_assert(before.st_mtime == after.st_mtime);
    json_decref(sigs);
}
END_TEST_DEFINITION()

/* A checkpoint short of its quorum archives nothing. */
DEFINE_TEST(test_a_checkpoint_short_of_quorum_archives_nothing)
{
    char root_dir[] = "/tmp/at-archive-XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root_dir));
    char etc[300];
    snprintf(etc, sizeof(etc), "%s/etc", root_dir);
    mkdir(etc, 0755);
    snprintf(etc, sizeof(etc), "%s/etc/at", root_dir);
    mkdir(etc, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", root_dir, 1);

    reputation_reset_state(2);
    identity_t *ver = _mk_identity("ver", "10.0.9.1");
    identity_t *subj = _mk_identity("subj", "10.0.9.2");
    identity_t *obs = _mk_identity("obs", "10.0.9.3");
    process_t *proc = _mk_process(obs);
    _add_peer(proc, ver);
    _add_peer(proc, subj);
    char o_str[UUID_STRING_LEN + 1], t_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(obs->uuid, o_str);
    uuid_t task;
    tx_attest_task_uuid(ver->uuid, subj->uuid, DIGEST, task);
    uuid_unparse_lower(task, t_str);
    ck_assert_ret_ok(reputation_install_tx_attested_scoped(
        ver->uuid, 0.3, "probe", subj->uuid, DIGEST, NULL, "{\"x\":\"y\"}"));
    char root[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_window_root(root);
    json_t *sigs = json_pack("{s:s}", o_str, "00");   /* one of three */
    reputation_test_store_checkpoint(proc, o_str, root, 1, 0, 1, "", sigs);
    json_decref(sigs);
    char path[400];
    snprintf(path, sizeof(path), "%s/etc/at/attested/%s.json", root_dir, t_str);
    ck_assert(access(path, F_OK) != 0);
}
END_TEST_DEFINITION()

/* A quorum checkpoint over a root our own window does not reproduce (we are
 * still on a fork the quorum did not sign) archives nothing; the record would
 * carry a proof that never verifies, and it is never rewritten (Stele
 * st-1410977). Once a checkpoint matches our window, the entry is archived. */
DEFINE_TEST(test_a_checkpoint_off_our_window_archives_nothing)
{
    char root_dir[] = "/tmp/at-archive-XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root_dir));
    char etc[300];
    snprintf(etc, sizeof(etc), "%s/etc", root_dir);
    mkdir(etc, 0755);
    snprintf(etc, sizeof(etc), "%s/etc/at", root_dir);
    mkdir(etc, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", root_dir, 1);

    reputation_reset_state(2);
    identity_t *ver = _mk_identity("ver", "10.0.9.1");
    identity_t *subj = _mk_identity("subj", "10.0.9.2");
    identity_t *obs = _mk_identity("obs", "10.0.9.3");
    process_t *proc = _mk_process(obs);
    _add_peer(proc, ver);
    _add_peer(proc, subj);
    char v_str[UUID_STRING_LEN + 1], s_str[UUID_STRING_LEN + 1];
    char o_str[UUID_STRING_LEN + 1], t_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(ver->uuid, v_str);
    uuid_unparse_lower(subj->uuid, s_str);
    uuid_unparse_lower(obs->uuid, o_str);
    uuid_t task;
    tx_attest_task_uuid(ver->uuid, subj->uuid, DIGEST, task);
    uuid_unparse_lower(task, t_str);
    ck_assert_ret_ok(reputation_install_tx_attested_scoped(
        ver->uuid, 0.3, "probe", subj->uuid, DIGEST, NULL, "{\"x\":\"y\"}"));
    char path[400];
    snprintf(path, sizeof(path), "%s/etc/at/attested/%s.json", root_dir, t_str);

    char fork[TX_HASH_HEX_LEN + 1];
    memset(fork, 'a', TX_HASH_HEX_LEN);
    fork[TX_HASH_HEX_LEN] = '\0';
    json_t *sigs = json_pack("{s:s, s:s, s:s}", o_str, "00", v_str, "00", s_str, "00");
    reputation_test_store_checkpoint(proc, v_str, fork, 1, 0, 1, "", sigs);
    ck_assert(access(path, F_OK) != 0);

    char root[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_window_root(root);
    reputation_test_store_checkpoint(proc, o_str, root, 2, 0, 1, "", sigs);
    json_decref(sigs);
    ck_assert(access(path, F_OK) == 0);
}
END_TEST_DEFINITION()

/* ISSUES §2.54: the application's team file, read when it changes. */
DEFINE_TEST(test_the_conflict_file_is_read_and_reread)
{
    char root_dir[] = "/tmp/at-conflicts-XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root_dir));
    char etc[300], path[400];
    snprintf(etc, sizeof(etc), "%s/etc", root_dir);
    mkdir(etc, 0755);
    snprintf(etc, sizeof(etc), "%s/etc/at", root_dir);
    mkdir(etc, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", root_dir, 1);
    snprintf(path, sizeof(path), "%s/attest_conflicts.cfg.json", etc);
    const char *A = "0f1e2d3c-4b5a-4968-8776-655443322110";
    const char *B = "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9";
    const char *C = "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a";
    reputation_set_attest_conflicts(NULL);
    ck_assert(!reputation_attest_conflicted(A, B));   /* no file */

    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fprintf(f, "{\"teams\": [[\"%s\", \"%s\"]]}", A, B);
    fclose(f);
    ck_assert(reputation_attest_conflicted(A, B));
    ck_assert(reputation_attest_conflicted(B, A));
    ck_assert(!reputation_attest_conflicted(A, C));
    ck_assert(!reputation_attest_conflicted(A, A));   /* not its own teammate */

    /* A changed file (a different size, so the stamp moves) is picked up. */
    f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fprintf(f, "{\"teams\": [[\"%s\", \"%s\", \"%s\"]]}", A, B, C);
    fclose(f);
    ck_assert(reputation_attest_conflicted(A, C));

    /* A malformed file is no teams at all. */
    f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fprintf(f, "{\"teams\": [[1, 2]]}");
    fclose(f);
    ck_assert(!reputation_attest_conflicted(A, B));

    /* An override wins over the file, and a malformed one changes nothing. */
    char doc[200];
    snprintf(doc, sizeof(doc), "{\"teams\": [[\"%s\", \"%s\"]]}", B, C);
    ck_assert_int_eq(reputation_set_attest_conflicts(doc), 0);
    ck_assert(reputation_attest_conflicted(B, C));
    ck_assert_int_eq(reputation_set_attest_conflicts("{\"teams\": 3}"), -1);
    ck_assert(reputation_attest_conflicted(B, C));
    reputation_set_attest_conflicts(NULL);

    unlink(path);
    ck_assert(!reputation_attest_conflicted(A, B));
}
END_TEST_DEFINITION()

RUN_TESTS(RepArchive,
          test_the_conflict_file_is_read_and_reread,
          test_a_checkpoint_archives_its_attested_entries,
          test_a_checkpoint_short_of_quorum_archives_nothing,
          test_a_checkpoint_off_our_window_archives_nothing)
