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

/** @file Commit certificates (doc/architecture/reputation.md).
 *
 *  The cross-language half is pinned by conformance/scenarios/reputation/
 *  commit-cert-*. These cover what a single-step scenario cannot: the
 *  designation's bytes against Python's, the group declaration's JSON and its
 *  knob, the certificate store (catch-up wire, reconcile, evidence), and the
 *  two catch-up exemptions -- a quorum checkpoint covering the past, and an
 *  entry this node already holds identically. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/group.h"
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

static char UPDATE_FN[] = "latest update";

/* ------------------------------------------------------------------ */
/* Fixtures (the rep_paxos_round_test shapes)                          */
/* ------------------------------------------------------------------ */

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

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
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

/* `signer`'s detached signature over `scorer`'s half, as hex. */
static json_t *_sig(identity_t *signer, const uuid_t scorer, const uuid_t task,
                    double score)
{
    uint8_t desig[512];
    size_t dlen = commit_designation(scorer, task, score, NULL, desig,
                                     sizeof(desig));
    ck_assert(dlen > 0);
    unsigned char sig[crypto_sign_BYTES];
    ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                   signer->signature.private) == 0);
    char hex[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex);
    return json_string(hex);
}

/* ------------------------------------------------------------------ */
/* Designation and declaration                                         */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_the_designation_matches_python_byte_for_byte)
{
    /* Python: commit_designation(UUID('1111...'), UUID('aaaa...'), 0.9) and
     * (..., 0.3, 'probe'). A drift here would make every certificate one
     * runtime cuts unverifiable in the other. */
    uuid_t s, t;
    ck_assert_int_eq(uuid_parse("11111111-2222-4333-8444-555555555555", s), 0);
    ck_assert_int_eq(uuid_parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", t), 0);
    static const char want1[] =
        "AT-COMMIT\0" "11111111-2222-4333-8444-555555555555|"
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee|0.90000000000000002|task_outcome";
    static const char want2[] =
        "AT-COMMIT\0" "11111111-2222-4333-8444-555555555555|"
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee|0.29999999999999999|probe";
    uint8_t out[512];
    size_t n = commit_designation(s, t, 0.9, NULL, out, sizeof(out));
    ck_assert_uint_eq(n, sizeof(want1) - 1);
    ck_assert_mem_eq(out, want1, n);
    /* An absent channel and the explicit default are one claim. */
    uint8_t out_d[512];
    size_t nd = commit_designation(s, t, 0.9, "task_outcome", out_d, sizeof(out_d));
    ck_assert_uint_eq(nd, n);
    ck_assert_mem_eq(out_d, out, n);
    n = commit_designation(s, t, 0.3, "probe", out, sizeof(out));
    ck_assert_uint_eq(n, sizeof(want2) - 1);
    ck_assert_mem_eq(out, want2, n);
    /* Too small a buffer is refused, never truncated. */
    ck_assert_uint_eq(commit_designation(s, t, 0.9, NULL, out, 20), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_group_declaration_is_omitted_unless_set)
{
    group_t g;
    char bcast[] = "10.0.0.255";
    ck_assert_ret_ok(group_init(NULL, bcast, &g));
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(&g, &obj));
    ck_assert_ptr_null(json_object_get(obj, "commit_certificates"));
    json_decref(obj);

    g.commit_certificates = true;
    ck_assert_ret_ok(group_to_json(&g, &obj));
    ck_assert(json_is_true(json_object_get(obj, "commit_certificates")));
    group_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(group_from_json(obj, &back));
    ck_assert(back.commit_certificates);
    group_free(&back);

    /* Only a literal true turns it on. */
    json_object_set_new(obj, "commit_certificates", json_string("yes"));
    group_t typo;
    memset(&typo, 0, sizeof(typo));
    ck_assert_ret_ok(group_from_json(obj, &typo));
    ck_assert(!typo.commit_certificates);
    group_free(&typo);
    json_decref(obj);
    group_free(&g);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_knob_reads_the_same_spellings_as_python)
{
    unsetenv("AT_COMMIT_CERTIFICATES");
    ck_assert(!group_commit_certificates_resolve());
    const char *on[] = { "1", "true", " Yes ", "ON" };
    for (size_t i = 0; i < sizeof(on) / sizeof(on[0]); i++)
    {
        setenv("AT_COMMIT_CERTIFICATES", on[i], 1);
        ck_assert(group_commit_certificates_resolve());
    }
    const char *off[] = { "0", "no", "garbage", "", "truetruetrue" };
    for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++)
    {
        setenv("AT_COMMIT_CERTIFICATES", off[i], 1);
        ck_assert(!group_commit_certificates_resolve());
    }
    unsetenv("AT_COMMIT_CERTIFICATES");
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* The certificate store                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_certificate_needs_its_half_and_travels_with_the_entry)
{
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b, stranger;
    uuid_generate(t); uuid_generate(a); uuid_generate(b); uuid_generate(stranger);
    tx_history_update(&h, t, a, 0.9, NULL);
    /* Not a half this history holds: refused. */
    ck_assert_int_eq(tx_history_attach_commit_cert(&h, t, stranger, "{\"v\":\"aa\"}"), -1);
    ck_assert_ret_ok(tx_history_attach_commit_cert(&h, t, a, "{\"v\":\"aa\"}"));
    tx_history_update(&h, t, b, 0.8, NULL);
    ck_assert_ret_ok(tx_history_attach_commit_cert(&h, t, b, "{\"w\":\"bb\"}"));
    ck_assert_str_eq(tx_history_commit_cert(&h, t, a), "{\"v\":\"aa\"}");

    /* The certificates do not change the entry hash. */
    char root_before[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&h, root_before);

    /* Catch-up wire, then reconcile into a fresh history. */
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, tx_history_len(&h), &arr));
    json_t *cs = json_object_get(json_array_get(arr, 0), "commit_sigs");
    ck_assert(json_is_object(cs));
    ck_assert_uint_eq(json_object_size(cs), 2);
    tx_history_t r;
    ck_assert_ret_ok(tx_history_init(&r));
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL };
    ck_assert_ret_ok(tx_history_reconcile(&r, arr, -1, &res));
    tx_reconcile_result_free(&res);
    ck_assert_str_eq(tx_history_commit_cert(&r, t, b), "{\"w\":\"bb\"}");
    char root_after[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&r, root_after);
    ck_assert_str_eq(root_before, root_after);
    json_decref(arr);

    /* Evidence document round trip. */
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&h, NULL, &doc));
    tx_history_t e;
    ck_assert_ret_ok(tx_history_init(&e));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &e, NULL));
    ck_assert_str_eq(tx_history_commit_cert(&e, t, a), "{\"v\":\"aa\"}");
    json_decref(doc);

    /* An undeclared group's entries keep their old shape. */
    tx_history_t plain;
    ck_assert_ret_ok(tx_history_init(&plain));
    tx_history_update(&plain, t, a, 0.9, NULL);
    tx_history_update(&plain, t, b, 0.8, NULL);
    ck_assert_ret_ok(tx_history_era_to_json(&plain, 0, 1, &arr));
    ck_assert_ptr_null(json_object_get(json_array_get(arr, 0), "commit_sigs"));
    json_decref(arr);

    tx_history_free(&plain);
    tx_history_free(&e);
    tx_history_free(&r);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Catch-up                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    identity_t *bob, *alice, *carol, *dave;
    process_t *proc;
    tx_history_t src;           /* alice's chain, built through production code */
    uuid_t tasks[3];
} cohort_t;

/* bob, rostered with alice, carol and dave (a quorum of more than 3 // 2), in
 * a group that declares certificates; alice holds three bilateral entries
 * between herself and carol, none certified. */
static void _cohort(cohort_t *c)
{
    reputation_reset_state(3);
    c->bob = _mk_identity("bob", "10.0.7.1");
    c->alice = _mk_identity("alice", "10.0.7.2");
    c->carol = _mk_identity("carol", "10.0.7.3");
    c->dave = _mk_identity("dave", "10.0.7.4");
    c->proc = _mk_process(c->bob);
    _add_peer(c->proc, c->alice);
    _add_peer(c->proc, c->carol);
    _add_peer(c->proc, c->dave);
    c->proc->protocol.group.commit_certificates = true;
    ck_assert_ret_ok(tx_history_init(&c->src));
    for (int i = 0; i < 3; i++)
    {
        uuid_generate(c->tasks[i]);
        tx_history_update(&c->src, c->tasks[i], c->alice->uuid, 0.9, NULL);
        tx_history_update(&c->src, c->tasks[i], c->carol->uuid, 0.8, NULL);
    }
}

static json_t *_segment(cohort_t *c, int count)
{
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&c->src, 0, count, &arr));
    return arr;
}

/* Certify both halves of segment entry `i` with the two members that are not
 * its scorer, as a real round would. */
static void _certify(cohort_t *c, json_t *arr, int i)
{
    json_t *all = json_object();
    char a[UUID_STRING_LEN + 1], cr[UUID_STRING_LEN + 1], d[UUID_STRING_LEN + 1];
    uuid_unparse_lower(c->alice->uuid, a);
    uuid_unparse_lower(c->carol->uuid, cr);
    uuid_unparse_lower(c->dave->uuid, d);
    json_t *alice_half = json_object();
    json_object_set_new(alice_half, cr, _sig(c->carol, c->alice->uuid, c->tasks[i], 0.9));
    json_object_set_new(alice_half, d, _sig(c->dave, c->alice->uuid, c->tasks[i], 0.9));
    json_t *carol_half = json_object();
    json_object_set_new(carol_half, a, _sig(c->alice, c->carol->uuid, c->tasks[i], 0.8));
    json_object_set_new(carol_half, d, _sig(c->dave, c->carol->uuid, c->tasks[i], 0.8));
    json_object_set_new(all, a, alice_half);
    json_object_set_new(all, cr, carol_half);
    json_object_set_new(json_array_get(arr, (size_t)i), "commit_sigs", all);
}

DEFINE_TEST(test_a_quorum_checkpoint_covers_what_it_commits_to)
{
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    ck_assert_ret_ok(tx_history_range_root(&c.src, 0, 2, root));
    reputation_install_checkpoint_window(root, 1, 0, 2);

    /* Entries 0 and 1 are covered; entry 2 is an uncertified tail. */
    json_t *all3 = _segment(&c, 3);
    _dispatch(c.proc, c.alice, UPDATE_FN, all3);
    json_decref(all3);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);

    json_t *two = _segment(&c, 2);
    _dispatch(c.proc, c.alice, UPDATE_FN, two);
    json_decref(two);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 2);

    /* With the tail certified, the rest follows. */
    json_t *again = _segment(&c, 3);
    _certify(&c, again, 2);
    _dispatch(c.proc, c.alice, UPDATE_FN, again);
    json_decref(again);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 3);
    tx_history_free(&c.src);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_checkpoint_the_segment_does_not_reproduce_covers_nothing)
{
    cohort_t c;
    _cohort(&c);
    char bogus[TX_HASH_HEX_LEN + 1];
    memset(bogus, '0', TX_HASH_HEX_LEN);
    bogus[TX_HASH_HEX_LEN] = '\0';
    reputation_install_checkpoint_window(bogus, 1, 0, 2);
    json_t *two = _segment(&c, 2);
    _dispatch(c.proc, c.alice, UPDATE_FN, two);
    json_decref(two);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    tx_history_free(&c.src);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_entry_we_already_hold_is_not_asked_again)
{
    cohort_t c;
    _cohort(&c);
    /* bob already holds entries 0 and 1, exactly as alice does. */
    for (int i = 0; i < 2; i++)
    {
        reputation_install_tx_single(c.tasks[i], c.alice->uuid, 0.9);
        reputation_install_tx_single(c.tasks[i], c.carol->uuid, 0.8);
    }
    ck_assert_int_eq(reputation_get_committed_tx_count(), 2);
    /* A segment repeating them uncertified, plus a certified new entry. */
    json_t *seg = _segment(&c, 3);
    _certify(&c, seg, 2);
    _dispatch(c.proc, c.alice, UPDATE_FN, seg);
    json_decref(seg);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 3);
    int held = 0, certified = 0;
    reputation_get_commit_cert_counts(&held, &certified);
    ck_assert_int_eq(held, 6);
    ck_assert_int_eq(certified, 2);
    tx_history_free(&c.src);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_undeclared_group_accepts_an_uncertified_segment)
{
    cohort_t c;
    _cohort(&c);
    c.proc->protocol.group.commit_certificates = false;
    json_t *seg = _segment(&c, 3);
    _dispatch(c.proc, c.alice, UPDATE_FN, seg);
    json_decref(seg);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 3);
    tx_history_free(&c.src);
}
END_TEST_DEFINITION()

RUN_TESTS(RepCommitCert,
          test_the_designation_matches_python_byte_for_byte,
          test_the_group_declaration_is_omitted_unless_set,
          test_the_knob_reads_the_same_spellings_as_python,
          test_a_certificate_needs_its_half_and_travels_with_the_entry,
          test_a_quorum_checkpoint_covers_what_it_commits_to,
          test_a_checkpoint_the_segment_does_not_reproduce_covers_nothing,
          test_an_entry_we_already_hold_is_not_asked_again,
          test_an_undeclared_group_accepts_an_uncertified_segment)
