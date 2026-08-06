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

/** @file Unit tests for the C operator-attended signal (ethne guardian edge,
 *  D8/Q9) — the mirror of Python tests/a_unit/test_operator_attestation.py
 *  (P-L1 data model + canonical carriage).
 *
 *  Covers the cross-runtime canonical carrier (public_identity_to_json /
 *  public_identity_from_json): the two new fields (operator_bound,
 *  operator_attested_at) plus the base64 ZTA binding round-trip, and the
 *  omit-when-default rule that keeps a plain (non-operator) peer's canonical
 *  form byte-identical to before. The operator-class VERIFICATION (distinct
 *  operator anchor) is exercised under the full toolchain via the conformance
 *  corpus (needs a real operator-CA test cert), not here.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include <pthread.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static public_identity_t *_mk_pub(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);
    return pub;
}

/* operator_bound + operator_attested_at survive the canonical JSON round-trip. */
DEFINE_TEST(test_json_roundtrip_operator_fields)
{
    public_identity_t *pub = _mk_pub("node-op", "10.0.0.5");
    pub->operator_bound = true;
    pub->operator_attested_at = 1721800000.0;

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert(json_is_true(json_object_get(obj, "operator_bound")));
    ck_assert(json_is_number(json_object_get(obj, "operator_attested_at")));

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert(back.operator_bound);
    ck_assert_double_eq_tol(back.operator_attested_at, 1721800000.0, 1e-6);

    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

/* A plain (non-operator) peer emits NEITHER key -> byte-identical to the
 * pre-feature canonical form (backward compat / cross-runtime parity). */
DEFINE_TEST(test_json_plain_peer_omits_operator_keys)
{
    public_identity_t *pub = _mk_pub("node-plain", "10.0.0.6");

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert_ptr_null(json_object_get(obj, "operator_bound"));
    ck_assert_ptr_null(json_object_get(obj, "operator_attested_at"));
    /* the six base keys and nothing else */
    ck_assert_int_eq((int)json_object_size(obj), 6);

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert(!back.operator_bound);
    ck_assert_double_eq_tol(back.operator_attested_at, 0.0, 1e-9);

    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

#ifdef AT_ZTA_ENABLED
/* The ZTA binding that backs the signal round-trips as base64 (matching Python
 * base64.b64encode / VARIANT_ORIGINAL). */
DEFINE_TEST(test_json_roundtrip_zta_binding_base64)
{
    public_identity_t *pub = _mk_pub("node-op", "10.0.0.7");
    const unsigned char cred[] = "FAKE-OPERATOR-DER-CERT";
    size_t cred_len = sizeof(cred) - 1;
    pub->zta_credential = malloc(cred_len);
    ck_assert_ptr_nonnull(pub->zta_credential);
    memcpy(pub->zta_credential, cred, cred_len);
    pub->zta_credential_len = cred_len;
    crypto_hash_sha256(pub->zta_credential_hash, cred, cred_len);
    snprintf(pub->zta_issuer, sizeof(pub->zta_issuer), "PIV:CN=Jane Operator");
    pub->operator_bound = true;

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert(json_is_string(json_object_get(obj, "zta_credential")));
    ck_assert(json_is_string(json_object_get(obj, "zta_credential_hash")));
    ck_assert_str_eq(json_string_value(json_object_get(obj, "zta_issuer")),
                     "PIV:CN=Jane Operator");

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert_int_eq((int)back.zta_credential_len, (int)cred_len);
    ck_assert_ptr_nonnull(back.zta_credential);
    ck_assert(memcmp(back.zta_credential, cred, cred_len) == 0);
    ck_assert(memcmp(back.zta_credential_hash, pub->zta_credential_hash, 32) == 0);
    ck_assert(back.operator_bound);

    free(back.zta_credential);
    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()
#endif



/* ------------------------------------------------------------------ */
/* Attended-now pull (ethne D8/Q9). C answers from the
 * identity_set_operator_attended seam rather than a live OperatorSession
 * (no console app, no PIV/MFA in C) — the documented asymmetry is in the
 * state SOURCE only; the verb shape and payload match Python exactly.
 * ------------------------------------------------------------------ */

static char ID_ATTEST_QUERY_FN[]    = "operator_attest_query";
static char ID_ATTEST_RESPONSE_FN[] = "operator_attest_response";

#define PINNED_CLOCK 1721800000.0

static size_t g_attest_count;
static json_t *g_last_attest;        /* owned; freed in _attest_end */

static int _attest_hook(const char *key, const message_type_t type,
                        generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    if (strcmp(msg->info.net_msg.function, ID_ATTEST_RESPONSE_FN) != 0)
        return 0;
    g_attest_count++;
    if (msg->info.net_msg.obj == NULL)
        return 0;
    json_error_t err;
    json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
    if (p == NULL || !json_is_object(p)) {
        if (p != NULL) json_decref(p);
        return 0;
    }
    if (g_last_attest != NULL) json_decref(g_last_attest);
    g_last_attest = p;
    return 0;
}

static void _attest_begin(void)
{
    identity_reset_state();
    g_attest_count = 0;
    g_last_attest = NULL;
    messaging_set_test_hook(_attest_hook);
}

static void _attest_end(void)
{
    messaging_set_test_hook(NULL);
    if (g_last_attest != NULL) { json_decref(g_last_attest); g_last_attest = NULL; }
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
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    identity_set_attest_clock(proc, PINNED_CLOCK);
    return proc;
}

static void _dispatch_pull(process_t *proc, const char *nonce)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ATTEST_QUERY_FN;
    json_t *payload = json_object();
    if (nonce != NULL)
        json_object_set_new(payload, "nonce", json_string(nonce));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* An attended node answers with the pinned stamp and echoes the nonce. */
DEFINE_TEST(test_attest_pull_attended_stamps_and_echoes_nonce)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    process_t *proc = _mk_process(me);
    identity_set_operator_attended(proc, true, PINNED_CLOCK);

    _dispatch_pull(proc, "cafebabe");

    ck_assert_int_eq((int)g_attest_count, 1);
    ck_assert_ptr_nonnull(g_last_attest);
    ck_assert_str_eq(json_string_value(json_object_get(g_last_attest, "nonce")),
                     "cafebabe");
    ck_assert_double_eq_tol(json_real_value(json_object_get(g_last_attest,
                                                           "operator_attested_at")),
                            PINNED_CLOCK, 1e-6);
    _attest_end();
}

/* A node with nobody at the console answers 0 — EXPLICITLY. "Asked, nobody
 * home" is a real answer and must not read as "declined to say". */
DEFINE_TEST(test_attest_pull_unattended_answers_explicit_zero)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    process_t *proc = _mk_process(me);
    identity_set_operator_attended(proc, false, 0.0);

    _dispatch_pull(proc, "cafebabe");

    ck_assert_int_eq((int)g_attest_count, 1);
    json_t *stamp = json_object_get(g_last_attest, "operator_attested_at");
    ck_assert_ptr_nonnull(stamp);            /* present, not omitted */
    ck_assert_double_eq_tol(json_real_value(stamp), 0.0, 1e-9);
    _attest_end();
}

/* An un-nonced pull is REFUSED, not answered: an attestation bound to nothing
 * replays forever, which defeats attended-NOW. */
DEFINE_TEST(test_attest_pull_without_nonce_is_refused)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    process_t *proc = _mk_process(me);
    identity_set_operator_attended(proc, true, PINNED_CLOCK);

    _dispatch_pull(proc, NULL);

    ck_assert_int_eq((int)g_attest_count, 0);
    _attest_end();
}

/* The seam clears the stamp when attendance is withdrawn (console locked). */
DEFINE_TEST(test_attest_seam_clears_stamp_when_unattended)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    process_t *proc = _mk_process(me);

    identity_set_operator_attended(proc, true, PINNED_CLOCK);
    _dispatch_pull(proc, "n1");
    ck_assert(json_real_value(json_object_get(g_last_attest,
                                              "operator_attested_at")) > 0.0);

    identity_set_operator_attended(proc, false, PINNED_CLOCK);
    _dispatch_pull(proc, "n2");
    ck_assert_double_eq_tol(json_real_value(json_object_get(g_last_attest,
                                                           "operator_attested_at")),
                            0.0, 1e-9);
    _attest_end();
}

/* The shared builder is what the wire path uses, so the conformance adapter
 * and the handler cannot disagree (mirrors identity_roster_response). */
DEFINE_TEST(test_attest_response_builder_matches_wire_payload)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    process_t *proc = _mk_process(me);
    identity_set_operator_attended(proc, true, PINNED_CLOCK);

    json_t *direct = identity_attest_response(proc, "n3");
    ck_assert_ptr_nonnull(direct);
    _dispatch_pull(proc, "n3");

    char *a = json_dumps(direct, JSON_SORT_KEYS | JSON_COMPACT);
    char *b = json_dumps(g_last_attest, JSON_SORT_KEYS | JSON_COMPACT);
    ck_assert_ptr_nonnull(a);
    ck_assert_ptr_nonnull(b);
    ck_assert_str_eq(a, b);
    free(a);
    free(b);
    json_decref(direct);
    _attest_end();
}

/* An answer whose nonce this node never minted is dropped: no stored peer is
 * touched. This is the replay guard on the requestor side. */
DEFINE_TEST(test_attest_response_unknown_nonce_leaves_peer_untouched)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    identity_t *other = _mk_identity("peer", "10.0.0.6");
    process_t *proc = _mk_process(me);

    public_identity_t *peer_pub = NULL;
    ck_assert_ret_ok(identity_publish(other, &peer_pub));
    memcpy(&proc->protocol.peers[0], peer_pub, sizeof(public_identity_t));
    proc->protocol.peers[0].operator_attested_at = 0.0;
    proc->protocol.num_peers = 1;

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ATTEST_RESPONSE_FN;
    memcpy(&msg.info.net_msg.from_whom, peer_pub, sizeof(public_identity_t));
    json_t *payload = json_object();
    json_object_set_new(payload, "nonce", json_string("never-minted"));
    json_object_set_new(payload, "operator_attested_at", json_real(PINNED_CLOCK));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);

    ck_assert_double_eq_tol(proc->protocol.peers[0].operator_attested_at, 0.0, 1e-9);
    smrt_deref(peer_pub);
    _attest_end();
}

/* A pull we DID issue records its nonce, so a matching answer is attributable
 * — and the same answer replayed after it is retired is not. */
DEFINE_TEST(test_attest_request_mints_a_unique_nonce_per_pull)
{
    _attest_begin();
    identity_t *me = _mk_identity("node-op", "10.0.0.5");
    identity_t *other = _mk_identity("peer", "10.0.0.6");
    process_t *proc = _mk_process(me);

    public_identity_t *peer_pub = NULL;
    ck_assert_ret_ok(identity_publish(other, &peer_pub));

    char n1[33] = {0};
    char n2[33] = {0};
    ck_assert_ret_ok(identity_request_attestation(proc, peer_pub, n1, sizeof(n1)));
    ck_assert_ret_ok(identity_request_attestation(proc, peer_pub, n2, sizeof(n2)));
    ck_assert(n1[0] != '\0');
    ck_assert(strcmp(n1, n2) != 0);

    smrt_deref(peer_pub);
    _attest_end();
}

#ifdef AT_ZTA_ENABLED
RUN_TESTS(OperatorAttestation,
          test_json_roundtrip_operator_fields,
          test_json_plain_peer_omits_operator_keys,
          test_json_roundtrip_zta_binding_base64,
          test_attest_pull_attended_stamps_and_echoes_nonce,
          test_attest_pull_unattended_answers_explicit_zero,
          test_attest_pull_without_nonce_is_refused,
          test_attest_seam_clears_stamp_when_unattended,
          test_attest_response_builder_matches_wire_payload,
          test_attest_response_unknown_nonce_leaves_peer_untouched,
          test_attest_request_mints_a_unique_nonce_per_pull)
#else
RUN_TESTS(OperatorAttestation,
          test_json_roundtrip_operator_fields,
          test_json_plain_peer_omits_operator_keys,
          test_attest_pull_attended_stamps_and_echoes_nonce,
          test_attest_pull_unattended_answers_explicit_zero,
          test_attest_pull_without_nonce_is_refused,
          test_attest_seam_clears_stamp_when_unattended,
          test_attest_response_builder_matches_wire_payload,
          test_attest_response_unknown_nonce_leaves_peer_untouched,
          test_attest_request_mints_a_unique_nonce_per_pull)
#endif
