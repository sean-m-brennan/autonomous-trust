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

/** @file Quorum attestation for the C slash / checkpoint rounds.
 *
 *  Both rounds used to carry no attestation at all on this side: the co-sign
 *  ack reported `uuid_clear`'d bytes as its signer and no signature, the tally
 *  was a BARE COUNT with no voter identity (so replaying one ack drove it past
 *  quorum and a single peer finalized alone), and the `*_final` handlers
 *  applied whatever arrived on transport authentication only. A slash floors a
 *  peer below COMM_CUTOFF into exclusion that is sticky, so that was a
 *  permanent-exclusion primitive available to any admitted member.
 *
 *  Two of these properties cannot be pinned in the conformance corpus — the
 *  harness resets rep_state between steps, so a proposer cannot hold a pending
 *  round across the ack that would finalize it — which is why the replay and
 *  ack-verification cases live here. The refusal of an unattested `*_final` IS
 *  in the corpus (slash-final-sub-quorum-refused,
 *  slash-final-forged-cosignatures-refused,
 *  checkpoint-final-unattested-root-refused); it is repeated here because this
 *  suite can assert the C-side state directly.
 *
 *  The designation byte-pins guard the cross-language hazard: the co-signature
 *  covers these exact bytes, so a drift between _slash_designation here and
 *  Python SlashAttestation.designation makes every co-signature verify nowhere.
 *  The same literals are asserted by
 *  tests/a_unit/test_repprocess_quorum_attestation.py.
 *
 *  Handlers are static, so they are driven through run_message_handlers with a
 *  crafted NET_MESSAGE, following the identity_resync_test precedent.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
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

/* net_msg_t.function is `char *`, so const literals cannot be assigned. */
static char SLASH_PROPOSE_FN[]     = "slash propose";
static char SLASH_SIGN_FN[]        = "slash sign";
static char SLASH_FINAL_FN[]       = "slash final";
static char CHECKPOINT_FINAL_FN[]  = "checkpoint final";
static char CHECKPOINT_SIGN_FN[]   = "checkpoint sign";
static char CHECKPOINT_PROPOSE_FN[] = "checkpoint propose";

#define SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* ------------------------------------------------------------------ */
/* Emission capture                                                    */
/* ------------------------------------------------------------------ */

static size_t g_slash_final_count;
static size_t g_slash_sign_count;
static size_t g_ckpt_final_count;
static char   g_last_sign_signer[UUID_STRING_LEN + 1];
static char   g_last_sign_sig[SIG_HEX_LEN + 1];
/* Last checkpoint_sign ack this node emitted: who it named, the signature, and
   the chain it echoed back to the proposer. */
static size_t g_ckpt_sign_count;
static char   g_last_ckpt_sig[SIG_HEX_LEN + 1];
static char   g_last_ckpt_group[UUID_STRING_LEN + 1];
static bool   g_last_ckpt_had_group;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, SLASH_FINAL_FN) == 0)
        g_slash_final_count++;
    else if (strcmp(fn, CHECKPOINT_FINAL_FN) == 0)
        g_ckpt_final_count++;
    else if (strcmp(fn, CHECKPOINT_SIGN_FN) == 0) {
        g_ckpt_sign_count++;
        if (msg->info.net_msg.obj != NULL) {
            json_error_t err;
            json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
            if (p != NULL && json_is_object(p)) {
                const char *s = json_string_value(
                    json_object_get(p, "signature"));
                json_t *g = json_object_get(p, "group_uuid");
                if (s != NULL) {
                    strncpy(g_last_ckpt_sig, s, SIG_HEX_LEN);
                    g_last_ckpt_sig[SIG_HEX_LEN] = '\0';
                }
                g_last_ckpt_had_group = (g != NULL && json_is_string(g));
                if (g_last_ckpt_had_group) {
                    strncpy(g_last_ckpt_group, json_string_value(g),
                            UUID_STRING_LEN);
                    g_last_ckpt_group[UUID_STRING_LEN] = '\0';
                }
            }
            if (p != NULL) json_decref(p);
        }
    }
    else if (strcmp(fn, SLASH_SIGN_FN) == 0) {
        g_slash_sign_count++;
        if (msg->info.net_msg.obj != NULL) {
            json_error_t err;
            json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
            if (p != NULL && json_is_object(p)) {
                const char *s = json_string_value(
                    json_object_get(p, "signer_uuid"));
                const char *g = json_string_value(
                    json_object_get(p, "signature"));
                if (s != NULL) {
                    strncpy(g_last_sign_signer, s, UUID_STRING_LEN);
                    g_last_sign_signer[UUID_STRING_LEN] = '\0';
                }
                if (g != NULL) {
                    strncpy(g_last_sign_sig, g, SIG_HEX_LEN);
                    g_last_sign_sig[SIG_HEX_LEN] = '\0';
                }
            }
            if (p != NULL) json_decref(p);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
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
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

static void _uuid_str(const uuid_t u, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(u, out);
}

/* Designation builders — deliberately written out here rather than shared with
 * rep_proc.c, so a change to the production bytes has to be made twice and one
 * of them is a failing test. Same reason Python pins the literals. */
static size_t _slash_desig(const char *slasher, const char *target,
                           const char *reason, double floor, int64_t epoch,
                           uint8_t *out, size_t cap)
{
    static const char tag[] = "AT-SLASH";
    size_t tag_len = sizeof(tag);
    int n = snprintf((char *)out + tag_len, cap - tag_len, "%s|%s|%s|%.6f|%lld",
                     slasher, target, reason, floor, (long long)epoch);
    ck_assert(n > 0 && (size_t)n < cap - tag_len);
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

static size_t _ckpt_desig_g(const char *proposer, const char *root,
                            int64_t epoch, int64_t first, int64_t count,
                            const char *group, uint8_t *out, size_t cap)
{
    static const char tag[] = "AT-CKPT";
    size_t tag_len = sizeof(tag);
    bool have_group = (group != NULL && group[0] != '\0');
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%lld|%lld|%lld%s%s",
                     proposer, root, (long long)epoch, (long long)first,
                     (long long)count, have_group ? "|" : "",
                     have_group ? group : "");
    ck_assert(n > 0 && (size_t)n < cap - tag_len);
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

/* The primary chain appends no group field, so most rounds want this. */
static size_t _ckpt_desig(const char *proposer, const char *root, int64_t epoch,
                          int64_t first, int64_t count, uint8_t *out, size_t cap)
{
    return _ckpt_desig_g(proposer, root, epoch, first, count, "", out, cap);
}

static void _sign_hex(const identity_t *signer, const uint8_t *desig,
                      size_t dlen, char out[SIG_HEX_LEN + 1])
{
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_ret_ok(crypto_sign_detached(sig, NULL, desig, dlen,
                                          signer->signature.private));
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)out);
    out[SIG_HEX_LEN] = '\0';
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

static void _begin(int num_peers)
{
    reputation_reset_state(num_peers);
    g_slash_final_count = 0;
    g_slash_sign_count = 0;
    g_ckpt_final_count = 0;
    g_ckpt_sign_count = 0;
    g_last_ckpt_sig[0] = '\0';
    g_last_ckpt_group[0] = '\0';
    g_last_ckpt_had_group = false;
    g_last_sign_signer[0] = '\0';
    g_last_sign_sig[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* Build the flat slash payload C's handlers read. */
static json_t *_slash_payload(const char *slasher, const char *target,
                              const char *reason, double floor, int64_t epoch)
{
    json_t *p = json_object();
    json_object_set_new(p, "slasher_uuid", json_string(slasher));
    json_object_set_new(p, "target_uuid", json_string(target));
    json_object_set_new(p, "reason", json_string(reason));
    json_object_set_new(p, "floor_score", json_real(floor));
    json_object_set_new(p, "epoch", json_integer(epoch));
    return p;
}

/* ------------------------------------------------------------------ */
/* Designation byte-pins (the cross-language hazard)                    */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_slash_designation_bytes_pinned)
{
    uint8_t desig[512];
    size_t dlen = _slash_desig("11111111-1111-1111-1111-111111111111",
                               "22222222-2222-2222-2222-222222222222",
                               "peer_exclude", 0.1, 7, desig, sizeof(desig));
    /* Tag, then a NUL, then the pipe-joined fields; the float fixed at 6dp. */
    static const char expected[] =
        "AT-SLASH\0"
        "11111111-1111-1111-1111-111111111111|"
        "22222222-2222-2222-2222-222222222222|peer_exclude|0.100000|7";
    ck_assert_uint_eq(dlen, sizeof(expected) - 1);
    ck_assert_mem_eq(desig, expected, dlen);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_designation_bytes_pinned)
{
    uint8_t desig[512];
    size_t dlen = _ckpt_desig("11111111-1111-1111-1111-111111111111",
                              "044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556",
                              7, 0, 3, desig, sizeof(desig));
    static const char expected[] =
        "AT-CKPT\0"
        "11111111-1111-1111-1111-111111111111|"
        "044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556|7|0|3";
    ck_assert_uint_eq(dlen, sizeof(expected) - 1);
    ck_assert_mem_eq(desig, expected, dlen);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Co-sign emission                                                     */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_cosign_ack_names_self_and_carries_verifiable_signature)
{
    _begin(2);
    identity_t *me = _mk_identity("bob", "10.0.0.2");
    identity_t *slasher = _mk_identity("alice", "10.0.0.1");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, slasher);
    _add_peer(proc, rogue);

    char slasher_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    char self_u[UUID_STRING_LEN + 1];
    _uuid_str(slasher->uuid, slasher_u);
    _uuid_str(rogue->uuid, rogue_u);
    _uuid_str(me->uuid, self_u);

    json_t *p = _slash_payload(slasher_u, rogue_u, "peer_exclude", 0.1, 5);
    _dispatch(proc, slasher, SLASH_PROPOSE_FN, p);
    json_decref(p);

    ck_assert_uint_eq(g_slash_sign_count, 1);
    /* It names ITSELF, not the nil uuid this used to emit ... */
    ck_assert_str_eq(g_last_sign_signer, self_u);
    /* ... and the signature verifies over the proposer's designation. */
    uint8_t desig[512];
    size_t dlen = _slash_desig(slasher_u, rogue_u, "peer_exclude", 0.1, 5,
                               desig, sizeof(desig));
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_uint_eq(strlen(g_last_sign_sig), SIG_HEX_LEN);
    ck_assert_ret_ok(unhexlify((const unsigned char *)g_last_sign_sig,
                               SIG_HEX_LEN, sig));
    ck_assert_ret_ok(crypto_sign_verify_detached(sig, desig, dlen,
                                                 me->signature.public));
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Ack tally: verified, sender-attributed, one vote per voter           */
/* ------------------------------------------------------------------ */

/* Drive a full round on ONE process: it receives the propose (recording the
 * pending round), then receives acks. Quorum is floor(num_peers/2). */
static void _propose_to(process_t *proc, identity_t *slasher,
                        const char *slasher_u, const char *rogue_u,
                        int64_t epoch)
{
    json_t *p = _slash_payload(slasher_u, rogue_u, "peer_exclude", 0.1, epoch);
    _dispatch(proc, slasher, SLASH_PROPOSE_FN, p);
    json_decref(p);
}

static void _ack(process_t *proc, identity_t *sender, const char *claimed,
                 const char *rogue_u, int64_t epoch, const char *sig_hex)
{
    json_t *p = json_object();
    json_object_set_new(p, "target_uuid", json_string(rogue_u));
    json_object_set_new(p, "epoch", json_integer(epoch));
    json_object_set_new(p, "signer_uuid", json_string(claimed));
    json_object_set_new(p, "signature", json_string(sig_hex));
    _dispatch(proc, sender, SLASH_SIGN_FN, p);
    json_decref(p);
}

DEFINE_TEST(test_replayed_ack_counts_once)
{
    /* THE C-specific defect: the tally was a bare count, so four deliveries of
     * one ack read as four votes and a single peer finalized alone. Three peers
     * put quorum at floor(3/2) = 1, so two distinct voters are needed — one
     * voter must never get there however often it speaks. */
    _begin(3);
    identity_t *me = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, carol);
    _add_peer(proc, rogue);

    char me_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char carol_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(carol->uuid, carol_u);
    _uuid_str(rogue->uuid, rogue_u);
    _propose_to(proc, bob, me_u, rogue_u, 5);
    g_slash_final_count = 0;   /* ignore anything the propose itself emitted */

    uint8_t desig[512];
    size_t dlen = _slash_desig(me_u, rogue_u, "peer_exclude", 0.1, 5, desig,
                               sizeof(desig));
    char bob_sig[SIG_HEX_LEN + 1], carol_sig[SIG_HEX_LEN + 1];
    _sign_hex(bob, desig, dlen, bob_sig);
    _sign_hex(carol, desig, dlen, carol_sig);

    for (int i = 0; i < 4; i++)
        _ack(proc, bob, bob_u, rogue_u, 5, bob_sig);
    ck_assert_uint_eq(g_slash_final_count, 0);   /* one voter, one vote */

    /* A SECOND distinct voter crosses quorum, so the round is not simply
     * stuck — the negative control for the control. */
    _ack(proc, carol, carol_u, rogue_u, 5, carol_sig);
    ck_assert(g_slash_final_count > 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_forged_ack_is_not_counted)
{
    _begin(2);
    identity_t *me = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, rogue);

    char me_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(rogue->uuid, rogue_u);
    _propose_to(proc, bob, me_u, rogue_u, 6);
    g_slash_final_count = 0;

    /* Quorum here is floor(2/2) = 1, so ONE good ack would finalize; this one
     * is signed over different bytes (a different floor). */
    uint8_t wrong[512];
    size_t wlen = _slash_desig(me_u, rogue_u, "peer_exclude", 0.9, 6, wrong,
                               sizeof(wrong));
    char bad_sig[SIG_HEX_LEN + 1];
    _sign_hex(bob, wrong, wlen, bad_sig);
    _ack(proc, bob, bob_u, rogue_u, 6, bad_sig);
    ck_assert_uint_eq(g_slash_final_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ack_claiming_another_voter_is_refused)
{
    _begin(2);
    identity_t *me = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, carol);

    char me_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char carol_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(carol->uuid, carol_u);
    _uuid_str(rogue->uuid, rogue_u);
    _propose_to(proc, bob, me_u, rogue_u, 7);
    g_slash_final_count = 0;

    /* Two peers put quorum at floor(2/2) = 1, so TWO distinct votes finalize.
     * bob supplies one legitimately and tries to manufacture the second by
     * relaying carol's GENUINE signature under carol's name — harvesting one is
     * easy, since every *_final broadcasts them. Crediting the payload's claim
     * would count both and finalize; crediting the authenticated sender counts
     * only bob's own, which is short. This is the case that distinguishes
     * attribution-by-sender from signature verification alone: the relayed
     * signature is perfectly valid FOR CAROL. */
    uint8_t desig[512];
    size_t dlen = _slash_desig(me_u, rogue_u, "peer_exclude", 0.1, 7, desig,
                               sizeof(desig));
    char carol_sig[SIG_HEX_LEN + 1], bob_sig[SIG_HEX_LEN + 1];
    _sign_hex(carol, desig, dlen, carol_sig);
    _sign_hex(bob, desig, dlen, bob_sig);
    _ack(proc, bob, carol_u, rogue_u, 7, carol_sig);   /* refused */
    _ack(proc, bob, bob_u, rogue_u, 7, bob_sig);       /* counted, one vote */
    ck_assert_uint_eq(g_slash_final_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Receiver-side enforcement on *_final                                 */
/* ------------------------------------------------------------------ */

static double _rep_of(identity_t *who)
{
    double out = -1.0;
    if (reputation_get_peer_reputation(who->uuid, &out) != 0)
        return -1.0;
    return out;
}

DEFINE_TEST(test_slash_final_without_signatures_refused)
{
    _begin(4);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);
    _add_peer(proc, carol);
    _add_peer(proc, rogue);

    char alice_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(alice->uuid, alice_u);
    _uuid_str(rogue->uuid, rogue_u);
    json_t *p = _slash_payload(alice_u, rogue_u, "peer_exclude", 0.0, 1);
    json_object_set_new(p, "sigs", json_object());
    _dispatch(proc, alice, SLASH_FINAL_FN, p);
    json_decref(p);

    /* No floor recorded: rogue is simply not in the reputation store. */
    ck_assert(_rep_of(rogue) < 0.0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_slash_final_with_quorum_applies_floor)
{
    _begin(4);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);
    _add_peer(proc, carol);
    _add_peer(proc, rogue);

    char alice_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char carol_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(alice->uuid, alice_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(carol->uuid, carol_u);
    _uuid_str(rogue->uuid, rogue_u);

    uint8_t desig[512];
    size_t dlen = _slash_desig(alice_u, rogue_u, "peer_exclude", 0.05, 1, desig,
                               sizeof(desig));
    char a_sig[SIG_HEX_LEN + 1], b_sig[SIG_HEX_LEN + 1], c_sig[SIG_HEX_LEN + 1];
    _sign_hex(alice, desig, dlen, a_sig);
    _sign_hex(bob, desig, dlen, b_sig);
    _sign_hex(carol, desig, dlen, c_sig);

    json_t *sigs = json_object();
    json_object_set_new(sigs, alice_u, json_string(a_sig));
    json_object_set_new(sigs, bob_u, json_string(b_sig));
    json_object_set_new(sigs, carol_u, json_string(c_sig));
    json_t *p = _slash_payload(alice_u, rogue_u, "peer_exclude", 0.05, 1);
    json_object_set_new(p, "sigs", sigs);
    _dispatch(proc, alice, SLASH_FINAL_FN, p);
    json_decref(p);

    ck_assert_double_eq_tol(_rep_of(rogue), 0.05, 1e-9);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_slash_final_forged_signature_map_refused)
{
    /* The right SIZE, all of it minted by the sender: only its own entry
     * verifies, which is under quorum. */
    _begin(4);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    identity_t *rogue = _mk_identity("rogue", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);
    _add_peer(proc, carol);
    _add_peer(proc, rogue);

    char alice_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char carol_u[UUID_STRING_LEN + 1], rogue_u[UUID_STRING_LEN + 1];
    _uuid_str(alice->uuid, alice_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(carol->uuid, carol_u);
    _uuid_str(rogue->uuid, rogue_u);

    uint8_t desig[512];
    size_t dlen = _slash_desig(alice_u, rogue_u, "peer_exclude", 0.0, 2, desig,
                               sizeof(desig));
    char a_sig[SIG_HEX_LEN + 1];
    _sign_hex(alice, desig, dlen, a_sig);

    json_t *sigs = json_object();
    json_object_set_new(sigs, alice_u, json_string(a_sig));
    json_object_set_new(sigs, bob_u, json_string(a_sig));    /* alice's, labelled bob */
    json_object_set_new(sigs, carol_u, json_string(a_sig));  /* and carol */
    json_t *p = _slash_payload(alice_u, rogue_u, "peer_exclude", 0.0, 2);
    json_object_set_new(p, "sigs", sigs);
    _dispatch(proc, alice, SLASH_FINAL_FN, p);
    json_decref(p);

    ck_assert(_rep_of(rogue) < 0.0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_final_unattested_root_refused)
{
    /* This root is what _verify_slash_evidence measures evidence against, so
     * accepting an unattested one hands the accuser the anchor. */
    _begin(4);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);
    _add_peer(proc, carol);

    char alice_u[UUID_STRING_LEN + 1];
    _uuid_str(alice->uuid, alice_u);
    const char *root =
        "044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556";
    json_t *p = json_object();
    json_object_set_new(p, "proposer_uuid", json_string(alice_u));
    json_object_set_new(p, "root", json_string(root));
    json_object_set_new(p, "epoch", json_integer(3));
    json_object_set_new(p, "first_index", json_integer(0));
    json_object_set_new(p, "count", json_integer(3));
    json_object_set_new(p, "sigs", json_object());
    _dispatch(proc, alice, CHECKPOINT_FINAL_FN, p);
    json_decref(p);

    char stored[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_checkpoint_root(stored);
    ck_assert_str_eq(stored, "");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_final_with_quorum_stores_root)
{
    _begin(4);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);
    _add_peer(proc, carol);

    char alice_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    char carol_u[UUID_STRING_LEN + 1];
    _uuid_str(alice->uuid, alice_u);
    _uuid_str(bob->uuid, bob_u);
    _uuid_str(carol->uuid, carol_u);
    const char *root =
        "044ff20acbca5c0d93e083ddc7f5cefbe404271250de10d0a15dd8e50d847556";

    uint8_t desig[512];
    size_t dlen = _ckpt_desig(alice_u, root, 4, 0, 3, desig, sizeof(desig));
    char a_sig[SIG_HEX_LEN + 1], b_sig[SIG_HEX_LEN + 1], c_sig[SIG_HEX_LEN + 1];
    _sign_hex(alice, desig, dlen, a_sig);
    _sign_hex(bob, desig, dlen, b_sig);
    _sign_hex(carol, desig, dlen, c_sig);

    json_t *sigs = json_object();
    json_object_set_new(sigs, alice_u, json_string(a_sig));
    json_object_set_new(sigs, bob_u, json_string(b_sig));
    json_object_set_new(sigs, carol_u, json_string(c_sig));
    json_t *p = json_object();
    json_object_set_new(p, "proposer_uuid", json_string(alice_u));
    json_object_set_new(p, "root", json_string(root));
    json_object_set_new(p, "epoch", json_integer(4));
    json_object_set_new(p, "first_index", json_integer(0));
    json_object_set_new(p, "count", json_integer(3));
    json_object_set_new(p, "sigs", sigs);
    _dispatch(proc, alice, CHECKPOINT_FINAL_FN, p);
    json_decref(p);

    char stored[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_checkpoint_root(stored);
    ck_assert_str_eq(stored, root);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_originated_round_tallies_a_peer_ack_to_quorum)
{
    /* The round we originate has to be FINDABLE by the ack handler.
     * _originate_checkpoint records the pending round and seeds its own
     * co-signature under a key that carries the chain; handle_checkpoint_sign
     * has to build the same key to tally against it. While the two disagreed
     * (originator keying "<proposer>:<epoch>:<chain>", the handler
     * "<proposer>:<epoch>"), every ack to a checkpoint THIS node proposed was
     * dropped as "not our round", so a self-originated checkpoint could never
     * reach quorum -- silently, since the proposer had already self-stored the
     * lone-signature version.
     *
     * The observable is therefore the checkpoint_final EMISSION, not the stored
     * root: origination stores the root by itself, and only quorum broadcasts.
     * Two peers puts quorum at 1, so the seeded self-signature plus one ack is
     * exactly the boundary. checkpoint_final is addressed per peer, so quorum
     * shows up as one emission per peer rather than a single broadcast. */
    _begin(3);
    identity_t *me = _mk_identity("dave", "10.0.0.4");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, carol);

    /* A window worth attesting; a checkpoint over nothing is skipped upstream. */
    uuid_t task;
    uuid_generate(task);
    reputation_install_tx_pair(task, me->uuid, 0.8, bob->uuid, 0.8);

    char me_u[UUID_STRING_LEN + 1], bob_u[UUID_STRING_LEN + 1];
    _uuid_str(me->uuid, me_u);
    _uuid_str(bob->uuid, bob_u);

    char root[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_window_root(root);
    ck_assert(root[0] != '\0');
    int count = reputation_get_committed_tx_count();

    reputation_force_checkpoint(proc, me_u, "");   /* epoch 1 on a fresh slot */
    ck_assert(g_ckpt_final_count == 0);            /* one signature is not quorum */

    /* bob co-signs the same bytes the proposer signed: no group element,
     * because this is the primary chain. */
    uint8_t desig[512];
    size_t dlen = _ckpt_desig(me_u, root, 1, 0, count, desig, sizeof(desig));
    char b_sig[SIG_HEX_LEN + 1];
    _sign_hex(bob, desig, dlen, b_sig);

    json_t *p = json_object();
    json_object_set_new(p, "proposer_uuid", json_string(me_u));
    json_object_set_new(p, "epoch", json_integer(1));
    json_object_set_new(p, "signer_uuid", json_string(bob_u));
    json_object_set_new(p, "signature", json_string(b_sig));
    _dispatch(proc, bob, CHECKPOINT_SIGN_FN, p);
    json_decref(p);

    ck_assert(g_ckpt_final_count == proc->protocol.num_peers);

    char stored[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_checkpoint_root(stored);
    ck_assert_str_eq(stored, root);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cosign_of_a_child_group_round_uses_the_proposers_chain_name)
{
    /* A gateway checkpoints a child group G and broadcasts to G's members. For
     * a MEMBER of G, G is its own primary group, so _chain_key(G) resolves to
     * "" -- correct for picking which window to compare, and wrong for both the
     * signed bytes and the ack, because the proposer never said "". Signing the
     * resolved name made the member's co-signature verify nowhere on the
     * proposer, so a child-group checkpoint could not reach quorum across the
     * boundary doc/architecture/gateway-reputation-tree.md exists to cross. */
    _begin(2);
    identity_t *me = _mk_identity("member", "10.0.0.5");
    identity_t *gateway = _mk_identity("gateway", "10.0.0.1");
    process_t *proc = _mk_process(me);
    _add_peer(proc, gateway);

    /* Our primary group IS the group the proposal names. */
    uuid_t group_uuid;
    uuid_generate(group_uuid);
    memcpy(proc->protocol.group.uuid, group_uuid, sizeof(uuid_t));
    char group_u[UUID_STRING_LEN + 1];
    _uuid_str(group_uuid, group_u);

    uuid_t task;
    uuid_generate(task);
    reputation_install_tx_pair(task, me->uuid, 0.8, gateway->uuid, 0.8);

    char gw_u[UUID_STRING_LEN + 1];
    _uuid_str(gateway->uuid, gw_u);
    char root[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_window_root(root);
    int count = reputation_get_committed_tx_count();

    json_t *p = json_object();
    json_object_set_new(p, "proposer_uuid", json_string(gw_u));
    json_object_set_new(p, "root", json_string(root));
    json_object_set_new(p, "epoch", json_integer(2));
    json_object_set_new(p, "first_index", json_integer(0));
    json_object_set_new(p, "count", json_integer(count));
    json_object_set_new(p, "group_uuid", json_string(group_u));
    _dispatch(proc, gateway, CHECKPOINT_PROPOSE_FN, p);
    json_decref(p);

    /* Our window matched, so we co-signed exactly once ... */
    ck_assert_uint_eq(g_ckpt_sign_count, 1);
    /* ... the ack echoes the chain AS THE PROPOSER NAMED IT ... */
    ck_assert(g_last_ckpt_had_group);
    ck_assert_str_eq(g_last_ckpt_group, group_u);
    /* ... and the signature verifies over the designation carrying that same
     * name, which is the one the proposer will check it against. */
    uint8_t desig[512];
    size_t dlen = _ckpt_desig_g(gw_u, root, 2, 0, count, group_u, desig,
                                sizeof(desig));
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_uint_eq(strlen(g_last_ckpt_sig), SIG_HEX_LEN);
    ck_assert_ret_ok(unhexlify((const unsigned char *)g_last_ckpt_sig,
                               SIG_HEX_LEN, sig));
    ck_assert_ret_ok(crypto_sign_verify_detached(sig, desig, dlen,
                                                 me->signature.public));
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepQuorum,
          test_slash_designation_bytes_pinned,
          test_checkpoint_designation_bytes_pinned,
          test_cosign_ack_names_self_and_carries_verifiable_signature,
          test_replayed_ack_counts_once,
          test_forged_ack_is_not_counted,
          test_ack_claiming_another_voter_is_refused,
          test_slash_final_without_signatures_refused,
          test_slash_final_with_quorum_applies_floor,
          test_slash_final_forged_signature_map_refused,
          test_checkpoint_final_unattested_root_refused,
          test_checkpoint_final_with_quorum_stores_root,
          test_originated_round_tallies_a_peer_ack_to_quorum,
          test_cosign_of_a_child_group_round_uses_the_proposers_chain_name)
