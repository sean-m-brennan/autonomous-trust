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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include <jansson.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "identity/id_proc_priv.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "structures/array.h"
#include "structures/data.h"

/*
 * Corresponds to Python tests/a_unit/test_partition_recovery.py.
 *
 * The Python tests build a minimal IdentityProcess via object.__new__ and
 * call the handler methods directly. The handlers here are static, but they
 * are reachable the way the process itself reaches them — through the
 * registered handler map, via run_message_handlers — and outbound messages
 * are observable through the messaging test hook. So this file covers:
 *
 *   1. Canonical signature inputs match Python's byte format (the
 *      cross-impl-interop requirement). Without this, Python peers and
 *      C peers exchange probe/response messages whose signatures don't
 *      verify on the other side.
 *   2. Ed25519 sign + hex + verify round-trip works against the
 *      canonical inputs. Both peers use the same primitives
 *      (libsodium's crypto_sign_detached + hex), so a round-trip in C
 *      that uses the same byte input + key serialization as Python is
 *      sufficient evidence of interop.
 *   3. Partition-recovery state (id_state.partition_*) clears on
 *      identity_reset_state.
 *   4. Replay refusal on both partition verbs, driven through the real
 *      handlers — the twins of Python's `test_replayed_probe_refused` and
 *      `test_replayed_response_refused_within_round`. These are the tests
 *      that prove the FRESHNESS MARK refuses a replay, as distinct from the
 *      cooldown and in-flight guards that would refuse it anyway for their
 *      own reasons; each of those is cleared between deliveries so the mark
 *      is the only thing left that can say no.
 *
 * The probe → response → request_access chain in aggregate is exercised
 * end-to-end through the conformance corpus scenarios.
 */

DEFINE_TEST(test_canonical_probe_matches_python_format)
{
    /* Python: ('%s|%s|%d' % (uuid, int(size), int(seq))).encode('utf-8')
     *
     * The trailing seq is the prober's freshness sequence, and it is inside
     * the signed bytes: without it the pre-image covered only the uuid and
     * size, neither of which changes between rounds, so a captured probe was
     * replayable indefinitely. */
    char out[128] = {0};
    int n = identity_partition_canonical_probe(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 1, 42, out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out, "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7|1|42");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_probe_zero_size)
{
    char out[128] = {0};
    int n = identity_partition_canonical_probe(
        "00000000-0000-0000-0000-000000000000", 0, 1, out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out, "00000000-0000-0000-0000-000000000000|0|1");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_probe_overflow_rejected)
{
    char out[8];  /* too small */
    int n = identity_partition_canonical_probe(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 1, 1, out, sizeof(out));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_response_matches_python_format)
{
    /* Python: ('%s|%s|%s|%d|%d' % (group_uuid, int(size), in_response_to,
     *                               int(probe_seq), int(seq))).encode('utf-8')
     *
     * probe_seq echoes the probe round being answered — in_response_to is only
     * the prober's uuid, which never changes, so it cannot distinguish an
     * answer to the current round from one captured earlier. seq is the
     * responder's own sequence. */
    char out[256] = {0};
    int n = identity_partition_canonical_response(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 5,
        "5a475006-904d-4cb8-9055-397f01931ca5", 7, 9,
        out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out,
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7|5|5a475006-904d-4cb8-9055-397f01931ca5|7|9");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_sign_verify_roundtrip_with_canonical_input)
{
    /* Build a canonical probe input, sign it with an identity's private
     * key, hex-encode, then verify via the public key. This mirrors
     * what the Python and C handlers do over the wire — if both sides
     * agree on canonical bytes + ed25519 + hex, the cross-impl
     * signature check works. */
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.3";
    char name[] = "coord";
    char nick[] = "coord";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, &ident));

    char group_uuid_str[] = "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7";
    int group_size = 1;
    char canonical[128];
    int clen = identity_partition_canonical_probe(
        group_uuid_str, group_size, 1, canonical, sizeof(canonical));
    ck_assert(clen > 0);

    /* Sign — detached, 64 raw bytes. */
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_ret_ok(crypto_sign_detached(sig, NULL,
                                          (unsigned char *)canonical,
                                          (size_t)clen,
                                          ident->signature.private));

    /* Hex-encode (128 ASCII chars + NUL). */
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
    ck_assert_int_eq(strlen(sig_hex), crypto_sign_BYTES * 2);

    /* Publish and decode the public-identity-only form (mimics what
     * the receiver of a probe would do — parse the embedded
     * from_identity object from JSON). */
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);

    /* Verify — happy path. */
    unsigned char sig_decoded[crypto_sign_BYTES];
    ck_assert_ret_ok(unhexlify((unsigned char *)sig_hex,
                               crypto_sign_BYTES * 2, sig_decoded));
    ck_assert_ret_ok(crypto_sign_verify_detached(sig_decoded,
                                                 (unsigned char *)canonical,
                                                 (size_t)clen,
                                                 pub->signature.public));

    /* Tampered canonical — must fail. */
    char tampered[128];
    snprintf(tampered, sizeof(tampered), "%s|%d", group_uuid_str,
             group_size + 1);
    ck_assert(crypto_sign_verify_detached(sig_decoded,
                                          (unsigned char *)tampered,
                                          strlen(tampered),
                                          pub->signature.public) != 0);

    smrt_deref(pub);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_partition_state_clears_on_reset)
{
    /* identity_reset_state must purge partition_recovery_target so a
     * fresh scenario doesn't inherit stale in-flight state. */
    char target[64];

    /* Force initialization. */
    identity_reset_state();
    size_t n = identity_get_partition_recovery_target(target,
                                                       sizeof(target));
    ck_assert_int_eq(n, 0);
    ck_assert_str_eq(target, "");

    /* (We can't easily *set* the state without going through
     * handle_partition_response — which needs a process_t + queues.
     * The reset behavior on an already-clean state is the most we can
     * cover from here; the set-then-reset path is exercised by the
     * conformance corpus.) */
}
END_TEST_DEFINITION()


/****************************
 * Handler-driving harness
 *
 * Enough of a process to run the partition handlers, plus a send hook to see
 * what they emit. Kept local to this file rather than shared with
 * app_events_test.c: that file's harness counts by message TYPE, and what
 * matters here is the protocol FUNCTION on the net_msg.
 ****************************/

#define MAX_SENT 16

static generic_msg_t sent[MAX_SENT];
static int num_sent;

static int _send_hook(const char *key, const message_type_t type,
                      generic_msg_t *msg, bool blocking)
{
    (void)key; (void)type; (void)blocking;
    if (num_sent < MAX_SENT && msg != NULL)
        memcpy(&sent[num_sent++], msg, sizeof(*msg));
    /* 0 = accepted. Returning a failure here would send _announce_identity
     * into its 20 x 100ms retry loop. */
    return 0;
}

static void sent_reset(void)
{
    memset(sent, 0, sizeof(sent));
    num_sent = 0;
    messaging_set_test_hook(_send_hook);
}

static void sent_done(void)
{
    messaging_set_test_hook(NULL);
}

/* How many emitted messages carried this protocol function. */
static int count_fn(const char *fn)
{
    int n = 0;
    for (int i = 0; i < num_sent; i++) {
        const char *f = sent[i].info.net_msg.function;
        if (f != NULL && strcmp(f, fn) == 0) n++;
    }
    return n;
}

/* A receiver able to run the partition handlers.
 *
 * Three things the handlers require and a zeroed process_t does not have: a
 * registered handler map (they are static, so dispatch is the only way in),
 * its own identity under the "identity" key of proc->configs (where
 * _partition_self_identity looks — without it the handlers treat the node as
 * mid-bootstrap and silently emit nothing), and a group whose address_map
 * size is the "our size" every adoption comparison reads. */
static void make_receiver(process_t *proc, identity_t **self_out,
                          size_t group_size)
{
    ck_assert(sodium_init() >= 0);
    memset(proc, 0, sizeof(*proc));
    snprintf(proc->name, sizeof(proc->name), "identity");
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    ck_assert_int_eq(map_create(&proc->protocol.handlers), 0);
    proc->protocol.phase = 3;
    ck_assert_ret_ok(identity_register_handlers(proc));

    uuid_t self_uuid;
    uuid_generate(self_uuid);
    char addr[] = "10.0.0.10";
    char name[] = "captain";
    identity_t *self = NULL;
    ck_assert_ret_ok(identity_create(&self_uuid, addr, name, name, &self));
    ck_assert_ptr_nonnull(self);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ptr_nonnull(id_dat);
    ck_assert_int_eq(map_create(&proc->configs), 0);
    ck_assert_int_eq(map_set(proc->configs, (map_key_t)"identity", id_dat), 0);

    /* Our own group. Members beyond ourselves are filler uuids: only the
     * address_map's SIZE is read. */
    uuid_t guuid;
    uuid_generate(guuid);
    char gaddr[] = "239.8.0.1";
    ck_assert_ret_ok(group_init(&guuid, gaddr, &proc->protocol.group));
    char self_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, self_uuid_str);
    group_add_address(&proc->protocol.group, self_uuid_str, addr);
    for (size_t i = 1; i < group_size; i++) {
        uuid_t filler;
        uuid_generate(filler);
        char fu[UUID_STRING_LEN + 1];
        uuid_unparse_lower(filler, fu);
        char faddr[ADDR_LEN + 1];
        snprintf(faddr, sizeof(faddr), "10.0.0.%zu", 100 + i);
        group_add_address(&proc->protocol.group, fu, faddr);
    }
    ck_assert_int_eq((int)map_size(&proc->protocol.group.address_map),
                     (int)group_size);

    *self_out = self;
}

static void free_receiver(process_t *proc, identity_t *self)
{
    if (proc->protocol.handlers != NULL) map_free(proc->protocol.handlers);
    pthread_rwlock_destroy(&proc->protocol.peers_rwlock);
    identity_free(self);
    /* proc->configs and its config_t are left as the conformance adapter's
     * _free_participant_impl leaves them: whether map_free also releases the
     * object a data_t wraps is not something this file should be guessing at,
     * and the alternative risks a double free. Bounded by the test binary's
     * lifetime. */
}

/* Release the payload net_msg_pack_json attached to a crafted message. */
static void free_crafted(generic_msg_t *msg)
{
    if (msg->info.net_msg.obj != NULL) {
        smrt_deref(msg->info.net_msg.obj);
        msg->info.net_msg.obj = NULL;
        msg->info.net_msg.len = 0;
    }
}

/* A queue directory naming "network", which _announce_identity requires
 * before it will send anything at all (EID_NOQ otherwise). */
static void queues_with_network(directory_t *queues)
{
    ck_assert_int_eq(array_init(queues), 0);
    static char net_name[] = "network";
    data_t *net = string_data(net_name, strlen(net_name));
    ck_assert_ptr_nonnull(net);
    ck_assert_int_eq(array_append(queues, net), 0);
}

/* Sign `canonical` with `signer` and hex-encode, the way both runtimes do. */
static void sign_hex(const identity_t *signer, const char *canonical,
                     size_t clen, char out_hex[129])
{
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_ret_ok(crypto_sign_detached(sig, NULL,
                                          (const unsigned char *)canonical,
                                          clen, signer->signature.private));
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)out_hex);
}

/* A validly signed partition_probe advertising `group_uuid`/`group_size` at
 * freshness sequence `seq`. */
static void craft_probe(const identity_t *sender,
                        const public_identity_t *sender_pub,
                        const char *group_uuid, int group_size, int64_t seq,
                        generic_msg_t *out)
{
    char canonical[UUID_STRING_LEN + 64];
    int clen = identity_partition_canonical_probe(group_uuid, group_size, seq,
                                                  canonical,
                                                  sizeof(canonical));
    ck_assert(clen > 0);
    char sig_hex[129];
    sign_hex(sender, canonical, (size_t)clen, sig_hex);

    json_t *from_id = NULL;
    ck_assert_int_eq(public_identity_to_json(sender_pub, &from_id), 0);
    json_t *body = json_object();
    json_object_set_new(body, "from_identity", from_id);
    json_object_set_new(body, "from_address", json_string(sender_pub->address));
    json_object_set_new(body, "my_group_uuid", json_string(group_uuid));
    json_object_set_new(body, "my_group_size", json_integer(group_size));
    json_object_set_new(body, "seq", json_integer((json_int_t)seq));
    json_object_set_new(body, "signature", json_string(sig_hex));

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    snprintf(out->info.net_msg.process, PROC_NAME_LEN, "identity");
    out->info.net_msg.function = (char *)"group_partition_probe";
    memcpy(&out->info.net_msg.from_whom, sender_pub,
           sizeof(public_identity_t));
    ck_assert_int_eq(net_msg_pack_json(&out->info.net_msg, body), 0);
    json_decref(body);
}

/* A validly signed partition_response answering `in_response_to` (the
 * prober's uuid) in round `probe_seq`, at the responder's own `seq`. */
static void craft_response(const identity_t *sender,
                           const public_identity_t *sender_pub,
                           const char *group_uuid, int group_size,
                           const char *in_response_to,
                           int64_t probe_seq, int64_t seq,
                           generic_msg_t *out)
{
    char canonical[UUID_STRING_LEN * 2 + 96];
    int clen = identity_partition_canonical_response(
        group_uuid, group_size, in_response_to, probe_seq, seq,
        canonical, sizeof(canonical));
    ck_assert(clen > 0);
    char sig_hex[129];
    sign_hex(sender, canonical, (size_t)clen, sig_hex);

    json_t *from_id = NULL;
    ck_assert_int_eq(public_identity_to_json(sender_pub, &from_id), 0);
    json_t *body = json_object();
    json_object_set_new(body, "from_identity", from_id);
    json_object_set_new(body, "from_address", json_string(sender_pub->address));
    json_object_set_new(body, "in_response_to", json_string(in_response_to));
    json_object_set_new(body, "in_response_to_seq",
                        json_integer((json_int_t)probe_seq));
    json_object_set_new(body, "my_group_uuid", json_string(group_uuid));
    json_object_set_new(body, "my_group_size", json_integer(group_size));
    json_object_set_new(body, "my_group_leader", json_string(group_uuid));
    json_object_set_new(body, "my_group_leader_address",
                        json_string(sender_pub->address));
    json_object_set_new(body, "seq", json_integer((json_int_t)seq));
    json_object_set_new(body, "signature", json_string(sig_hex));

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    snprintf(out->info.net_msg.process, PROC_NAME_LEN, "identity");
    out->info.net_msg.function = (char *)"group_partition_response";
    memcpy(&out->info.net_msg.from_whom, sender_pub,
           sizeof(public_identity_t));
    ck_assert_int_eq(net_msg_pack_json(&out->info.net_msg, body), 0);
    json_decref(body);
}

/* Twin of Python test_replayed_probe_refused.
 *
 * Before the freshness sequence the probe pre-image covered only the group
 * uuid and size, so a captured probe — plaintext multicast, no prior access
 * needed — could be re-presented indefinitely, and each replay drove the
 * responder's work. The cooldown only ever narrowed that to one per window
 * per prober, which is why it is cleared between every delivery below: with
 * it out of the way, the mark is the only thing that can refuse. */
DEFINE_TEST(test_replayed_probe_refused)
{
    sent_reset();
    identity_reset_state();

    process_t proc;
    identity_t *self = NULL;
    /* Our group is the LARGER one (3 vs the probed 1), so the handler
     * responds and never takes the adopt-from-probe branch — the count below
     * is then unambiguous. */
    make_receiver(&proc, &self, 3);
    directory_t queues = {0};
    queues_with_network(&queues);

    uuid_t sender_uuid;
    uuid_generate(sender_uuid);
    char sender_addr[] = "10.0.0.3";
    char sender_name[] = "probing-coord";
    identity_t *sender = NULL;
    ck_assert_ret_ok(identity_create(&sender_uuid, sender_addr, sender_name,
                                      sender_name, &sender));
    public_identity_t *sender_pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &sender_pub));

    generic_msg_t probe;
    craft_probe(sender, sender_pub, "0b000000-0000-4000-8000-000000000002", 1,
                7, &probe);
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &probe));
    ck_assert_int_eq(count_fn("group_partition_response"), 1);

    /* The exact same round again. */
    identity_clear_partition_cooldowns();
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &probe));
    ck_assert_int_eq(count_fn("group_partition_response"), 1);

    /* An OLDER round from the same prober is refused too, not just an exact
     * repeat — the mark is a high-water mark, not a last-seen comparison. */
    identity_clear_partition_cooldowns();
    generic_msg_t older;
    craft_probe(sender, sender_pub, "0c000000-0000-4000-8000-000000000003", 1,
                6, &older);
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &older));
    ck_assert_int_eq(count_fn("group_partition_response"), 1);

    /* A NEWER round is still answered: the guard bounds replay, not
     * legitimate re-probing. */
    identity_clear_partition_cooldowns();
    generic_msg_t newer;
    craft_probe(sender, sender_pub, "0d000000-0000-4000-8000-000000000004", 1,
                8, &newer);
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &newer));
    ck_assert_int_eq(count_fn("group_partition_response"), 2);

    free_crafted(&probe);
    free_crafted(&older);
    free_crafted(&newer);
    smrt_deref(sender_pub);
    identity_free(sender);
    array_free(&queues);
    free_receiver(&proc, self);
    sent_done();
}
END_TEST_DEFINITION()

/* Twin of Python test_replayed_response_refused_within_round.
 *
 * Two presentations of one response drive one adoption. The echoed round
 * bounds a response to the probe it answers; this mark bounds a responder to
 * one answer inside that round. The in-flight recovery marker would refuse
 * the second delivery on its own, so it is cleared in between. */
DEFINE_TEST(test_replayed_response_refused_within_round)
{
    sent_reset();
    identity_reset_state();

    process_t proc;
    identity_t *self = NULL;
    /* Size 1, so the size-5 group the response advertises is strictly larger
     * and adoption fires — which is what emits the request_access counted
     * below. */
    make_receiver(&proc, &self, 1);
    directory_t queues = {0};
    queues_with_network(&queues);

    /* We are treated as running probe round 4; the response must echo it. */
    identity_set_partition_probe_round(4);

    uuid_t responder_uuid;
    uuid_generate(responder_uuid);
    char responder_addr[] = "10.0.0.11";
    char responder_name[] = "captain-b";
    identity_t *responder = NULL;
    ck_assert_ret_ok(identity_create(&responder_uuid, responder_addr,
                                      responder_name, responder_name,
                                      &responder));
    public_identity_t *responder_pub = NULL;
    ck_assert_ret_ok(identity_publish(responder, &responder_pub));

    char self_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid_str);

    generic_msg_t resp;
    craft_response(responder, responder_pub,
                   "0a000000-0000-4000-8000-000000000001", 5, self_uuid_str,
                   4, 9, &resp);
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &resp));
    ck_assert_int_eq(count_fn("request_access"), 1);

    /* Same response again, with the in-flight guard out of the way. */
    identity_clear_partition_recovery();
    ck_assert(run_message_handlers(&proc, &queues, NET_MESSAGE, &resp));
    ck_assert_int_eq(count_fn("request_access"), 1);

    free_crafted(&resp);
    smrt_deref(responder_pub);
    identity_free(responder);
    array_free(&queues);
    free_receiver(&proc, self);
    sent_done();
}
END_TEST_DEFINITION()

RUN_TESTS(PartitionRecovery,
          test_canonical_probe_matches_python_format,
          test_canonical_probe_zero_size,
          test_canonical_probe_overflow_rejected,
          test_canonical_response_matches_python_format,
          test_sign_verify_roundtrip_with_canonical_input,
          test_partition_state_clears_on_reset,
          test_replayed_probe_refused,
          test_replayed_response_refused_within_round)
