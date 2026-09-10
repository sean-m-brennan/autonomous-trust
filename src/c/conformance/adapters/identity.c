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

/** @file Identity-protocol adapter.
 *
 *  Builds participants, installs the messaging_send test hook, and drives
 *  the universal scenario_engine. The adapter's only protocol-specific
 *  responsibilities are participant construction (per-id `process_t`
 *  instantiation + handler registration) and inbound construction (turn a
 *  scenario step into a `generic_msg_t` the C handler can dispatch).
 *
 *  Phase C: both amnesia-readmission and new-node-admission run end-to-
 *  end. The adapter flips `identity_set_synchronous_dispatch(true)` on
 *  the file-scope id_state so welcoming_committee inline-finalizes (no
 *  inbound vote messages required) and emits propose_peer / peer_accepted
 *  as one broadcast each — mirroring Python's group-targeted sends.
 */

#include "identity.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"   /* hexlify / public_identity_to_json */
#include "identity/id_proc_priv.h"
#include "utilities/util.h"
#include "identity/group.h"           /* group_init / group_add_address */
#include "config/configuration.h"     /* config_t (proc->configs["identity"]) */
#include "structures/data.h"          /* object_ptr_data */
#ifdef AT_ZTA_ENABLED
#include <openssl/evp.h>              /* scenario-time operator-binding signing */
#include <openssl/pem.h>
#include "zta/zta_policy.h"           /* zta_policy_t / defaults / from_json */
#include "zta/zta_binding.h"          /* credential->identity binding
# (doc/architecture/zta-integration.md) */
#endif
#include "network/net_message.h"
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"
#include "contacts/contacts.h"
#include "identity/first_contact.h"

#include "../negative_runner.h"
#include "../scenario_engine.h"

/* Provided by runner.c; needed for kind:negative case dispatch to resolve
 * based_on references inside the JSON corpus mirror. */
extern const char *at_runner_corpus_json_root(void);

/* ------------------------------------------------------------------------- */
/* Per-participant impl carries a process_t plus a public_identity_t copy    */
/* for the to_whom→id resolution path.                                        */
/* ------------------------------------------------------------------------- */

typedef struct {
    identity_t *full;
    public_identity_t *pub;
    process_t *proc;
    /* The scenario's participant id, so a result can be reported under the name
     * the scenario uses rather than a uuid. */
    char id[SCE_ID_LEN];
    /* Result of a trigger_subtree_roster enumeration: a json array of the
     * flattened subtree's member participant ids (sorted). Read by the
     * subtree_roster expected-state check. Mirrors the Python adapter's
     * _Participant.subtree_roster. */
    json_t *subtree_roster;
    /* Result of trigger_hierarchy: the DERIVED parent gateway as a participant
     * id, or "" for a node that tops its own cohort. Mirrors the Python
     * adapter's _Participant.parent_gateway_pid. */
    char parent_gateway_pid[SCE_ID_LEN];
    /* Results of trigger_attest_pull / trigger_attest_replay with this
     * participant as the PULLER (ethne D8/Q9): the attested-now stamp the last
     * ACCEPTED pull yielded, the accept/reject verdict of each pull in order,
     * and the last answer kept so a replay can re-present it. Mirrors the
     * Python adapter's _Participant.attest_* fields. */
    double attest_stamp;
    json_t *attest_accepted;    /* json array of booleans */
    json_t *attest_last_answer;
    double attest_clock;        /* pinned clock from operator_session / clocks */
    /* Cohort clock samples this participant MEASURED as the puller, keyed by
     * the TARGET's participant id so expected_state can name a peer
     * language-agnostically. Values are {offset, delay, usable} read out of the
     * production handler's store (identity_get_peer_clock_sample) -- the
     * adapter relabels, it does not compute. Mirrors the Python adapter's
     * _Participant.attest_clock_samples.
     * See doc/architecture/cohort-clock-skew.md. */
    json_t *attest_clock_samples;
    /* Where trigger_first_contact_initiate actually addressed its hello: the
     * host on the outbound to_whom, recorded by _send_hook. Read by the
     * first_contact_hello_endpoint check, which pins that `initiate` prefers
     * the invitation's rendezvous hint over the inviter's advertised address.
     * Mirrors the Python adapter's _Participant.fc_hello_endpoint. */
    char fc_hello_endpoint[ADDR_LEN + 1];
} ic_impl_t;

/* The engine ctx is global because the messaging-hook signature has no
 * void* context; one scenario runs at a time. */
static sce_run_ctx_t *g_active_ctx = NULL;

/* Scan ctx->participants for a uuid match — the messaging hook gets a
 * net_msg.to_whom (public_identity_t) and needs to map back to a
 * participant id.
 *
 * Identity protocol's `peer_accepted` and `propose_peer` are conceptually
 * group broadcasts (Python sends each as a single `to_whom=self.group`
 * Message). In synchronous_dispatch mode the C implementation now also
 * emits one broadcast per call, with a zeroed to_whom — `is_broadcast`
 * detects that. Either way we surface them as "broadcast" so cross-
 * language scenarios match. */
static bool _is_zero_uuid(const uuid_t u) {
    for (size_t i = 0; i < sizeof(uuid_t); i++)
        if (u[i] != 0) return false;
    return true;
}

static const char *_resolve_to_id(const generic_msg_t *msg) {
    if (msg->type != NET_MESSAGE) return "internal";
    const char *fn = msg->info.net_msg.function;
    if (fn != NULL
        && (strcmp(fn, "peer_accepted") == 0
            || strcmp(fn, "propose_peer") == 0)) {
        return "broadcast";
    }
    if (_is_zero_uuid(msg->info.net_msg.to_whom.uuid)) {
        return "broadcast";
    }
    if (g_active_ctx == NULL) return "unknown";
    for (size_t i = 0; i < g_active_ctx->participant_count; i++) {
        ic_impl_t *impl = (ic_impl_t *)g_active_ctx->participants[i].impl;
        if (impl == NULL || impl->pub == NULL) continue;
        if (uuid_compare(impl->pub->uuid, msg->info.net_msg.to_whom.uuid) == 0) {
            return g_active_ctx->participants[i].id;
        }
    }
    return "unknown";
}

static int _send_hook(const char *key,
                      const message_type_t type,
                      generic_msg_t *msg,
                      bool blocking) {
    (void)key; (void)blocking;
    if (g_active_ctx == NULL) return 0;
    const char *to_id = _resolve_to_id(msg);
    const char *function = (type == NET_MESSAGE && msg->info.net_msg.function != NULL)
        ? msg->info.net_msg.function : "__internal__";
    /* A first-contact hello carries WHERE it was addressed, which the captured
     * (from, to, function) triple does not. Recorded against the emitter so
     * first_contact_hello_endpoint can pin the resolution order `initiate`
     * used. */
    if (type == NET_MESSAGE && strcmp(function, ID_FC_HELLO) == 0) {
        for (size_t i = 0; i < g_active_ctx->participant_count; i++) {
            if (strcmp(g_active_ctx->participants[i].id,
                       g_active_ctx->current_dispatcher) != 0)
                continue;
            ic_impl_t *emitter = (ic_impl_t *)g_active_ctx->participants[i].impl;
            if (emitter != NULL)
                at_strlcpy(emitter->fc_hello_endpoint,
                           msg->info.net_msg.to_whom.address,
                           sizeof(emitter->fc_hello_endpoint));
            break;
        }
    }
    sce_capture(g_active_ctx, to_id, function);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Participant construction                                                    */
/* ------------------------------------------------------------------------- */

static int _make_identity(const char *id, size_t idx, identity_t **out) {
    uuid_t uuid;
    crypto_generichash(uuid, sizeof(uuid_t),
                       (const unsigned char *)id, strlen(id), NULL, 0);
    /* Cosmetic v4-shaped uuid: clearer in logs than raw hash bytes. */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    char addr[ADDR_LEN + 1] = {0};
    snprintf(addr, sizeof(addr), "10.0.70.%zu", idx + 1);
    char nickname[NAME_LEN + 1] = {0};
    snprintf(nickname, sizeof(nickname), "%s.scenario", id);
    return identity_create(&uuid, addr, nickname, id, out);
}

static ic_impl_t *_build_participant_impl(const char *id, size_t idx) {
    ic_impl_t *impl = calloc(1, sizeof(ic_impl_t));
    if (impl == NULL) return NULL;
    strncpy(impl->id, id, sizeof(impl->id) - 1);
    if (_make_identity(id, idx, &impl->full) != 0 || impl->full == NULL) goto fail;
    if (identity_publish(impl->full, &impl->pub) != 0 || impl->pub == NULL) goto fail;
    impl->proc = smrt_create(sizeof(process_t));
    if (impl->proc == NULL) goto fail;
    pthread_rwlock_init(&impl->proc->protocol.peers_rwlock, NULL);
    strncpy(impl->proc->name, "identity", PROC_NAME_LEN);
    if (map_create(&impl->proc->protocol.handlers) != 0) goto fail;
    impl->proc->protocol.phase = 3;
    if (identity_register_handlers(impl->proc) != 0) goto fail;

    /* Wire the participant's own identity into proc->configs under the
     * "identity" key — exactly where _partition_self_identity (and the
     * welcoming-committee's _resolve_self_identity) look for it. Without
     * this the partition handlers find no self identity and silently emit
     * nothing. Python's adapter already supplies a full identity config;
     * this brings the C participant to parity. */
    {
        config_t *id_cfg = calloc(1, sizeof(config_t));
        if (id_cfg == NULL) goto fail;
        id_cfg->name = "identity";
        id_cfg->data_struct = impl->full;
        data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
        if (id_dat == NULL) { free(id_cfg); goto fail; }
        if (map_create(&impl->proc->configs) != 0) { free(id_cfg); goto fail; }
        if (map_set(impl->proc->configs, (map_key_t)"identity", id_dat) != 0)
            goto fail;
    }
    return impl;
fail:
    if (impl != NULL) {
        if (impl->proc != NULL) {
            if (impl->proc->protocol.handlers != NULL) map_free(impl->proc->protocol.handlers);
            pthread_rwlock_destroy(&impl->proc->protocol.peers_rwlock);
            smrt_deref(impl->proc);
        }
        if (impl->pub != NULL) smrt_deref(impl->pub);
        if (impl->full != NULL) identity_free(impl->full);
        free(impl);
    }
    return NULL;
}

static void _free_participant_impl(ic_impl_t *impl) {
    if (impl == NULL) return;
    if (impl->subtree_roster != NULL) json_decref(impl->subtree_roster);
    if (impl->proc != NULL) {
        if (impl->proc->protocol.handlers != NULL) map_free(impl->proc->protocol.handlers);
        pthread_rwlock_destroy(&impl->proc->protocol.peers_rwlock);
        smrt_deref(impl->proc);
    }
    if (impl->pub != NULL) smrt_deref(impl->pub);
    if (impl->full != NULL) identity_free(impl->full);
    free(impl);
}

/* ---- Subtree member-roster enumeration (mirror of the Python adapter) ---- */

/* This participant's identity uuid as a string. */
static void _ic_uuid_str(ic_impl_t *impl, char out[UUID_STRING_LEN + 1]) {
    uuid_unparse_lower(impl->full->uuid, out);
}

/* Participant id whose identity uuid == @p uuid, or NULL. */
static const char *_ic_pid_for_uuid(sce_run_ctx_t *ctx, const char *uuid) {
    char u[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < ctx->participant_count; i++) {
        ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
        if (impl == NULL || impl->full == NULL) continue;
        _ic_uuid_str(impl, u);
        if (strcmp(u, uuid) == 0) return ctx->participants[i].id;
    }
    return NULL;
}

static int _roster_strp_cmp(const void *a, const void *b) {
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    if (sa == NULL) return sb == NULL ? 0 : -1;
    if (sb == NULL) return 1;
    return strcmp(sa, sb);
}

/* Aggregation fetch: the gateway with uuid @p gw_uuid produces its roster
 * response via the SAME helper the wire handler uses. ctx is the run ctx. */
static json_t *_roster_fetch(void *vctx, const char *gw_uuid) {
    sce_run_ctx_t *ctx = (sce_run_ctx_t *)vctx;
    char u[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < ctx->participant_count; i++) {
        ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
        if (impl == NULL || impl->full == NULL) continue;
        _ic_uuid_str(impl, u);
        if (strcmp(u, gw_uuid) == 0)
            return identity_roster_response(impl->proc);
    }
    return NULL;  /* unreachable gateway */
}

/* Participant impl whose identity carries @p uuid, or NULL. */
static ic_impl_t *_ic_impl_for_uuid(sce_run_ctx_t *ctx, const uuid_t uuid) {
    for (size_t i = 0; i < ctx->participant_count; i++) {
        ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
        if (impl == NULL || impl->full == NULL) continue;
        if (memcmp(impl->full->uuid, uuid, sizeof(uuid_t)) == 0) return impl;
    }
    return NULL;
}

/* One attended-now pull, end to end (ethne D8/Q9).
 *
 * Drives the real API on both ends: the puller mints and records a nonce, the
 * target answers through the shared builder, and the answer is dispatched into
 * the puller's handler. `accepted` is decided by whether the answer CONSUMED
 * an outstanding pull — the nonce state machine — so a replay, whose nonce is
 * already retired, reads false and leaves the recorded stamp alone.
 *
 * Mirrors the Python adapter's _run_attest_pull exactly, including taking the
 * reported stamp from the answer payload: credential verification against the
 * operator anchor is pinned separately (operator-bound-*), which needs X.509.
 */
static int _ic_run_attest_pull(sce_run_ctx_t *ctx, ic_impl_t *puller,
                               ic_impl_t *target, bool replay) {
    json_t *answer = NULL;
    char nonce[65] = {0};

    if (replay) {
        if (puller->attest_last_answer == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "attest replay: no prior answer to replay");
            return -1;
        }
        answer = json_incref(puller->attest_last_answer);
        const char *n = json_string_value(json_object_get(answer, "nonce"));
        if (n != NULL) strncpy(nonce, n, sizeof(nonce) - 1);
    } else {
        if (identity_request_attestation(puller->proc, target->pub,
                                         nonce, sizeof(nonce)) != 0) {
            snprintf(ctx->err, sizeof(ctx->err), "attest pull: request failed");
            return -1;
        }
        /* The target's own clock is its receive time on this path: the
         * adapter builds the answer directly instead of dispatching a
         * wire message, so nothing else can supply t2. */
        answer = identity_attest_response(target->proc, nonce,
                                         identity_attest_clock(target->proc));
        if (answer == NULL) {
            snprintf(ctx->err, sizeof(ctx->err), "attest pull: no answer built");
            return -1;
        }
        if (puller->attest_last_answer != NULL)
            json_decref(puller->attest_last_answer);
        puller->attest_last_answer = json_incref(answer);
    }

    bool was_outstanding = identity_attest_pull_outstanding(nonce);

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)"operator_attest_response";
    memcpy(&msg.info.net_msg.from_whom, target->pub, sizeof(public_identity_t));
    net_msg_pack_json(&msg.info.net_msg, answer);
    run_message_handlers(puller->proc, NULL, NET_MESSAGE, &msg);

    bool accepted = was_outstanding
                    && !identity_attest_pull_outstanding(nonce);
    if (puller->attest_accepted == NULL)
        puller->attest_accepted = json_array();
    json_array_append_new(puller->attest_accepted, json_boolean(accepted));
    if (accepted)
        puller->attest_stamp = json_real_value(
            json_object_get(answer, "operator_attested_at"));

    /* Relabel whatever the handler measured for this peer under the target's
     * participant id. Absent (no readings in the answer) records nothing, so a
     * scenario asserting on it fails loudly rather than reading a stale one. */
    {
        char target_uuid[UUID_STR_LEN + 1] = {0};
        uuid_unparse_lower(target->pub->uuid, target_uuid);
        at_clock_sample_t sample;
        memset(&sample, 0, sizeof(sample));
        if (identity_get_peer_clock_sample(target_uuid, &sample)
            && sample.valid) {
            if (puller->attest_clock_samples == NULL)
                puller->attest_clock_samples = json_object();
            json_t *entry = json_object();
            json_object_set_new(entry, "offset", json_real(sample.offset_s));
            json_object_set_new(entry, "delay", json_real(sample.delay_s));
            json_object_set_new(entry, "usable", json_boolean(sample.usable));
            json_object_set_new(puller->attest_clock_samples, target->id, entry);
        }
    }

    json_decref(answer);
    return 0;
}

#ifdef AT_ZTA_ENABLED
/* Mint a scenario participant's (operator_pubkey, operator_key_binding) pair,
 * matching the Python adapter byte for byte.
 *
 * The operator key is DERIVED from the participant's uuid rather than
 * generated: a conformance corpus has to produce identical bytes on every run
 * and in both languages, and a fresh keypair would make the two adapters
 * disagree for a reason unrelated to the rule under test. It is not a real
 * ed25519 secret — nothing here signs with it, and AT only ever verifies the
 * BINDING over it.
 *
 * `variant` selects what is wrong with the binding, if anything:
 *   "valid"          signed by the leaf whose certificate the peer presents
 *   "forged"         signed by an unrelated key of the same kind, so the ONE
 *                    difference from "valid" is who held the private key
 *   "other-identity" correctly signed by the real operator, but over a
 *                    pre-image naming a DIFFERENT node (doc/architecture/zta-integration.md's
 *                    harvested credential)
 */
static int _scenario_operator_binding(const char *root, const char *variant,
                                      public_identity_t *pub)
{
    if (root == NULL || variant == NULL || pub == NULL)
        return -1;

    /* The derived operator key: SHA-256 over a domain tag and the uuid. Keep
     * this tag byte-identical to the Python adapter's. */
    static const char TAG[] = "conformance-operator-key:";
    uint8_t seed[sizeof(TAG) - 1 + UUID_LEN];
    memcpy(seed, TAG, sizeof(TAG) - 1);
    memcpy(seed + sizeof(TAG) - 1, pub->uuid, UUID_LEN);
    uint8_t op_pub[crypto_sign_PUBLICKEYBYTES];
    crypto_hash_sha256(op_pub, seed, sizeof(seed));

    /* The pre-image, built by the production function so a drift between it and
     * the scenario would be caught rather than papered over. For
     * "other-identity" the uuid is perturbed first — the signature is perfect
     * and still must be refused. */
    public_identity_t bind_to = *pub;
    if (strcmp(variant, "other-identity") == 0)
        for (size_t i = 0; i < UUID_LEN; i++)
            bind_to.uuid[i] = (uint8_t)((pub->uuid[i] + 1) % 256);

    uint8_t preimage[OPERATOR_BINDING_PREIMAGE_LEN];
    if (operator_binding_preimage(&bind_to, op_pub, preimage) != 0)
        return -1;

    char path[1024];
    snprintf(path, sizeof(path), "%s/testdata/zta/certs/%s", root,
             strcmp(variant, "forged") == 0 ? "impostor_leaf.key"
                                            : "operator_leaf.key");
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    EVP_PKEY *priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (priv == NULL)
        return -1;

    /* RSA PKCS#1 v1.5 over SHA-256 — deterministic, which is why the two
     * adapters can produce the same bytes without either pinning them. */
    int rc = -1;
    uint8_t *sig = NULL;
    size_t siglen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) != 1)
        goto out;
    if (EVP_DigestSign(ctx, NULL, &siglen, preimage, sizeof(preimage)) != 1)
        goto out;
    sig = malloc(siglen);
    if (sig == NULL)
        goto out;
    if (EVP_DigestSign(ctx, sig, &siglen, preimage, sizeof(preimage)) != 1)
        goto out;

    memcpy(pub->operator_pubkey, op_pub, sizeof(op_pub));
    free(pub->operator_key_binding);
    pub->operator_key_binding = sig;
    pub->operator_key_binding_len = siglen;
    sig = NULL;   /* ownership moved to the identity */
    rc = 0;

out:
    free(sig);
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(priv);
    return rc;
}

/* Mint a credential->identity binding for a scenario participant
 * (doc/architecture/zta-integration.md).
 * C twin of the Python adapter's _scenario_zta_binding, variant for variant:
 *
 *   "valid"          signed by the leaf whose certificate the peer presents
 *   "forged"         signed by an unrelated key — somebody tried to prove
 *                    entitlement and could not
 *   "other-identity" correctly signed by the real leaf but over a pre-image
 *                    naming a DIFFERENT node: the harvested credential, and the
 *                    case the binding exists to stop
 *
 * The binding is written into the peer's credential LIST rather than a singular
 * field, because proto fields 6-8 have nowhere to carry one — which is the whole
 * reason field 16 exists. */
static int _scenario_zta_binding(const char *root, const char *variant,
                                 public_identity_t *pub)
{
    if (root == NULL || variant == NULL || pub == NULL
        || pub->zta_credential == NULL || pub->zta_credential_len == 0)
        return -1;

    public_identity_t bind_to = *pub;
    if (strcmp(variant, "other-identity") == 0)
        for (size_t i = 0; i < UUID_LEN; i++)
            bind_to.uuid[i] = (uint8_t)((pub->uuid[i] + 1) % 256);

    uint8_t preimage[ZTA_BINDING_PREIMAGE_LEN];
    if (zta_binding_preimage(&bind_to, pub->zta_credential,
                             pub->zta_credential_len, preimage) != 0)
        return -1;

    char path[1024];
    snprintf(path, sizeof(path), "%s/testdata/zta/certs/%s", root,
             strcmp(variant, "forged") == 0 ? "impostor_leaf.key"
                                            : "operator_leaf.key");
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    EVP_PKEY *priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (priv == NULL)
        return -1;

    int rc = -1;
    uint8_t *sig = NULL;
    size_t siglen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) != 1)
        goto out;
    if (EVP_DigestSign(ctx, NULL, &siglen, preimage, sizeof(preimage)) != 1)
        goto out;
    sig = malloc(siglen);
    if (sig == NULL)
        goto out;
    if (EVP_DigestSign(ctx, sig, &siglen, preimage, sizeof(preimage)) != 1)
        goto out;

    public_identity_zta_credentials_clear(pub);
    rc = public_identity_add_zta_credential(pub, pub->zta_credential,
                                            pub->zta_credential_len,
                                            sig, siglen, pub->zta_issuer);

out:
    free(sig);
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(priv);
    return rc;
}

/* ZTA fixtures (zta-x509-* scenarios). Mirrors the Python adapter:
 *   fixtures.zta_policy   -> a zta_policy_t in each participant's
 *                            proc->configs["zta_policy"] (object_ptr_data
 *                            (config_t), exactly as load_all_configs stores
 *                            configs and the gate reads them).
 *   fixtures.credentials  -> attach the DER credential to each named peer's
 *                            public identity so its announce (from_whom copy)
 *                            carries it to the welcoming committee.
 * Cert paths are corpus-relative (testdata/ is mirrored into the C corpus
 * root by tools/corpus_to_json). Allocations here outlive the scenario and
 * are reclaimed at process exit — the same convention as the "identity"
 * config built in _build_participant_impl. */
static void _apply_zta_fixtures(sce_run_ctx_t *ctx, json_t *fixtures) {
    const char *root = at_runner_corpus_json_root();

    json_t *creds = json_object_get(fixtures, "credentials");
    if (json_is_object(creds) && root != NULL) {
        const char *pid; json_t *relv;
        json_object_foreach(creds, pid, relv) {
            if (!json_is_string(relv)) continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", root, json_string_value(relv));
            FILE *fp = fopen(path, "rb");
            if (fp == NULL) continue;
            fseek(fp, 0, SEEK_END);
            long n = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (n <= 0) { fclose(fp); continue; }
            uint8_t *buf = malloc((size_t)n);
            size_t got = (buf != NULL) ? fread(buf, 1, (size_t)n, fp) : 0;
            fclose(fp);
            if (buf == NULL || got != (size_t)n) { free(buf); continue; }
            sce_participant_t *p = sce_find_participant(ctx, pid);
            if (p == NULL) { free(buf); continue; }
            ic_impl_t *impl = (ic_impl_t *)p->impl;
            impl->pub->zta_credential = buf;
            impl->pub->zta_credential_len = (size_t)n;
            /* Also onto the participant's OWN identity (proc->configs
             * ["identity"]), not just the published copy it announces with. A
             * node's credential belongs to its identity; `pub` is a copy of it.
             * The gate's replay check reads the self identity to answer "is our
             * own credential being worn by somebody else", so without this the C
             * side could not see its own credential and would diverge from
             * Python, whose adapter uses ONE Identity object for both roles.
             * Pinned by zta-credential-replay-different-identity. */
            if (impl->full != NULL) {
                uint8_t *own = malloc((size_t)n);
                if (own != NULL) {
                    memcpy(own, buf, (size_t)n);
                    free(impl->full->zta_credential);
                    impl->full->zta_credential = own;
                    impl->full->zta_credential_len = (size_t)n;
                }
            }
        }
    }

    /* Advertised operator-attended claim (ethne D8/Q9): set the announcing
     * identity's operator_bound so the gate sees the CLAIM on from_whom. It is
     * always neutralized and re-derived from operator-anchor verification, so a
     * `true` claim on a non-operator credential must end up false. Mirrors the
     * Python adapter's operator_claims wiring. */
    json_t *claims = json_object_get(fixtures, "operator_claims");
    if (json_is_object(claims)) {
        const char *pid; json_t *cv;
        json_object_foreach(claims, pid, cv) {
            sce_participant_t *p = sce_find_participant(ctx, pid);
            if (p == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)p->impl;
            impl->pub->operator_bound = json_is_true(cv);
        }
    }

    /* The OPT-IN guardian identity. `operator_bindings: {<pid>: <variant>}`
     * makes that participant advertise an operator key plus a binding signed
     * AT SCENARIO TIME, so the two implementations are held to the same
     * signature scheme and the same pre-image rather than to one of them having
     * recorded its own output. Mirrors the Python adapter's
     * _scenario_operator_binding, variant for variant. */
    json_t *binds = json_object_get(fixtures, "operator_bindings");
    if (json_is_object(binds) && root != NULL) {
        const char *pid; json_t *bv;
        json_object_foreach(binds, pid, bv) {
            if (!json_is_string(bv)) continue;
            sce_participant_t *p = sce_find_participant(ctx, pid);
            if (p == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)p->impl;
            if (_scenario_operator_binding(root, json_string_value(bv),
                                           impl->pub) != 0) {
                /* Fatal, not skipped. This applier is void and cannot fail a
                 * scenario, and a skipped mint would leave the participant
                 * advertising nothing — which is precisely the expected
                 * outcome of the forged and other-identity cases, so they
                 * would PASS for the wrong reason and the corpus would report
                 * green while testing nothing. A fixture that will not load is
                 * a harness fault; the run stops and says so. */
                fprintf(stderr,
                        "conformance: %s: cannot mint operator binding '%s' "
                        "(missing testdata/zta/certs key?) — aborting rather "
                        "than running a scenario that would pass vacuously\n",
                        pid, json_string_value(bv));
                exit(2);
            }
        }
    }

    /* The credential->identity binding. Runs AFTER the credentials loop above
     * because it signs over the credential attached there. Same fatal-not-skipped
     * rule as the operator binding: a skipped mint would leave the participant
     * unbound, which is exactly the expected outcome of the reject cases, so they
     * would pass vacuously. */
    json_t *zbinds = json_object_get(fixtures, "zta_bindings");
    if (json_is_object(zbinds) && root != NULL) {
        const char *pid; json_t *bv;
        json_object_foreach(zbinds, pid, bv) {
            if (!json_is_string(bv)) continue;
            sce_participant_t *p = sce_find_participant(ctx, pid);
            if (p == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)p->impl;
            if (_scenario_zta_binding(root, json_string_value(bv),
                                      impl->pub) != 0) {
                fprintf(stderr,
                        "conformance: %s: cannot mint ZTA binding '%s' "
                        "(missing testdata/zta/certs key?) — aborting rather "
                        "than running a scenario that would pass vacuously\n",
                        pid, json_string_value(bv));
                exit(2);
            }
        }
    }

    json_t *zp = json_object_get(fixtures, "zta_policy");
    if (json_is_object(zp)) {
        for (size_t i = 0; i < ctx->participant_count; i++) {
            ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
            zta_policy_t *pol = calloc(1, sizeof(zta_policy_t));
            if (pol == NULL) continue;
            zta_policy_defaults(pol);
            zta_policy_from_json(zp, pol);
            if (root != NULL && pol->ca_bundle_path[0] != '\0'
                && pol->ca_bundle_path[0] != '/') {
                /* Make the corpus-relative bundle path absolute. Bounded
                 * widths keep the total provably within the buffers, so
                 * -Wformat-truncation is satisfied (the combined path is
                 * ~140 chars in practice). */
                char abs[1024];
                snprintf(abs, sizeof(abs), "%.700s/%.255s", root,
                         pol->ca_bundle_path);
                snprintf(pol->ca_bundle_path, sizeof(pol->ca_bundle_path),
                         "%.*s", (int)(sizeof(pol->ca_bundle_path) - 1), abs);
            }
            /* Same corpus-relative -> absolute fixup for the CRL path, so a
             * revocation scenario's CRL is fopen-able from any CWD (mirrors
             * Python, whose crl_path is resolved relative to the corpus root).
             * Without this the C verifier silently fails to load the CRL and
             * reports UNAVAILABLE -> admit, diverging from Python's REVOKED. */
            if (root != NULL && pol->crl_path[0] != '\0'
                && pol->crl_path[0] != '/') {
                char abs[1024];
                snprintf(abs, sizeof(abs), "%.700s/%.255s", root,
                         pol->crl_path);
                snprintf(pol->crl_path, sizeof(pol->crl_path),
                         "%.*s", (int)(sizeof(pol->crl_path) - 1), abs);
            }
            /* Same corpus-relative -> absolute fixup for the distinct operator
             * trust anchor (ethne D8/Q9); mirrors Python's operator_ca_bundle_path
             * resolution so operator-class classification loads the right CA. */
            if (root != NULL && pol->operator_ca_bundle_path[0] != '\0'
                && pol->operator_ca_bundle_path[0] != '/') {
                char abs[1024];
                snprintf(abs, sizeof(abs), "%.700s/%.255s", root,
                         pol->operator_ca_bundle_path);
                snprintf(pol->operator_ca_bundle_path,
                         sizeof(pol->operator_ca_bundle_path),
                         "%.*s", (int)(sizeof(pol->operator_ca_bundle_path) - 1), abs);
            }
            /* And the NAMED anchors, each carrying its own bundle path. Easy to
             * miss, and the failure is quiet: an anchor whose bundle will not
             * load verifies nothing, so the peer is simply not admitted and the
             * scenario reads as a policy disagreement rather than a path bug.
             * Mirrors the Python adapter. */
            for (size_t ai = 0; root != NULL && ai < pol->num_anchors; ai++) {
                char *p = pol->anchors[ai].ca_bundle_path;
                if (p[0] == '\0' || p[0] == '/')
                    continue;
                char abs[1024];
                snprintf(abs, sizeof(abs), "%.700s/%.255s", root, p);
                snprintf(p, ZTA_PATH_LEN, "%.*s", (int)(ZTA_PATH_LEN - 1), abs);
            }
            config_t *cfg = calloc(1, sizeof(config_t));
            if (cfg == NULL) { free(pol); continue; }
            cfg->name = "zta_policy";
            cfg->data_struct = pol;
            data_t *d = object_ptr_data(cfg, sizeof(config_t));
            if (d == NULL) { free(cfg); free(pol); continue; }
            map_set(impl->proc->configs, (map_key_t)"zta_policy", d);
        }
    }
}
#endif /* AT_ZTA_ENABLED */

/* Apply scenario fixtures: amnesia_known => pre-stage non-newcomer
 * participants' peer lists with the newcomer (so welcoming_committee's
 * already-known branch is reachable). */
static void _apply_fixtures(sce_run_ctx_t *ctx) {
    /* border_guard: optional per-participant bool on the participant spec
     * (doc/architecture/identity-protocol.md, Policy B). Default true (set in
     * identity_register_handlers); `border_guard: false` makes that peer
     * abstain from voting on received proposals. Read here — before the
     * fixtures early-return — because it lives on the participant entry, not
     * under `fixtures`. Mirrors the Python adapter reading spec['border_guard']. */
    json_t *participants = json_object_get(ctx->case_data, "participants");
    if (json_is_array(participants)) {
        size_t np = json_array_size(participants);
        for (size_t i = 0; i < np; i++) {
            json_t *pj = json_array_get(participants, i);
            if (!json_is_object(pj)) continue;
            json_t *bg = json_object_get(pj, "border_guard");
            if (!json_is_boolean(bg)) continue;  /* absent => keep default */
            const char *pid = json_string_value(json_object_get(pj, "id"));
            if (pid == NULL) continue;
            sce_participant_t *part = sce_find_participant(ctx, pid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL) continue;
            identity_set_border_guard_mode(impl->proc, json_is_true(bg));
        }
    }

    json_t *fixtures = json_object_get(ctx->case_data, "fixtures");
    if (!json_is_object(fixtures)) return;

#ifdef AT_ZTA_ENABLED
    _apply_zta_fixtures(ctx, fixtures);
#endif

    /* capabilities: { "<participant>": ["<cap>", ...], ... } —
     * install each participant's own-capability allowlist via
     * identity_set_own_capabilities so handle_caps_query emits the
     * matching JSON-array payload. Mirrors the negotiation adapter's
     * fixture wiring; Python's identity adapter populates
     * `process.protocol.capabilities` from the same fixture key. */
    json_t *caps = json_object_get(fixtures, "capabilities");
    if (json_is_object(caps))
    {
        const char *pid;
        json_t *cap_arr;
        json_object_foreach(caps, pid, cap_arr) {
            sce_participant_t *part = sce_find_participant(ctx, pid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL) continue;
            if (!json_is_array(cap_arr)) continue;
            size_t n = json_array_size(cap_arr);
            const char **names = (n > 0) ? calloc(n, sizeof(char *)) : NULL;
            size_t k = 0;
            for (size_t i = 0; i < n; i++)
            {
                const char *name = json_string_value(json_array_get(cap_arr, i));
                if (name) names[k++] = name;
            }
            identity_set_own_capabilities(impl->proc, names, k);
            free((void *)names);
        }
    }

    /* positions: { "<participant>": "<geohash>", ... } (Increment 2, the
     * "with-distance" feature) — install each named participant's opt-in coarse
     * position via identity_set_own_geohash so its handle_position_query answers
     * with that bucket. id_state is a singleton per scenario, so a scenario opts
     * in exactly ONE participant (the responder); an unlisted participant is
     * opted OUT, the default. Mirrors the Python adapter reading
     * fixtures.positions into process.own_geohash. */
    json_t *positions = json_object_get(fixtures, "positions");
    if (json_is_object(positions))
    {
        const char *ppid;
        json_t *pval;
        json_object_foreach(positions, ppid, pval) {
            sce_participant_t *part = sce_find_participant(ctx, ppid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL) continue;
            identity_set_own_geohash(json_string_value(pval));
        }
    }

    /* admission_quorum: { "<participant>": <int>, ... } — two-phase admission
     * (doc/architecture/identity-protocol.md). A member withholds the group key until this many
     * DISTINCT border-guards confirm. Default 1 (no fixture). Mirrors the
     * Python adapter reading fixtures.admission_quorum. */
    json_t *quorums = json_object_get(fixtures, "admission_quorum");
    if (json_is_object(quorums))
    {
        const char *qpid;
        json_t *qval;
        json_object_foreach(quorums, qpid, qval) {
            if (!json_is_integer(qval)) continue;
            sce_participant_t *part = sce_find_participant(ctx, qpid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL) continue;
            identity_set_admission_quorum(impl->proc, (int)json_integer_value(qval));
        }
    }

    /* groups: { "<participant>": { "uuid": "<str>", "size": <int> }, ... }
     * Distinct-group mode for partition-recovery scenarios. Each listed
     * participant gets its OWN group (pinned uuid + `size` members) and
     * peers are NOT cross-populated, so each peer sees the other's group
     * traffic as foreign — the split-brain precondition. Mirrors the
     * Python adapter's _build_group_from_fixture. The pinned uuid keeps
     * the equal-size tiebreak deterministic and identical across harnesses;
     * filler members exist only to set map_size(group.address_map) (the
     * value the partition handlers sign and compare) and use distinct
     * addresses because group_add_address dedups by address. */
    json_t *groups = json_object_get(fixtures, "groups");
    if (json_is_object(groups))
    {
        const char *gpid;
        json_t *gspec;
        size_t gi = 0;
        json_object_foreach(groups, gpid, gspec) {
            sce_participant_t *part = sce_find_participant(ctx, gpid);
            if (part != NULL && json_is_object(gspec)) {
                ic_impl_t *impl = (ic_impl_t *)part->impl;
                if (impl != NULL && impl->proc != NULL && impl->pub != NULL) {
                    const char *guuid_str = NULL;
                    json_t *gu = json_object_get(gspec, "uuid");
                    if (json_is_string(gu)) guuid_str = json_string_value(gu);
                    int gsize = 1;
                    json_t *gs = json_object_get(gspec, "size");
                    if (json_is_integer(gs)) gsize = (int)json_integer_value(gs);
                    /* public_only: build a group holding ONLY the public key
                     * (zero the private key below) — the wire shape of a
                     * membership-only group_key_update from a peer without the
                     * shared private key. Mirrors the Python adapter's
                     * public_only fixture. */
                    json_t *gpo = json_object_get(gspec, "public_only");
                    bool gpublic_only = json_is_true(gpo);

                    char gaddr[ADDR_LEN + 1];
                    snprintf(gaddr, sizeof(gaddr), "239.9.%zu.1", gi);
                    uuid_t guuid;
                    if (guuid_str != NULL && uuid_parse(guuid_str, guuid) == 0)
                        group_init(&guuid, gaddr, &impl->proc->protocol.group);
                    else
                        group_init(NULL, gaddr, &impl->proc->protocol.group);

                    /* member 0: the participant itself */
                    char own_uuid_str[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(impl->pub->uuid, own_uuid_str);
                    group_add_address(&impl->proc->protocol.group,
                                      own_uuid_str, impl->pub->address);
                    /* fillers to reach `size` members */
                    for (int k = 0; k < gsize - 1; k++) {
                        char fuuid[UUID_STRING_LEN + 1];
                        char faddr[ADDR_LEN + 1];
                        snprintf(fuuid, sizeof(fuuid),
                                 "f111%04zu-0000-4000-8000-%012d", gi, k);
                        snprintf(faddr, sizeof(faddr), "10.9.%zu.%d", gi, k + 2);
                        group_add_address(&impl->proc->protocol.group,
                                          fuuid, faddr);
                    }
                    /* Strip the private key so group_to_json emits
                     * public_only=true (it gates on sodium_is_zero(private)). */
                    if (gpublic_only)
                        sodium_memzero(impl->proc->protocol.group.encryptor.private,
                                       crypto_box_SECRETKEYBYTES);
                }
            }
            gi++;
        }
    }

    /* shared_group: { "uuid": "<str>" } — identity-resync scenarios. ONE
     * group shared by every participant (each member's uuid:address in the
     * address_map) assigned to all, with peers NOT cross-populated. That is
     * the cold/late-joiner precondition handle_identity_response backfills:
     * each node knows the others' addresses but not their Identities. The
     * uuid is pinned to match the Python harness (the resync query/response
     * gate on group uuid). Mirrors the Python adapter's shared_group_obj. */
    json_t *shared = json_object_get(fixtures, "shared_group");
    if (json_is_object(shared))
    {
        const char *guuid_str =
            json_string_value(json_object_get(shared, "uuid"));
        uuid_t guuid;
        bool have_uuid = (guuid_str != NULL && uuid_parse(guuid_str, guuid) == 0);
        for (size_t i = 0; i < ctx->participant_count; i++) {
            ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
            if (impl == NULL || impl->proc == NULL || impl->pub == NULL) continue;
            char gaddr[ADDR_LEN + 1];
            snprintf(gaddr, sizeof(gaddr), "239.8.0.1");
            if (have_uuid)
                group_init(&guuid, gaddr, &impl->proc->protocol.group);
            else
                group_init(NULL, gaddr, &impl->proc->protocol.group);
            for (size_t j = 0; j < ctx->participant_count; j++) {
                ic_impl_t *other = (ic_impl_t *)ctx->participants[j].impl;
                if (other == NULL || other->pub == NULL) continue;
                char u[UUID_STRING_LEN + 1];
                uuid_unparse_lower(other->pub->uuid, u);
                group_add_address(&impl->proc->protocol.group, u,
                                  other->pub->address);
            }
        }
    }

    /* capless_peers: { "<participant>": <N>, ... } -- inject N synthetic
     * cap-less peers (present in proc->protocol.peers[] but absent from the
     * peer_caps_map) so the periodic caps-resync sweep has more than the
     * per-sweep cap to query. Mirrors the Python adapter's capless_peers
     * injection; pins CAPS_RESYNC_MAX_PER_SWEEP via caps-resync-max-per-sweep.
     * (Pair with shared_group so the sweep's in-a-group gate is satisfied.) */
    json_t *capless = json_object_get(fixtures, "capless_peers");
    if (json_is_object(capless)) {
        const char *cl_pid;
        json_t *cl_cnt;
        json_object_foreach(capless, cl_pid, cl_cnt) {
            sce_participant_t *part = sce_find_participant(ctx, cl_pid);
            if (part == NULL || !json_is_integer(cl_cnt)) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL || impl->pub == NULL) continue;
            process_t *p = impl->proc;
            json_int_t n = json_integer_value(cl_cnt);
            for (json_int_t i = 0; i < n; i++) {
                if (p->protocol.num_peers >= DEFAULT_MAX_PEERS) break;
                public_identity_t *slot =
                    &p->protocol.peers[p->protocol.num_peers];
                memcpy(slot, impl->pub, sizeof(public_identity_t));
                /* deterministic, distinct, cap-less uuid; the 0xCA71 marker
                 * bytes keep it from colliding with any real participant. */
                memset(slot->uuid, 0, sizeof(slot->uuid));
                slot->uuid[0] = (unsigned char)(i & 0xff);
                slot->uuid[1] = (unsigned char)((i >> 8) & 0xff);
                slot->uuid[2] = 0xCA;
                slot->uuid[3] = 0x71;
                snprintf(slot->nickname, sizeof(slot->nickname),
                         "capless-%s-%lld", cl_pid, (long long)i);
                p->protocol.num_peers++;
            }
        }
    }

    /* operator_session: who has a human at the console, and the pinned clock
     * every attestation stamp is taken from (ethne D8/Q9). Mirrors the Python
     * adapter's _apply_operator_session — but where Python attaches a stub
     * OperatorSession for its process to poll, C has no session type at all
     * and asserts the same two-valued state through the seam. That difference
     * in ROUTE is the documented asymmetry; the resulting answer is identical,
     * which is what the scenarios compare. */
    json_t *op_sess = json_object_get(fixtures, "operator_session");
    if (json_is_object(op_sess)) {
        double clock = json_real_value(json_object_get(op_sess, "clock"));
        const char *spid;
        json_t *sval;
        json_object_foreach(op_sess, spid, sval) {
            if (strcmp(spid, "clock") == 0) continue;
            sce_participant_t *part = sce_find_participant(ctx, spid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            impl->attest_clock = clock;
            identity_set_attest_clock(impl->proc, clock);
            const char *state = json_string_value(sval);
            /* Only an ACTIVE session counts as attended; `locked` (a guardian
             * exists but has stepped away) and `absent` (no console at all)
             * both read as nobody home. */
            bool attended = (state != NULL && strcmp(state, "active") == 0);
            identity_set_operator_attended(impl->proc, attended, clock);
        }
    }

    /* clocks: per-participant clocks, so a scenario can pin two nodes that
     * DISAGREE. operator_session.clock pins ONE clock for everybody, which is
     * all the attended-now scenarios need; cohort skew is the difference
     * BETWEEN two nodes' clocks and needs a distinct value each. Applied after
     * operator_session so it overrides that shared value. Mirrors the Python
     * adapter's _apply_clocks. See doc/architecture/cohort-clock-skew.md. */
    json_t *clocks = json_object_get(fixtures, "clocks");
    if (json_is_object(clocks)) {
        const char *cpid2;
        json_t *cval;
        json_object_foreach(clocks, cpid2, cval) {
            sce_participant_t *part = sce_find_participant(ctx, cpid2);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            double epoch = json_number_value(cval);
            impl->attest_clock = epoch;
            identity_set_attest_clock(impl->proc, epoch);
            /* Re-stamp attendance against THIS node's clock: a node stamps with
             * its own, which is the whole point of the two clocks differing. */
            if (impl->proc->protocol.operator_attended)
                identity_set_operator_attended(impl->proc, true, epoch);
        }
    }

    /* ranks: {pid: int} -- the topology rank each participant HAS, applied to
     * its own identity AND to every other node's view of it. Rank is what the
     * hierarchy derivation reads (protocol step 7), so a scenario pinning a
     * parent has to be able to state it. Mirrors the Python adapter's ranks
     * handling; both sides write the peer_ranks seam, because a cohort's
     * membership is an address map and a member's rank has to be knowable
     * before its Identity is. */
    json_t *ranks = json_object_get(fixtures, "ranks");
    if (json_is_object(ranks)) {
        const char *rpid;
        json_t *rval;
        json_object_foreach(ranks, rpid, rval) {
            int rank = (int)json_integer_value(rval);
            sce_participant_t *rpart = sce_find_participant(ctx, rpid);
            if (rpart == NULL) continue;
            ic_impl_t *target = (ic_impl_t *)rpart->impl;
            char ru[UUID_STRING_LEN + 1];
            uuid_unparse_lower(target->full->uuid, ru);
            target->full->rank = rank;
            for (size_t pi = 0; pi < ctx->participant_count; pi++) {
                ic_impl_t *other = (ic_impl_t *)ctx->participants[pi].impl;
                if (other != NULL)
                    identity_set_peer_rank(other->proc, ru, rank);
            }
        }
    }

    /* cohort_tree: seed a gateway hierarchy so a subtree-roster enumeration
     * spans multiple levels. Mirrors the Python adapter's _apply_cohort_tree.
     * Each node gets a primary group (self + `members`) and, if it has a
     * `child_group`, a child cohort + the `gateway` recursion target. */
    json_t *cohort = json_object_get(fixtures, "cohort_tree");
    if (json_is_object(cohort)) {
        json_t *nodes = json_object_get(cohort, "nodes");
        const char *cpid;
        json_t *cspec;
        json_object_foreach(nodes, cpid, cspec) {
            sce_participant_t *part = sce_find_participant(ctx, cpid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
            process_t *proc = impl->proc;
            /* Primary group = self + any extra members. */
            uuid_t guuid;
            uuid_generate(guuid);
            group_init(&guuid, (char *)impl->full->address, &proc->protocol.group);
            char su[UUID_STRING_LEN + 1];
            uuid_unparse_lower(impl->full->uuid, su);
            group_add_address(&proc->protocol.group, su, impl->full->address);
            json_t *members = json_object_get(cspec, "members");
            if (json_is_array(members)) {
                size_t i, n = json_array_size(members);
                for (i = 0; i < n; i++) {
                    const char *m_pid =
                        json_string_value(json_array_get(members, i));
                    sce_participant_t *mp =
                        m_pid ? sce_find_participant(ctx, m_pid) : NULL;
                    if (mp == NULL) continue;
                    ic_impl_t *mi = (ic_impl_t *)mp->impl;
                    char mu[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(mi->full->uuid, mu);
                    group_add_address(&proc->protocol.group, mu,
                                      mi->full->address);
                }
            }
            /* A child cohort this node gateways + the recursion target. */
            json_t *cg = json_object_get(cspec, "child_group");
            if (json_is_array(cg) && json_array_size(cg) > 0) {
                group_t *child = calloc(1, sizeof(group_t));
                if (child == NULL) continue;
                uuid_t cguuid;
                uuid_generate(cguuid);
                group_init(&cguuid, (char *)impl->full->address, child);
                size_t i, n = json_array_size(cg);
                for (i = 0; i < n; i++) {
                    const char *m_pid =
                        json_string_value(json_array_get(cg, i));
                    sce_participant_t *mp =
                        m_pid ? sce_find_participant(ctx, m_pid) : NULL;
                    if (mp == NULL) continue;
                    ic_impl_t *mi = (ic_impl_t *)mp->impl;
                    char mu[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(mi->full->uuid, mu);
                    group_add_address(child, mu, mi->full->address);
                }
                char gwb[UUID_STRING_LEN + 1];
                const char *gw_uuid_str = NULL;
                const char *gw_pid =
                    json_string_value(json_object_get(cspec, "gateway"));
                if (gw_pid != NULL) {
                    sce_participant_t *gp = sce_find_participant(ctx, gw_pid);
                    if (gp != NULL) {
                        ic_impl_t *gi = (ic_impl_t *)gp->impl;
                        uuid_unparse_lower(gi->full->uuid, gwb);
                        gw_uuid_str = gwb;
                    }
                }
                identity_add_child_group(proc, child, gw_uuid_str);
            }
        }
    }

    json_t *amnesia_j = json_object_get(fixtures, "amnesia_known");
    bool amnesia_known = json_is_true(amnesia_j);

    /* Find the new_node by role. */
    int newcomer_idx = -1;
    for (size_t i = 0; i < ctx->participant_count; i++) {
        if (strcmp(ctx->participants[i].role, "new_node") == 0) {
            newcomer_idx = (int)i;
            break;
        }
    }
    if (!amnesia_known || newcomer_idx < 0) return;

    /* Add the newcomer to each existing peer's peers list. */
    ic_impl_t *new_impl = (ic_impl_t *)ctx->participants[newcomer_idx].impl;
    for (size_t i = 0; i < ctx->participant_count; i++) {
        if ((int)i == newcomer_idx) continue;
        ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
        process_t *p = impl->proc;
        if (p->protocol.num_peers >= DEFAULT_MAX_PEERS) continue;
        memcpy(&p->protocol.peers[p->protocol.num_peers],
               new_impl->pub, sizeof(public_identity_t));
        p->protocol.num_peers++;
    }
}

/* ------------------------------------------------------------------------- */
/* Freshness sequences on inbound payloads                                     */
/* ------------------------------------------------------------------------- */

/* Read the freshness sequence a step wants on the payload it is building.
 *
 * Several identity verbs now carry a monotonic per-process sequence that the
 * receiver checks against a per-(sender, verb) high-water mark
 * (utilities/freshness.h; doc/architecture/security-hardening.md, "Replay
 * resistance, per verb"). The scenario grammar for it is shared with the
 * Python adapter, so both runtimes read the same YAML:
 *
 *   - absent            -> 1, which is fresh against a scenario's empty marks,
 *                          so every pre-existing scenario keeps working with
 *                          no edit.
 *   - `seq: N`          -> N. Two steps with the same N is a replay; N below a
 *                          mark already advanced is a stale message.
 *   - `unstamped: true` -> 0, the never-seen floor. Stands for a peer that has
 *                          not been rebuilt, and for an attacker stripping the
 *                          field; both must be refused, not admitted.
 *
 * Named `_ic_step_seq` rather than folded into each builder because four verbs
 * need it and they must not drift apart. */
static int64_t _ic_step_seq(json_t *payload, const char *key)
{
    if (!json_is_object(payload))
        return 1;
    if (json_is_true(json_object_get(payload, "unstamped")))
        return 0;
    json_t *j = json_object_get(payload, key);
    if (json_is_integer(j))
        return (int64_t)json_integer_value(j);
    return 1;
}

/* Set `seq` on an envelope, or leave it off entirely when the step asked for
 * an unstamped message.
 *
 * Off rather than zero, because for the envelope-shaped verbs (caps_response,
 * peer_accepted) the receiver's check is `json_is_integer(seq)` — a missing key
 * is exactly the pre-change wire shape being modelled, and a literal 0 would
 * test a different thing (a sender that stamped a nonsense value). The
 * signature-covered verbs differ and are handled at their own call sites. */
static void _ic_set_seq(json_t *body, json_t *payload)
{
    if (json_is_object(payload)
        && json_is_true(json_object_get(payload, "unstamped")))
        return;
    json_object_set_new(body, "seq",
                        json_integer((json_int_t)_ic_step_seq(payload, "seq")));
}

/* ------------------------------------------------------------------------- */
/* Engine callbacks                                                           */
/* ------------------------------------------------------------------------- */

static int _build_inbound(sce_run_ctx_t *ctx,
                          const char *from_id,
                          const char *to_id,
                          const char *function,
                          json_t *payload,
                          generic_msg_t *out) {
    (void)to_id;
    sce_participant_t *sender = sce_find_participant(ctx, from_id);
    if (sender == NULL) {
        snprintf(ctx->err, sizeof(ctx->err), "build_inbound: unknown from %s", from_id);
        return -1;
    }
    ic_impl_t *sender_impl = (ic_impl_t *)sender->impl;

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    strncpy(out->info.net_msg.process, "identity", PROC_NAME_LEN);
    /* function string is owned by the JSON loaded by the runner; lifetime
     * spans the entire scenario, which is what the handler dispatch
     * requires (strcmp against handler keys). */
    out->info.net_msg.function = (char *)function;
    out->info.net_msg.encrypt = false;
    memcpy(&out->info.net_msg.from_whom, sender_impl->pub, sizeof(public_identity_t));

    /* trigger_cohort_join — the only pseudo-function that carries a payload: it names
     * the cohort to solicit (doc/architecture/gateway-reputation-tree.md). Without
     * packing it the adapter would ask to join "" and the request would be refused
     * locally, which reads downstream as "emitted nothing". Mirrors the Python adapter,
     * which likewise leaves the payload in place for this one pseudo-function while
     * blanking it for the others. */
    if ((strcmp(function, "trigger_cohort_join") == 0
         || strcmp(function, "trigger_first_contact_initiate") == 0)
        && json_is_object(payload)) {
        json_t *body = json_deep_copy(payload);
        if (body != NULL) {
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* peer_caps_response — pack the payload as the JSON envelope
     * handle_caps_response expects. Two YAML forms (mirrors the Python
     * adapter):
     *   - `descriptors: [{name, required_tier, description, kind, arg_schema}]`
     *     → packed verbatim as an array of objects (descriptor form).
     *   - `caps: [name, ...]` → packed as an array of name strings (legacy).
     * Either array goes under the `caps` key of the envelope, beside the
     * freshness `seq` (see _ic_step_seq). Without this the C handler sees no
     * payload and silently no-ops. */
    if (strcmp(function, "peer_caps_response") == 0 && json_is_object(payload)) {
        json_t *items = NULL;
        json_t *descs = json_object_get(payload, "descriptors");
        if (json_is_array(descs)) {
            /* deep-copy so the body is independent of the scenario JSON's
             * lifetime; net_msg_pack_json serializes the array of objects. */
            items = json_deep_copy(descs);
        } else {
            json_t *src = json_object_get(payload, "caps");
            if (json_is_array(src)) {
                items = json_array();
                size_t n = json_array_size(src);
                for (size_t i = 0; i < n; i++) {
                    json_t *v = json_array_get(src, i);
                    if (json_is_string(v))
                        json_array_append_new(items,
                                              json_string(json_string_value(v)));
                }
            }
        }
        if (items != NULL) {
            json_t *body = json_object();
            json_object_set_new(body, "caps", items);
            _ic_set_seq(body, payload);
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* peer_position_response — pack {pos, seq} as the envelope
     * handle_position_response expects (Increment 2, the "with-distance"
     * feature). `pos` is the opaque geohash bucket; `seq` is the responder's
     * freshness sequence (_ic_set_seq honors `unstamped: true` by omitting it,
     * so the replay/unstamped-refusal case is exercised the same way caps is).
     * Mirrors the Python position_response builder; peer_position_query needs
     * no branch (empty payload, generic path, like caps_query). Without this
     * the C handler sees no payload and silently no-ops. */
    if (strcmp(function, "peer_position_response") == 0 && json_is_object(payload)) {
        json_t *body = json_object();
        json_t *jpos = json_object_get(payload, "pos");
        json_object_set_new(body, "pos",
                            json_string(json_is_string(jpos)
                                        ? json_string_value(jpos) : ""));
        _ic_set_seq(body, payload);
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }

    /* vote_on_peer is the only identity function whose C handler
     * (`handle_count_vote`) requires a structured JSON payload —
     * `{uuid, approved}` keyed off the candidate's uuid. Other
     * identity functions either expect empty/unused payloads or use
     * the generic obj passthrough. */
    if (strcmp(function, "vote_on_peer") == 0 && json_is_object(payload)) {
        const char *cand_id = NULL;
        json_t *c = json_object_get(payload, "candidate");
        if (json_is_string(c)) cand_id = json_string_value(c);
        bool approved = true;
        json_t *a = json_object_get(payload, "approved");
        if (json_is_boolean(a)) approved = json_boolean_value(a);

        char uuid_buf[UUID_STRING_LEN + 1] = {0};
        if (cand_id != NULL) {
            sce_participant_t *cand = sce_find_participant(ctx, cand_id);
            if (cand != NULL) {
                ic_impl_t *cand_impl = (ic_impl_t *)cand->impl;
                if (cand_impl && cand_impl->pub)
                    uuid_unparse_lower(cand_impl->pub->uuid, uuid_buf);
            }
        }
        json_t *body = json_object();
        json_object_set_new(body, "uuid", json_string(uuid_buf));
        json_object_set_new(body, "approved", json_boolean(approved));
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }

    /* peer_accepted — drives the receiver's handle_confirm_peer (ID_CONFIRM).
     * The payload names the newcomer by participant id in `peer` (or the
     * `candidate` alias); pack that participant's full public identity so
     * handle_confirm_peer's public_identity_from_json can parse it and record
     * the two-phase-admission confirmation. Without this the C handler sees an
     * empty payload and returns early, so no confirmation is recorded and the
     * provisional hold never registers (provisional_peer_count stays 0).
     * Mirrors the Python adapter's IdentityProtocol.confirm case
     * (`payload.get('peer') or payload.get('candidate')`).
     *
     * The identity goes under `peer` in an envelope carrying the confirmer's
     * freshness sequence beside it, which is the shape handle_confirm_peer
     * now requires. It sits beside the identity rather than inside it because
     * the canonical public-identity form is shared byte-for-byte with
     * Python's public_identity_to_json and must not gain a field. */
    if (strcmp(function, "peer_accepted") == 0 && json_is_object(payload)) {
        json_t *p = json_object_get(payload, "peer");
        if (!json_is_string(p)) p = json_object_get(payload, "candidate");
        const char *peer_pid = json_is_string(p) ? json_string_value(p) : NULL;
        sce_participant_t *pp = peer_pid ? sce_find_participant(ctx, peer_pid) : NULL;
        if (pp != NULL) {
            ic_impl_t *pp_impl = (ic_impl_t *)pp->impl;
            if (pp_impl != NULL && pp_impl->pub != NULL) {
                json_t *peer_json = NULL;
                if (public_identity_to_json(pp_impl->pub, &peer_json) == 0
                    && peer_json != NULL) {
                    json_t *body = json_object();
                    json_object_set_new(body, "peer", peer_json);
                    _ic_set_seq(body, payload);
                    net_msg_pack_json(&out->info.net_msg, body);
                    json_decref(body);
                }
            }
        }
        return 0;
    }

    /* propose_peer — drives the receiver's handle_vote_on_peer. The payload
     * carries the candidate's full public identity (uuid + nickname +
     * address + signature/encryptor hex), exactly the shape the production
     * welcoming_committee emits, so the receiver can run the sybil/blacklist
     * guards. public_identity_to_json produces a superset of those keys. The
     * candidate is named by participant id in `candidate`. */
    if (strcmp(function, "propose_peer") == 0 && json_is_object(payload)) {
        const char *cand_id = NULL;
        json_t *c = json_object_get(payload, "candidate");
        if (json_is_string(c)) cand_id = json_string_value(c);
        sce_participant_t *cand = cand_id ? sce_find_participant(ctx, cand_id) : NULL;
        if (cand != NULL) {
            ic_impl_t *cand_impl = (ic_impl_t *)cand->impl;
            if (cand_impl != NULL && cand_impl->pub != NULL) {
                json_t *body = NULL;
                if (public_identity_to_json(cand_impl->pub, &body) == 0
                    && body != NULL) {
                    net_msg_pack_json(&out->info.net_msg, body);
                    json_decref(body);
                }
            }
        }
        return 0;
    }

    /* partition_signal — local-only IPC payload is just the from_addr
     * string. See doc/architecture/partition-recovery.md §5.1. */
    if (strcmp(function, "partition_signal") == 0) {
        const char *from_addr = "mock-addr:0";
        if (json_is_object(payload)) {
            json_t *fa = json_object_get(payload, "from_addr");
            if (json_is_string(fa)) from_addr = json_string_value(fa);
        }
        json_t *body = json_string(from_addr);
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }

    /* first_contact_hello — the OPTIONAL 1:1 handshake's ticket. The scenario
     * names WHO minted the invitation (`minted_by`) plus the nonce and expiry,
     * and the adapter mints it here from that participant's own signable
     * identity rather than pinning a blob, because the participants' keys are
     * generated per run. What the case compares is the inviter's DECISION.
     *
     * The obj is the RAW base64url blob, not JSON: Python's Message puts
     * str(obj) straight on the wire (network/message.py _obj_str), and the
     * inviter's signature covers exactly those bytes. net_msg_pack_json would
     * JSON-quote it and the handler would (correctly) fail to decode it.
     * Mirrors the Python adapter's IdentityProtocol.hello branch. */
    if (strcmp(function, ID_FC_HELLO) == 0) {
        const char *minter_pid = from_id;
        const char *nonce = "";
        long expiry = 0;
        json_t *rv_list = NULL;
        if (json_is_object(payload)) {
            json_t *m = json_object_get(payload, "minted_by");
            if (json_is_string(m)) minter_pid = json_string_value(m);
            json_t *n = json_object_get(payload, "nonce");
            if (json_is_string(n)) nonce = json_string_value(n);
            json_t *e = json_object_get(payload, "expiry");
            if (json_is_integer(e)) expiry = (long)json_integer_value(e);
            json_t *r = json_object_get(payload, "rendezvous");
            if (json_is_array(r)) rv_list = r;
        }
        sce_participant_t *minter = sce_find_participant(ctx, minter_pid);
        if (minter == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: first_contact_hello names unknown "
                     "minted_by %s", minter_pid);
            return -1;
        }
        size_t n_rv = rv_list != NULL ? json_array_size(rv_list) : 0;
        const char *rv[8];
        if (n_rv > 8) n_rv = 8;
        for (size_t i = 0; i < n_rv; i++) {
            const char *hint = json_string_value(json_array_get(rv_list, i));
            rv[i] = hint != NULL ? hint : "";
        }
        char *blob = NULL;
        if (at_create_invitation(((ic_impl_t *)minter->impl)->full,
                                 n_rv > 0 ? rv : NULL, n_rv,
                                 expiry, nonce, &blob) != 0 || blob == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: could not mint an invitation for %s",
                     minter_pid);
            return -1;
        }
        size_t blen = strlen(blob);
        out->info.net_msg.obj = smrt_create(blen + 1);
        if (out->info.net_msg.obj == NULL) {
            free(blob);
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: out of memory for the invitation blob");
            return -1;
        }
        memcpy(out->info.net_msg.obj, blob, blen + 1);
        out->info.net_msg.len = blen;
        free(blob);
        return 0;
    }

    /* first_contact_hello_ack — the accept. The echoed nonce is informational
     * (the initiator already holds the accepter's key from the invitation it
     * redeemed), so the handler reads no further on either runtime; carried
     * anyway because it is what production sends. */
    if (strcmp(function, ID_FC_HELLO_ACK) == 0) {
        const char *nonce = "";
        if (json_is_object(payload)) {
            json_t *n = json_object_get(payload, "nonce");
            if (json_is_string(n)) nonce = json_string_value(n);
        }
        json_t *body = json_object();
        if (body != NULL) {
            json_object_set_new(body, "nonce", json_string(nonce));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* partition_probe — cross-group probe, signed JSON payload. */
    if (strcmp(function, "group_partition_probe") == 0
        && json_is_object(payload)) {
        const char *group_uuid = "00000000-0000-0000-0000-000000000000";
        int group_size = 1;
        json_t *g = json_object_get(payload, "group_uuid");
        if (json_is_string(g)) group_uuid = json_string_value(g);
        json_t *sz = json_object_get(payload, "group_size");
        if (json_is_integer(sz)) group_size = (int)json_integer_value(sz);

        /* The sequence is part of the SIGNED bytes, via the same canonical
         * builder production uses. The old pre-image covered only the group
         * uuid and size, neither of which changes between rounds, so a
         * captured probe — plaintext multicast, no prior access needed — was
         * replayable indefinitely.
         *
         * Signed even when the step asks for `unstamped`: the field is
         * stripped from the body below but the signature still covers it, so
         * what the receiver sees is a well-signed message missing its
         * sequence. That is precisely an attacker's strip, and the refusal
         * being pinned has to come from the freshness check rather than
         * incidentally from a bad signature. */
        int64_t probe_seq = _ic_step_seq(payload, "seq");
        char canon[UUID_STRING_LEN + 64];
        int clen = identity_partition_canonical_probe(group_uuid, group_size,
                                                     probe_seq, canon,
                                                     sizeof(canon));
        unsigned char sig[crypto_sign_BYTES];
        if (clen > 0 && (size_t)clen < sizeof(canon)
            && sender_impl->full != NULL) {
            crypto_sign_detached(sig, NULL, (const unsigned char *)canon,
                                 (size_t)clen,
                                 sender_impl->full->signature.private);
            char sig_hex[crypto_sign_BYTES * 2 + 1];
            hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
            json_t *from_id_json = NULL;
            public_identity_to_json(sender_impl->pub, &from_id_json);
            json_t *body = json_object();
            if (from_id_json != NULL)
                json_object_set_new(body, "from_identity", from_id_json);
            json_object_set_new(body, "from_address",
                                json_string(sender_impl->pub->address));
            json_object_set_new(body, "my_group_uuid",
                                json_string(group_uuid));
            json_object_set_new(body, "my_group_size",
                                json_integer(group_size));
            /* Omitted entirely when the step asked for an unstamped probe;
             * handle_partition_probe requires json_is_integer(seq), so a
             * missing key is the pre-change wire shape. */
            if (!(json_is_object(payload)
                  && json_is_true(json_object_get(payload, "unstamped"))))
                json_object_set_new(body, "seq",
                                    json_integer((json_int_t)probe_seq));
            json_object_set_new(body, "signature", json_string(sig_hex));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
    }

    /* partition_response — same shape + in_response_to + leader info. */
    if (strcmp(function, "group_partition_response") == 0
        && json_is_object(payload)) {
        const char *group_uuid = "00000000-0000-0000-0000-000000000000";
        int group_size = 1;
        const char *in_resp = "00000000-0000-0000-0000-000000000000";
        const char *leader_uuid = group_uuid;
        const char *leader_addr = sender_impl->pub != NULL
            ? sender_impl->pub->address : "";
        json_t *g = json_object_get(payload, "group_uuid");
        if (json_is_string(g)) group_uuid = json_string_value(g);
        json_t *sz = json_object_get(payload, "group_size");
        if (json_is_integer(sz)) group_size = (int)json_integer_value(sz);
        json_t *ir = json_object_get(payload, "in_response_to");
        if (json_is_string(ir)) in_resp = json_string_value(ir);
        /* in_response_to_id: a participant id resolved to that participant's
         * actual uuid. The probe sender's uuid is runtime-derived (it
         * differs between the Python and C harnesses), so scenarios that
         * chain probe->response can't hard-code it — they name the probing
         * participant and each adapter resolves it locally. */
        char in_resp_buf[UUID_STRING_LEN + 1] = {0};
        json_t *ir_id = json_object_get(payload, "in_response_to_id");
        if (json_is_string(ir_id)) {
            sce_participant_t *t = sce_find_participant(ctx, json_string_value(ir_id));
            if (t != NULL) {
                ic_impl_t *ti = (ic_impl_t *)t->impl;
                if (ti != NULL && ti->pub != NULL) {
                    uuid_unparse_lower(ti->pub->uuid, in_resp_buf);
                    in_resp = in_resp_buf;
                }
            }
        }
        json_t *lu = json_object_get(payload, "leader_uuid");
        if (json_is_string(lu)) leader_uuid = json_string_value(lu);
        json_t *la = json_object_get(payload, "leader_address");
        if (json_is_string(la)) leader_addr = json_string_value(la);

        /* Two sequences, both inside the signed bytes (same canonical builder
         * production uses):
         *
         *   `probe_seq` echoes the probe ROUND being answered. Without it,
         *   `in_response_to` is only the prober's uuid, which never changes,
         *   so a genuine response could be captured and re-presented for the
         *   life of the node — each time steering a request_access toward the
         *   group the responder named. The receiver refuses an echo that does
         *   not match the probe it is currently running, so this has to line
         *   up with the round the scenario's earlier step started. Default 1:
         *   the first stamp of a scenario, which is what a probe emitted by
         *   step 1 draws.
         *
         *   `seq` is the responder's own, bounding a responder to one answer
         *   within that round. */
        int64_t probe_seq = _ic_step_seq(payload, "probe_seq");
        int64_t resp_seq = _ic_step_seq(payload, "seq");
        char canon[UUID_STRING_LEN * 2 + 96];
        int clen = identity_partition_canonical_response(
            group_uuid, group_size, in_resp, probe_seq, resp_seq,
            canon, sizeof(canon));
        unsigned char sig[crypto_sign_BYTES];
        if (clen > 0 && (size_t)clen < sizeof(canon)
            && sender_impl->full != NULL) {
            crypto_sign_detached(sig, NULL, (const unsigned char *)canon,
                                 (size_t)clen,
                                 sender_impl->full->signature.private);
            char sig_hex[crypto_sign_BYTES * 2 + 1];
            hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
            json_t *from_id_json = NULL;
            public_identity_to_json(sender_impl->pub, &from_id_json);
            json_t *body = json_object();
            if (from_id_json != NULL)
                json_object_set_new(body, "from_identity", from_id_json);
            json_object_set_new(body, "from_address",
                                json_string(sender_impl->pub->address));
            json_object_set_new(body, "in_response_to",
                                json_string(in_resp));
            json_object_set_new(body, "my_group_uuid",
                                json_string(group_uuid));
            json_object_set_new(body, "my_group_size",
                                json_integer(group_size));
            json_object_set_new(body, "my_group_leader",
                                json_string(leader_uuid));
            json_object_set_new(body, "my_group_leader_address",
                                json_string(leader_addr));
            json_object_set_new(body, "in_response_to_seq",
                                json_integer((json_int_t)probe_seq));
            json_object_set_new(body, "seq",
                                json_integer((json_int_t)resp_seq));
            json_object_set_new(body, "signature", json_string(sig_hex));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
    }

    /* request_access with a JOIN TARGET (doc/architecture/gateway-reputation-tree.md). The C engine
     * REBUILDS a propagated message from the step rather than re-delivering
     * the captured bytes (it records from/to/function, not the payload), so a
     * targeted solicitation would arrive here stripped of the cohort it names
     * and be handled as an ordinary open request — the opposite of what the
     * scenario is pinning. Emitted only when the step names `group_uuid`, so
     * every untargeted request_access keeps its historical empty payload and
     * no pre-existing scenario changes shape. Slots 0-2 mirror
     * _build_announcement: package_hash (empty; C has no package hash),
     * capabilities, attestation. */
    if (strcmp(function, "request_access") == 0 && json_is_object(payload)) {
        const char *jt = json_string_value(json_object_get(payload,
                                                           "group_uuid"));
        if (jt != NULL && jt[0] != '\0') {
            json_t *body = json_array();
            json_array_append_new(body, json_string(""));
            json_array_append_new(body, json_array());
            json_array_append_new(body, json_object());
            json_array_append_new(body, json_string(jt));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
            return 0;
        }
    }

    /* full_history — the SENDER's group, history steps, and peer roster, the
     * same three-slot payload _peer_accepted emits. The C engine rebuilds
     * propagated messages (see request_access above), and a full_history
     * carrying no group is not a full history: the receiver's handler reads no
     * payload and returns, so nothing about group transfer could be observed
     * cross-language. The group is serialized AFTER the sender's admission, so
     * it carries the rotated key -- which is exactly what the joiner should
     * receive. Steps ship empty (the harness drives no DAG); the peers slot is
     * what late-joiner sync actually consumes. */
    if (strcmp(function, "full_history") == 0) {
        json_t *body = json_array();
        json_t *gj = NULL;
        if (group_to_json(&sender_impl->proc->protocol.group, &gj) == 0
            && gj != NULL)
            json_array_append_new(body, gj);
        else
            json_array_append_new(body, json_null());
        json_array_append_new(body, json_array());
        json_t *peers_json = json_array();
        for (size_t i = 0; i < sender_impl->proc->protocol.num_peers; i++) {
            json_t *pj = NULL;
            if (public_identity_to_json(&sender_impl->proc->protocol.peers[i],
                                        &pj) == 0 && pj != NULL)
                json_array_append_new(peers_json, pj);
        }
        json_array_append_new(body, peers_json);
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }

    /* group_key_update — serialize the SENDER's group as the DRY canonical
     * flat form (group_to_json), matching the Python adapter which sends
     * sender.process.group.to_canonical(). handle_group_update parses it via
     * group_from_json and adopts/rejects. Without this the C handler would see
     * an empty obj and no-op, diverging from Python on any non-degenerate
     * group update. A public_only sender (key zeroed at fixture time) emits
     * public_only=true, driving the keep-our-private-key adopt path. */
    /* hierarchy_query — a late joiner asking the group to state their
     * positions (protocol step 7). The handler answers from its own claim and
     * reads nothing out of the payload; the requestor field is carried anyway
     * because it is what production sends (identity_request_hierarchy), and a
     * scenario should exercise the bytes the wire actually has. */
    if (strcmp(function, "hierarchy_query") == 0) {
        char su[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(sender_impl->pub->uuid, su);
        json_t *body = json_pack("{s:s}", "requestor", su);
        if (body != NULL) {
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* hierarchy_root — a node's claim about ITS OWN place in the tree.
     * `node` is the sender by construction (handle_hierarchy refuses a claim
     * naming anybody else); `claims` lets a scenario name another participant
     * deliberately to exercise that refusal. `children` is a COUNT: the real
     * field holds the group uuids of the cohorts the sender gateways, and a
     * scenario has no group it created to name, so the adapter mints them.
     * They are never compared across runtimes — only the count is. `seq` is
     * the freshness stamp; `unstamped` omits it, which both runtimes must
     * refuse rather than record. */
    if (strcmp(function, "hierarchy_root") == 0) {
        char node[UUID_STRING_LEN + 1] = {0};
        const char *claims = NULL;
        int rank = 0, n_children = 0;
        bool unstamped = false;
        json_int_t seq = 1;
        const char *parent_pid = NULL;
        if (json_is_object(payload)) {
            json_t *c = json_object_get(payload, "claims");
            if (json_is_string(c)) claims = json_string_value(c);
            json_t *r = json_object_get(payload, "rank");
            if (json_is_integer(r)) rank = (int)json_integer_value(r);
            json_t *k = json_object_get(payload, "children");
            if (json_is_integer(k)) n_children = (int)json_integer_value(k);
            json_t *u = json_object_get(payload, "unstamped");
            unstamped = json_is_true(u);
            json_t *q = json_object_get(payload, "seq");
            if (json_is_integer(q)) seq = json_integer_value(q);
            json_t *pp = json_object_get(payload, "parent");
            if (json_is_string(pp)) parent_pid = json_string_value(pp);
        }
        const public_identity_t *claimant = sender_impl->pub;
        if (claims != NULL) {
            sce_participant_t *cp = sce_find_participant(ctx, claims);
            if (cp == NULL) {
                snprintf(ctx->err, sizeof(ctx->err),
                         "build_inbound: hierarchy_root claims unknown %s",
                         claims);
                return -1;
            }
            claimant = ((ic_impl_t *)cp->impl)->pub;
        }
        uuid_unparse_lower(claimant->uuid, node);
        char parent[UUID_STRING_LEN + 1] = {0};
        if (parent_pid != NULL) {
            sce_participant_t *pp2 = sce_find_participant(ctx, parent_pid);
            if (pp2 == NULL) {
                snprintf(ctx->err, sizeof(ctx->err),
                         "build_inbound: hierarchy_root parent unknown %s",
                         parent_pid);
                return -1;
            }
            uuid_unparse_lower(((ic_impl_t *)pp2->impl)->pub->uuid, parent);
        }
        json_t *children = json_array();
        for (int i = 0; i < n_children; i++) {
            /* Deterministic per (node, index), the same shape the Python
             * adapter mints. Hashed rather than uuid5 because this adapter
             * already derives its participant uuids by hash, so the two
             * runtimes' uuids differ everywhere and only counts are compared. */
            char label[128];
            snprintf(label, sizeof(label), "%s:cohort:%d", node, i);
            uuid_t cu;
            crypto_generichash(cu, sizeof(uuid_t),
                               (const unsigned char *)label, strlen(label),
                               NULL, 0);
            cu[6] = (cu[6] & 0x0F) | 0x40;
            cu[8] = (cu[8] & 0x3F) | 0x80;
            char cus[UUID_STRING_LEN + 1] = {0};
            uuid_unparse_lower(cu, cus);
            json_array_append_new(children, json_string(cus));
        }
        json_t *body = json_pack("{s:s, s:s, s:o, s:i}",
                                 "node", node, "parent", parent,
                                 "children", children, "rank", rank);
        if (body != NULL) {
            if (!unstamped)
                json_object_set_new(body, "seq", json_integer(seq));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        } else {
            json_decref(children);
        }
        return 0;
    }

    /* subtree_roster_query — {requestor, requesting_process}.
     * `requesting_process` is load-bearing: the answer is addressed to the
     * process the requestor names, and the aggregation that consumes it lives
     * in the main loop, not in the identity process. */
    /* operator_attest_query — the attended-now pull as it arrives on the wire.
     * The nonce binds an answer to the request that asked for it, so the
     * scenario spells it out rather than having the adapter mint one; omitting
     * it (`no_nonce`) is a distinct case, because an attestation bound to
     * nothing is replayable forever and must be refused rather than answered.
     * Mirrors the Python adapter's IdentityProtocol.attest_req branch. */
    if (strcmp(function, "operator_attest_query") == 0) {
        const char *nonce = "n1";
        bool no_nonce = false;
        if (json_is_object(payload)) {
            json_t *nn = json_object_get(payload, "no_nonce");
            no_nonce = json_is_true(nn);
            json_t *nj = json_object_get(payload, "nonce");
            if (json_is_string(nj)) nonce = json_string_value(nj);
        }
        json_t *body = no_nonce ? json_object()
                                : json_pack("{s:s}", "nonce", nonce);
        if (body != NULL) {
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    if (strcmp(function, "subtree_roster_query") == 0) {
        char su[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(sender_impl->pub->uuid, su);
        const char *req_proc = "main";
        if (json_is_object(payload)) {
            json_t *pr = json_object_get(payload, "proc");
            if (json_is_string(pr)) req_proc = json_string_value(pr);
        }
        json_t *body = json_pack("{s:s, s:s}", "requestor", su,
                                 "requesting_process", req_proc);
        if (body != NULL) {
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* tier_update — local IPC from the reputation process, not a wire
     * message: the (peer_uuid, tier) pair _publish_tier_change emits. `peer`
     * names a participant; `unknown_peer` sends a uuid for nobody, which both
     * runtimes must drop quietly rather than apply to somebody. */
    if (strcmp(function, "tier_update") == 0) {
        char target[UUID_STRING_LEN + 1] = {0};
        int tier = 0;
        const char *peer_pid = NULL;
        bool unknown = false;
        if (json_is_object(payload)) {
            json_t *pp = json_object_get(payload, "peer");
            if (json_is_string(pp)) peer_pid = json_string_value(pp);
            json_t *t = json_object_get(payload, "tier");
            if (json_is_integer(t)) tier = (int)json_integer_value(t);
            unknown = json_is_true(json_object_get(payload, "unknown_peer"));
        }
        if (unknown) {
            uuid_t nobody;
            const char label[] = "tier:nobody";
            crypto_generichash(nobody, sizeof(uuid_t),
                               (const unsigned char *)label, strlen(label),
                               NULL, 0);
            nobody[6] = (nobody[6] & 0x0F) | 0x40;
            nobody[8] = (nobody[8] & 0x3F) | 0x80;
            uuid_unparse_lower(nobody, target);
        } else if (peer_pid != NULL) {
            sce_participant_t *tp = sce_find_participant(ctx, peer_pid);
            if (tp == NULL) {
                snprintf(ctx->err, sizeof(ctx->err),
                         "build_inbound: tier_update names unknown %s",
                         peer_pid);
                return -1;
            }
            uuid_unparse_lower(((ic_impl_t *)tp->impl)->pub->uuid, target);
        } else {
            uuid_unparse_lower(sender_impl->pub->uuid, target);
        }
        json_t *body = json_array();
        json_array_append_new(body, json_string(target));
        json_array_append_new(body, json_integer(tier));
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }

    if (strcmp(function, "group_key_update") == 0) {
        json_t *gj = NULL;
        if (group_to_json(&sender_impl->proc->protocol.group, &gj) == 0
            && gj != NULL) {
            net_msg_pack_json(&out->info.net_msg, gj);
            json_decref(gj);
        }
        return 0;
    }

    /* peer_identity_query — identity-resync layer 3. {group_uuid,
     * have:[uuids]}. group_uuid is the asker's group (== the responder's in
     * a shared-group scenario); handle_identity_query gates on that match
     * and on the asker's uuid being absent from the have-list. */
    if (strcmp(function, "peer_identity_query") == 0) {
        char guuid[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(sender_impl->proc->protocol.group.uuid, guuid);
        json_t *have = json_array();
        if (json_is_object(payload)) {
            json_t *h = json_object_get(payload, "have");
            if (json_is_array(h)) {
                size_t hn = json_array_size(h);
                for (size_t i = 0; i < hn; i++) {
                    json_t *v = json_array_get(h, i);
                    if (json_is_string(v))
                        json_array_append_new(have,
                                              json_string(json_string_value(v)));
                }
            }
        }
        json_t *body = json_object();
        json_object_set_new(body, "group_uuid", json_string(guuid));
        json_object_set_new(body, "have", have);
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }

    /* peer_identity_response — the sender's published identity + address.
     * handle_identity_response gates on from_address being a known group
     * address, then adds the identity to peers[]. No signature: the
     * handler does not verify one (the address-in-group gate is the
     * trust anchor). */
    if (strcmp(function, "peer_identity_response") == 0) {
        json_t *from_id_json = NULL;
        public_identity_to_json(sender_impl->pub, &from_id_json);
        json_t *body = json_object();
        if (from_id_json != NULL)
            json_object_set_new(body, "from_identity", from_id_json);
        json_object_set_new(body, "from_address",
                            json_string(sender_impl->pub->address));
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }

    return 0;
}

static int _dispatch(sce_run_ctx_t *ctx,
                     sce_participant_t *target,
                     generic_msg_t *inbound) {
    (void)ctx;
    ic_impl_t *impl = (ic_impl_t *)target->impl;
    /* trigger_first_contact_initiate — drive the INITIATOR half through the
     * production call rather than handing the target a hello the harness
     * built. A pseudo-step because `initiate` is an API call, not an inbound
     * message. Mirrors the Python adapter's _TRIGGER_FC_INITIATE. */
    if (inbound->type == NET_MESSAGE && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function,
                  "trigger_first_contact_initiate") == 0) {
        json_t *spec = NULL;
        if (net_msg_unpack_json(&inbound->info.net_msg, &spec) != 0
            || !json_is_object(spec)) {
            if (spec != NULL) json_decref(spec);
            snprintf(ctx->err, sizeof(ctx->err),
                     "trigger_first_contact_initiate: missing payload");
            return -1;
        }
        const char *minter_pid =
            json_string_value(json_object_get(spec, "minted_by"));
        const char *nonce = json_string_value(json_object_get(spec, "nonce"));
        json_t *e = json_object_get(spec, "expiry");
        long expiry = json_is_integer(e) ? (long)json_integer_value(e) : 0;
        json_t *rv_list = json_object_get(spec, "rendezvous");
        sce_participant_t *minter = minter_pid != NULL
            ? sce_find_participant(ctx, minter_pid) : NULL;
        if (minter == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "trigger_first_contact_initiate: unknown minted_by %s",
                     minter_pid != NULL ? minter_pid : "(null)");
            json_decref(spec);
            return -1;
        }
        size_t n_rv = json_is_array(rv_list) ? json_array_size(rv_list) : 0;
        const char *rv[8];
        if (n_rv > 8) n_rv = 8;
        for (size_t i = 0; i < n_rv; i++) {
            const char *hint = json_string_value(json_array_get(rv_list, i));
            rv[i] = hint != NULL ? hint : "";
        }
        char *blob = NULL;
        int mrc = at_create_invitation(((ic_impl_t *)minter->impl)->full,
                                       n_rv > 0 ? rv : NULL, n_rv, expiry,
                                       nonce != NULL ? nonce : "", &blob);
        json_decref(spec);
        if (mrc != 0 || blob == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "trigger_first_contact_initiate: could not mint the ticket");
            return -1;
        }
        int rc = at_first_contact_initiate(impl->proc, NULL, blob, NULL, NULL);
        free(blob);
        if (rc != 0) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "trigger_first_contact_initiate: initiate failed (%d)", rc);
            return -1;
        }
        return 0;
    }

    /* trigger_first_contact_restart — drop the OPTIONAL 1:1 handshake's
     * in-memory spent-nonce guard WITHOUT touching the file it persists to:
     * the closest a single-process harness gets to restarting the node.
     * Whatever the guard knows afterwards it read back off disk. Mirrors the
     * Python adapter's _TRIGGER_FC_RESTART, which rebuilds SpentNonces. */
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function,
                  "trigger_first_contact_restart") == 0) {
        at_first_contact_reset();
        return 0;
    }
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function, "trigger_caps_resync") == 0) {
        /* Pseudo-function: drive the periodic caps-resync sweep directly (it is
         * timer-gated in production, so there is no wire message to dispatch).
         * Emitted peer_caps_query messages are captured via the messaging_send
         * hook -> ctx->captured (attributed to current_dispatcher == target).
         * Mirrors the Python adapter's trigger_caps_resync handling. */
        identity_periodic_caps_resync(impl->proc);
        return 0;
    }
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && (strcmp(inbound->info.net_msg.function, "trigger_attest_pull") == 0
            || strcmp(inbound->info.net_msg.function,
                      "trigger_attest_replay") == 0)) {
        /* Pseudo-function: one operator-attended pull, end to end. `impl` is
         * the pull TARGET; from_whom is the puller. Runs the real API on both
         * ends — the puller mints and records a nonce
         * (identity_request_attestation), the target answers through the same
         * builder the wire handler uses (identity_attest_response), and the
         * answer is dispatched back into the puller's handler. Mirrors the
         * Python adapter's _run_attest_pull; the routes to the attended state
         * differ by language (seam here, main-loop round trip there) but the
         * observables do not. */
        bool replay = (strcmp(inbound->info.net_msg.function,
                              "trigger_attest_replay") == 0);
        ic_impl_t *puller =
            _ic_impl_for_uuid(ctx, inbound->info.net_msg.from_whom.uuid);
        if (puller == NULL) {
            snprintf(ctx->err, sizeof(ctx->err), "attest pull: unknown puller");
            return -1;
        }
        return _ic_run_attest_pull(ctx, puller, impl, replay);
    }
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function, "trigger_cohort_join") == 0) {
        /* Pseudo-function: solicit membership in a cohort this participant is
         * NOT in (runtime cross-group join, doc/architecture/gateway-reputation-tree.md).
         * The payload names
         * the target cohort; the scenario pins that uuid via fixtures.groups so
         * it is the same string in both harnesses. Unlike the other
         * pseudo-functions this one DOES emit wire traffic — the ordinary
         * request_access, now carrying the target in payload slot 3 — because
         * the whole point is that a join IS the ordinary admission and not a
         * private side channel. Mirrors the Python adapter's
         * trigger_cohort_join handling. */
        json_t *jp = NULL;
        char join_target[UUID_STRING_LEN + 1] = {0};
        if (net_msg_unpack_json(&inbound->info.net_msg, &jp) == 0 && jp != NULL) {
            const char *g = json_string_value(json_object_get(jp, "group_uuid"));
            if (g != NULL)
                snprintf(join_target, sizeof(join_target), "%s", g);
            json_decref(jp);
        }
        /* Same synthetic directory the wire path below builds: without
         * "network" in it, _announce_identity returns early and the join would
         * emit nothing at all. */
        array_t *jq = NULL;
        array_create(&jq);
        static const char *const jq_names[] = {"network", "identity",
                                               "negotiation", "main"};
        for (size_t i = 0; i < sizeof(jq_names) / sizeof(jq_names[0]); i++) {
            data_t *qn = string_data((string_t)jq_names[i], strlen(jq_names[i]));
            if (qn != NULL) array_append(jq, qn);
        }
        int jrc = identity_request_cohort_join(impl->proc, jq, join_target);
        array_free(jq);
        if (jrc != 0) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "trigger_cohort_join: request for %s refused",
                     join_target);
            return -1;
        }
        return 0;
    }
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function, "trigger_hierarchy") == 0) {
        /* Pseudo-function: re-derive this participant's place in the gateway
         * tree (protocol step 7) and record the parent as a participant id.
         * Mirrors the Python adapter's trigger_hierarchy handling. */
        char parent[UUID_STRING_LEN + 1] = {0};
        identity_get_parent_gateway(impl->proc, parent, sizeof(parent));
        impl->parent_gateway_pid[0] = '\0';
        if (parent[0] != '\0') {
            const char *pid = _ic_pid_for_uuid(ctx, parent);
            /* at_strlcpy, not snprintf: the fallback value is a 36-char uuid
             * string and this field is SCE_ID_LEN (32), so the truncation is
             * deliberate — it keeps a recognisable prefix in the mismatch
             * message at the check site, and a truncated uuid can never equal
             * a participant id, which is the "no match" outcome wanted. Said
             * with a bounded copy rather than a format, so it does not read as
             * an accidental overflow (GCC 15 -Wformat-truncation flags the
             * snprintf form as an error under -Werror). */
            at_strlcpy(impl->parent_gateway_pid, pid != NULL ? pid : parent,
                       sizeof(impl->parent_gateway_pid));
        }
        return 0;
    }
    if (inbound->type == NET_MESSAGE
        && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function, "trigger_subtree_roster") == 0) {
        /* Pseudo-function: run the requestor-side subtree-roster walk on this
         * participant. The fetch asks each gateway for its roster response via
         * the SAME helper the wire handler uses. The flattened member uuids are
         * mapped back to participant ids and stored (sorted) for the check.
         * Mirrors the Python adapter's trigger_subtree_roster handling. */
        char top_uuid[UUID_STRING_LEN + 1];
        _ic_uuid_str(impl, top_uuid);
        json_t *members = NULL, *privates = NULL;
        bool complete = false;
        identity_aggregate_subtree_roster(top_uuid, _roster_fetch, ctx,
                                          &members, &complete, &privates);
        json_t *ids = json_array();
        if (json_is_array(members)) {
            size_t i, n = json_array_size(members);
            for (i = 0; i < n; i++) {
                const char *mu = json_string_value(
                    json_object_get(json_array_get(members, i), "uuid"));
                const char *pid = mu ? _ic_pid_for_uuid(ctx, mu) : NULL;
                if (pid != NULL) json_array_append_new(ids, json_string(pid));
            }
        }
        if (impl->subtree_roster != NULL) json_decref(impl->subtree_roster);
        impl->subtree_roster = ids;
        if (members != NULL) json_decref(members);
        if (privates != NULL) json_decref(privates);
        return 0;
    }
    /* directory_t is array_t of sibling-process queue names. Populate it
     * with the names handlers expect to find: _announce_identity (the
     * partition-recovery request_access re-broadcast) returns early unless
     * the directory contains "network" (array_contains check), and other
     * handlers index it similarly. The real runtime supplies this
     * directory; an empty array silently suppresses those emissions. */
    array_t *queues = NULL;
    array_create(&queues);
    static const char *const qnames[] = {"network", "identity",
                                         "negotiation", "main"};
    for (size_t i = 0; i < sizeof(qnames) / sizeof(qnames[0]); i++) {
        data_t *qn = string_data((string_t)qnames[i], strlen(qnames[i]));
        if (qn != NULL) array_append(queues, qn);
    }
    run_message_handlers(impl->proc, queues, NET_MESSAGE, inbound);
    array_free(queues);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Adapter entry                                                              */
/* ------------------------------------------------------------------------- */

/* Validate `expected_state` against post-scenario participant state.
 * Mirrors the Python identity adapter's _Participant._check_expected_state
 * (src/autonomous-trust/conformance/harness/python/adapters/identity.py:86-111).
 * Supported keys: phase (int), peer_count (int), has_peer (uuid string).
 * Unsupported keys produce an error so the corpus and the two adapters
 * stay aligned — an asymmetry caught at the gate beats a silent skip.
 *
 * Returns 0 if all checks pass, -1 with ctx->err on the first mismatch. */
static int _identity_check_expected_state(sce_run_ctx_t *ctx) {
    json_t *expected = json_object_get(ctx->case_data, "expected_state");
    if (!json_is_object(expected)) return 0;

    const char *pid;
    json_t *checks;
    json_object_foreach(expected, pid, checks) {
        if (strcmp(pid, "group") == 0) {
            /* Engine convention from the Python side: group-state is
             * adapter-driven; identity has no group-aware checks yet, so
             * skip silently. */
            continue;
        }
        if (!json_is_object(checks)) continue;
        sce_participant_t *p = sce_find_participant(ctx, pid);
        if (p == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "expected_state references unknown participant %s", pid);
            return -1;
        }
        ic_impl_t *impl = (ic_impl_t *)p->impl;
        process_t *proc = impl->proc;

        const char *key;
        json_t *val;
        json_object_foreach(checks, key, val) {
            if (strcmp(key, "phase") == 0) {
                int want = (int)json_integer_value(val);
                int got = (int)proc->protocol.phase;
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: phase=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "peer_count") == 0) {
                int want = (int)json_integer_value(val);
                /* protocol.num_peers is the same field the production
                 * peer-add path advances; mirrors Python's
                 * `sum(len(level) for level in self.process.peers.hierarchy)`
                 * (which collapses all hierarchy levels to a flat count). */
                int got = (int)proc->protocol.num_peers;
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: peer_count=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "has_peer") == 0) {
                const char *uuid_str = json_string_value(val);
                if (uuid_str == NULL) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer expects a uuid string", pid);
                    return -1;
                }
                uuid_t want_uuid;
                if (uuid_parse(uuid_str, want_uuid) != 0) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer uuid %s not parseable",
                             pid, uuid_str);
                    return -1;
                }
                bool found = false;
                for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                    if (memcmp(proc->protocol.peers[i].uuid, want_uuid,
                               sizeof(uuid_t)) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer %s not present (have %d peers)",
                             pid, uuid_str, (int)proc->protocol.num_peers);
                    return -1;
                }
            } else if (strcmp(key, "direct_peers") == 0) {
                /* The OPTIONAL 1:1 first-contact handshake's admission, as
                 * {participant_id: bool}. True asserts BOTH halves of what a
                 * direct peer is: present in peers[], and ABSENT from the
                 * group address map. The second half is the security property
                 * -- a first-contact peer is directly reachable, not a group
                 * member, so the shared group key must not follow it in.
                 * False asserts the peer was not admitted at all (the refusal
                 * cases). Mirrors the Python adapter's direct_peers. */
                const char *dp_pid;
                json_t *dp_want;
                json_object_foreach(val, dp_pid, dp_want) {
                    sce_participant_t *other = sce_find_participant(ctx, dp_pid);
                    if (other == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: direct_peers names unknown participant %s",
                                 pid, dp_pid);
                        return -1;
                    }
                    const public_identity_t *want_id =
                        ((ic_impl_t *)other->impl)->pub;
                    bool found = false;
                    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                        if (memcmp(proc->protocol.peers[i].uuid, want_id->uuid,
                                   sizeof(uuid_t)) == 0) {
                            found = true;
                            break;
                        }
                    }
                    if (!json_is_true(dp_want)) {
                        if (found) {
                            snprintf(ctx->err, sizeof(ctx->err),
                                     "%s: %s was admitted as a peer, expected "
                                     "refusal", pid, dp_pid);
                            return -1;
                        }
                        continue;
                    }
                    if (!found) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: %s is not a peer, expected a direct-peer "
                                 "admission", pid, dp_pid);
                        return -1;
                    }
                    char want_uuid[UUID_STR_LEN + 1];
                    uuid_unparse_lower(want_id->uuid, want_uuid);
                    data_t *addr_dat = NULL;
                    if (map_get(&proc->protocol.group.address_map, want_uuid,
                                &addr_dat) == 0) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: %s landed in the GROUP address map; a "
                                 "first-contact peer must not become a group "
                                 "member (the group key would follow)",
                                 pid, dp_pid);
                        return -1;
                    }
                }
            } else if (strcmp(key, "peer_position") == 0) {
                /* {peer_id: geohash} (Increment 2) — the coarse position this
                 * participant recorded for another, via
                 * identity_get_peer_position. '' means none recorded (the peer
                 * opted out, or the response was dropped/refused) — the ordinary
                 * default. Mirrors the Python adapter's peer_position, keyed by
                 * the same lowercased uuid. */
                const char *pp_pid;
                json_t *pp_want;
                json_object_foreach(val, pp_pid, pp_want) {
                    sce_participant_t *other = sce_find_participant(ctx, pp_pid);
                    if (other == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: peer_position names unknown participant %s",
                                 pid, pp_pid);
                        return -1;
                    }
                    const public_identity_t *want_id =
                        ((ic_impl_t *)other->impl)->pub;
                    char want_uuid[UUID_STR_LEN + 1];
                    uuid_unparse_lower(want_id->uuid, want_uuid);
                    char got[64];
                    identity_get_peer_position(want_uuid, got, sizeof(got));
                    const char *want = json_string_value(pp_want);
                    if (want == NULL) want = "";
                    if (strcmp(got, want) != 0) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: peer_position[%s]=%s, expected %s",
                                 pid, pp_pid, got, want);
                        return -1;
                    }
                }
            } else if (strcmp(key, "first_contact_hello_endpoint") == 0) {
                /* Where trigger_first_contact_initiate addressed its hello.
                 * Pins the resolution ORDER: the invitation's rendezvous hint
                 * wins over the address the inviter's identity advertises.
                 * Both are well-formed addresses, so preferring the wrong one
                 * fails silently -- it works on a LAN and never reaches a
                 * remote friend. Mirrors the Python adapter's check. */
                const char *want = json_string_value(val);
                if (want == NULL) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: first_contact_hello_endpoint expects a string",
                             pid);
                    return -1;
                }
                if (strcmp(impl->fc_hello_endpoint, want) != 0) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: first_contact_hello_endpoint=%s, expected %s",
                             pid, impl->fc_hello_endpoint, want);
                    return -1;
                }
            } else if (strcmp(key, "first_contact_acks_emitted") == 0) {
                /* How many first_contact_hello_ack messages this participant
                 * emitted over the whole scenario. The observable for the
                 * single-use guard: the peer is legitimately admitted on the
                 * first redemption, so a replay that was honored twice differs
                 * ONLY in what went back out. Mirrors the Python adapter's
                 * emit_tally-based check. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function,
                                  ID_FC_HELLO_ACK) == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: first_contact_acks_emitted=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "first_contact_nonce_spent") == 0) {
                /* The durable single-use guard itself, as {nonce: bool}. Read
                 * after a trigger_first_contact_restart, this is the only
                 * place the on-disk store is observed rather than inferred --
                 * and the two runtimes read each other's file only if they
                 * agree on its shape. Mirrors the Python adapter, which reads
                 * the process's SpentNonces. */
                const char *nonce;
                json_t *nwant;
                json_object_foreach(val, nonce, nwant) {
                    bool got = at_first_contact_nonce_spent(nonce);
                    bool want = json_is_true(nwant);
                    if (got != want) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: first_contact_nonce_spent[%s]=%s, "
                                 "expected %s", pid, nonce,
                                 got ? "true" : "false",
                                 want ? "true" : "false");
                        return -1;
                    }
                }
            } else if (strcmp(key, "attested_now") == 0) {
                /* The attended-now stamp this participant's last ACCEPTED pull
                 * yielded: the pinned epoch when a human is at the target's
                 * console, 0.0 when nobody is. A rejected pull leaves it
                 * untouched — that is how "a replay changes nothing" is
                 * stated. Compared exactly, which is only safe because the
                 * scenario pins the clock (fixtures.operator_session.clock)
                 * rather than letting a wall-clock stamp in. Symmetric with
                 * the Python adapter's accessor. */
                double want_stamp = json_number_value(val);
                /* The clock is pinned, so these are the same literal on both
                 * sides; an epsilon only guards the double round-trip through
                 * JSON, not any real tolerance for drift. */
                double diff = impl->attest_stamp - want_stamp;
                if (diff < 0.0) diff = -diff;
                if (diff > 1e-6) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: attested_now=%f, expected %f",
                             pid, impl->attest_stamp, want_stamp);
                    return -1;
                }
            } else if (strcmp(key, "peer_clock_offset") == 0
                       || strcmp(key, "peer_clock_delay") == 0
                       || strcmp(key, "peer_clock_usable") == 0) {
                /* Cohort clock skew measured from the attest round trip
                 * (cohort-clock-skew.md, Stage 0). val = {peer_id: value}.
                 *
                 * These read what the PRODUCTION handler recorded (via
                 * identity_get_peer_clock_sample), not anything the adapter
                 * computed -- unlike attested_now/attest_accepted, which the
                 * adapter derives itself. */
                const char *peer_ref;
                json_t *want;
                json_object_foreach(val, peer_ref, want) {
                    json_t *entry = impl->attest_clock_samples != NULL
                        ? json_object_get(impl->attest_clock_samples, peer_ref)
                        : NULL;
                    if (entry == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: no clock sample for %s", pid, peer_ref);
                        return -1;
                    }
                    if (strcmp(key, "peer_clock_usable") == 0) {
                        bool got_u = json_is_true(json_object_get(entry, "usable"));
                        if (got_u != json_is_true(want)) {
                            snprintf(ctx->err, sizeof(ctx->err),
                                     "%s: %s clock_usable=%s, expected %s",
                                     pid, peer_ref, got_u ? "true" : "false",
                                     json_is_true(want) ? "true" : "false");
                            return -1;
                        }
                        continue;
                    }
                    const char *field = strcmp(key, "peer_clock_offset") == 0
                                        ? "offset" : "delay";
                    double got = json_number_value(json_object_get(entry, field));
                    double diff = got - json_number_value(want);
                    if (diff < 0.0) diff = -diff;
                    /* Tolerance, not equality: both runtimes reach this through
                     * double arithmetic, and pinned clocks make the value exact
                     * to well inside a microsecond. Matches Python's 1e-6. */
                    if (diff > 1e-6) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: %s %s=%f, expected %f", pid, peer_ref,
                                 key, got, json_number_value(want));
                        return -1;
                    }
                }
            } else if (strcmp(key, "attest_accepted") == 0) {
                /* Per-pull accept/reject verdicts, in step order — the nonce
                 * state machine: an answer counts only against the pull that
                 * asked for it, so a re-presented answer must read false. */
                if (!json_is_array(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: attest_accepted expects an array", pid);
                    return -1;
                }
                json_t *got = impl->attest_accepted;
                size_t want_n = json_array_size(val);
                size_t got_n = got ? json_array_size(got) : 0;
                if (want_n != got_n) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: attest_accepted has %d entries, expected %d",
                             pid, (int)got_n, (int)want_n);
                    return -1;
                }
                for (size_t ai = 0; ai < want_n; ai++) {
                    bool w = json_is_true(json_array_get(val, ai));
                    bool g = json_is_true(json_array_get(got, ai));
                    if (w != g) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: attest_accepted[%d]=%d, expected %d",
                                 pid, (int)ai, (int)g, (int)w);
                        return -1;
                    }
                }
            } else if (strcmp(key, "operator_bound") == 0) {
                /* { "<peer_ref>": bool } — the welcomer's VERIFIED
                 * operator-attended determination per stored peer (ethne
                 * D8/Q9). peer_ref matches the stored peer's nickname
                 * "<id>.scenario" or a raw uuid; symmetric with the Python
                 * adapter's accessor. */
                if (!json_is_object(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: operator_bound expects an object", pid);
                    return -1;
                }
                const char *ref; json_t *wantv;
                json_object_foreach(val, ref, wantv) {
                    bool want_bound = json_is_true(wantv);
                    char nick[NAME_LEN + 1];
                    snprintf(nick, sizeof(nick), "%s.scenario", ref);
                    bool found = false, actual = false;
                    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                        char ustr[UUID_STRING_LEN + 1];
                        uuid_unparse_lower(proc->protocol.peers[i].uuid, ustr);
                        if (strcmp(proc->protocol.peers[i].nickname, nick) == 0
                            || strcmp(proc->protocol.peers[i].nickname, ref) == 0
                            || strcmp(ustr, ref) == 0) {
                            found = true;
                            actual = proc->protocol.peers[i].operator_bound;
                            break;
                        }
                    }
                    if (!found) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: operator_bound: no stored peer %s", pid, ref);
                        return -1;
                    }
                    if (actual != want_bound) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: operator_bound[%s]=%d, expected %d",
                                 pid, ref, (int)actual, (int)want_bound);
                        return -1;
                    }
                }
            } else if (strcmp(key, "operator_guardian") == 0) {
                /* { "<peer_ref>": bool } — whether the welcomer KEPT the peer's
                 * advertised guardian key, which it does only after verifying
                 * the binding against the operator anchor. A bool rather than
                 * the key bytes on purpose: the assertion is the verdict, and
                 * comparing key material would pin each adapter's derivation
                 * instead of the rule. The stored key IS the verdict — there is
                 * no separate verified flag — so empty means refused or never
                 * offered. Symmetric with the Python adapter's accessor. */
                if (!json_is_object(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: operator_guardian expects an object", pid);
                    return -1;
                }
                const char *gref; json_t *gwant;
                json_object_foreach(val, gref, gwant) {
                    bool want_g = json_is_true(gwant);
                    char nick[NAME_LEN + 1];
                    snprintf(nick, sizeof(nick), "%s.scenario", gref);
                    bool found = false, actual = false;
                    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                        char ustr[UUID_STRING_LEN + 1];
                        uuid_unparse_lower(proc->protocol.peers[i].uuid, ustr);
                        if (strcmp(proc->protocol.peers[i].nickname, nick) == 0
                            || strcmp(proc->protocol.peers[i].nickname, gref) == 0
                            || strcmp(ustr, gref) == 0) {
                            found = true;
                            actual = !at_operator_pubkey_empty(
                                proc->protocol.peers[i].operator_pubkey);
                            break;
                        }
                    }
                    if (!found) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: operator_guardian: no stored peer %s",
                                 pid, gref);
                        return -1;
                    }
                    if (actual != want_g) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: operator_guardian[%s]=%d, expected %d",
                                 pid, gref, (int)actual, (int)want_g);
                        return -1;
                    }
                }
            } else if (strcmp(key, "peer_caps_count") == 0) {
                /* `peer_caps_count: <int>` — assert the number of caps
                 * recorded for THIS participant under their own uuid in
                 * id_state.peer_caps_map. Populated by handle_caps_response
                 * on inbound peer_caps_response. Wait — actually we want
                 * the caps recorded ABOUT a peer; the key references the
                 * recipient and the value is the count under the SENDER
                 * uuid. The scenario authoring convention is that
                 * `peer_caps_count` is keyed by participant id whose
                 * peer_caps_map entry under the OTHER participant's uuid
                 * we want — but with a 2-party scenario the only sender
                 * is the other participant. Simplest reading: assert
                 * `id_state.peer_caps_map` has `int` total entries for
                 * SOME peer registered after the scenario; we encode
                 * that as: count across all entries in the map for THIS
                 * participant. The map is shared, so the count is the
                 * global peer count — that's fine for a 2-party probe. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->participant_count; i++) {
                    ic_impl_t *other = (ic_impl_t *)ctx->participants[i].impl;
                    if (other == NULL || other->pub == NULL) continue;
                    if (strcmp(ctx->participants[i].id, pid) == 0) continue;
                    got += identity_get_peer_caps_count(other->pub->uuid);
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: peer_caps_count=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "partition_probes_emitted") == 0
                       || strcmp(key, "partition_responses_emitted") == 0) {
                /* Count emissions of the named function attributed to this
                 * participant across the whole scenario. The engine records
                 * every emitted (from, to, function) in ctx->captured; the
                 * cooldown scenario delivers N signals and asserts the
                 * per-from_addr cooldown collapses them to a single probe.
                 * Mirrors the Python adapter's per-participant emit_tally. */
                const char *want_fn =
                    (key[10] == 'p') ? "group_partition_probe"
                                     : "group_partition_response";
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function, want_fn) == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: %s=%d, expected %d", pid, key, got, want);
                    return -1;
                }
            } else if (strcmp(key, "freshness_refusals") == 0) {
                /* {verb: N} -- messages refused as stale, per verb. The
                 * positive observable for the freshness guard: every other
                 * partition observable counts emissions, and a second
                 * delivery is already suppressed by the per-sender response
                 * cooldown, so "one response after two deliveries" is a
                 * number the cooldown alone produces. Only the mark produces
                 * a refusal. id_state is process-global, so the count is not
                 * per-participant -- the cases asserting it have exactly one
                 * refusing participant. Mirrors the Python adapter's
                 * Freshness.refusals(verb). */
                const char *verb = NULL;
                json_t *want_val = NULL;
                json_object_foreach(val, verb, want_val) {
                    int64_t want = (int64_t)json_integer_value(want_val);
                    int64_t got = identity_freshness_refusals(verb);
                    if (got != want) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: freshness_refusals[%s]=%lld, expected %lld",
                                 pid, verb, (long long)got, (long long)want);
                        return -1;
                    }
                }
            } else if (strcmp(key, "caps_query_emitted") == 0) {
                /* Directed peer_caps_query emissions from the periodic caps-
                 * resync sweep (driven by the trigger_caps_resync pseudo-step).
                 * With more cap-less peers than the per-sweep cap, the sweep
                 * emits exactly CAPS_RESYNC_MAX_PER_SWEEP. Mirrors the Python
                 * emit_tally check; pins the cap cross-language. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function,
                                  "peer_caps_query") == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: caps_query_emitted=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "position_responses_emitted") == 0) {
                /* peer_position_response emissions by this participant
                 * (Increment 2). The opt-in guard's observable: an opted-OUT
                 * node emits 0 (position-absent-is-normal), an opted-IN one
                 * emits 1 per answered query — so dropping the guard makes the
                 * opt-out case fail. Mirrors the Python emit_tally check. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function,
                                  "peer_position_response") == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: position_responses_emitted=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "propose_emitted") == 0) {
                /* Admit/reject observable for the zta-x509-* scenarios: a
                 * welcomed newcomer triggers one propose_peer; a ZTA-rejected
                 * one triggers none. Mirrors the Python emit_tally check. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function, "propose_peer") == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: propose_emitted=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "votes_emitted") == 0) {
                /* Approval-vote observable for the propose-vote scenarios: a
                 * receiver that accepts a proposal emits one vote_on_peer; a
                 * receiver whose sybil/blacklist guard fires emits none.
                 * Mirrors the Python emit_tally check (which ticks
                 * vote_response after the propose dispatch to flush the
                 * deferred vote, so both sides count the same emission). */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function, "vote_on_peer") == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: votes_emitted=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "group_owns_private_key") == 0) {
                /* True iff this participant's group still holds the shared
                 * PRIVATE box key. Mirrors Python Group.owns_private_key.
                 * group_to_json uses the same sodium_is_zero(private) gate. */
                bool want = json_is_true(val);
                bool got = !sodium_is_zero(proc->protocol.group.encryptor.private,
                                           crypto_box_SECRETKEYBYTES);
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: group_owns_private_key=%d, expected %d",
                             pid, (int)got, (int)want);
                    return -1;
                }
            } else if (strcmp(key, "group_size") == 0) {
                /* Address-map size — proves the larger membership WAS adopted.
                 * Mirrors Python len(group.addresses). */
                int want = (int)json_integer_value(val);
                int got = (int)map_size(&proc->protocol.group.address_map);
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: group_size=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "group_key_epoch") == 0) {
                /* How many times this participant's group key has been rotated.
                 * Admission rotates (doc/architecture/gateway-reputation-tree.md), so a
                 * welcomer that
                 * admitted one peer sits at 1 — that is what keeps cohort
                 * traffic recorded BEFORE a join closed to the joiner. Mirrors
                 * Python Group.key_epoch. */
                int want = (int)json_integer_value(val);
                int got = (int)proc->protocol.group.key_epoch;
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: group_key_epoch=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "group_uuid") == 0) {
                /* This participant's PRIMARY group, pinned by fixtures.groups
                 * so the scenario can state it language-agnostically. The
                 * cross-group join asserts it is UNCHANGED: a gateway joining a
                 * child cohort must not have swapped its own group for the one
                 * it just joined. Mirrors Python str(group.uuid). */
                const char *want = json_string_value(val);
                char got[UUID_STRING_LEN + 1];
                uuid_unparse_lower(proc->protocol.group.uuid, got);
                if (want == NULL || strcmp(got, want) != 0) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: group_uuid=%s, expected %s", pid, got,
                             want != NULL ? want : "(non-string)");
                    return -1;
                }
            } else if (strcmp(key, "child_group_count") == 0) {
                /* Cohorts this participant gateways. A runtime join lands HERE
                 * and not in the primary group — that separation is the whole
                 * observable. Mirrors Python len(process.child_groups). */
                int want = (int)json_integer_value(val);
                int got = (proc->protocol.child_groups == NULL)
                          ? 0 : (int)map_size(proc->protocol.child_groups);
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: child_group_count=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "peer_caps_descriptor") == 0) {
                /* `peer_caps_descriptor: {cap_name: {field: value, ...}}` —
                 * assert each field matches the size-bounded descriptor
                 * recorded by handle_caps_response (stored by cap name in the
                 * shared id_state.peer_cap_descriptors_map; read via
                 * identity_get_peer_cap_descriptor). Mirrors the Python
                 * adapter's peer_caps_descriptor check. */
                if (!json_is_object(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: peer_caps_descriptor must be an object", pid);
                    return -1;
                }
                const char *cap_name = NULL;
                json_t *fields = NULL;
                json_object_foreach(val, cap_name, fields) {
                    /* descriptors are small; bound the buffer generously and
                     * note that expected_state targets compact descriptors. */
                    char dbuf[2048];
                    if (identity_get_peer_cap_descriptor(cap_name, dbuf,
                                                         sizeof(dbuf)) != 0) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: no descriptor for cap %s", pid, cap_name);
                        return -1;
                    }
                    json_error_t jerr;
                    json_t *stored = json_loads(dbuf, 0, &jerr);
                    if (stored == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: descriptor for %s unparseable", pid,
                                 cap_name);
                        return -1;
                    }
                    const char *fk = NULL;
                    json_t *fv = NULL;
                    char bad_field[128] = {0};
                    int mismatch = 0;
                    json_object_foreach(fields, fk, fv) {
                        json_t *sv = json_object_get(stored, fk);
                        if (sv == NULL || !json_equal(sv, fv)) {
                            mismatch = 1;
                            snprintf(bad_field, sizeof(bad_field), "%s", fk);
                            break;
                        }
                    }
                    json_decref(stored);
                    if (mismatch) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: descriptor[%s][%s] mismatch", pid,
                                 cap_name, bad_field);
                        return -1;
                    }
                }
            } else if (strcmp(key, "provisional_peer_count") == 0) {
                /* Two-phase admission (doc/architecture/identity-protocol.md): peers held provisional
                 * (confirm seen, quorum not met, group key withheld). Mirrors
                 * the Python adapter's provisional_peer_count. */
                int want = (int)json_integer_value(val);
                int got = (int)identity_provisional_count(proc);
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: provisional_peer_count=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "hierarchy_of") == 0) {
                /* What this participant RECORDED from a peer's hierarchy
                 * claim, as {participant_id: {rank, children}} (or null for
                 * "nothing recorded"). The gates that can refuse a claim are
                 * invisible in emitted traffic, so the store is the only
                 * place a refusal is observable. Mirrors the Python adapter's
                 * hierarchy_of check; `children` is a COUNT, because the
                 * cohort uuids inside a claim are minted per runtime and
                 * never compared. */
                const char *sub_pid;
                json_t *want;
                json_object_foreach(val, sub_pid, want) {
                    sce_participant_t *sp = sce_find_participant(ctx, sub_pid);
                    if (sp == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: hierarchy_of names unknown participant %s",
                                 pid, sub_pid);
                        return -1;
                    }
                    ic_impl_t *s_impl = (ic_impl_t *)sp->impl;
                    char peer_uuid[UUID_STRING_LEN + 1] = {0};
                    if (s_impl != NULL && s_impl->pub != NULL)
                        uuid_unparse_lower(s_impl->pub->uuid, peer_uuid);
                    int got_rank = 0, got_children = 0;
                    bool have = identity_get_peer_hierarchy(peer_uuid,
                                                            &got_rank,
                                                            &got_children);
                    if (json_is_null(want)) {
                        if (have) {
                            snprintf(ctx->err, sizeof(ctx->err),
                                     "%s: recorded a hierarchy claim from %s, "
                                     "expected none", pid, sub_pid);
                            return -1;
                        }
                        continue;
                    }
                    if (!have) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: no hierarchy claim recorded from %s",
                                 pid, sub_pid);
                        return -1;
                    }
                    json_t *w_rank = json_object_get(want, "rank");
                    if (w_rank != NULL
                        && got_rank != (int)json_integer_value(w_rank)) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: hierarchy_of[%s].rank=%d, expected %d",
                                 pid, sub_pid, got_rank,
                                 (int)json_integer_value(w_rank));
                        return -1;
                    }
                    json_t *w_kids = json_object_get(want, "children");
                    if (w_kids != NULL
                        && got_children != (int)json_integer_value(w_kids)) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: hierarchy_of[%s].children=%d, "
                                 "expected %d", pid, sub_pid, got_children,
                                 (int)json_integer_value(w_kids));
                        return -1;
                    }
                }
            } else if (strcmp(key, "peer_tier") == 0) {
                /* The reputation-derived trust tier this participant applied
                 * to a peer, as {participant_id: tier}. Distinct from rank:
                 * tier is the runtime, local-view trust attribute a
                 * negotiation tier-gate reads, and it arrives only over local
                 * IPC. Mirrors the Python adapter's peer_tier check. */
                const char *sub_pid;
                json_t *want;
                json_object_foreach(val, sub_pid, want) {
                    sce_participant_t *sp = sce_find_participant(ctx, sub_pid);
                    if (sp == NULL) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: peer_tier names unknown participant %s",
                                 pid, sub_pid);
                        return -1;
                    }
                    ic_impl_t *s_impl = (ic_impl_t *)sp->impl;
                    int got = 0;
                    if (s_impl != NULL && s_impl->pub != NULL) {
                        /* Self-target reads the node's own tier, exactly as
                         * the handler writes it. */
                        if (impl->pub != NULL
                            && uuid_compare(s_impl->pub->uuid,
                                            impl->pub->uuid) == 0)
                            got = identity_get_self_tier();
                        else
                            got = identity_get_peer_tier(s_impl->pub->uuid);
                    }
                    if (got != (int)json_integer_value(want)) {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: peer_tier[%s]=%d, expected %d",
                                 pid, sub_pid, got,
                                 (int)json_integer_value(want));
                        return -1;
                    }
                }
            } else if (strcmp(key, "parent_gateway") == 0) {
                /* The higher-rank node this participant DERIVES as its parent
                 * (protocol step 7), as a participant id or "" for a node that
                 * tops its own cohort. Filled by trigger_hierarchy; mirrors the
                 * Python adapter's parent_gateway check. */
                const char *want = json_string_value(val);
                if (want == NULL) want = "";
                if (strcmp(impl->parent_gateway_pid, want) != 0) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: parent_gateway='%s', expected '%s'",
                             pid, impl->parent_gateway_pid, want);
                    return -1;
                }
            } else if (strcmp(key, "subtree_roster") == 0) {
                /* Flattened membership roll of this gateway's subtree, as
                 * sorted participant ids (filled by trigger_subtree_roster).
                 * Compared as sorted lists; mirrors the Python adapter's
                 * subtree_roster check. */
                if (!json_is_array(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: subtree_roster expects a list", pid);
                    return -1;
                }
                const char *av[SCE_MAX_PARTICIPANTS];
                const char *ev[SCE_MAX_PARTICIPANTS];
                size_t an = 0, en = 0, i;
                json_t *actual = impl->subtree_roster;
                if (json_is_array(actual)) {
                    size_t n = json_array_size(actual);
                    for (i = 0; i < n && an < SCE_MAX_PARTICIPANTS; i++)
                        av[an++] = json_string_value(json_array_get(actual, i));
                }
                size_t vn = json_array_size(val);
                for (i = 0; i < vn && en < SCE_MAX_PARTICIPANTS; i++)
                    ev[en++] = json_string_value(json_array_get(val, i));
                qsort(av, an, sizeof(av[0]), _roster_strp_cmp);
                qsort(ev, en, sizeof(ev[0]), _roster_strp_cmp);
                bool eq = (an == en);
                for (i = 0; eq && i < an; i++)
                    if (av[i] == NULL || ev[i] == NULL
                        || strcmp(av[i], ev[i]) != 0) eq = false;
                if (!eq) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: subtree_roster mismatch (got %d, expected %d)",
                             pid, (int)an, (int)en);
                    return -1;
                }
            } else {
                snprintf(ctx->err, sizeof(ctx->err),
                         "%s: unsupported expected_state key %s", pid, key);
                return -1;
            }
        }
    }
    return 0;
}

void at_identity_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "negative") == 0) {
        at_neg_run_wire(c, out);
        return;
    }
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C identity adapter only handles kind:scenario|negative (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    /* ZTA admission scenarios (fixtures.zta_policy present) require the ZTA
     * gate, which is compiled in only under AT_ZTA. When built without it,
     * skip — a skip on one side is not an asymmetric failure (diff_results.py)
     * and the Python adapter still pins the scenario. When built with
     * -DAT_ZTA=ON the adapter wires the policy + credentials (_apply_zta_
     * fixtures) and runs the scenario symmetrically. */
#ifndef AT_ZTA_ENABLED
    {
        json_t *fx = json_object_get(c->data, "fixtures");
        if (json_is_object(fx) && json_object_get(fx, "zta_policy") != NULL) {
            at_case_result_set_skip(
                out, "ZTA scenario skipped: C built without AT_ZTA "
                     "(build -DAT_ZTA=ON to run it symmetrically)");
            return;
        }
    }
#endif

    char err[256] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Inline-finalize the welcoming-committee cascade and emit propose /
     * peer_accepted as broadcasts, so a single-bg scenario sees the full
     * outbound. Mirrors Python's per-instance synchronous_dispatch=True. */
    identity_set_synchronous_dispatch(true);

    sce_run_ctx_t ctx;
    sce_init(&ctx);
    ctx.case_data = c->data;
    ctx.build_inbound = _build_inbound;
    ctx.dispatch = _dispatch;

    /* Wipe singleton id_state so observables (peer_caps_count etc.) are
     * not polluted by prior scenarios. Preserves synchronous_dispatch. */
    identity_reset_state();

    /* First contact is OPT-IN, and the opt-in is read when the process
     * registers its handlers -- so it has to be set BEFORE the participants
     * are built, and restored after, or the next scenario inherits it. The
     * durable spent-nonce store is redirected to a per-scenario temp root for
     * the same reason: a nonce spent by one case must not be spent for the
     * next. Mirrors the Python adapter, whose scratch TemporaryDirectory does
     * both jobs. */
    at_first_contact_reset();
    bool fc_enabled = false;
    {
        json_t *fx = json_object_get(c->data, "fixtures");
        json_t *fc = json_is_object(fx) ? json_object_get(fx, "first_contact")
                                        : NULL;
        fc_enabled = json_is_object(fc)
                     && json_is_true(json_object_get(fc, "enabled"));
    }
    char fc_root[] = "/tmp/at-conformance-fc-XXXXXX";
    char fc_saved_flag[64] = {0};
    char fc_saved_root[PATH_MAX] = {0};
    bool fc_had_flag = false, fc_had_root = false;
    if (fc_enabled) {
        const char *prior = getenv(AT_FIRST_CONTACT_ENV);
        if (prior != NULL) {
            fc_had_flag = true;
            at_strlcpy(fc_saved_flag, prior, sizeof(fc_saved_flag));
        }
        prior = getenv("AUTONOMOUS_TRUST_ROOT");
        if (prior != NULL) {
            fc_had_root = true;
            at_strlcpy(fc_saved_root, prior, sizeof(fc_saved_root));
        }
        setenv(AT_FIRST_CONTACT_ENV, "1", 1);
        if (mkdtemp(fc_root) != NULL)
            setenv("AUTONOMOUS_TRUST_ROOT", fc_root, 1);
    }

    /* Build participants. */
    json_t *parts = json_object_get(c->data, "participants");
    if (!json_is_array(parts)) {
        snprintf(err, sizeof(err), "scenario: participants array missing");
        goto fail;
    }
    size_t n = json_array_size(parts);
    if (n > SCE_MAX_PARTICIPANTS) {
        snprintf(err, sizeof(err), "scenario: too many participants (%zu)", n);
        goto fail;
    }
    for (size_t i = 0; i < n; i++) {
        json_t *p = json_array_get(parts, i);
        const char *id = json_string_value(json_object_get(p, "id"));
        const char *role = json_string_value(json_object_get(p, "role"));
        if (id == NULL || role == NULL) {
            snprintf(err, sizeof(err), "participants[%zu] missing id or role", i);
            goto fail;
        }
        snprintf(ctx.participants[i].id, SCE_ID_LEN, "%s", id);
        snprintf(ctx.participants[i].role, SCE_ID_LEN, "%s", role);
        ctx.participants[i].impl = _build_participant_impl(id, i);
        if (ctx.participants[i].impl == NULL) {
            snprintf(err, sizeof(err),
                     "participants[%zu] (%s) impl build failed", i, id);
            goto fail;
        }
        ctx.participant_count++;
    }

    _apply_fixtures(&ctx);

    g_active_ctx = &ctx;
    messaging_set_test_hook(_send_hook);

    int rc = sce_run(&ctx);
    /* The engine's stub _check_expected_state is a no-op; per-protocol
     * enforcement lives here so a scenario's bg.peer_count: 1 (and
     * friends) is checked symmetrically with the Python adapter. */
    if (rc == 0) rc = _identity_check_expected_state(&ctx);

    messaging_set_test_hook(NULL);
    g_active_ctx = NULL;
    identity_set_synchronous_dispatch(false);
    /* Undo the first-contact opt-in and the redirected data root (no-ops when
     * the scenario never asked for them), so neither leaks into the next case. */
    if (fc_enabled) {
        at_first_contact_reset();
        if (fc_had_flag) setenv(AT_FIRST_CONTACT_ENV, fc_saved_flag, 1);
        else unsetenv(AT_FIRST_CONTACT_ENV);
        if (fc_had_root) setenv("AUTONOMOUS_TRUST_ROOT", fc_saved_root, 1);
        else unsetenv("AUTONOMOUS_TRUST_ROOT");
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) {
        at_case_result_set_pass(out, duration_ms);
    } else {
        at_case_result_set_fail(out, duration_ms, "AssertionError", ctx.err);
    }

    /* Cleanup. */
    for (size_t i = 0; i < ctx.participant_count; i++) {
        _free_participant_impl((ic_impl_t *)ctx.participants[i].impl);
    }
    return;

fail:
    g_active_ctx = NULL;
    messaging_set_test_hook(NULL);
    identity_set_synchronous_dispatch(false);
    /* Undo the first-contact opt-in and the redirected data root (no-ops when
     * the scenario never asked for them), so neither leaks into the next case. */
    if (fc_enabled) {
        at_first_contact_reset();
        if (fc_had_flag) setenv(AT_FIRST_CONTACT_ENV, fc_saved_flag, 1);
        else unsetenv(AT_FIRST_CONTACT_ENV);
        if (fc_had_root) setenv("AUTONOMOUS_TRUST_ROOT", fc_saved_root, 1);
        else unsetenv("AUTONOMOUS_TRUST_ROOT");
    }

    for (size_t i = 0; i < ctx.participant_count; i++) {
        _free_participant_impl((ic_impl_t *)ctx.participants[i].impl);
    }
    at_case_result_set_fail(out, 0, "AssertionError", err);
}
