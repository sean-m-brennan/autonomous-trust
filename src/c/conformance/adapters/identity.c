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
#include "identity/group.h"           /* group_init / group_add_address */
#include "config/configuration.h"     /* config_t (proc->configs["identity"]) */
#include "structures/data.h"          /* object_ptr_data */
#ifdef AT_ZTA_ENABLED
#include <openssl/evp.h>              /* scenario-time operator-binding signing */
#include <openssl/pem.h>
#include "zta/zta_policy.h"           /* zta_policy_t / defaults / from_json */
#include "zta/zta_binding.h"          /* credential->identity binding (ISSUES §1.5) */
#endif
#include "network/net_message.h"
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

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
 *                    pre-image naming a DIFFERENT node (ISSUES.md §1.5's
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

/* Mint a credential->identity binding for a scenario participant (ISSUES §1.5).
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
     * (ISSUES.md §3.1-c, Policy B). Default true (set in
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

    /* admission_quorum: { "<participant>": <int>, ... } — two-phase admission
     * (ISSUES.md §3.1-a). A member withholds the group key until this many
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

    /* peer_caps_response — pack the payload as the JSON array
     * handle_caps_response expects. Two YAML forms (mirrors the Python
     * adapter):
     *   - `descriptors: [{name, required_tier, description, kind, arg_schema}]`
     *     → packed verbatim as an array of objects (descriptor form).
     *   - `caps: [name, ...]` → packed as an array of name strings (legacy).
     * Without this the C handler sees no payload and silently no-ops. */
    if (strcmp(function, "peer_caps_response") == 0 && json_is_object(payload)) {
        json_t *descs = json_object_get(payload, "descriptors");
        if (json_is_array(descs)) {
            /* deep-copy so the body is independent of the scenario JSON's
             * lifetime; net_msg_pack_json serializes the array of objects. */
            json_t *body = json_deep_copy(descs);
            if (body != NULL) {
                net_msg_pack_json(&out->info.net_msg, body);
                json_decref(body);
            }
            return 0;
        }
        json_t *src = json_object_get(payload, "caps");
        if (json_is_array(src)) {
            json_t *body = json_array();
            size_t n = json_array_size(src);
            for (size_t i = 0; i < n; i++) {
                json_t *v = json_array_get(src, i);
                if (json_is_string(v))
                    json_array_append_new(body, json_string(json_string_value(v)));
            }
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
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
     * (`payload.get('peer') or payload.get('candidate')`). */
    if (strcmp(function, "peer_accepted") == 0 && json_is_object(payload)) {
        json_t *p = json_object_get(payload, "peer");
        if (!json_is_string(p)) p = json_object_get(payload, "candidate");
        const char *peer_pid = json_is_string(p) ? json_string_value(p) : NULL;
        sce_participant_t *pp = peer_pid ? sce_find_participant(ctx, peer_pid) : NULL;
        if (pp != NULL) {
            ic_impl_t *pp_impl = (ic_impl_t *)pp->impl;
            if (pp_impl != NULL && pp_impl->pub != NULL) {
                json_t *body = NULL;
                if (public_identity_to_json(pp_impl->pub, &body) == 0
                    && body != NULL) {
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

    /* partition_probe — cross-group probe, signed JSON payload. */
    if (strcmp(function, "group_partition_probe") == 0
        && json_is_object(payload)) {
        const char *group_uuid = "00000000-0000-0000-0000-000000000000";
        int group_size = 1;
        json_t *g = json_object_get(payload, "group_uuid");
        if (json_is_string(g)) group_uuid = json_string_value(g);
        json_t *sz = json_object_get(payload, "group_size");
        if (json_is_integer(sz)) group_size = (int)json_integer_value(sz);

        char canon[UUID_STRING_LEN + 32];
        int clen = snprintf(canon, sizeof(canon), "%s|%d",
                            group_uuid, group_size);
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

        char canon[UUID_STRING_LEN * 2 + 64];
        int clen = snprintf(canon, sizeof(canon), "%s|%d|%s",
                            group_uuid, group_size, in_resp);
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
            json_object_set_new(body, "signature", json_string(sig_hex));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
    }

    /* group_key_update — serialize the SENDER's group as the DRY canonical
     * flat form (group_to_json), matching the Python adapter which sends
     * sender.process.group.to_canonical(). handle_group_update parses it via
     * group_from_json and adopts/rejects. Without this the C handler would see
     * an empty obj and no-op, diverging from Python on any non-degenerate
     * group update. A public_only sender (key zeroed at fixture time) emits
     * public_only=true, driving the keep-our-private-key adopt path. */
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
                /* Two-phase admission (§3.1-a): peers held provisional
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
    for (size_t i = 0; i < ctx.participant_count; i++) {
        _free_participant_impl((ic_impl_t *)ctx.participants[i].impl);
    }
    at_case_result_set_fail(out, 0, "AssertionError", err);
}
