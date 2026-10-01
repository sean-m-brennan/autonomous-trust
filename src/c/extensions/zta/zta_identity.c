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

/** @file ZTA as an admission authority for the identity process
 *  (FEATURE_SPLIT_PLAN Phase 6). Moved verbatim from identity/id_proc.c and
 *  reputation/rep_proc.c, where it sat under AT_ZTA_ENABLED; it now attaches
 *  through identity_ext_t (identity/id_ext.h) as the extension "zta", so the
 *  core names none of it. Mirrors Python IdentityProcess._zta_admit and
 *  friends (doc/architecture/zta-integration.md). */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "identity/id_ext.h"
#include "identity/id_proc_priv.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "processes/processes.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/util.h"
#include "zta/zta_policy.h"
#include "zta/zta_verifier.h"
#include "zta/zta_audit.h"
#include "zta/x509_verifier.h"   /* x509_verify_data_signature, for the binding */
#include "zta/at_zta.h"
#include "zta/zta_msg_types.h"
#include "zta/zta_process.h"
#include "zta/zta_binding.h"     /* the credential->identity binding
                                    (doc/architecture/zta-integration.md) */

static bool _is_operator_credential(const zta_policy_t *policy,
                                    const uint8_t *cred, size_t cred_len,
                                    const uint8_t *advertised_hash);
static void _verify_operator_key(const process_t *proc,
                                 public_identity_t *pub,
                                 const uint8_t *cred, size_t cred_len,
                                 const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES]);
typedef enum { ZTA_GATE_ADMIT, ZTA_GATE_ADMIT_CAPPED, ZTA_GATE_REJECT } zta_gate_t;
/* Hand the gate's verdict to the reputation process (doc/architecture/zta-integration.md).
 * Mirrors Python IdentityProcess._publish_zta_decision. */
static void _publish_zta_standing(const process_t *proc,
                                  const zta_policy_t *policy,
                                  const public_identity_t *peer,
                                  zta_gate_t decision);
static zta_gate_t _zta_admit(const process_t *proc, const zta_policy_t *policy,
                             public_identity_t *pub,
                             const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES]);

/* The ZTA policy this process was configured with, or NULL. Values in
 * proc->configs are object_ptr_data(config_t) (load_all_configs), so unwrap
 * data_t -> config_t -> data_struct. One helper, because one call site (the
 * attestation re-verify) unwrapped it one level short and read a config_t as
 * the policy. */
static const zta_policy_t *_policy(const process_t *proc)
{
    data_t *zta_dat = NULL;
    config_t *zta_cfg = NULL;
    char zta_key[] = "zta_policy";
    if (proc == NULL || proc->configs == NULL
        || map_get(proc->configs, zta_key, &zta_dat) != 0 || zta_dat == NULL
        || data_object_ptr(zta_dat, (void **)&zta_cfg) != 0
        || zta_cfg == NULL || zta_cfg->data_struct == NULL)
        return NULL;
    return (const zta_policy_t *)zta_cfg->data_struct;
}

/* True iff the credential is operator-class: it chain-verifies against the
 * DISTINCT operator trust anchor AND its sha256 matches the advertised hash
 * (ethne D8/Q9). Non-forgeable (derived from verification, never the advertised
 * bool) and fail-safe (no anchor / no match / not verified -> false). Mirror of
 * Python IdentityProcess._is_operator_credential. Issuer-based markers are NOT
 * used (a distinct anchor is the agreed discriminator). */
static bool _is_operator_credential(const zta_policy_t *policy,
                                    const uint8_t *cred, size_t cred_len,
                                    const uint8_t *advertised_hash)
{
    if (cred == NULL || cred_len == 0)
        return false;
    uint8_t actual[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(actual, cred, cred_len);
    bool adv_present = false;
    for (size_t i = 0; i < sizeof(actual); i++)
        if (advertised_hash[i] != 0) { adv_present = true; break; }
    if (adv_present && sodium_memcmp(actual, advertised_hash, sizeof(actual)) != 0)
        return false;
    zta_verifier_t *op = NULL;
    if (zta_policy_create_operator_verifier(policy, &op) != 0 || op == NULL)
        return false;
    zta_result_t r;
    memset(&r, 0, sizeof(r));
    op->verify_credential(op, cred, cred_len, &r);
    bool ok = (r.status == ZTA_VERIFIED);
    op->destroy(op);
    return ok;
}

/* True if this exact credential is already bound to a DIFFERENT network identity
 * — a harvested/replayed credential (doc/architecture/zta-integration.md). C twin of Python
 * IdentityProcess._zta_credential_replayed.
 *
 * The chain-only verifier accepts a chain-valid certificate regardless of WHO
 * presents it, so one lifted from a peer's clear-text announce could be
 * re-announced under a different uuid and still pass. This enforces a
 * credential<->identity uniqueness invariant: first-use-wins, where "previously
 * seen" means present in our peer roster (rosters propagate, so this is the
 * "seen by other nodes" check) or on our own identity.
 *
 * Superseded by the binding for any credential that carries one; it stays
 * because it is the only defence left for an UNBOUND credential under
 * binding_mode prefer/off.
 *
 * Fingerprints are recomputed from the actual bytes, never the announcer-
 * controlled zta_credential_hash. Caller must NOT hold the peers lock. */
static bool _zta_credential_replayed(const process_t *proc,
                                     const public_identity_t *pub,
                                     const uint8_t *cred, size_t cred_len)
{
    if (proc == NULL || pub == NULL || cred == NULL || cred_len == 0)
        return false;
    uint8_t fp[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(fp, cred, cred_len);

    const identity_t *self = identity_self_identity(proc);
    if (self != NULL && uuid_compare(self->uuid, (unsigned char *)pub->uuid) != 0
        && self->zta_credential != NULL && self->zta_credential_len > 0) {
        uint8_t own[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(own, self->zta_credential, self->zta_credential_len);
        if (memcmp(fp, own, sizeof(fp)) == 0)
            return true;  /* our own credential, worn by somebody else */
    }

    bool found = false;
    peers_read_lock((process_t *)proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !found; i++) {
        const public_identity_t *peer = &proc->protocol.peers[i];
        if (uuid_compare((unsigned char *)peer->uuid,
                         (unsigned char *)pub->uuid) == 0)
            continue;  /* same identity re-announcing its own credential: fine */
        for (size_t j = 0; j < peer->num_zta_credentials && !found; j++) {
            const zta_credential_t *c = &peer->zta_credentials[j];
            if (c->der == NULL || c->der_len == 0)
                continue;
            uint8_t pfp[crypto_hash_sha256_BYTES];
            crypto_hash_sha256(pfp, c->der, c->der_len);
            if (memcmp(fp, pfp, sizeof(fp)) == 0)
                found = true;
        }
    }
    peers_read_unlock((process_t *)proc);
    return found;
}

/* Credit a peer's OPT-IN guardian identity, if it advertised one and the binding
 * holds. Called only after the peer's credential has been classified
 * operator-class, because a binding signed by a credential with no standing to
 * name a guardian names nobody.
 *
 * Three outcomes, and the middle one is the point of the whole design:
 *   - no claim         -> silent. The default, and it must stay costless.
 *   - claim + binding verifies -> the key is written onto the peer. From here on,
 *     a stored peer with a key is one we verified.
 *   - claim + binding fails    -> the key stays zero and we say so. operator_bound
 *     is NOT demoted: it was earned independently, and a stale binding after node
 *     key rotation is an honest cause of this. */
static void _verify_operator_key(const process_t *proc,
                                 public_identity_t *pub,
                                 const uint8_t *cred, size_t cred_len,
                                 const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES])
{
    if (pub == NULL || claimed_key == NULL)
        return;
    bool claimed = !at_operator_pubkey_empty(claimed_key);
    if (!claimed && (pub->operator_key_binding == NULL
                     || pub->operator_key_binding_len == 0))
        return;                      /* declined; the normal case */
    if (!claimed || pub->operator_key_binding == NULL
        || pub->operator_key_binding_len == 0) {
        /* Half a claim is not a claim: a key with no binding is unverifiable and a
         * binding with no key names nothing. Worth a word either way, because both
         * halves are written by the same code path — one arriving without the
         * other means something upstream is broken, not that a peer declined. */
        log_warn(proc->logger,
                 "Identity: %s advertised half an operator-key binding "
                 "(key %s, binding %s); no guardian recorded\n",
                 pub->nickname, claimed ? "present" : "absent",
                 pub->operator_key_binding_len > 0 ? "present" : "absent");
        return;
    }

    uint8_t preimage[OPERATOR_BINDING_PREIMAGE_LEN];
    if (operator_binding_preimage(pub, claimed_key, preimage) != 0)
        return;
    /* Against the credential that actually verified operator-class, which with
       several credentials in play need not be the primary in fields 6-8. */
    if (x509_verify_data_signature(cred, cred_len,
                                   preimage, sizeof(preimage),
                                   pub->operator_key_binding,
                                   pub->operator_key_binding_len)) {
        memcpy(pub->operator_pubkey, claimed_key, crypto_sign_PUBLICKEYBYTES);
        log_info(proc->logger,
                 "Identity: %s guardian key bound and verified\n", pub->nickname);
    } else {
        log_warn(proc->logger,
                 "Identity: %s advertised an operator key whose binding does not "
                 "verify against its operator credential; no guardian recorded "
                 "(operator_bound stands on its own)\n", pub->nickname);
    }
}

/* The ZTA admission decision. C twin of Python IdentityProcess._zta_admit.
 *
 * ADMISSION IS ANY-OF (doc/architecture/zta-integration.md): at least one credential must
 * chain to some
 * configured anchor AND be bound to this identity. Each verified credential
 * records authority for its anchor on the peer (zta_anchors), and that — not a
 * self-declared role — is what lets a node gateway across an agency boundary.
 * Gatewayhood is emergent from group membership and nothing on the wire declares
 * it, so "a gateway must present N credentials" would rest on the peer's own
 * claim and buy nothing; an attacker just declines to claim.
 *
 * FAILURE IS GRADED, because forgery and ignorance are different things. A
 * binding that is present and fails, a credential already bound elsewhere, an
 * oversized blob, or an affirmative revocation all reject the identity — each is
 * evidence someone is lying. A credential merely expired, or chaining to no
 * anchor we hold, is SKIPPED: that says nothing about the peer's honesty, only
 * about our ability to evaluate it. For a single-credential node this collapses
 * to the previous behavior (nothing usable left => reject), which is why the
 * zta-x509-reject-* conformance pins still hold unchanged.
 *
 * Caller must already have neutralized pub->operator_bound and moved the claimed
 * guardian key aside; this function sets the authoritative operator_bound. */

/* Hand the ZTA gate's verdict to the reputation process
 * (doc/architecture/zta-integration.md).
 *
 * Nothing is sent when the gate did not run -- a disabled policy, or one that does not
 * require verification at admission, never reaches this call at all. That silence is
 * deliberate and load-bearing: reputation must not be told a peer is `proved` merely
 * because nobody checked, and an unbounded peer is exactly what a deployment that has
 * not enabled ZTA has already chosen.
 *
 * Mirrors Python IdentityProcess._publish_zta_decision, including the failure posture:
 * a propagation error is logged, never raised, because losing a ceiling must not take
 * admission down -- but it IS logged at WARNING, since the failure case is precisely a
 * peer that goes on to score unbounded with nothing saying why.
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _publish_zta_standing(const process_t *proc,
                                  const zta_policy_t *policy,
                                  const public_identity_t *peer,
                                  zta_gate_t decision)
{
    if (peer == NULL || policy == NULL)
        return;
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = PEER_STANDING;
    msg.size = sizeof(peer_standing_msg_t);
    memcpy(msg.info.peer_standing.peer_uuid, peer->uuid, sizeof(uuid_t));
    /* Name the authority — see zta_process.c's _send_zta_standing. */
    at_strlcpy(msg.info.peer_standing.source, PEER_STANDING_SOURCE_ZTA,
               sizeof(msg.info.peer_standing.source));
    if (decision == ZTA_GATE_ADMIT_CAPPED) {
        msg.info.peer_standing.standing = (int32_t)PEER_STANDING_CAPPED;
        msg.info.peer_standing.ceiling = policy->ddil_fallback_reputation_cap;
        at_strlcpy(msg.info.peer_standing.reason,
                   "admitted unproved (DDIL fallback or unbound credential)",
                   sizeof(msg.info.peer_standing.reason));
    } else {
        /* Proved: a credential verified against a configured anchor AND is
         * bound to this identity. The only path that anchors the doc/architecture/zta-integration.md
         * unwind -- everything earned after this moment is standing a later
         * failure calls into question. */
        msg.info.peer_standing.standing = (int32_t)PEER_STANDING_PROVED;
        msg.info.peer_standing.ceiling = PEER_NO_CEILING;
        at_strlcpy(msg.info.peer_standing.reason, "verified at admission",
                   sizeof(msg.info.peer_standing.reason));
    }
    if (messaging_send("reputation", PEER_STANDING, &msg, false) != 0) {
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer->uuid, uuid_str);
        log_warn(proc->logger,
                 "Identity: could not propagate ZTA standing for %s "
                 "(ceiling %.2f)\n", uuid_str, msg.info.peer_standing.ceiling);
    }
}

static zta_gate_t _zta_admit(const process_t *proc, const zta_policy_t *policy,
                             public_identity_t *pub,
                             const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES])
{
    if (policy == NULL || pub == NULL)
        return ZTA_GATE_ADMIT;
    if (!policy->enabled || !policy->require_at_admission)
        return ZTA_GATE_ADMIT;
    const char *nick = pub->nickname;

    /* Working set. Normally the list, which sync_in/_apply_operator_attestation
       seed with the primary; the fallback covers a caller that set only the
       singular field (the conformance adapter attaches a live from_whom that way,
       and so does any pre-list code path). */
    zta_credential_t fallback;
    const zta_credential_t *creds = pub->zta_credentials;
    size_t n_creds = pub->num_zta_credentials;
    if (n_creds == 0) {
        memset(&fallback, 0, sizeof(fallback));
        if (pub->zta_credential != NULL && pub->zta_credential_len > 0) {
            fallback.der = pub->zta_credential;
            fallback.der_len = pub->zta_credential_len;
            at_strlcpy(fallback.issuer, pub->zta_issuer, sizeof(fallback.issuer));
        }
        /* Even when that leaves an EMPTY entry. A peer presenting nothing still
           has to be evaluated, not silently skipped: the verifiers are what
           distinguish "we cannot reach the PKI" (DDIL, admit capped) from "we can,
           and there is no credential" (reject). x509 reports REJECTED "no
           credential data"; the OIDC stub reports UNAVAILABLE. That is what the
           zta-ddil-defer and zta-x509-reject-unsigned pins turn on. */
        creds = &fallback;
        n_creds = 1;
    }

    /* Size guard BEFORE handing any blob to a verifier: an oversized credential
       is almost certainly hostile/corrupt and would let a remote cause an OOM or
       parse-time DoS. Enforced here as well as at deserialization because the
       conformance harness attaches a live from_whom with no wire round trip.
       Keep ZTA_CRED_MAX in lockstep with Python. */
    for (size_t i = 0; i < n_creds; i++) {
        if (creds[i].der_len > ZTA_CRED_MAX) {
            log_warn(proc->logger,
                     "Identity: ZTA credential too large for %s (%zu > %u)\n",
                     nick, creds[i].der_len, (unsigned)ZTA_CRED_MAX);
            return ZTA_GATE_REJECT;
        }
    }
    /* Credential<->identity uniqueness, before chain verification: the cert may
       verify fine; the point is that it is already bound elsewhere. */
    for (size_t i = 0; i < n_creds; i++) {
        if (_zta_credential_replayed(proc, pub, creds[i].der, creds[i].der_len)) {
            log_warn(proc->logger,
                     "Identity: ZTA rejecting %s: credential bound to a different "
                     "identity (replay)\n", nick);
            return ZTA_GATE_REJECT;
        }
    }

    /* One chain-walking verifier per resolved anchor. Mirrors Python
       ZtaPolicy.create_anchor_verifiers, including both of its escape hatches:
       an anchor IS a CA bundle, so for any non-x509 verifier_type (oidc, mfa)
       there is nothing to enumerate and the single configured verifier stands in
       under the name "default"; and an x509 policy with no bundle anywhere gets
       the same treatment, because a verifier over an empty bundle reports
       UNAVAILABLE, which is what drives the DDIL defer path. Resolving to zero
       anchors there would silently turn a defer into a flat rejection. */
    zta_anchor_t anchors[ZTA_POLICY_MAX_ANCHORS];
    zta_verifier_t *verifiers[ZTA_POLICY_MAX_ANCHORS] = {0};
    size_t n_anchors = 0;
    if (strcmp(policy->verifier_type, "x509") == 0)
        n_anchors = zta_policy_resolved_anchors(policy, anchors,
                                                ZTA_POLICY_MAX_ANCHORS);
    if (n_anchors == 0) {
        memset(&anchors[0], 0, sizeof(anchors[0]));
        at_strlcpy(anchors[0].name, "default", ZTA_ANCHOR_NAME_MAX);
        anchors[0].is_operator = false;
        n_anchors = 1;
        zta_policy_create_verifier(policy, &verifiers[0]);
    } else {
        for (size_t a = 0; a < n_anchors; a++)
            zta_policy_create_anchor_verifier(policy, &anchors[a], &verifiers[a]);
    }

    const char *san = policy->san_uri_template;
    zta_gate_t decision;
    bool any_usable = false;
    bool any_unbound_usable = false;
    bool have_failure = false, have_deferred = false;
    zta_status_t failure_status = ZTA_REJECTED;
    char failure_reason[ZTA_REASON_LEN] = {0};
    zta_status_t deferred_status = ZTA_UNAVAILABLE;
    char deferred_reason[ZTA_REASON_LEN] = {0};
    /* Deferred outcomes are tracked separately from real failures so the
       nothing-usable branch can tell "we could not evaluate" (DDIL, fallback
       applies) from "we evaluated and did not like it" (reject). */

    for (size_t i = 0; i < n_creds; i++) {
        const uint8_t *cred = creds[i].der;
        size_t cred_len = creds[i].der_len;
        /* NOT skipped when empty — see the working-set note above: the verifiers
           are what tell DDIL apart from an absent credential. */

        bool matched = false, is_operator = false, revoked = false;
        size_t first_match = 0;
        uint8_t match_hash[ZTA_HASH_LEN] = {0};
        for (size_t a = 0; a < n_anchors; a++) {
            if (verifiers[a] == NULL || verifiers[a]->verify_credential == NULL)
                continue;
            zta_result_t r;
            memset(&r, 0, sizeof(r));
            verifiers[a]->verify_credential(verifiers[a], cred, cred_len, &r);
            if (r.status == ZTA_VERIFIED) {
                /* Every anchor is tried, deliberately not stopping at the first
                   match: a credential may legitimately chain to more than one
                   (the synthesized legacy pair is frequently the same CA), and
                   both operator classification and gateway authority depend on
                   the full set rather than whichever was checked first. */
                if (!matched) { first_match = a; memcpy(match_hash, r.credential_hash,
                                                        sizeof(match_hash)); }
                matched = true;
                is_operator = is_operator || anchors[a].is_operator;
                if (!revoked && verifiers[a]->check_revocation != NULL) {
                    /* A chain-valid certificate may nonetheless have been
                       revoked; verify_credential walks only chain + expiry. Only
                       an affirmative ZTA_REVOKED blocks — ZTA_UNAVAILABLE (the
                       default with no CRL/OCSP source) keeps the peer admitted,
                       so deployments without one are unchanged. */
                    zta_result_t rev;
                    memset(&rev, 0, sizeof(rev));
                    verifiers[a]->check_revocation(verifiers[a],
                                                   r.credential_hash, &rev);
                    if (rev.status == ZTA_REVOKED) {
                        revoked = true;
                        at_strlcpy(failure_reason, rev.reason[0] ? rev.reason
                                   : "credential revoked", ZTA_REASON_LEN);
                    }
                }
            } else if (r.status == ZTA_REJECTED || r.status == ZTA_EXPIRED
                       || r.status == ZTA_REVOKED) {
                have_failure = true;
                failure_status = r.status;
                at_strlcpy(failure_reason, r.reason, ZTA_REASON_LEN);
            } else {  /* DEFERRED / UNAVAILABLE — the verifier could not answer */
                have_deferred = true;
                deferred_status = r.status;
                at_strlcpy(deferred_reason, r.reason, ZTA_REASON_LEN);
            }
        }
        if (revoked) {
            log_warn(proc->logger, "Identity: ZTA rejecting %s: %s\n",
                     nick, failure_reason);
            decision = ZTA_GATE_REJECT;
            goto done;
        }
        if (!matched)
            continue;  /* chains to no anchor we hold: ignorance, not forgery */

        /* The credential is genuine. Is THIS node entitled to present it? */
        bool bound = zta_identity_is_bound(pub, cred, cred_len,
                                           creds[i].binding, creds[i].binding_len,
                                           san, claimed_key,
                                           pub->operator_key_binding,
                                           pub->operator_key_binding_len);
        if (creds[i].binding != NULL && creds[i].binding_len > 0 && !bound) {
            /* A binding was offered and does not verify. Unlike absence, that is
               affirmative evidence of forgery — somebody tried and failed to
               prove entitlement — so it condemns the whole identity rather than
               costing just this one credential. */
            log_warn(proc->logger,
                     "Identity: ZTA rejecting %s: credential binding does not "
                     "verify for this identity\n", nick);
            decision = ZTA_GATE_REJECT;
            goto done;
        }
        if (!bound && policy->binding_mode == ZTA_BINDING_MODE_REQUIRE) {
            /* Unbound is a provisioning state, not a lie. The credential earns no
               authority; if nothing else survives the peer is refused below,
               which for a single-credential node is exactly the old reject. */
            log_warn(proc->logger,
                     "Identity: %s presented an unbound ZTA credential and "
                     "binding_mode is require; credential unusable\n", nick);
            continue;
        }

        any_usable = true;
        if (!bound)
            any_unbound_usable = true;
        for (size_t a = 0; a < n_anchors; a++) {
            if (verifiers[a] == NULL)
                continue;
            /* Re-derive rather than cache a per-anchor verdict array: n_anchors
               is <= 8 and the verifier caches parsed certs, so this is cheap and
               keeps the match loop above from needing a parallel result buffer. */
            zta_result_t r;
            memset(&r, 0, sizeof(r));
            if (verifiers[a]->verify_credential(verifiers[a], cred, cred_len, &r) == 0
                && r.status == ZTA_VERIFIED)
                public_identity_add_zta_anchor(pub, anchors[a].name);
        }
        if (!pub->operator_bound) {
            /* Operator-class (ethne D8/Q9) by EITHER route, because a deployment
               may express the operator anchor either way: as an anchor carrying
               `operator: true`, or as the separate operator_ca_bundle_path that
               _is_operator_credential consults. Both derive the answer from
               verifying the actual credential against an operator trust anchor,
               never from the peer-advertised operator_bound/zta_issuer. */
            if (is_operator
                || _is_operator_credential(policy, cred, cred_len,
                                           pub->zta_credential_hash)) {
                pub->operator_bound = true;
                log_info(proc->logger,
                         "Identity: %s is operator-attended (human guardian)\n",
                         nick);
                _verify_operator_key(proc, pub, cred, cred_len, claimed_key);
            }
        }
        (void)first_match;
        (void)match_hash;
    }

    if (any_usable) {
        if (policy->binding_mode == ZTA_BINDING_MODE_PREFER && any_unbound_usable) {
            /* `prefer` only: admitted on an unbound credential, so the
               roster-based TOFU check is all that stood between us and a
               harvested cert — cap it like any other deferred verification.
               `off` deliberately does NOT cap: absence of a binding carries no
               penalty there, which is what makes it the no-change setting for a
               deployment that has not provisioned bindings yet. */
            log_info(proc->logger,
                     "Identity: %s admitted on an unbound ZTA credential "
                     "(binding_mode prefer); reputation cap %.2f\n",
                     nick, policy->ddil_fallback_reputation_cap);
            decision = ZTA_GATE_ADMIT_CAPPED;
            goto done;
        }
        decision = ZTA_GATE_ADMIT;
        goto done;
    }

    /* Nothing usable. A verifier that could not answer is a DDIL condition and
       gets the fallback; an answer we did not like is a rejection. */
    if (have_deferred && !have_failure) {
        if (policy->allow_ddil_fallback) {
            log_info(proc->logger,
                     "Identity: ZTA verification deferred (DDIL) for %s (%s); "
                     "admitting with reputation cap %.2f\n",
                     nick, zta_status_str(deferred_status),
                     policy->ddil_fallback_reputation_cap);
            decision = ZTA_GATE_ADMIT_CAPPED;
            goto done;
        }
        log_warn(proc->logger,
                 "Identity: ZTA unavailable for %s (%s) and DDIL fallback "
                 "disabled; rejecting: %s\n", nick,
                 zta_status_str(deferred_status), deferred_reason);
        decision = ZTA_GATE_REJECT;
        goto done;
    }
    if (have_failure)
        log_warn(proc->logger, "Identity: ZTA credential %s for %s: %s\n",
                 zta_status_str(failure_status), nick, failure_reason);
    else
        log_warn(proc->logger,
                 "Identity: ZTA rejecting %s: no verifiable credential presented\n",
                 nick);
    decision = ZTA_GATE_REJECT;

done:
    for (size_t a = 0; a < n_anchors; a++)
        if (verifiers[a] != NULL)
            verifiers[a]->destroy(verifiers[a]);
    return decision;
}

/* The anchor names OUR OWN credentials verify against. Mirrors Python
 * IdentityProcess._own_zta_anchors.
 *
 * Computed locally rather than read from our identity's zta_anchors, because
 * that field is what a PEER proved to us at admission and we never admit
 * ourselves. This walks our own credentials through the same anchor verifiers.
 *
 * Cached, because the alternative is re-reading every CA bundle off disk on each
 * roster query and the identity loop is single-threaded (see the other
 * handler-side reads in this file).
 *
 * KEYED ON THE IDENTITY, not a bare `computed` flag: the conformance runner hosts
 * every participant in ONE process, so a process-wide cache would answer for
 * whichever node asked first and silently hand its anchors to the others. A
 * production node has exactly one identity and hits the cache every time. */
static size_t _own_zta_anchors(const process_t *proc, const zta_policy_t *policy,
                               char out[][ZTA_ANCHOR_NAME_LEN], size_t max)
{
    static char cache[ZTA_MAX_ANCHORS][ZTA_ANCHOR_NAME_LEN];
    static size_t cache_n = 0;
    static const identity_t *cached_for = NULL;
    const identity_t *self_key = identity_self_identity(proc);
    if (self_key == NULL || cached_for != self_key) {
        cached_for = self_key;
        cache_n = 0;
        const identity_t *self = self_key;
        if (self != NULL && policy != NULL) {
            zta_anchor_t anchors[ZTA_POLICY_MAX_ANCHORS];
            size_t n_anchors = zta_policy_resolved_anchors(policy, anchors,
                                                           ZTA_POLICY_MAX_ANCHORS);
            /* Our own credential list, with the singular field as the fallback —
               the same working set the admission gate builds for a peer. */
            for (size_t a = 0; a < n_anchors && cache_n < ZTA_MAX_ANCHORS; a++) {
                zta_verifier_t *v = NULL;
                if (zta_policy_create_anchor_verifier(policy, &anchors[a], &v) != 0
                    || v == NULL)
                    continue;
                bool hit = false;
                size_t n = self->num_zta_credentials;
                for (size_t i = 0; i < n && !hit; i++) {
                    const zta_credential_t *c = &self->zta_credentials[i];
                    if (c->der == NULL || c->der_len == 0)
                        continue;
                    zta_result_t r;
                    memset(&r, 0, sizeof(r));
                    v->verify_credential(v, c->der, c->der_len, &r);
                    hit = (r.status == ZTA_VERIFIED);
                }
                if (!hit && n == 0 && self->zta_credential != NULL
                    && self->zta_credential_len > 0) {
                    zta_result_t r;
                    memset(&r, 0, sizeof(r));
                    v->verify_credential(v, self->zta_credential,
                                         self->zta_credential_len, &r);
                    hit = (r.status == ZTA_VERIFIED);
                }
                v->destroy(v);
                if (hit)
                    at_strlcpy(cache[cache_n++], anchors[a].name,
                               ZTA_ANCHOR_NAME_LEN);
            }
        }
    }
    size_t n_out = cache_n < max ? cache_n : max;
    for (size_t i = 0; i < n_out; i++)
        at_strlcpy(out[i], cache[i], ZTA_ANCHOR_NAME_LEN);
    return n_out;
}

/* Whether this node may federate through @p uuid. Mirrors Python
 * IdentityProcess._gateway_authorized.
 *
 * The candidate must have PROVED, at admission, an anchor we also hold. That is
 * the derived-authority rule: crossing an agency boundary requires a credential
 * from an agency both sides recognize, and since nothing on the wire declares
 * gatewayhood, deriving the permission from verified credentials is the only form
 * of it a peer cannot simply assert. A candidate we never admitted has no proved
 * anchors and is refused — which is the point, not a side effect.
 *
 * Inert (true) when the policy is not enforcing at admission, or when we hold no
 * anchors ourselves: with nothing to compare against, refusing every candidate
 * would break federation for every non-ZTA deployment rather than protect
 * anything. */
static bool _gateway_authorized(const process_t *proc, const char *uuid)
{
    if (proc == NULL || uuid == NULL || uuid[0] == '\0')
        return true;
    data_t *zta_dat = NULL;
    config_t *zta_cfg = NULL;
    const zta_policy_t *policy = NULL;
    char zta_key[] = "zta_policy";
    if (proc->configs != NULL
        && map_get(proc->configs, zta_key, &zta_dat) == 0 && zta_dat != NULL
        && data_object_ptr(zta_dat, (void **)&zta_cfg) == 0
        && zta_cfg != NULL && zta_cfg->data_struct != NULL)
        policy = (const zta_policy_t *)zta_cfg->data_struct;
    if (policy == NULL || !policy->enabled || !policy->require_at_admission)
        return true;

    char own[ZTA_MAX_ANCHORS][ZTA_ANCHOR_NAME_LEN];
    size_t n_own = _own_zta_anchors(proc, policy, own, ZTA_MAX_ANCHORS);
    if (n_own == 0)
        return true;

    bool ok = false, seen = false;
    peers_read_lock((process_t *)proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !ok; i++) {
        const public_identity_t *peer = &proc->protocol.peers[i];
        char pu[UUID_STRING_LEN + 1];
        uuid_unparse_lower((const unsigned char *)peer->uuid, pu);
        if (strcmp(pu, uuid) != 0)
            continue;
        seen = true;
        for (size_t j = 0; j < peer->num_zta_anchors && !ok; j++)
            for (size_t k = 0; k < n_own; k++)
                if (strcmp(peer->zta_anchors[j], own[k]) == 0) { ok = true; break; }
    }
    peers_read_unlock((process_t *)proc);
    if (!ok)
        log_warn(proc->logger,
                 "Identity: gateway: refusing to federate through %s (%s)\n",
                 uuid, seen ? "shares no proved anchor with ours"
                            : "no proved anchors — never admitted here");
    return ok;
}

/* -- the hooks ------------------------------------------------------------------ */

/* Admission (the welcoming committee): the whole decision lives in _zta_admit,
 * and its verdict is handed to the reputation process before the vote. */
static identity_ext_gate_t _hook_admission_gate(const process_t *proc,
                                                public_identity_t *peer,
                                                const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES])
{
    const zta_policy_t *policy = _policy(proc);
    if (policy == NULL)
        return IDENTITY_EXT_ADMIT;
    zta_gate_t decision = _zta_admit(proc, (zta_policy_t *)policy, peer, claimed_key);
    if (decision == ZTA_GATE_REJECT)
        return IDENTITY_EXT_REJECT;
    _publish_zta_standing(proc, policy, peer, decision);
    return decision == ZTA_GATE_ADMIT_CAPPED ? IDENTITY_EXT_ADMIT_CAPPED
                                             : IDENTITY_EXT_ADMIT;
}

/* A join request (the ZTA half of id_proc.c's _join_authorized): refused when
 * we enforce at admission, hold anchors of our own, and the requester proved
 * none of them. */
static bool _hook_join_refused(const process_t *proc, const public_identity_t *new_id)
{
    if (proc == NULL || new_id == NULL)
        return false;
    const zta_policy_t *policy = _policy(proc);
    if (policy != NULL)
    {
        if (policy->enabled && policy->require_at_admission)
        {
            /* OUR anchors are computed from our own credentials, exactly as
               Python's _join_authorized calls _own_zta_anchors(): the
               zta_anchors field on an identity records what a PEER proved to us
               at admission, and we never admit ourselves, so reading it for our
               side would compare the requester against an empty set. n_own == 0
               is the inert case _gateway_authorized also takes. */
            char own[ZTA_MAX_ANCHORS][ZTA_ANCHOR_NAME_LEN];
            size_t n_own = _own_zta_anchors(proc, policy, own, ZTA_MAX_ANCHORS);
            bool shared = (n_own == 0);
            for (size_t i = 0; i < n_own && !shared; i++)
                for (size_t j = 0; j < new_id->num_zta_anchors; j++)
                    if (strncmp(own[i], new_id->zta_anchors[j],
                                ZTA_ANCHOR_NAME_LEN) == 0)
                    {
                        shared = true;
                        break;
                    }
            if (!shared)
            {
                log_warn(proc->logger,
                         "Identity: join request from %s refused: no proved "
                         "shared anchor\n", new_id->nickname);
                return true;
            }
        }
    }
    return false;
}

static bool _hook_gateway_refused(const process_t *proc, const char *uuid_str)
{
    return !_gateway_authorized(proc, uuid_str);
}

static bool _hook_operator_credential(const process_t *proc,
                                      const public_identity_t *claim)
{
    const zta_policy_t *policy = _policy(proc);
    return policy != NULL && claim != NULL
           && _is_operator_credential(policy, claim->zta_credential,
                                      claim->zta_credential_len,
                                      claim->zta_credential_hash);
}

/* From reputation/rep_proc.c's _resolve_trust_signer. */
static zta_verifier_t *_resolve_zta_verifier(const process_t *proc)
{
    static zta_verifier_t *cached = NULL;
    static bool tried = false;
    if (tried)
        return cached;
    tried = true;
    if (proc == NULL || proc->configs == NULL)
        return NULL;
    data_t *zta_dat = NULL;
    config_t *zta_cfg = NULL;
    char zta_key[] = "zta_policy";
    if (map_get(proc->configs, zta_key, &zta_dat) != 0 || zta_dat == NULL
        || data_object_ptr(zta_dat, (void **)&zta_cfg) != 0
        || zta_cfg == NULL || zta_cfg->data_struct == NULL)
        return NULL;
    zta_policy_t *policy = (zta_policy_t *)zta_cfg->data_struct;
    if (zta_policy_create_verifier(policy, &cached) != 0)
        cached = NULL;
    return cached;
}

static bool _hook_credential_anchored(const process_t *proc,
                                      const public_identity_t *carried)
{
    if (carried == NULL || carried->zta_credential_len == 0)
        return false;
    zta_verifier_t *verifier = _resolve_zta_verifier(proc);
    if (verifier == NULL || verifier->verify_credential == NULL)
        return false;
    zta_result_t result = {0};
    if (verifier->verify_credential(verifier, carried->zta_credential,
                                    carried->zta_credential_len, &result) != 0)
        return false;
    return result.status == ZTA_VERIFIED;
}

static const identity_ext_t zta_identity_ext = {
    .name = "zta",
    .admission_gate = _hook_admission_gate,
    .join_refused = _hook_join_refused,
    .gateway_refused = _hook_gateway_refused,
    .operator_credential = _hook_operator_credential,
    .credential_anchored = _hook_credential_anchored,
};
IDENTITY_EXT_REGISTER(zta, &zta_identity_ext)

/* The anchor (extensions.md, "Static links"): referenced so a static link
 * keeps this object, and with it the registration above. */
void at_zta_identity_link(void) {}

/* The library's anchor (at_zta.h): one call keeps every ZTA object a
 * constructor lives in. The verifiers, policy and audit come with them, as
 * these reach into them. */
void at_zta_link(void)
{
    at_zta_identity_link();
    at_zta_msg_types_link();
    at_zta_process_link();
}
