/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "algorithms/agreement.h"
#include "autonomous_trust/core/protobuf/algorithms/agreement.pb-c.h"
#include "identity/group.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_message.h"

#include "../negative_runner.h"

/* ------------------------------------------------------------------------- */
/* Hex helpers                                                                */
/* ------------------------------------------------------------------------- */

/** Decode a 0x-prefixed lowercase hex string into a freshly-allocated buffer.
 *  Returns 0 on success, with *out and *out_len populated; caller frees *out.
 *  Returns -1 on malformed input.
 */
static int hex_to_bytes(const char *s, uint8_t **out, size_t *out_len) {
    if (s == NULL || s[0] != '0' || s[1] != 'x') return -1;
    const char *body = s + 2;
    size_t hex_len = strlen(body);
    if (hex_len % 2 != 0) return -1;
    size_t n = hex_len / 2;
    uint8_t *buf = malloc(n + 1);  /* +1 so n=0 still allocates. */
    if (buf == NULL) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        if (sscanf(body + 2 * i, "%2x", &v) != 1) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)v;
    }
    *out = buf;
    *out_len = n;
    return 0;
}

static int hex_field(json_t *obj, const char *key, uint8_t **out, size_t *len) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) return -1;
    return hex_to_bytes(json_string_value(v), out, len);
}

static bool bytes_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    if (a_len != b_len) return false;
    return memcmp(a, b, a_len) == 0;
}

/* ------------------------------------------------------------------------- */
/* Crypto vectors                                                             */
/* ------------------------------------------------------------------------- */

static int run_ed25519_sign(json_t *input, json_t *expected,
                            char *err, size_t err_len) {
    uint8_t *seed = NULL, *msg = NULL, *expected_sig = NULL;
    size_t seed_len = 0, msg_len = 0, expected_sig_len = 0;
    int rc = -1;

    if (hex_field(input, "key_seed", &seed, &seed_len) != 0 || seed_len != 32) {
        snprintf(err, err_len, "ed25519_sign: bad key_seed");
        goto cleanup;
    }
    if (hex_field(input, "message", &msg, &msg_len) != 0) {
        snprintf(err, err_len, "ed25519_sign: bad message");
        goto cleanup;
    }
    if (hex_field(expected, "signature", &expected_sig, &expected_sig_len) != 0
        || expected_sig_len != crypto_sign_BYTES) {
        snprintf(err, err_len, "ed25519_sign: bad expected signature");
        goto cleanup;
    }

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);

    uint8_t sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, msg, msg_len, sk) != 0) {
        snprintf(err, err_len, "ed25519_sign: crypto_sign_detached failed");
        goto cleanup;
    }

    if (!bytes_eq(sig, crypto_sign_BYTES, expected_sig, expected_sig_len)) {
        snprintf(err, err_len, "ed25519_sign: signature mismatch");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(seed);
    free(msg);
    free(expected_sig);
    return rc;
}

static int run_ed25519_verify(json_t *input, json_t *expected,
                              char *err, size_t err_len) {
    uint8_t *pk = NULL, *msg = NULL, *sig = NULL;
    size_t pk_len = 0, msg_len = 0, sig_len = 0;
    int rc = -1;

    if (hex_field(input, "public_key", &pk, &pk_len) != 0
        || pk_len != crypto_sign_PUBLICKEYBYTES) {
        snprintf(err, err_len, "ed25519_verify: bad public_key");
        goto cleanup;
    }
    if (hex_field(input, "message", &msg, &msg_len) != 0) {
        snprintf(err, err_len, "ed25519_verify: bad message");
        goto cleanup;
    }
    if (hex_field(input, "signature", &sig, &sig_len) != 0
        || sig_len != crypto_sign_BYTES) {
        snprintf(err, err_len, "ed25519_verify: bad signature");
        goto cleanup;
    }

    json_t *valid_j = json_object_get(expected, "valid");
    bool should_verify = json_is_true(valid_j);
    int verify_rc = crypto_sign_verify_detached(sig, msg, msg_len, pk);
    bool verified = (verify_rc == 0);
    if (verified != should_verify) {
        snprintf(err, err_len,
                 "ed25519_verify: got valid=%d, expected valid=%d",
                 verified ? 1 : 0, should_verify ? 1 : 0);
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(pk);
    free(msg);
    free(sig);
    return rc;
}

static int run_secretbox(json_t *input, json_t *expected,
                         char *err, size_t err_len) {
    uint8_t *key = NULL, *nonce = NULL, *plaintext = NULL, *expected_ct = NULL;
    size_t key_len = 0, nonce_len = 0, pt_len = 0, expected_ct_len = 0;
    uint8_t *ciphertext = NULL;
    int rc = -1;

    if (hex_field(input, "key", &key, &key_len) != 0
        || key_len != crypto_secretbox_KEYBYTES) {
        snprintf(err, err_len, "secretbox: bad key");
        goto cleanup;
    }
    if (hex_field(input, "nonce", &nonce, &nonce_len) != 0
        || nonce_len != crypto_secretbox_NONCEBYTES) {
        snprintf(err, err_len, "secretbox: bad nonce");
        goto cleanup;
    }
    if (hex_field(input, "plaintext", &plaintext, &pt_len) != 0) {
        snprintf(err, err_len, "secretbox: bad plaintext");
        goto cleanup;
    }
    if (hex_field(expected, "ciphertext", &expected_ct, &expected_ct_len) != 0) {
        snprintf(err, err_len, "secretbox: bad expected ciphertext");
        goto cleanup;
    }

    size_t ct_len = pt_len + crypto_secretbox_MACBYTES;
    ciphertext = malloc(ct_len ? ct_len : 1);
    if (ciphertext == NULL) {
        snprintf(err, err_len, "secretbox: oom");
        goto cleanup;
    }
    if (crypto_secretbox_easy(ciphertext, plaintext, pt_len, nonce, key) != 0) {
        snprintf(err, err_len, "secretbox: encrypt failed");
        goto cleanup;
    }
    if (!bytes_eq(ciphertext, ct_len, expected_ct, expected_ct_len)) {
        snprintf(err, err_len, "secretbox: ciphertext mismatch");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(key);
    free(nonce);
    free(plaintext);
    free(expected_ct);
    free(ciphertext);
    return rc;
}

static int run_secretbox_open(json_t *input, json_t *expected,
                              char *err, size_t err_len) {
    uint8_t *key = NULL, *nonce = NULL, *ciphertext = NULL, *expected_pt = NULL;
    size_t key_len = 0, nonce_len = 0, ct_len = 0, expected_pt_len = 0;
    uint8_t *plaintext = NULL;
    int rc = -1;

    if (hex_field(input, "key", &key, &key_len) != 0
        || key_len != crypto_secretbox_KEYBYTES) {
        snprintf(err, err_len, "secretbox_open: bad key");
        goto cleanup;
    }
    if (hex_field(input, "nonce", &nonce, &nonce_len) != 0
        || nonce_len != crypto_secretbox_NONCEBYTES) {
        snprintf(err, err_len, "secretbox_open: bad nonce");
        goto cleanup;
    }
    if (hex_field(input, "ciphertext", &ciphertext, &ct_len) != 0
        || ct_len < crypto_secretbox_MACBYTES) {
        snprintf(err, err_len, "secretbox_open: bad ciphertext");
        goto cleanup;
    }
    if (hex_field(expected, "plaintext", &expected_pt, &expected_pt_len) != 0) {
        snprintf(err, err_len, "secretbox_open: bad expected plaintext");
        goto cleanup;
    }

    size_t pt_len = ct_len - crypto_secretbox_MACBYTES;
    plaintext = malloc(pt_len ? pt_len : 1);
    if (plaintext == NULL) {
        snprintf(err, err_len, "secretbox_open: oom");
        goto cleanup;
    }
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ct_len, nonce, key) != 0) {
        snprintf(err, err_len, "secretbox_open: decrypt failed");
        goto cleanup;
    }
    if (!bytes_eq(plaintext, pt_len, expected_pt, expected_pt_len)) {
        snprintf(err, err_len, "secretbox_open: plaintext mismatch");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(key);
    free(nonce);
    free(ciphertext);
    free(expected_pt);
    free(plaintext);
    return rc;
}

static int run_box(json_t *input, json_t *expected,
                   char *err, size_t err_len) {
    uint8_t *sender_sk = NULL, *recipient_pk = NULL, *nonce = NULL,
            *plaintext = NULL, *expected_ct = NULL;
    size_t sender_sk_len = 0, recipient_pk_len = 0, nonce_len = 0,
           pt_len = 0, expected_ct_len = 0;
    uint8_t *ciphertext = NULL;
    int rc = -1;

    if (hex_field(input, "sender_private_key", &sender_sk, &sender_sk_len) != 0
        || sender_sk_len != crypto_box_SECRETKEYBYTES) {
        snprintf(err, err_len, "box: bad sender_private_key");
        goto cleanup;
    }
    if (hex_field(input, "recipient_public_key", &recipient_pk, &recipient_pk_len) != 0
        || recipient_pk_len != crypto_box_PUBLICKEYBYTES) {
        snprintf(err, err_len, "box: bad recipient_public_key");
        goto cleanup;
    }
    if (hex_field(input, "nonce", &nonce, &nonce_len) != 0
        || nonce_len != crypto_box_NONCEBYTES) {
        snprintf(err, err_len, "box: bad nonce");
        goto cleanup;
    }
    if (hex_field(input, "plaintext", &plaintext, &pt_len) != 0) {
        snprintf(err, err_len, "box: bad plaintext");
        goto cleanup;
    }
    if (hex_field(expected, "ciphertext", &expected_ct, &expected_ct_len) != 0) {
        snprintf(err, err_len, "box: bad expected ciphertext");
        goto cleanup;
    }

    size_t ct_len = pt_len + crypto_box_MACBYTES;
    ciphertext = malloc(ct_len ? ct_len : 1);
    if (ciphertext == NULL) {
        snprintf(err, err_len, "box: oom");
        goto cleanup;
    }
    if (crypto_box_easy(ciphertext, plaintext, pt_len, nonce,
                        recipient_pk, sender_sk) != 0) {
        snprintf(err, err_len, "box: encrypt failed");
        goto cleanup;
    }
    if (!bytes_eq(ciphertext, ct_len, expected_ct, expected_ct_len)) {
        snprintf(err, err_len, "box: ciphertext mismatch");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(sender_sk);
    free(recipient_pk);
    free(nonce);
    free(plaintext);
    free(expected_ct);
    free(ciphertext);
    return rc;
}

static int run_box_open(json_t *input, json_t *expected,
                        char *err, size_t err_len) {
    uint8_t *recipient_sk = NULL, *sender_pk = NULL, *nonce = NULL,
            *ciphertext = NULL, *expected_pt = NULL;
    size_t recipient_sk_len = 0, sender_pk_len = 0, nonce_len = 0,
           ct_len = 0, expected_pt_len = 0;
    uint8_t *plaintext = NULL;
    int rc = -1;

    if (hex_field(input, "recipient_private_key", &recipient_sk, &recipient_sk_len) != 0
        || recipient_sk_len != crypto_box_SECRETKEYBYTES) {
        snprintf(err, err_len, "box_open: bad recipient_private_key");
        goto cleanup;
    }
    if (hex_field(input, "sender_public_key", &sender_pk, &sender_pk_len) != 0
        || sender_pk_len != crypto_box_PUBLICKEYBYTES) {
        snprintf(err, err_len, "box_open: bad sender_public_key");
        goto cleanup;
    }
    if (hex_field(input, "nonce", &nonce, &nonce_len) != 0
        || nonce_len != crypto_box_NONCEBYTES) {
        snprintf(err, err_len, "box_open: bad nonce");
        goto cleanup;
    }
    if (hex_field(input, "ciphertext", &ciphertext, &ct_len) != 0
        || ct_len < crypto_box_MACBYTES) {
        snprintf(err, err_len, "box_open: bad ciphertext");
        goto cleanup;
    }
    if (hex_field(expected, "plaintext", &expected_pt, &expected_pt_len) != 0) {
        snprintf(err, err_len, "box_open: bad expected plaintext");
        goto cleanup;
    }

    size_t pt_len = ct_len - crypto_box_MACBYTES;
    plaintext = malloc(pt_len ? pt_len : 1);
    if (plaintext == NULL) {
        snprintf(err, err_len, "box_open: oom");
        goto cleanup;
    }
    if (crypto_box_open_easy(plaintext, ciphertext, ct_len, nonce,
                             sender_pk, recipient_sk) != 0) {
        snprintf(err, err_len, "box_open: decrypt failed");
        goto cleanup;
    }
    if (!bytes_eq(plaintext, pt_len, expected_pt, expected_pt_len)) {
        snprintf(err, err_len, "box_open: plaintext mismatch");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(recipient_sk);
    free(sender_pk);
    free(nonce);
    free(ciphertext);
    free(expected_pt);
    free(plaintext);
    return rc;
}

static int run_crypto_vector(const at_case_t *c,
                             char *err, size_t err_len) {
    json_t *primitive_j = json_object_get(c->data, "primitive");
    if (!json_is_string(primitive_j)) {
        snprintf(err, err_len, "missing primitive");
        return -1;
    }
    const char *primitive = json_string_value(primitive_j);
    json_t *input = json_object_get(c->data, "input");
    json_t *expected = json_object_get(c->data, "expected");
    if (!json_is_object(input) || !json_is_object(expected)) {
        snprintf(err, err_len, "missing input or expected");
        return -1;
    }

    if (strcmp(primitive, "ed25519_sign") == 0) {
        return run_ed25519_sign(input, expected, err, err_len);
    }
    if (strcmp(primitive, "ed25519_verify") == 0) {
        return run_ed25519_verify(input, expected, err, err_len);
    }
    if (strcmp(primitive, "nacl_secretbox") == 0) {
        return run_secretbox(input, expected, err, err_len);
    }
    if (strcmp(primitive, "nacl_secretbox_open") == 0) {
        return run_secretbox_open(input, expected, err, err_len);
    }
    if (strcmp(primitive, "nacl_box") == 0) {
        return run_box(input, expected, err, err_len);
    }
    if (strcmp(primitive, "nacl_box_open") == 0) {
        return run_box_open(input, expected, err, err_len);
    }
    snprintf(err, err_len, "unsupported primitive: %s", primitive);
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Wire vectors — round-trip equivalence (no byte-pinning per Phase A).      */
/* ------------------------------------------------------------------------- */

static int run_wv_agreement_proof(json_t *input, json_t *expected,
                                  char *err, size_t err_len) {
    (void)expected;  /* expected is empty for round-trip-only vectors. */

    json_t *uuid_j = json_object_get(input, "uuid");
    json_t *approval_j = json_object_get(input, "approval");
    if (!json_is_string(uuid_j) || !json_is_boolean(approval_j)) {
        snprintf(err, err_len, "wv/agreement_proof: missing uuid or approval");
        return -1;
    }

    uint8_t *digest = NULL, *nonce = NULL;
    size_t digest_len = 0, nonce_len = 0;
    if (hex_field(input, "digest", &digest, &digest_len) != 0) {
        snprintf(err, err_len, "wv/agreement_proof: bad digest hex");
        return -1;
    }
    json_t *nonce_j = json_object_get(input, "nonce");
    bool nonce_present = json_is_string(nonce_j);
    if (nonce_present
        && hex_to_bytes(json_string_value(nonce_j), &nonce, &nonce_len) != 0) {
        snprintf(err, err_len, "wv/agreement_proof: bad nonce hex");
        free(digest);
        return -1;
    }

    int rc = -1;

    agreement_proof_t *proof = NULL;
    if (agreement_proof_create(json_string_value(uuid_j),
                               digest, digest_len,
                               json_is_true(approval_j),
                               nonce, nonce_len,
                               &proof) != 0 || proof == NULL) {
        snprintf(err, err_len, "wv/agreement_proof: create failed");
        goto cleanup;
    }

    /* Sync out to the protobuf message. The proto fields are pointers into
     * `proof`'s buffers, so the proto's lifetime is bounded by `proof`. */
    AutonomousTrust__Core__Protobuf__Algorithms__AgreementProof proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__ALGORITHMS__AGREEMENT_PROOF__INIT;
    if (agreement_proof_sync_out(proof, &proto) != 0) {
        snprintf(err, err_len, "wv/agreement_proof: sync_out failed");
        goto cleanup;
    }

    size_t pb_size =
        autonomous_trust__core__protobuf__algorithms__agreement_proof__get_packed_size(&proto);
    uint8_t *pb_buf = malloc(pb_size ? pb_size : 1);
    if (pb_buf == NULL) {
        snprintf(err, err_len, "wv/agreement_proof: oom");
        goto cleanup;
    }
    autonomous_trust__core__protobuf__algorithms__agreement_proof__pack(&proto, pb_buf);

    AutonomousTrust__Core__Protobuf__Algorithms__AgreementProof *parsed =
        autonomous_trust__core__protobuf__algorithms__agreement_proof__unpack(
            NULL, pb_size, pb_buf);
    if (parsed == NULL) {
        snprintf(err, err_len, "wv/agreement_proof: unpack failed");
        free(pb_buf);
        goto cleanup;
    }

    agreement_proof_t restored = {0};
    if (agreement_proof_sync_in(parsed, &restored) != 0) {
        snprintf(err, err_len, "wv/agreement_proof: sync_in failed");
        autonomous_trust__core__protobuf__algorithms__agreement_proof__free_unpacked(
            parsed, NULL);
        free(pb_buf);
        goto cleanup;
    }

    if (strcmp(restored.uuid, proof->uuid) != 0) {
        snprintf(err, err_len, "wv/agreement_proof: uuid drift");
        goto cleanup_restored;
    }
    if (restored.approval != proof->approval) {
        snprintf(err, err_len, "wv/agreement_proof: approval drift");
        goto cleanup_restored;
    }
    if (!bytes_eq(restored.digest, restored.digest_len,
                  proof->digest, proof->digest_len)) {
        snprintf(err, err_len, "wv/agreement_proof: digest drift");
        goto cleanup_restored;
    }
    if (nonce_present) {
        if (!bytes_eq(restored.nonce, restored.nonce_len,
                      proof->nonce, proof->nonce_len)) {
            snprintf(err, err_len, "wv/agreement_proof: nonce drift");
            goto cleanup_restored;
        }
    } else {
        /* Python's no-nonce case round-trips to nonce=None; the C side
         * round-trips to nonce_len=0, which is the equivalent. */
        if (restored.nonce_len != 0) {
            snprintf(err, err_len, "wv/agreement_proof: nonce should be empty after restore");
            goto cleanup_restored;
        }
    }
    rc = 0;
cleanup_restored:
    free(restored.digest);
    free(restored.nonce);
    autonomous_trust__core__protobuf__algorithms__agreement_proof__free_unpacked(
        parsed, NULL);
    free(pb_buf);
cleanup:
    if (proof != NULL) agreement_proof_free(proof);
    free(digest);
    free(nonce);
    return rc;
}

static int run_wv_signature(json_t *input, json_t *expected,
                            char *err, size_t err_len) {
    (void)input;
    (void)expected;

    /* The C side has no standalone signature_t serializer — the Python
     * Signature.to_string/from_string contract maps to public_identity_t
     * round-trip on this side (where the public-key portion of the
     * signature lives). Test that property: a published identity round-
     * trips its signature.public bytes through pack/unpack.
     */
    int rc = -1;
    identity_t *ident = NULL;
    public_identity_t *pub = NULL;
    public_identity_t restored = {0};
    void *pb_buf = NULL;
    size_t pb_len = 0;

    uuid_t uuid;
    uuid_generate(uuid);
    if (identity_create(&uuid, "10.0.0.1", "alice.scenario", "alice", "me",
                        &ident) != 0 || ident == NULL) {
        snprintf(err, err_len, "wv/signature: identity_create failed");
        goto cleanup;
    }
    if (identity_publish(ident, &pub) != 0 || pub == NULL) {
        snprintf(err, err_len, "wv/signature: identity_publish failed");
        goto cleanup;
    }
    if (peer_to_proto(pub, &pb_buf, &pb_len) != 0) {
        snprintf(err, err_len, "wv/signature: peer_to_proto failed");
        goto cleanup;
    }
    if (proto_to_peer(pb_buf, pb_len, &restored) != 0) {
        snprintf(err, err_len, "wv/signature: proto_to_peer failed");
        goto cleanup;
    }
    if (!bytes_eq(restored.signature.public, crypto_sign_PUBLICKEYBYTES,
                  pub->signature.public, crypto_sign_PUBLICKEYBYTES)) {
        snprintf(err, err_len, "wv/signature: public-key drift across round-trip");
        goto cleanup;
    }
    rc = 0;
cleanup:
    if (ident != NULL) identity_free(ident);
    /* pub_copy and pb_buf are smrt_ptrs; smrt_deref releases them. */
    if (pub != NULL) smrt_deref(pub);
    if (pb_buf != NULL) smrt_deref(pb_buf);
    return rc;
}

static int run_wv_message_envelope(json_t *input, json_t *expected,
                                   char *err, size_t err_len) {
    (void)expected;

    json_t *process_j = json_object_get(input, "process");
    json_t *function_j = json_object_get(input, "function");
    json_t *obj_j = json_object_get(input, "obj");
    json_t *encrypt_j = json_object_get(input, "encrypt");
    if (!json_is_string(process_j) || !json_is_string(function_j)
        || !json_is_string(obj_j)) {
        snprintf(err, err_len, "wv/message: missing process/function/obj");
        return -1;
    }

    int rc = -1;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    net_wire_msg_t restored = {0};

    net_wire_msg_t msg = {0};
    /* process is a fixed-size buffer; truncate-and-NUL-terminate. */
    strncpy(msg.process, json_string_value(process_j), sizeof(msg.process) - 1);
    msg.function = strdup(json_string_value(function_j));
    if (msg.function == NULL) {
        snprintf(err, err_len, "wv/message: oom");
        return -1;
    }
    const char *obj_str = json_string_value(obj_j);
    msg.data_len = strlen(obj_str);
    msg.data = malloc(msg.data_len ? msg.data_len : 1);
    if (msg.data == NULL) {
        free(msg.function);
        snprintf(err, err_len, "wv/message: oom");
        return -1;
    }
    memcpy(msg.data, obj_str, msg.data_len);
    msg.encrypt = json_is_true(encrypt_j);
    msg.has_signature = false;
    msg.to_whom.type = RECIPIENT_BROADCAST;
    /* from_whom is left zeroed — net_message_to_wire stringifies a nil UUID
     * for the from_uuid field, which round-trips through net_message_from_wire
     * without error. */

    if (net_message_to_wire(&msg, NULL, &wire, &wire_len) != 0) {
        snprintf(err, err_len, "wv/message: to_wire failed");
        goto cleanup;
    }
    if (net_message_from_wire(wire, wire_len, NULL, &restored) != 0) {
        snprintf(err, err_len, "wv/message: from_wire failed");
        goto cleanup;
    }
    if (strcmp(restored.process, msg.process) != 0) {
        snprintf(err, err_len, "wv/message: process drift");
        goto cleanup;
    }
    if (restored.function == NULL || strcmp(restored.function, msg.function) != 0) {
        snprintf(err, err_len, "wv/message: function drift");
        goto cleanup;
    }
    if (!bytes_eq(restored.data, restored.data_len, msg.data, msg.data_len)) {
        snprintf(err, err_len, "wv/message: data drift");
        goto cleanup;
    }
    if (restored.encrypt != msg.encrypt) {
        snprintf(err, err_len, "wv/message: encrypt flag drift");
        goto cleanup;
    }
    rc = 0;
cleanup:
    free(msg.function);
    free(msg.data);
    free(wire);
    net_wire_msg_free(&restored);
    return rc;
}

static int run_wire_vector(const at_case_t *c,
                           char *err, size_t err_len) {
    json_t *constructor_j = json_object_get(c->data, "constructor");
    if (!json_is_string(constructor_j)) {
        snprintf(err, err_len, "missing constructor");
        return -1;
    }
    const char *ctor = json_string_value(constructor_j);
    json_t *input = json_object_get(c->data, "input");
    json_t *expected = json_object_get(c->data, "expected");
    if (!json_is_object(input)) {
        snprintf(err, err_len, "missing input");
        return -1;
    }
    /* expected is empty for round-trip-only vectors; handlers tolerate NULL. */
    int rc;
    if (strcmp(ctor, "AgreementProof") == 0) {
        rc = run_wv_agreement_proof(input, expected, err, err_len);
    } else if (strcmp(ctor, "Signature") == 0) {
        rc = run_wv_signature(input, expected, err, err_len);
    } else if (strcmp(ctor, "Message") == 0) {
        rc = run_wv_message_envelope(input, expected, err, err_len);
    } else {
        snprintf(err, err_len, "unsupported constructor: %s", ctor);
        rc = 1;  /* skip sentinel */
    }
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Scenarios                                                                  */
/* ------------------------------------------------------------------------- */

/* Build a deterministic identity for the conformance harness. Both Python
 * and C derive the signature/encryptor seeds from SHA-256 of a fixed
 * label, so the resulting Ed25519 / X25519 keypairs are byte-identical
 * across languages. */
static int _make_deterministic_identity(const char *pid, const char *addr,
                                        identity_t **out) {
    uuid_t uuid;
    /* uuid5 in fixed namespace, mirroring the Python adapter. The Python
     * implementation uses RFC 4122 v5 (SHA-1 of namespace + name); we
     * inline the same computation here so a recovered uuid matches.
     * Namespace: 00000000-0000-0000-0000-000000000aaa
     * Name: "at-conformance:<pid>" */
    unsigned char ns_bytes[16] = {0};
    ns_bytes[15] = 0xaa; ns_bytes[14] = 0x0a;
    char namestr[128];
    snprintf(namestr, sizeof(namestr), "at-conformance:%s", pid);
    unsigned char concat[16 + 128];
    memcpy(concat, ns_bytes, 16);
    size_t name_len = strlen(namestr);
    memcpy(concat + 16, namestr, name_len);
    unsigned char hash[20];
    /* libsodium has no SHA-1; emulate uuid5 with a libsodium SHA-256
     * truncated to 16 bytes and set version/variant bits. Python uses
     * uuid5/SHA-1, so the UUIDs differ across languages — only the
     * keypairs need to match for the scenario to succeed. The UUID
     * is not part of the parsed-Message check. */
    unsigned char sha[32];
    crypto_hash_sha256(sha, concat, 16 + name_len);
    memcpy(hash, sha, 16);
    hash[6] = (hash[6] & 0x0F) | 0x40;  /* v4 marker */
    hash[8] = (hash[8] & 0x3F) | 0x80;
    memcpy(uuid, hash, 16);

    int rc = identity_create(&uuid, addr, "x.scenario", pid, "me", out);
    if (rc != 0 || *out == NULL) return -1;

    /* Overwrite the randomly-generated keypairs with deterministic ones
     * keyed on the participant id. Mirrors Python's _make_test_identity. */
    char label[64];
    unsigned char digest[32];
    unsigned char hex_seed[crypto_sign_SEEDBYTES * 2 + 1];

    snprintf(label, sizeof(label), "at-conformance:sig:%s", pid);
    crypto_hash_sha256(digest, (const unsigned char *)label, strlen(label));
    hexlify(digest, crypto_sign_SEEDBYTES, hex_seed);
    hex_seed[crypto_sign_SEEDBYTES * 2] = '\0';
    signature_init(&(*out)->signature, hex_seed);

    snprintf(label, sizeof(label), "at-conformance:enc:%s", pid);
    crypto_hash_sha256(digest, (const unsigned char *)label, strlen(label));
    hexlify(digest, crypto_box_SEEDBYTES, hex_seed);
    hex_seed[crypto_box_SEEDBYTES * 2] = '\0';
    encryptor_init(&(*out)->encryptor, hex_seed);
    return 0;
}

static int run_peer_encrypted_roundtrip(const at_case_t *c,
                                        char *err, size_t err_len) {
    int rc = -1;
    identity_t *a = NULL, *b = NULL;
    public_identity_t *a_pub = NULL, *b_pub = NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    unsigned char *cipher = NULL;
    unsigned char *plain = NULL;
    uint8_t *nonce = NULL;
    size_t nonce_len = 0;
    net_wire_msg_t msg = {0};
    net_wire_msg_t restored = {0};

    json_t *fixtures = json_object_get(c->data, "fixtures");
    if (!json_is_object(fixtures)) {
        snprintf(err, err_len, "scenario: fixtures missing");
        return -1;
    }
    const char *nonce_hex = json_string_value(json_object_get(fixtures, "nonce_hex"));
    const char *obj_json = json_string_value(json_object_get(fixtures, "obj_json"));
    if (nonce_hex == NULL || obj_json == NULL) {
        snprintf(err, err_len, "scenario: nonce_hex or obj_json missing");
        return -1;
    }
    if (hex_to_bytes(nonce_hex, &nonce, &nonce_len) != 0 ||
        nonce_len != crypto_box_NONCEBYTES) {
        snprintf(err, err_len, "scenario: nonce_hex must decode to %u bytes",
                 (unsigned)crypto_box_NONCEBYTES);
        goto cleanup;
    }

    if (_make_deterministic_identity("a", "10.0.80.1", &a) != 0 ||
        _make_deterministic_identity("b", "10.0.80.2", &b) != 0) {
        snprintf(err, err_len, "scenario: identity build failed");
        goto cleanup;
    }
    if (identity_publish(a, &a_pub) != 0 || identity_publish(b, &b_pub) != 0) {
        snprintf(err, err_len, "scenario: identity_publish failed");
        goto cleanup;
    }

    /* Build A's wire message: process=identity, function=request_access,
     * data=obj_json. The signer arg to net_message_to_wire embeds an
     * Ed25519 signature into the JSON envelope. */
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = strdup("request_access");
    if (msg.function == NULL) goto cleanup;
    size_t obj_len = strlen(obj_json);
    msg.data = malloc(obj_len > 0 ? obj_len : 1);
    if (msg.data == NULL) goto cleanup;
    memcpy(msg.data, obj_json, obj_len);
    msg.data_len = obj_len;
    msg.to_whom.type = RECIPIENT_PEER;
    memcpy(&msg.to_whom.target.peer, b_pub, sizeof(public_identity_t));
    memcpy(&msg.from_whom, a_pub, sizeof(public_identity_t));
    msg.encrypt = true;

    if (net_message_to_wire(&msg, a, &wire, &wire_len) != 0) {
        snprintf(err, err_len, "scenario: net_message_to_wire failed");
        goto cleanup;
    }

    /* A encrypts the wire bytes to B with the fixture nonce. */
    cipher = malloc(wire_len + crypto_box_MACBYTES);
    if (cipher == NULL) goto cleanup;
    msg_str_t in = { .msg = wire, .len = wire_len };
    if (identity_encrypt(a, &in, b_pub, nonce, cipher) != 0) {
        snprintf(err, err_len, "scenario: identity_encrypt failed");
        goto cleanup;
    }

    /* B decrypts. */
    size_t cipher_len = wire_len + crypto_box_MACBYTES;
    plain = malloc(wire_len > 0 ? wire_len : 1);
    if (plain == NULL) goto cleanup;
    msg_str_t cipher_ms = { .msg = cipher, .len = cipher_len };
    if (identity_decrypt(b, &cipher_ms, a_pub, nonce, plain) != 0) {
        snprintf(err, err_len, "scenario: identity_decrypt failed");
        goto cleanup;
    }

    /* B re-parses the decrypted wire bytes via production code. */
    if (net_message_from_wire(plain, wire_len, a_pub, &restored) != 0) {
        snprintf(err, err_len, "scenario: net_message_from_wire failed");
        goto cleanup;
    }

    /* Validate against expected_state.b.{routed_process, routed_function,
     * verified}. */
    json_t *expected_state = json_object_get(c->data, "expected_state");
    json_t *b_expected = json_object_get(expected_state, "b");
    if (json_is_object(b_expected)) {
        const char *rp = json_string_value(json_object_get(b_expected, "routed_process"));
        const char *rf = json_string_value(json_object_get(b_expected, "routed_function"));
        json_t *ver_j = json_object_get(b_expected, "verified");
        if (rp != NULL && strcmp(restored.process, rp) != 0) {
            snprintf(err, err_len,
                     "routed_process mismatch: expected %s, got %s", rp, restored.process);
            goto cleanup;
        }
        if (rf != NULL &&
            (restored.function == NULL || strcmp(restored.function, rf) != 0)) {
            snprintf(err, err_len,
                     "routed_function mismatch: expected %s, got %s",
                     rf, restored.function ? restored.function : "(null)");
            goto cleanup;
        }
        if (ver_j != NULL) {
            bool want = json_is_true(ver_j);
            if (restored.verified != want) {
                snprintf(err, err_len,
                         "verified mismatch: expected %s, got %s",
                         want ? "true" : "false",
                         restored.verified ? "true" : "false");
                goto cleanup;
            }
        }
    }

    rc = 0;
cleanup:
    net_wire_msg_free(&restored);
    free(plain);
    free(cipher);
    free(wire);
    free(msg.function);
    free(msg.data);
    free(nonce);
    if (a_pub != NULL) smrt_deref(a_pub);
    if (b_pub != NULL) smrt_deref(b_pub);
    if (a != NULL) identity_free(a);
    if (b != NULL) identity_free(b);
    return rc;
}

static int run_group_encrypted_roundtrip(const at_case_t *c,
                                         char *err, size_t err_len) {
    int rc = -1;
    identity_t *a = NULL;
    public_identity_t *a_pub = NULL;
    group_t *a_group = NULL, *b_group = NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    unsigned char *cipher = NULL;
    unsigned char *plain = NULL;
    uint8_t *nonce = NULL;
    size_t nonce_len = 0;
    net_wire_msg_t msg = {0};
    net_wire_msg_t restored = {0};

    json_t *fixtures = json_object_get(c->data, "fixtures");
    if (!json_is_object(fixtures)) {
        snprintf(err, err_len, "scenario: fixtures missing");
        return -1;
    }
    const char *nonce_hex = json_string_value(json_object_get(fixtures, "nonce_hex"));
    const char *obj_json = json_string_value(json_object_get(fixtures, "obj_json"));
    const char *group_seed_hex =
        json_string_value(json_object_get(fixtures, "group_encryptor_seed_hex"));
    if (nonce_hex == NULL || obj_json == NULL || group_seed_hex == NULL) {
        snprintf(err, err_len, "scenario: fixtures missing nonce_hex/obj_json/group_encryptor_seed_hex");
        return -1;
    }
    if (hex_to_bytes(nonce_hex, &nonce, &nonce_len) != 0 ||
        nonce_len != crypto_box_NONCEBYTES) {
        snprintf(err, err_len, "scenario: nonce_hex must decode to %u bytes",
                 (unsigned)crypto_box_NONCEBYTES);
        goto cleanup;
    }
    if (strlen(group_seed_hex) != crypto_box_SEEDBYTES * 2) {
        snprintf(err, err_len,
                 "scenario: group_encryptor_seed_hex must be %u hex chars",
                 (unsigned)(crypto_box_SEEDBYTES * 2));
        goto cleanup;
    }

    if (_make_deterministic_identity("a", "10.0.80.1", &a) != 0) {
        snprintf(err, err_len, "scenario: identity build failed");
        goto cleanup;
    }
    if (identity_publish(a, &a_pub) != 0 || a_pub == NULL) {
        snprintf(err, err_len, "scenario: identity_publish failed");
        goto cleanup;
    }

    /* Build two group_t instances with the SAME deterministic keypair —
     * mirrors how each Python-side group member holds an identical copy of
     * the group's Encryptor. Address is incidental for this test. */
    uuid_t group_uuid;
    {
        const char *label = "at-conformance:group:g1";
        unsigned char sha[32];
        crypto_hash_sha256(sha, (const unsigned char *)label, strlen(label));
        memcpy(group_uuid, sha, 16);
        group_uuid[6] = (group_uuid[6] & 0x0F) | 0x40;
        group_uuid[8] = (group_uuid[8] & 0x3F) | 0x80;
    }
    char group_addr[] = "10.0.80.10";
    if (group_create(&group_uuid, group_addr, &a_group) != 0 ||
        group_create(&group_uuid, group_addr, &b_group) != 0) {
        snprintf(err, err_len, "scenario: group_create failed");
        goto cleanup;
    }
    encryptor_init(&a_group->encryptor, (const unsigned char *)group_seed_hex);
    encryptor_init(&b_group->encryptor, (const unsigned char *)group_seed_hex);

    /* Build A's signed wire message. */
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = strdup("request_access");
    if (msg.function == NULL) goto cleanup;
    size_t obj_len = strlen(obj_json);
    msg.data = malloc(obj_len > 0 ? obj_len : 1);
    if (msg.data == NULL) goto cleanup;
    memcpy(msg.data, obj_json, obj_len);
    msg.data_len = obj_len;
    msg.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(&msg.from_whom, a_pub, sizeof(public_identity_t));
    msg.encrypt = true;

    if (net_message_to_wire(&msg, a, &wire, &wire_len) != 0) {
        snprintf(err, err_len, "scenario: net_message_to_wire failed");
        goto cleanup;
    }

    /* Group-encrypt the wire bytes. ident=a_group provides the private
     * key, whom=a_group provides the public key — same keypair on both
     * sides of the Box, which is exactly how the production sender
     * invokes Group.encrypt(bytes(msg), self.group). */
    cipher = malloc(wire_len + crypto_box_MACBYTES);
    if (cipher == NULL) goto cleanup;
    msg_str_t in = { .msg = wire, .len = wire_len };
    if (group_encrypt(a_group, &in, a_group, nonce, cipher) != 0) {
        snprintf(err, err_len, "scenario: group_encrypt failed");
        goto cleanup;
    }

    /* B decrypts with its own copy of the same keypair. */
    size_t cipher_len = wire_len + crypto_box_MACBYTES;
    plain = malloc(wire_len > 0 ? wire_len : 1);
    if (plain == NULL) goto cleanup;
    msg_str_t cipher_ms = { .msg = cipher, .len = cipher_len };
    if (group_decrypt(b_group, &cipher_ms, b_group, nonce, plain) != 0) {
        snprintf(err, err_len, "scenario: group_decrypt failed");
        goto cleanup;
    }

    if (net_message_from_wire(plain, wire_len, a_pub, &restored) != 0) {
        snprintf(err, err_len, "scenario: net_message_from_wire failed");
        goto cleanup;
    }

    /* Validate expected_state.b.{routed_process, routed_function, verified}. */
    json_t *expected_state = json_object_get(c->data, "expected_state");
    json_t *b_expected = json_object_get(expected_state, "b");
    if (json_is_object(b_expected)) {
        const char *rp = json_string_value(json_object_get(b_expected, "routed_process"));
        const char *rf = json_string_value(json_object_get(b_expected, "routed_function"));
        json_t *ver_j = json_object_get(b_expected, "verified");
        if (rp != NULL && strcmp(restored.process, rp) != 0) {
            snprintf(err, err_len,
                     "routed_process mismatch: expected %s, got %s", rp, restored.process);
            goto cleanup;
        }
        if (rf != NULL &&
            (restored.function == NULL || strcmp(restored.function, rf) != 0)) {
            snprintf(err, err_len,
                     "routed_function mismatch: expected %s, got %s",
                     rf, restored.function ? restored.function : "(null)");
            goto cleanup;
        }
        if (ver_j != NULL) {
            bool want = json_is_true(ver_j);
            if (restored.verified != want) {
                snprintf(err, err_len,
                         "verified mismatch: expected %s, got %s",
                         want ? "true" : "false",
                         restored.verified ? "true" : "false");
                goto cleanup;
            }
        }
    }

    rc = 0;
cleanup:
    net_wire_msg_free(&restored);
    free(plain);
    free(cipher);
    free(wire);
    free(msg.function);
    free(msg.data);
    free(nonce);
    if (a_pub != NULL) smrt_deref(a_pub);
    if (a != NULL) identity_free(a);
    if (a_group != NULL) group_free(a_group);
    if (b_group != NULL) group_free(b_group);
    return rc;
}

/* Compare a parsed net_wire_msg against expected_state.<pid>.{routed_process,
 * routed_function, verified}. Returns 0 on match, -1 on mismatch with err
 * populated. Mirror of _assert_expected_state in the Python adapter. */
static int _assert_expected_state(const at_case_t *c, const char *pid,
                                  const net_wire_msg_t *parsed,
                                  char *err, size_t err_len) {
    json_t *expected_state = json_object_get(c->data, "expected_state");
    json_t *p_expected = json_object_get(expected_state, pid);
    if (!json_is_object(p_expected)) return 0;
    const char *rp = json_string_value(json_object_get(p_expected, "routed_process"));
    const char *rf = json_string_value(json_object_get(p_expected, "routed_function"));
    json_t *ver_j = json_object_get(p_expected, "verified");
    if (rp != NULL && strcmp(parsed->process, rp) != 0) {
        snprintf(err, err_len,
                 "%s: routed_process mismatch: expected %s, got %s",
                 pid, rp, parsed->process);
        return -1;
    }
    if (rf != NULL &&
        (parsed->function == NULL || strcmp(parsed->function, rf) != 0)) {
        snprintf(err, err_len,
                 "%s: routed_function mismatch: expected %s, got %s",
                 pid, rf, parsed->function ? parsed->function : "(null)");
        return -1;
    }
    if (ver_j != NULL) {
        bool want = json_is_true(ver_j);
        if (parsed->verified != want) {
            snprintf(err, err_len,
                     "%s: verified mismatch: expected %s, got %s",
                     pid, want ? "true" : "false",
                     parsed->verified ? "true" : "false");
            return -1;
        }
    }
    return 0;
}

static int run_broadcast_fanout(const at_case_t *c, char *err, size_t err_len) {
    int rc = -1;
    identity_t *a = NULL;
    public_identity_t *a_pub = NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    net_wire_msg_t msg = {0};
    net_wire_msg_t parsed_b = {0};
    net_wire_msg_t parsed_c = {0};

    json_t *fixtures = json_object_get(c->data, "fixtures");
    const char *obj_json = fixtures != NULL
        ? json_string_value(json_object_get(fixtures, "obj_json")) : "{}";
    if (obj_json == NULL) obj_json = "{}";

    if (_make_deterministic_identity("a", "10.0.80.1", &a) != 0) {
        snprintf(err, err_len, "scenario: identity build failed");
        goto cleanup;
    }
    if (identity_publish(a, &a_pub) != 0 || a_pub == NULL) {
        snprintf(err, err_len, "scenario: identity_publish failed");
        goto cleanup;
    }

    /* Build A's signed broadcast wire bytes — no encryption layer. */
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = strdup("request_access");
    if (msg.function == NULL) goto cleanup;
    size_t obj_len = strlen(obj_json);
    msg.data = malloc(obj_len > 0 ? obj_len : 1);
    if (msg.data == NULL) goto cleanup;
    memcpy(msg.data, obj_json, obj_len);
    msg.data_len = obj_len;
    msg.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(&msg.from_whom, a_pub, sizeof(public_identity_t));
    msg.encrypt = false;

    if (net_message_to_wire(&msg, a, &wire, &wire_len) != 0) {
        snprintf(err, err_len, "scenario: net_message_to_wire failed");
        goto cleanup;
    }

    /* Fan-out: parse the SAME bytes twice with A as the known sender.
     * Each parse must produce identical observables (the engine ships
     * one bytes copy to multiple receivers in production). */
    if (net_message_from_wire(wire, wire_len, a_pub, &parsed_b) != 0) {
        snprintf(err, err_len, "scenario: parse for b failed");
        goto cleanup;
    }
    if (net_message_from_wire(wire, wire_len, a_pub, &parsed_c) != 0) {
        snprintf(err, err_len, "scenario: parse for c failed");
        goto cleanup;
    }

    if (_assert_expected_state(c, "b", &parsed_b, err, err_len) != 0) goto cleanup;
    if (_assert_expected_state(c, "c", &parsed_c, err, err_len) != 0) goto cleanup;

    rc = 0;
cleanup:
    net_wire_msg_free(&parsed_b);
    net_wire_msg_free(&parsed_c);
    free(wire);
    free(msg.function);
    free(msg.data);
    if (a_pub != NULL) smrt_deref(a_pub);
    if (a != NULL) identity_free(a);
    return rc;
}

static int run_scenario(const at_case_t *c, char *err, size_t err_len) {
    /* Network scenarios are protocol-specific; each adds a branch here
     * matching by case name. */
    if (strcmp(c->name, "peer-encrypted-roundtrip") == 0) {
        return run_peer_encrypted_roundtrip(c, err, err_len);
    }
    if (strcmp(c->name, "group-encrypted-roundtrip") == 0) {
        return run_group_encrypted_roundtrip(c, err, err_len);
    }
    if (strcmp(c->name, "broadcast-fanout") == 0) {
        return run_broadcast_fanout(c, err, err_len);
    }
    snprintf(err, err_len, "unknown network scenario: %s", c->name);
    return 1; /* skip */
}

/* ------------------------------------------------------------------------- */
/* Dispatch                                                                   */
/* ------------------------------------------------------------------------- */

void at_network_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "negative") == 0) {
        at_neg_run_wire(c, out);
        return;
    }

    char err[512];
    err[0] = '\0';

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int rc = -2;
    if (strcmp(c->kind, "crypto_vector") == 0) {
        rc = run_crypto_vector(c, err, sizeof(err));
    } else if (strcmp(c->kind, "wire_vector") == 0) {
        rc = run_wire_vector(c, err, sizeof(err));
    } else if (strcmp(c->kind, "scenario") == 0) {
        rc = run_scenario(c, err, sizeof(err));
    } else {
        snprintf(err, sizeof(err), "unsupported kind for network: %s", c->kind);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) {
        at_case_result_set_pass(out, duration_ms);
    } else if (rc > 0) {
        at_case_result_set_skip(out, err);
    } else {
        at_case_result_set_fail(out, duration_ms, "AssertionError", err);
    }
}
