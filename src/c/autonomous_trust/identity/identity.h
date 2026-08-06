/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef IDENTITY_H
#define IDENTITY_H

/** @addtogroup internal_identity
 *  @{
 */

#include <stdlib.h>
#include <stdbool.h>

#include <uuid/uuid.h>
#include <sodium.h>

#include "utilities/allocation.h"
#include "identity/identity.pb-c.h"

typedef struct identity_s identity_t;

typedef struct
{
    smrt_ptr_t;
    unsigned char private[crypto_sign_SECRETKEYBYTES];
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
} signature_t;

typedef struct
{
    smrt_ptr_t;
    unsigned char private[crypto_box_SECRETKEYBYTES];
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
} encryptor_t;

#define ADDR_LEN 32

#define NAME_LEN 128

#define UUID_LEN 16

#define UUID_STRING_LEN 36

/* Hard cap on a ZTA credential blob carried on the wire.  Real X.509 chains
 * and JWTs comfortably fit; a larger value almost certainly indicates a
 * hostile or corrupted peer and would let a remote cause an OOM. */
#define ZTA_CRED_MAX (64u * 1024u)

/* Domain separation for the operator-key binding (proto field 15). Versioned in
 * the tag itself: a v2 pre-image must not be verifiable as a v1 one. Keep this
 * string byte-identical to Python
 * `identity/operator_binding.py::OPERATOR_BINDING_TAG` — the two pre-image
 * builders are the one place this design can drift silently, which is why a
 * conformance vector pins the bytes. */
#define OPERATOR_BINDING_TAG "at-operator-binding-v1"
#define OPERATOR_BINDING_TAG_LEN (sizeof(OPERATOR_BINDING_TAG) - 1)
#define OPERATOR_BINDING_PREIMAGE_LEN \
    (OPERATOR_BINDING_TAG_LEN + UUID_LEN + crypto_sign_PUBLICKEYBYTES \
     + crypto_sign_PUBLICKEYBYTES)

/* Hard cap on a binding signature carried on the wire. An RSA-4096 PKCS#1
 * signature is 512 bytes and an ECDSA P-384 DER signature well under 128, so
 * 1 KiB fits every credential a PIV can hold; more is hostile or corrupt. Same
 * reasoning as ZTA_CRED_MAX, three orders of magnitude smaller. */
#define OPERATOR_BINDING_MAX 1024u

/* Domain separation for the CREDENTIAL->identity binding (ISSUES §1.5): which
 * node a ZTA credential authorizes, and the holder's proof of it. Distinct from
 * OPERATOR_BINDING_TAG, which binds the *operator's* ed25519 key to the node
 * (WHICH human); this one binds the *credential* to the node (WHO may present
 * it). A signature over one must never verify as the other, which is what the
 * differing tags buy. Versioned in the tag itself so a v2 pre-image can never be
 * verified as a v1 one.
 *
 * Keep byte-identical to Python `identity/zta_binding.py::ZTA_BINDING_TAG`. */
#define ZTA_BINDING_TAG "at-zta-binding-v1"
#define ZTA_BINDING_TAG_LEN (sizeof(ZTA_BINDING_TAG) - 1)
#define ZTA_FINGERPRINT_LEN 32
#define ZTA_BINDING_PREIMAGE_LEN \
    (ZTA_BINDING_TAG_LEN + UUID_LEN + crypto_sign_PUBLICKEYBYTES \
     + ZTA_FINGERPRINT_LEN)

/* Same cap and same reasoning as OPERATOR_BINDING_MAX: an RSA-4096 PKCS#1
 * signature is 512 bytes, ECDSA P-384 DER well under 128. */
#define ZTA_BINDING_MAX 1024u

/* Default URI SAN naming the node, for the CA-asserted binding.
 *
 * The `{uuid}` placeholder is Python's `str.format` spelling, and C uses it
 * verbatim rather than a printf `%s` BECAUSE THE POLICY FILE IS SHARED: one
 * `zta_policy.cfg.json` is read by both runtimes, so a C-only spelling would
 * render `at://{uuid}` literally against a Python-written config and silently
 * match nothing — a binding check that never fires, which is worse than one that
 * errors. C therefore substitutes the placeholder textually
 * (@ref zta_render_san_uri) instead of calling printf on peer-adjacent data. */
#define ZTA_SAN_URI_TEMPLATE "at://{uuid}"
#define ZTA_SAN_URI_PLACEHOLDER "{uuid}"

/* Upper bound on the credentials one identity may carry. Several arise ONLY at
 * a network gateway bridging agencies, one per agency bridged; an ordinary node
 * carries one. Small on purpose: each credential costs a chain walk against
 * every configured anchor at admission, so an unbounded list is a remote's lever
 * on our CPU. Excess entries are dropped at deserialization, not rejected —
 * a peer with more agencies than we will evaluate is odd, not hostile. */
#define ZTA_MAX_CREDENTIALS 4u

/* Upper bound on trust anchors, and on the anchor names a peer can prove. */
#define ZTA_MAX_ANCHORS 8u
#define ZTA_ANCHOR_NAME_LEN 64

/* One credential a peer presents, mirroring proto `ZtaCredential`. Declared
 * unconditionally (a typedef costs nothing) even though only an AT_ZTA build has
 * a field of this type, so a header consumer sees one shape either way. */
typedef struct
{
    uint8_t *der;          /**< raw credential, heap-allocated; NULL = empty slot */
    size_t der_len;
    uint8_t *binding;      /**< holder-asserted binding signature, heap; may be NULL */
    size_t binding_len;
    char issuer[64];       /**< issuer/anchor label, ADVISORY ONLY — never trusted */
} zta_credential_t;

typedef struct
{
    smrt_ptr_t;
    uuid_t uuid;
    char address[ADDR_LEN+1];
    char nickname[NAME_LEN+1];  /* Zooko ONLINE name (was fullname); the only
                                  name carried on the wire. */
    char petname[NAME_LEN+1];   /* Zooko LOCAL name -- never serialized. */
    signature_t signature;
    encryptor_t encryptor;
    /* Operator-attended signal (proto fields 12-13; parity with Python
       Identity). Kept OUTSIDE the AT_ZTA_ENABLED guard so the fields always
       exist and default false/0 even in non-ZTA builds (mirrors from_rank);
       only the operator-class VERIFICATION is ZTA-gated. Advertises whether a
       node has a human behind it (ethne guardian edge, D8/Q9). operator_bound
       is durable ("has a human guardian", authoritative only after the receiver
       verifies the operator credential); operator_attended_at is a live
       freshness stamp (epoch secs of the last verified operator session, 0 =
       none). NOT part of identity equality. */
    bool operator_bound;
    double operator_attested_at;
    /* WHICH human (proto fields 14-15), and STRICTLY OPT-IN. The two fields
       above say a human exists and when one was last present; neither names
       them. ethne's chartered node->guardian edge (D15) needs a guardian that
       can co-sign, so a node MAY advertise `operator_pubkey` (the guardian's
       ed25519 public key, one per OPERATOR and stable across the nodes that
       human guards) together with `operator_key_binding` — a signature by the
       operator's PIV private key over
       OPERATOR_BINDING_TAG || uuid || signature.public || operator_pubkey,
       verified against the operator credential's public key.

       ABSENT BY DEFAULT, AND ABSENCE COSTS NOTHING: AT never requires a
       guardian identity, so a node that declines stays anonymous, is admitted
       identically, and serializes byte-for-byte as it does today (both fields
       are emitted only when non-default). Requiring one is a consumer's rule.

       Outside the AT_ZTA_ENABLED guard, like operator_bound: the fields — and
       therefore the app-facing carrier's ABI — must not depend on a build flag.
       Only VERIFICATION is ZTA-gated.

       There is deliberately NO `operator_key_verified` flag. On a STORED PEER a
       non-empty `operator_pubkey` *means* our receiver verified the binding: an
       unverified or forged claim is zeroed at admission rather than kept beside a
       flag saying not to believe it. One representation, so there is nothing to
       disagree with — and with ZTA off nothing is ever verified, so no peer
       carries a key, which is the fail-safe `operator_bound` already takes.

       NOT part of identity equality. */
    uint8_t operator_pubkey[crypto_sign_PUBLICKEYBYTES];
    uint8_t *operator_key_binding;      /* heap-allocated, may be NULL */
    size_t operator_key_binding_len;
#ifdef AT_ZTA_ENABLED
    uint8_t zta_credential_hash[32];  /* SHA-256 of ZTA credential at admission */
    char zta_issuer[64];              /* Credential issuer identifier */
    uint8_t *zta_credential;          /* Raw credential bytes (heap-allocated) */
    size_t zta_credential_len;        /* Length of zta_credential */
    /* The full credential set (proto field 16), INCLUDING the primary above, so
       the primary normally appears twice and is deduplicated by fingerprint on
       receipt. Fields 6/7/8 stay the primary so a peer predating field 16
       interoperates unchanged — and they have nowhere to carry a binding, which
       is the other reason this exists. */
    zta_credential_t zta_credentials[ZTA_MAX_CREDENTIALS];
    size_t num_zta_credentials;
    /* Anchors this peer PROVED at admission, and the reason gateway function
       across an agency boundary can be enforced at all.

       LOCAL-ONLY AND NEVER SERIALIZED, for the same reason `_rank_adjustment` is
       not on the wire in Python: this is the observer's finding, not the peer's
       claim. A peer able to state which anchors it satisfies would be asserting
       exactly the authority it is supposed to earn. public_identity_to_json and
       sync_out therefore skip it, and a copy carries it because a copy is still
       our own view. */
    char zta_anchors[ZTA_MAX_ANCHORS][ZTA_ANCHOR_NAME_LEN];
    size_t num_zta_anchors;
#endif
} public_identity_t;

#ifdef __FRAMAC__
#include "algorithms/algorithms.h"
struct identity_s
{
    public_identity_t;
    int rank;
    block_impl_t block;
};
#endif

#define DEFAULT_MAX_PEERS 128  /* approx Dunbar number; compile-time array bound */
#define MAX_PEERS (peers_max_count())  /* runtime-configurable limit (<= DEFAULT_MAX_PEERS) */

/*@
  assigns \nothing;
  ensures \result > 0;
  ensures \result <= DEFAULT_MAX_PEERS;
*/
size_t peers_max_count(void);

/*@
  requires count > 0;
  requires count <= DEFAULT_MAX_PEERS;
  assigns \nothing;
*/
void peers_set_max_count(size_t count);

typedef struct
{
    unsigned char *msg;
    unsigned long long len;
} msg_str_t;


/*@
  requires uuid == \null || \valid(uuid);
  requires address != \null && \valid_read(address);
  requires nickname != \null && \valid_read(nickname);
  requires \valid(identity);
  assigns identity->uuid[0 .. UUID_LEN - 1],
          identity->address[0 .. ADDR_LEN],
          identity->nickname[0 .. NAME_LEN],
          identity->petname[0 .. NAME_LEN],
          identity->signature, identity->encryptor;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int identity_init(uuid_t *uuid, const char *address, const char *nickname,
                  const char *petname, identity_t *identity);

/*@
  requires uuid == \null || \valid(uuid);
  requires address != \null && \valid_read(address);
  requires nickname != \null && \valid_read(nickname);
  requires \valid(ident);
  allocates *ident;
  behavior success:
    ensures \result == 0;
    ensures *ident != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int identity_create(uuid_t *uuid, const char *address, const char *nickname,
                    const char *petname, identity_t **ident);

/**
 * @brief Produce a shareable public copy of an identity.
 *
 * Strips private key material and returns a newly-allocated
 * @ref public_identity_t suitable for sending to peers.
 *
 * @param[in]  ident     Full identity (source).
 * @param[out] pub_copy  Receives the allocated public-only copy.
 * @return 0 on success, @c EINVAL if @p ident is NULL, -1 on allocation error.
 */
/*@
  requires ident == \null || \valid(ident);
  requires \valid(pub_copy);
  allocates *pub_copy;
  behavior null_ident:
    assumes ident == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes ident != \null;
    ensures \result == 0 ==> *pub_copy != \null;
  behavior failure:
    assumes ident != \null;
    ensures \result != 0 ==> \result == -1;
  disjoint behaviors null_ident, success;
*/
int identity_publish(const identity_t *ident, public_identity_t **pub_copy);

/**
 * @brief Whether an operator public key slot holds no key.
 *
 * All-zero is the "no guardian advertised" sentinel: a valid ed25519 public key
 * is a curve point encoding and is never all-zero, and the opt-out path has to be
 * representable without a second flag that could disagree with the bytes.
 *
 * @param[in] pubkey  Key slot (@ref public_identity_t::operator_pubkey).
 * @return true when the slot is empty.
 */
/*@
  requires \valid_read(pubkey + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns \nothing;
*/
bool at_operator_pubkey_empty(const uint8_t pubkey[crypto_sign_PUBLICKEYBYTES]);

/**
 * @brief Build the pre-image an operator's PIV signs to bind @p operator_pubkey
 *        to @p ident.
 *
 *     OPERATOR_BINDING_TAG || uuid (16) || ident->signature.public (32)
 *                          || operator_pubkey (32)
 *
 * The node is named inside the signed bytes on purpose: without that, a
 * `(key, binding)` pair lifted from another node's announce would let any node
 * claim that human as its guardian, and a count of guardians would mean nothing.
 *
 * Must stay byte-identical to Python
 * `identity/operator_binding.py::operator_binding_preimage`; the pair is pinned
 * by a conformance vector because two hand-written builders are exactly the kind
 * of thing that drifts unnoticed.
 *
 * @param[in]  ident           Node whose uuid and signing key are bound.
 * @param[in]  operator_pubkey The guardian's ed25519 public key.
 * @param[out] out             Receives @ref OPERATOR_BINDING_PREIMAGE_LEN bytes.
 * @return 0, or EINVAL on a NULL argument.
 */
/*@
  requires \valid_read(ident);
  requires \valid_read(operator_pubkey + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  requires \valid(out + (0 .. OPERATOR_BINDING_PREIMAGE_LEN - 1));
  assigns out[0 .. OPERATOR_BINDING_PREIMAGE_LEN - 1];
*/
int operator_binding_preimage(const public_identity_t *ident,
                              const uint8_t operator_pubkey[crypto_sign_PUBLICKEYBYTES],
                              uint8_t out[OPERATOR_BINDING_PREIMAGE_LEN]);

/**
 * @brief Build the pre-image a ZTA credential's private key signs to authorize
 *        @p ident to present it (ISSUES §1.5).
 *
 *     ZTA_BINDING_TAG || uuid (16) || ident->signature.public (32)
 *                     || sha256(credential) (32)
 *
 * A chain-valid certificate says nothing about *who may present it*: one lifted
 * from another peer's clear-text announce chains to the agency CA exactly as well
 * under a different uuid. Naming the node inside the signed bytes is what closes
 * that — a harvested `(credential, binding)` pair will not verify under another
 * identity, and forging a fresh one needs the credential's private key.
 *
 * The fingerprint is computed over the bytes passed here, NEVER read from the
 * announcer-controlled @ref public_identity_t::zta_credential_hash; the whole
 * gate turns on that distinction.
 *
 * Must stay byte-identical to Python
 * `identity/zta_binding.py::zta_binding_preimage`, and is pinned by a conformance
 * vector for the same reason the operator pre-image is: two hand-written builders
 * drift silently.
 *
 * @param[in]  ident     Node whose uuid and signing key are bound.
 * @param[in]  cred      Raw credential bytes (DER).
 * @param[in]  cred_len  Length of @p cred; must be non-zero.
 * @param[out] out       Receives @ref ZTA_BINDING_PREIMAGE_LEN bytes.
 * @return 0, or EINVAL on a NULL argument or an empty credential — binding an
 *         empty credential would produce a signature nothing can verify, so the
 *         caller hears about it rather than getting silent garbage.
 */
/*@
  requires \valid_read(ident);
  requires cred == \null || \valid_read(cred + (0 .. cred_len - 1));
  requires \valid(out + (0 .. ZTA_BINDING_PREIMAGE_LEN - 1));
  assigns out[0 .. ZTA_BINDING_PREIMAGE_LEN - 1];
*/
int zta_binding_preimage(const public_identity_t *ident,
                         const uint8_t *cred, size_t cred_len,
                         uint8_t out[ZTA_BINDING_PREIMAGE_LEN]);

/**
 * @brief Release every heap buffer in @p ident's credential list and zero it.
 *
 * Not a full identity destructor — there is none, because peers live in a fixed
 * array for as long as they are known. This exists because the credential list
 * is the first *variable-length* thing on an identity, so the free-before-
 * overwrite discipline the singular `zta_credential` follows by hand would have
 * to be repeated per slot at every deserialization site. Safe on a zeroed or
 * already-cleared identity, and safe to call twice.
 */
void public_identity_zta_credentials_clear(public_identity_t *ident);

/**
 * @brief Append a credential to @p ident's list, deduplicating by fingerprint.
 *
 * Dedup is by SHA-256 over @p der, not by pointer or issuer label: the primary
 * credential legitimately arrives twice (once in fields 6-8, once in field 16),
 * and an issuer string is peer-controlled advisory text that must never decide
 * identity. On a duplicate, a binding is adopted when the existing entry has
 * none — the singular fields have nowhere to carry one, so the field-16 copy is
 * frequently the only bound one.
 *
 * @return 0 on success (including a dedup merge), EINVAL on a bad argument, or
 *         ENOSPC when the list is full — full is a bound being enforced, not a
 *         failure, and callers ignore it deliberately.
 */
int public_identity_add_zta_credential(public_identity_t *ident,
                                       const uint8_t *der, size_t der_len,
                                       const uint8_t *binding, size_t binding_len,
                                       const char *issuer);

/**
 * @brief Record that @p ident proved authority for trust anchor @p name.
 *
 * Deduplicated and capped at @ref ZTA_MAX_ANCHORS. Ignores NULL/empty names.
 */
void public_identity_add_zta_anchor(public_identity_t *ident, const char *name);

/**
 * @brief Whether @p ident proved authority for trust anchor @p name.
 */
bool public_identity_has_zta_anchor(const public_identity_t *ident,
                                    const char *name);

/**
 * @brief Produce a detached Ed25519 signature prepended to the message.
 *
 * Output buffer must have room for @p in->len + @c crypto_sign_BYTES.
 *
 * @param[in]  ident  Identity providing the private signing key.
 * @param[in]  in     Message to sign.
 * @param[out] out    Receives the signed message (signature prefix + payload).
 * @return 0 on success, non-zero on signing failure.
 */
/*@
  requires \valid(ident);
  requires \valid(in);
  requires in->msg != \null && \valid(in->msg + (0 .. in->len - 1));
  requires \valid(out);
  requires out->msg != \null &&
           \valid(out->msg + (0 .. in->len + crypto_sign_BYTES - 1));
  assigns out->msg[0 .. in->len + crypto_sign_BYTES - 1], out->len;
  ensures \result == 0 || \result != 0;
*/
int identity_sign(const identity_t *ident, const msg_str_t *in, msg_str_t *out);

/**
 * @brief Verify an Ed25519-signed message produced by identity_sign().
 *
 * On success writes the original payload (signature stripped) into @p out.
 *
 * @param[in]  ident  Public identity of the purported signer.
 * @param[in]  in     Signed message (signature prefix + payload).
 * @param[out] out    Receives the verified payload and its length.
 * @return 0 on successful verification, -1 on failure.
 */
/*@
  requires \valid(ident);
  requires \valid(in);
  requires in->msg != \null && \valid(in->msg + (0 .. in->len - 1));
  requires \valid(out);
  requires out->msg != \null && \valid(out->msg + (0 .. in->len - 1));
  assigns out->msg[0 .. in->len - 1], out->len;
  behavior verified:
    ensures \result == 0;
  behavior failed:
    ensures \result == -1;
  disjoint behaviors;
*/
int identity_verify(const public_identity_t *ident, const msg_str_t *in, msg_str_t *out);

/**
 * @brief Authenticated-encrypt a message to a peer using libsodium crypto_box.
 *
 * @param[in]  ident   Sender identity (holds private encryption key).
 * @param[in]  in      Plaintext payload.
 * @param[in]  whom    Recipient public identity (holds target public key).
 * @param[in]  nonce   Caller-supplied nonce of @c crypto_box_NONCEBYTES. The
 *                     caller is responsible for per-message uniqueness.
 * @param[out] cipher  Output buffer of at least @c in->len + @c crypto_box_MACBYTES.
 * @return 0 on success, -1 on failure.
 */
/*@
  requires \valid(ident);
  requires \valid(in);
  requires in->msg != \null && \valid(in->msg + (0 .. in->len - 1));
  requires \valid(whom);
  requires \valid_read(nonce + (0 .. crypto_box_NONCEBYTES - 1));
  requires \valid(cipher + (0 .. in->len + crypto_box_MACBYTES - 1));
  assigns cipher[0 .. in->len + crypto_box_MACBYTES - 1];
  ensures \result == 0 || \result == -1;
*/
int identity_encrypt(const identity_t *ident, const msg_str_t *in, const public_identity_t *whom, const unsigned char *nonce, unsigned char *cipher);

/**
 * @brief Decrypt and verify a crypto_box ciphertext from a peer.
 *
 * @param[in]  ident   Receiver identity (holds private key).
 * @param[in]  cipher  Input ciphertext (length must include the MAC).
 * @param[in]  whom    Sender public identity (holds source public key).
 * @param[in]  nonce   Same nonce used by the encryptor.
 * @param[out] out     Output buffer of at least @c cipher->len - @c crypto_box_MACBYTES.
 * @return 0 on success, -1 on authentication failure.
 */
/*@
  requires \valid(ident);
  requires \valid(cipher);
  requires cipher->msg != \null && \valid(cipher->msg + (0 .. cipher->len - 1));
  requires cipher->len >= crypto_box_MACBYTES;
  requires \valid(whom);
  requires \valid_read(nonce + (0 .. crypto_box_NONCEBYTES - 1));
  requires \valid(out + (0 .. cipher->len - crypto_box_MACBYTES - 1));
  assigns out[0 .. cipher->len - crypto_box_MACBYTES - 1];
  behavior success:
    ensures \result == 0;
  behavior auth_failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int identity_decrypt(const identity_t *ident, const msg_str_t *cipher, const public_identity_t *whom, const unsigned char *nonce, unsigned char *out);

/**
 * @brief Serialize a public identity to its protobuf wire representation.
 *
 * @param[in]  msg           Public identity to serialize.
 * @param[out] data_ptr      Receives a malloc'd buffer owned by the caller.
 * @param[out] data_len_ptr  Receives the length of @p data_ptr in bytes.
 * @return 0 on success, non-zero on serialization failure.
 */
int peer_to_proto(public_identity_t *msg, void **data_ptr, size_t *data_len_ptr);

/**
 * @brief Parse protobuf-encoded bytes into a caller-allocated public identity.
 *
 * @param[in]  data  Serialized bytes (typically from peer_to_proto()).
 * @param[in]  len   Length of @p data in bytes.
 * @param[out] peer  Caller-allocated public identity to populate.
 * @return 0 on success, non-zero on parse or validation failure.
 */
int proto_to_peer(uint8_t *data, size_t len, public_identity_t *peer);

/**
 * @brief Release an identity allocated by identity_create().
 *
 * Safe to call with NULL. Zeroes private-key material before freeing.
 *
 * @param[in] ident  Identity pointer, or NULL.
 */
/*@
  requires ident == \null || \valid(ident);
  behavior null_ident:
    assumes ident == \null;
    assigns \nothing;
  behavior valid_ident:
    assumes ident != \null;
    assigns ident->signature.private[0 .. crypto_sign_SECRETKEYBYTES - 1],
            ident->signature.public[0 .. crypto_sign_PUBLICKEYBYTES - 1],
            ident->encryptor.private[0 .. crypto_box_SECRETKEYBYTES - 1],
            ident->encryptor.public[0 .. crypto_box_PUBLICKEYBYTES - 1];
    frees ident;
  disjoint behaviors;
  complete behaviors;
*/
void identity_free(identity_t *ident);

/**
 * @brief Is @p verb one this protocol legitimately sends in PLAINTEXT?
 *
 * The point-to-point receive path attributes a frame by source address and then
 * decrypts it, so once a peer is in the peer table every frame from it takes the
 * decrypt branch. Verbs sent with encrypt=false by design cannot be decrypted,
 * and were therefore dropped AND annoy-tracked toward blacklisting. This
 * predicate bounds the plaintext fallback to named verbs, so a peer already in
 * the table cannot downgrade an arbitrary message to plaintext and have it
 * honored. Mirrors Python's identity.protocol.UNENCRYPTED_VERBS.
 *
 * Receive-side policy, so it covers every verb a PEER may legitimately send
 * unencrypted, including ones this implementation never sends itself.
 *
 * MAINTENANCE: adding an encrypt=false send REQUIRES adding its verb to the
 * table in id_proc.c, on both sides of the language boundary.
 *
 * @param verb Wire function selector; NULL is safe and returns false.
 */
bool identity_verb_is_unencrypted(const char *verb);


/** @} */ /* end of internal_identity */

#endif  // IDENTITY_H
