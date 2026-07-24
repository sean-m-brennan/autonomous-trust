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
#ifdef AT_ZTA_ENABLED
    uint8_t zta_credential_hash[32];  /* SHA-256 of ZTA credential at admission */
    char zta_issuer[64];              /* Credential issuer identifier */
    uint8_t *zta_credential;          /* Raw credential bytes (heap-allocated) */
    size_t zta_credential_len;        /* Length of zta_credential */
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


/** @} */ /* end of internal_identity */

#endif  // IDENTITY_H
