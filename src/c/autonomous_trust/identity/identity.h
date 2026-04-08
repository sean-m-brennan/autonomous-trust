/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <stdlib.h>

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

typedef struct
{
    smrt_ptr_t;
    uuid_t uuid;
    char address[ADDR_LEN+1];
    char fullname[NAME_LEN+1];
    char nickname[NAME_LEN+1];
    char petname[NAME_LEN+1];
    signature_t signature;
    encryptor_t encryptor;
#ifdef AT_ZTA_ENABLED
    uint8_t zta_credential_hash[32];  /* SHA-256 of ZTA credential at admission */
    char zta_issuer[64];              /* Credential issuer identifier */
    uint8_t *zta_credential;          /* Raw credential bytes (heap-allocated) */
    size_t zta_credential_len;        /* Length of zta_credential */
#endif
} public_identity_t;


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
  requires fullname != \null && \valid_read(fullname);
  requires \valid(identity);
  assigns identity->uuid[0 .. UUID_LEN - 1],
          identity->address[0 .. ADDR_LEN],
          identity->fullname[0 .. NAME_LEN],
          identity->nickname[0 .. NAME_LEN],
          identity->petname[0 .. NAME_LEN],
          identity->signature, identity->encryptor;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int identity_init(uuid_t *uuid, char *address, char *fullname,
                  char *nickname, char *petname, identity_t *identity);

/*@
  requires uuid == \null || \valid(uuid);
  requires address != \null && \valid_read(address);
  requires fullname != \null && \valid_read(fullname);
  requires \valid(ident);
  allocates *ident;
  behavior success:
    ensures \result == 0;
    ensures *ident != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int identity_create(uuid_t *uuid, char *address, char *fullname,
                    char *nickname, char *petname, identity_t **ident);

/**
 * @brief
 *
 * @param ident
 * @param pub_copy
 * @return int
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
 * @brief
 *
 * @param ident
 * @param in
 * @param out
 * @return int
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
 * @brief
 *
 * @param ident
 * @param in
 * @param out
 * @return int
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
 * @brief
 *
 * @param ident
 * @param in
 * @param whom
 * @param nonce
 * @param cipher
 * @return int
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
 * @brief
 *
 * @param ident
 * @param cipher
 * @param whom
 * @param nonce
 * @param out
 * @return int
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
 * @brief
 *
 * @param msg
 * @param data_ptr
 * @param data_len_ptr
 * @return int
 */
int peer_to_proto(public_identity_t *msg, void **data_ptr, size_t *data_len_ptr);

/**
 * @brief
 *
 * @param data
 * @param len
 * @param peer
 * @return int
 */
int proto_to_peer(uint8_t *data, size_t len, public_identity_t *peer);

/**
 * @brief
 *
 * @param ident
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

#endif  // IDENTITY_H
