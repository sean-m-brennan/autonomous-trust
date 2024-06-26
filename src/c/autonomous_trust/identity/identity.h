/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include "identity/identity.pb-c.h"

typedef struct identity_s identity_t;

typedef struct
{
    unsigned char private[crypto_sign_SECRETKEYBYTES];
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_sign_PUBLICKEYBYTES * 2];
} signature_t;

typedef struct
{
    unsigned char private[crypto_box_SECRETKEYBYTES];
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_box_PUBLICKEYBYTES * 2];
} encryptor_t;

#define ADDR_LEN 32

#define NAME_LEN 128

#define UUID_LEN 16

#define UUID_STRING_LEN 36

typedef struct
{
    uuid_t uuid;
    char address[ADDR_LEN+1];
    char fullname[NAME_LEN+1];
    signature_t signature;
    encryptor_t encryptor;
} public_identity_t;


#define MAX_PEERS 128 // approx Dunbar number

typedef struct
{
    unsigned char *msg;
    unsigned long long len;
} msg_str_t; // FIXME separate file


/** */
int identiry_init(uuid_t *uuid, char *address, char *fullname, identity_t *identity);

/***/
int identity_create(uuid_t *uuid, char *address, char *fullname, identity_t **ident);

/**
 * @brief
 *
 * @param ident
 * @param pub_copy
 * @return int
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
int identity_sign(const identity_t *ident, const msg_str_t *in, msg_str_t *out);

/**
 * @brief
 *
 * @param ident
 * @param in
 * @param out
 * @return int
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
void identity_free(identity_t *ident);

#endif  // IDENTITY_H
