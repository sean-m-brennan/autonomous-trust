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

#ifndef IDENTITY_PRIV_H
#define IDENTITY_PRIV_H

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "identity/identity.h"


#ifndef __FRAMAC__
struct identity_s
{
    public_identity_t;
    int rank;
    block_impl_t block;
};
#endif

int identity_to_json(const void *data_struct, json_t **obj_ptr);

int identity_from_json(const json_t *obj, void *data_struct);

/** Serialize a published-form identity (no private key material) to a
 *  fresh JSON object. Caller takes ownership of @p *obj_ptr. Used by
 *  id_proc.c when building the peer-bundle inside the ID_HISTORY wire
 *  payload (matches Python `p.publish()` in idprocess.py:507). */
int public_identity_to_json(const public_identity_t *p, json_t **obj_ptr);

/** Inverse of @ref public_identity_to_json. Writes into the
 *  caller-owned @p p (which is zeroed first). Returns 0 on success. */
int public_identity_from_json(const json_t *obj, public_identity_t *p);

int group_to_json(const void *data_struct, json_t **obj_ptr);

int group_from_json(const json_t *obj, void *data_struct);

/*@
  requires len > 0;
  requires \valid_read(buf + (0 .. len - 1));
  requires \valid(result + (0 .. len * 2));
  assigns result[0 .. len * 2];
  ensures result[len * 2] == '\0';
*/
void hexlify(const unsigned char *buf, size_t len, unsigned char *result);

/*@
  requires len > 0;
  requires len % 2 == 0;
  requires \valid_read(buf + (0 .. len - 1));
  requires \valid(result + (0 .. len / 2 - 1));
  assigns result[0 .. len / 2 - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int unhexlify(const unsigned char *buf, size_t len, unsigned char *result);

/*@
  requires \valid(sig);
  requires hex_seed == \null ||
           \valid_read(hex_seed + (0 .. hex_len - 1));
  ensures \result == 0 || \result == -1;
*/
int public_signature_init(signature_t *sig, const unsigned char *hex_seed, size_t hex_len);

/*@
  requires \valid(sig);
  requires hex_seed == \null ||
           \valid_read(hex_seed + (0 .. hex_len - 1));
  assigns sig->private[0 .. crypto_sign_SECRETKEYBYTES - 1],
          sig->public[0 .. crypto_sign_PUBLICKEYBYTES - 1],
          sig->public_hex[0 .. crypto_sign_PUBLICKEYBYTES * 2];
  ensures \result == 0 || \result == -1;
*/
int signature_init(signature_t *sig, const unsigned char *hex_seed, size_t hex_len);

/*@
  requires \valid(sig);
  allocates \result;
  assigns \nothing;
  ensures \result == \null ||
          \valid(\result + (0 .. crypto_sign_PUBLICKEYBYTES * 2 - 1));
*/
unsigned char *signature_publish(const signature_t *sig);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null ||
          \valid(\result + (0 .. crypto_sign_SEEDBYTES * 2 - 1));
*/
unsigned char *signature_generate(void);

/*@
  requires \valid(encr);
  requires hex_seed == \null ||
           \valid_read(hex_seed + (0 .. hex_len - 1));
  assigns encr->private[0 .. crypto_box_SECRETKEYBYTES - 1],
          encr->public[0 .. crypto_box_PUBLICKEYBYTES - 1],
          encr->public_hex[0 .. crypto_box_PUBLICKEYBYTES * 2];
  ensures \result == 0 || \result == -1;
*/
int public_encryptor_init(encryptor_t *encr, const unsigned char *hex_seed, size_t hex_len);

/*@
  requires \valid(encr);
  requires hex_seed == \null ||
           \valid_read(hex_seed + (0 .. hex_len - 1));
  assigns encr->private[0 .. crypto_box_SECRETKEYBYTES - 1],
          encr->public[0 .. crypto_box_PUBLICKEYBYTES - 1],
          encr->public_hex[0 .. crypto_box_PUBLICKEYBYTES * 2];
  ensures \result == 0 || \result == -1;
*/
int encryptor_init(encryptor_t *encr, const unsigned char *hex_seed, size_t hex_len);

/** Init from a RAW box private key hex (64 chars), reproducing the public
 *  key via crypto_scalarmult_base. Cross-runtime canonical for group-key
 *  transport (matches Python Encryptor(self.private.encode())). */
int encryptor_init_from_private(encryptor_t *encr, const unsigned char *hex_priv, size_t hex_len);

/** Serialize the RAW box private key as hex (64 chars + NUL); caller frees.
 *  NULL if the encryptor holds no private key. Mirrors Python serialize(). */
unsigned char *encryptor_serialize_private(const encryptor_t *encr);

/*@
  requires \valid(encr);
  allocates \result;
  assigns \nothing;
  ensures \result == \null ||
          \valid(\result + (0 .. crypto_box_PUBLICKEYBYTES * 2 - 1));
*/
unsigned char *encryptor_publish(const encryptor_t *encr);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null ||
          \valid(\result + (0 .. crypto_box_SEEDBYTES * 2 - 1));
*/
unsigned char *encryptor_generate(void);


#endif  // IDENTITY_PRIV_H
