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

#ifndef GROUP_H
#define GROUP_H

/** @addtogroup internal_identity
 *  @{
 */

#include "identity.h"
#include "structures/map.h"

/* Retired-key grace window and depth. Must match Python
 * Group.PREVIOUS_KEY_GRACE / PREVIOUS_KEY_MAX: a runtime that kept a retired
 * key alive longer than its twin would still be reading traffic the other had
 * already stopped accepting. */
#define GROUP_PREVIOUS_KEY_GRACE 60.0
#define GROUP_PREVIOUS_KEY_MAX   2

typedef struct
{
    smrt_ptr_t;
    uuid_t uuid;
    char address[ADDR_LEN+1];
    map_t address_map;  /* UUID string -> address string (mirrors Python _address_map) */
    encryptor_t encryptor;
    /* Group age (ISSUES.md §3.1-b): comparable creation epoch (seconds), or 0
     * if unknown. Merge size-tie tiebreaker — the OLDER group wins. Mirrors
     * Python Group._created. Carried on the wire by group_to_json. */
    double created;
    /* How many times this group's shared key has been rotated (ISSUES.md
     * 10.2). Mirrors Python Group.key_epoch and rides group_to_json as
     * "key_epoch". The key used to be permanent, so admitting a member also
     * handed it the ability to decrypt cohort traffic recorded BEFORE it
     * joined; admission now rotates, and this is what makes a rotation safe to
     * accept — a receiver adopts a new key only with a strictly HIGHER epoch,
     * so a captured older key cannot be replayed back over a newer one.
     * 0 = never rotated, which is every group minted before this existed. */
    int64_t key_epoch;
    /* Superseded keys, newest first, with the time each was retired. Kept only
     * so traffic already in flight when the key changed still decrypts: a
     * rotation is not synchronous across a cohort, and dropping every frame
     * from a member that has not yet processed the update would make rotation
     * cost more than it buys. Mirrors Python Group._previous_keys. */
    encryptor_t previous_keys[GROUP_PREVIOUS_KEY_MAX];
    double      previous_retired_at[GROUP_PREVIOUS_KEY_MAX];
    size_t      num_previous_keys;
} group_t;

/**
 * @brief Initialize a caller-allocated group_t with a fresh UUID (or the one
 *        supplied) and an empty member address map.
 *
 * @param[in]  uuid     Optional UUID to adopt; pass NULL to generate one.
 * @param[in]  address  NUL-terminated multicast or broadcast address for the
 *                      group. Copied into @p group.
 * @param[out] group    Caller-allocated group object to populate.
 * @return 0 on success, -1 on allocation or keygen failure.
 */
/*@
  requires uuid == \null || \valid(uuid);
  requires address != \null && \valid_read(address);
  requires \valid(group);
  assigns group->uuid[0 .. UUID_LEN - 1],
          group->address[0 .. ADDR_LEN],
          group->address_map, group->encryptor;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int group_init(uuid_t *uuid, char *address, group_t *group);

/**
 * @brief Allocate a new group_t (smart-pointer managed) and initialize it.
 *
 * Release with group_free() when done.
 *
 * @param[in]  uuid     Optional UUID to adopt; pass NULL to generate one.
 * @param[in]  address  NUL-terminated group address string.
 * @param[out] grp      Receives the newly allocated group pointer on success.
 * @return 0 on success, non-zero on allocation or initialization failure.
 */
/*@
  requires uuid == \null || \valid(uuid);
  requires address != \null && \valid_read(address);
  requires \valid(grp);
  allocates *grp;
  behavior success:
    ensures \result == 0;
    ensures *grp != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int group_create(uuid_t *uuid, char *address, group_t **grp);

/**
 * @brief Authenticated-encrypt a plaintext message to another group's public
 *        key using libsodium's crypto_box primitive.
 *
 * @param[in]  ident   Sender identity (holds the private key).
 * @param[in]  in      Plaintext message payload.
 * @param[in]  whom    Recipient group (holds the target public key).
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
int group_encrypt(const group_t *ident, const msg_str_t *in, const group_t *whom, const unsigned char *nonce, unsigned char *cipher);

/**
 * @brief Decrypt and verify a ciphertext produced by group_encrypt().
 *
 * @param[in]  ident   Receiver identity (holds the private key).
 * @param[in]  cipher  Input ciphertext (length must include the MAC).
 * @param[in]  whom    Sender group (holds the source public key).
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
int group_decrypt(const group_t *ident, const msg_str_t *cipher, const group_t *whom, const unsigned char *nonce, unsigned char *out);

/** Mint a fresh shared key, retiring the current one into the grace window
 *  (ISSUES.md 10.2). Returns the new epoch, or -1 if we do not hold the
 *  current private key. Mirrors Python Group.rotate_key. */
int64_t group_rotate_key(group_t *group);

/** Adopt @p other's key if it supersedes ours: same group, strictly higher
 *  epoch, and @p other must hold the private key. Returns whether it was
 *  adopted. Mirrors Python Group.accept_rotation. */
bool group_accept_rotation(group_t *group, const group_t *other);

/**
 * @brief Serialize a group into its protobuf wire representation.
 *
 * @param[in]  msg           Group to serialize.
 * @param[out] data_ptr      Receives a malloc'd buffer owned by the caller.
 * @param[out] data_len_ptr  Receives the length of @p data_ptr in bytes.
 * @return 0 on success, non-zero on serialization failure.
 */
int group_to_proto(group_t *msg, void **data_ptr, size_t *data_len_ptr);

/**
 * @brief Parse a protobuf-encoded group into a caller-allocated group_t.
 *
 * @param[in]  data   Serialized bytes (typically from group_to_proto()).
 * @param[in]  len    Length of @p data in bytes.
 * @param[out] group  Caller-allocated group to populate.
 * @return 0 on success, non-zero on parse or validation failure.
 */
int proto_to_group(uint8_t *data, size_t len, group_t *group);

/**
 * @brief Release a group allocated by group_create().
 *
 * Safe to call with NULL. Decrements the smart-pointer refcount and tears
 * down the internal address map on the last reference.
 *
 * @param[in] group  Group pointer, or NULL.
 */
/*@
  requires group == \null || \valid(group);
  requires group != \null ==> ((smrt_ptr_t *)group)->refs >= 1;
  requires group != \null ==> group->address_map.length <= group->address_map.capacity;
  behavior null_group:
    assumes group == \null;
    assigns \nothing;
  behavior valid_group:
    assumes group != \null;
    assigns group->address_map,
            ((smrt_ptr_t *)group)->alloc, ((smrt_ptr_t *)group)->refs;
    frees group;
  disjoint behaviors;
  complete behaviors;
*/
void group_free(group_t *group);

/**
 * @brief Add a member address to the group's address map.
 *        Handles collision by replacing existing UUID mapping to the same address.
 *
 * @param group
 * @param uuid_str UUID string key
 * @param address IP address value
 * @return int
 */
/*@
  requires group == \null || \valid(group);
  requires uuid_str == \null || \valid_read(uuid_str);
  requires address == \null || \valid_read(address);
  assigns group->address_map;
  behavior null_args:
    assumes group == \null || uuid_str == \null || address == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes group != \null && uuid_str != \null && address != \null;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int group_add_address(group_t *group, const char *uuid_str, const char *address);



/** @} */ /* end of internal_identity */

#endif  // GROUP_H
