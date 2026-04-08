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

#ifndef GROUP_H
#define GROUP_H

#include "identity.h"
#include "structures/map_priv.h"

typedef struct
{
    smrt_ptr_t;
    uuid_t uuid;
    char address[ADDR_LEN+1];
    map_t address_map;  /* UUID string -> address string (mirrors Python _address_map) */
    encryptor_t encryptor;
} group_t;

/**
 * @brief
 *
 * @param group
 * @return int
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
 * @brief
 *
 * @param address
 * @param grp
 * @return int
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
int group_encrypt(const group_t *ident, const msg_str_t *in, const group_t *whom, const unsigned char *nonce, unsigned char *cipher);

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
int group_decrypt(const group_t *ident, const msg_str_t *cipher, const group_t *whom, const unsigned char *nonce, unsigned char *out);

/**
 * @brief
 *
 * @param msg
 * @param data_ptr
 * @param data_len_ptr
 * @return int
 */
int group_to_proto(group_t *msg, void **data_ptr, size_t *data_len_ptr);

/**
 * @brief
 *
 * @param data
 * @param len
 * @param group
 * @return int
 */
int proto_to_group(uint8_t *data, size_t len, group_t *group);

/**
 * @brief
 *
 * @param group
 */
/*@
  requires group == \null || \valid(group);
  behavior null_group:
    assumes group == \null;
    assigns \nothing;
  behavior valid_group:
    assumes group != \null;
    assigns group->address_map;
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


#endif  // GROUP_H
