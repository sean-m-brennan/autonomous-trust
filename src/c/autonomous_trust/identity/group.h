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

#ifndef GROUP_H
#define GROUP_H

#include "identity.h"

typedef struct
{
    uuid_t uuid;
    char address[ADDR_LEN+1];
    encryptor_t encryptor;
} group_t;

/**
 * @brief
 *
 * @param group
 * @return int
 */
int group_init(uuid_t *uuid, char *address, group_t *group);

/**
 * @brief
 *
 * @param address
 * @param grp
 * @return int
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
void group_free(group_t *group);


#endif  // GROUP_H
