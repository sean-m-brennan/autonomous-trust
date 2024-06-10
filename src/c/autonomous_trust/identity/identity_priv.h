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

#ifndef IDENTITY_PRIV_H
#define IDENTITY_PRIV_H

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "identity/identity.h"

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

struct identity_s
{
    uuid_t uuid;
    int rank;
    unsigned char *address;
    char *fullname;
    char *nickname;
    char *petname;
    signature_t signature;
    encryptor_t encryptor;
    bool public_only;
    block_impl_t block;
};

int identity_to_json(const void *data_struct, json_t **obj_ptr);

int identity_from_json(const json_t *obj, void *data_struct);

#endif // IDENTITY_PRIV_H
