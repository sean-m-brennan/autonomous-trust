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


struct identity_s
{
    public_identity_t;
    int rank;
    char nickname[NAME_LEN];
    char petname[NAME_LEN];
    block_impl_t block;
};

int identity_to_json(const void *data_struct, json_t **obj_ptr);

int identity_from_json(const json_t *obj, void *data_struct);

int group_to_json(const void *data_struct, json_t **obj_ptr);

int group_from_json(const json_t *obj, void *data_struct);

void hexlify(const unsigned char *buf, size_t len, unsigned char *result);

int unhexlify(const unsigned char *buf, size_t len, unsigned char *result);

void public_signature_init(signature_t *sig, const unsigned char *hex_seed);

void signature_init(signature_t *sig, const unsigned char *hex_seed);

unsigned char *signature_publish(const signature_t *sig);

unsigned char *signature_generate();

void public_encryptor_init(encryptor_t *encr, const unsigned char *hex_seed);

void encryptor_init(encryptor_t *encr, const unsigned char *hex_seed);

unsigned char *encryptor_publish(const encryptor_t *encr);

unsigned char *encryptor_generate();


#endif  // IDENTITY_PRIV_H
