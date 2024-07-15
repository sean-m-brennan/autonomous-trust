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

#ifndef ENCRYPTOR_I
#define ENCRYPTOR_I

#include <stdbool.h>
#include <string.h>

#include <sodium.h>

#include "identity_priv.h"
#include "utilities/exception.h"

void public_encryptor_init(encryptor_t *encr, const unsigned char *hex_seed)
{
    memset(encr->private, 0, sizeof(encr->private));
    unhexlify(hex_seed, crypto_box_PUBLICKEYBYTES * 2, (unsigned char *)encr->public);
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char *)encr->public_hex);
}

void encryptor_init(encryptor_t *encr, const unsigned char *hex_seed)
{
    unsigned char seed[crypto_box_SEEDBYTES];
    unhexlify(hex_seed, crypto_box_SEEDBYTES * 2, seed);
    crypto_box_seed_keypair((unsigned char *)encr->public, (unsigned char *)encr->private, seed);
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char *)encr->public_hex);
}

unsigned char *encryptor_publish(const encryptor_t *encr)
{
    unsigned char *hex = smrt_create(crypto_box_PUBLICKEYBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    memcpy(hex, encr->public_hex, crypto_box_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *encryptor_generate()
{
    unsigned char key[crypto_box_SEEDBYTES];
    randombytes(key, crypto_box_SEEDBYTES);
    unsigned char *hex = smrt_create(crypto_box_SEEDBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    hexlify(key, crypto_box_SEEDBYTES, hex);
    return hex;
}

#endif // ENCRYPTOR_I
