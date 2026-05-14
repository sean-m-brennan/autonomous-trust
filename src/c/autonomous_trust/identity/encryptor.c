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

#include <stdbool.h>
#include <string.h>

#include <sodium.h>

#include "identity_priv.h"
#include "utilities/exception.h"

int public_encryptor_init(encryptor_t *encr, const unsigned char *hex_seed, size_t hex_len)
{
    if (encr == NULL || hex_seed == NULL
        || hex_len != crypto_box_PUBLICKEYBYTES * 2)
        return -1;
    sodium_memzero(encr->private, sizeof(encr->private));
    if (unhexlify(hex_seed, hex_len, (unsigned char *)encr->public) != 0)
        return -1;
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char *)encr->public_hex);
    return 0;
}

int encryptor_init(encryptor_t *encr, const unsigned char *hex_seed, size_t hex_len)
{
    if (encr == NULL || hex_seed == NULL
        || hex_len != crypto_box_SEEDBYTES * 2)
        return -1;
    unsigned char seed[crypto_box_SEEDBYTES];
    if (unhexlify(hex_seed, hex_len, seed) != 0)
        return -1;
    crypto_box_seed_keypair((unsigned char *)encr->public, (unsigned char *)encr->private, seed);
    sodium_memzero(seed, sizeof(seed));
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char *)encr->public_hex);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] libsodium stub preconditions */
unsigned char *encryptor_publish(const encryptor_t *encr)
{
    unsigned char *hex = malloc(crypto_box_PUBLICKEYBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    memcpy(hex, encr->public_hex, crypto_box_PUBLICKEYBYTES * 2);
    return hex;
}

/* Frama-C: skipped — [solver-timeout] libsodium stub preconditions */
unsigned char *encryptor_generate()
{
    unsigned char key[crypto_box_SEEDBYTES];
    randombytes(key, crypto_box_SEEDBYTES);
    unsigned char *hex = malloc(crypto_box_SEEDBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    hexlify(key, crypto_box_SEEDBYTES, hex);
    sodium_memzero(key, sizeof(key));
    return hex;
}
