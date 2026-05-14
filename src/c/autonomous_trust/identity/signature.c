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

int public_signature_init(signature_t *sig, const unsigned char *hex_seed, size_t hex_len)
{
    if (sig == NULL || hex_seed == NULL
        || hex_len != crypto_sign_PUBLICKEYBYTES * 2)
        return -1;
    sodium_memzero(sig->private, sizeof(sig->private));
    if (unhexlify(hex_seed, hex_len, (unsigned char *)sig->public) != 0)
        return -1;
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char *)sig->public_hex);
    return 0;
}

int signature_init(signature_t *sig, const unsigned char *hex_seed, size_t hex_len)
{
    if (sig == NULL || hex_seed == NULL
        || hex_len != crypto_sign_SEEDBYTES * 2)
        return -1;
    unsigned char seed[crypto_sign_SEEDBYTES];
    if (unhexlify(hex_seed, hex_len, seed) != 0)
        return -1;
    crypto_sign_seed_keypair((unsigned char *)sig->public, (unsigned char *)sig->private, seed);
    sodium_memzero(seed, sizeof(seed));
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char *)sig->public_hex);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] libsodium stub preconditions */
unsigned char *signature_publish(const signature_t *sig)
{
    unsigned char *hex = malloc(crypto_sign_PUBLICKEYBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    memcpy(hex, sig->public_hex, crypto_sign_PUBLICKEYBYTES * 2);
    return hex;
}

/* Frama-C: skipped — [solver-timeout] libsodium stub preconditions */
unsigned char *signature_generate()
{
    unsigned char key[crypto_sign_SEEDBYTES];
    randombytes(key, crypto_sign_SEEDBYTES);
    unsigned char *hex = malloc(crypto_sign_SEEDBYTES * 2);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    hexlify(key, crypto_sign_SEEDBYTES, hex);
    sodium_memzero(key, sizeof(key));
    return hex;
}
