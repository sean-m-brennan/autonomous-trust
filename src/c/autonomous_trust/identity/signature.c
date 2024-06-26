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

#ifndef SIGNATURE_I
#define SIGNATURE_I

#include <stdbool.h>
#include <string.h>

#include <sodium.h>

#include "identity_priv.h"
#include "utilities/exception.h"

void public_signature_init(signature_t *sig, const unsigned char *hex_seed)
{
    memset(sig->private, 0, sizeof(sig->private));
    unhexlify(hex_seed, crypto_sign_PUBLICKEYBYTES * 2, (unsigned char *)sig->public);
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char *)sig->public_hex);
}

void signature_init(signature_t *sig, const unsigned char *hex_seed)
{
    unsigned char seed[crypto_sign_SEEDBYTES];
    unhexlify(hex_seed, crypto_sign_SEEDBYTES * 2, seed);
    crypto_sign_seed_keypair((unsigned char *)sig->public, (unsigned char *)sig->private, seed);
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char *)sig->public_hex);
}

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
    return hex;
}


#endif // SIGNATURE_I
