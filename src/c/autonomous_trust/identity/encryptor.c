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

/* Init an encryptor from a RAW box private key (the Curve25519 secret
 * scalar), NOT a libsodium seed. This is the cross-runtime canonical form:
 * Python's Encryptor serializes `self.private.encode()` (the raw 32-byte
 * private key), and `crypto_scalarmult_base(pk, sk)` reproduces the same
 * public key PyNaCl derives from those bytes (verified). Distinct from
 * encryptor_init(), which hashes a seed via crypto_box_seed_keypair and is
 * used for seed-based identity provisioning. Used for group-key transport. */
int encryptor_init_from_private(encryptor_t *encr, const unsigned char *hex_priv, size_t hex_len)
{
    if (encr == NULL || hex_priv == NULL
        || hex_len != crypto_box_SECRETKEYBYTES * 2)
        return -1;
    if (unhexlify(hex_priv, hex_len, (unsigned char *)encr->private) != 0)
        return -1;
    if (crypto_scalarmult_base((unsigned char *)encr->public,
                               (const unsigned char *)encr->private) != 0)
        return -1;
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char *)encr->public_hex);
    return 0;
}

/* Serialize the RAW box private key as hex (64 chars + NUL). Mirrors
 * Python Encryptor.serialize(). Caller frees. Returns NULL if the
 * encryptor holds no private key (all-zero) — callers must publish the
 * public key instead in that case. */
unsigned char *encryptor_serialize_private(const encryptor_t *encr)
{
    if (encr == NULL || sodium_is_zero(encr->private, crypto_box_SECRETKEYBYTES))
        return NULL;
    unsigned char *hex = malloc(crypto_box_SECRETKEYBYTES * 2 + 1);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    hexlify(encr->private, crypto_box_SECRETKEYBYTES, hex);
    return hex;
}

/* Frama-C: skipped — [solver-timeout] libsodium stub preconditions */
unsigned char *encryptor_publish(const encryptor_t *encr)
{
    /* public_hex is NUL-terminated ([... * 2 + 1]); copy the terminator too
     * so callers treating the result as a C string (json_string in
     * public_identity_to_json) read exactly the 64 hex chars instead of
     * over-running into the heap. Length-passing callers are unaffected. */
    unsigned char *hex = malloc(crypto_box_PUBLICKEYBYTES * 2 + 1);
    if (hex == NULL)
    {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    memcpy(hex, encr->public_hex, crypto_box_PUBLICKEYBYTES * 2 + 1);
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
