/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/**
 * artifact_proc_helpers.c — pure, dependency-free helper functions for artifact_proc.
 *
 * Kept in a separate translation unit so that unit tests can link only
 * artifact_proc_helpers.c without pulling in the full process/messaging
 * infrastructure that artifact_proc.c depends upon.
 */

#include <string.h>
#include <sodium.h>

#include "fleet/artifact_proc.h"

int artifact_calc_total_chunks(size_t total_size, size_t chunk_size)
{
    if (total_size == 0 || chunk_size == 0)
        return 0;
    return (int)((total_size + chunk_size - 1) / chunk_size);
}

/* Frama-C: skipped — [solver-timeout] memset/logging preconditions */
int artifact_download_state_init(download_state_t *state,
                                 const char *hash_hex,
                                 int total_chunks,
                                 const uint8_t *expected_hash,
                                 const char *version)
{
    if (!state || !hash_hex || !expected_hash || !version)
        return -1;

    memset(state, 0, sizeof(*state));
    strncpy(state->hash_hex, hash_hex, sizeof(state->hash_hex) - 1);
    state->hash_hex[sizeof(state->hash_hex) - 1] = '\0';
    state->total_chunks = total_chunks;
    state->received_chunks = 0;
    memcpy(state->expected_hash, expected_hash, UPDATE_HASH_LEN);
    strncpy(state->version, version, sizeof(state->version) - 1);
    state->version[sizeof(state->version) - 1] = '\0';

    return 0;
}

bool artifact_download_state_record(download_state_t *state)
{
    state->received_chunks++;
    return state->received_chunks >= state->total_chunks;
}

int artifact_verify_chunk_hash(const uint8_t *data, size_t len,
                               const uint8_t *chunk_hash)
{
    uint8_t computed[UPDATE_HASH_LEN];
    crypto_generichash_blake2b(computed, UPDATE_HASH_LEN, data, len, NULL, 0);
    if (sodium_memcmp(computed, chunk_hash, UPDATE_HASH_LEN) == 0)
        return 0;
    return -1;
}

/* Frama-C: skipped — [solver-timeout] base64 stub reasoning */
int artifact_encode_chunk(const uint8_t *data, size_t len,
                          char *b64_out, size_t b64_max)
{
    if (!b64_out)
        return -1;
    /* sodium_bin2base64 aborts (sodium_misuse) on an undersized buffer, so
     * check the required length up front and fail gracefully instead. */
    if (b64_max < sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL))
        return -1;
    sodium_bin2base64(b64_out, b64_max, data, len,
                      sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] base64 stub reasoning */
int artifact_decode_chunk(const char *b64, size_t expected_len,
                          uint8_t *out, size_t out_max, size_t *out_len)
{
    if (!b64 || !out)
        return -1;
    size_t bin_len = 0;
    /* Bounded by out_max: sodium_base642bin fails rather than overflowing if
     * the payload would exceed the buffer. */
    if (sodium_base642bin(out, out_max, b64, strlen(b64),
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return -1;
    /* Integrity gate: the advertised length must match what actually decoded,
     * so a bogus expected_len can never drive an over-read downstream. */
    if (bin_len != expected_len)
        return -1;
    if (out_len)
        *out_len = bin_len;
    return 0;
}
