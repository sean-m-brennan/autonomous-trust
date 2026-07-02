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
