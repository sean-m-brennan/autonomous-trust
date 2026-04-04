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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <sodium.h>
#include <string.h>
#include <jansson.h>

#include "autonomous_trust/fleet/artifact_proc.h"

/* ---------------------------------------------------------------
 * test_chunk_size_calculation
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_size_calculation)
{
    ck_assert_int_eq(artifact_calc_total_chunks(3840, 960), 4);
    ck_assert_int_eq(artifact_calc_total_chunks(3841, 960), 5);
    ck_assert_int_eq(artifact_calc_total_chunks(1, 960), 1);
    ck_assert_int_eq(artifact_calc_total_chunks(0, 960), 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_download_state_tracking
 * --------------------------------------------------------------- */
DEFINE_TEST(test_download_state_tracking)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    download_state_t state;
    uint8_t hash[UPDATE_HASH_LEN];
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];

    randombytes_buf(hash, UPDATE_HASH_LEN);
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, UPDATE_HASH_LEN);

    ck_assert_int_eq(artifact_download_state_init(&state, hash_hex, 3, hash, "1.0.0"), 0);
    ck_assert_int_eq(state.received_chunks, 0);

    ck_assert(!artifact_download_state_record(&state));
    ck_assert_int_eq(state.received_chunks, 1);

    ck_assert(!artifact_download_state_record(&state));
    ck_assert_int_eq(state.received_chunks, 2);

    ck_assert(artifact_download_state_record(&state));
    ck_assert_int_eq(state.received_chunks, 3);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_per_chunk_hash_verification
 * --------------------------------------------------------------- */
DEFINE_TEST(test_per_chunk_hash_verification)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t data[128];
    randombytes_buf(data, sizeof(data));

    uint8_t hash[UPDATE_HASH_LEN];
    crypto_generichash_blake2b(hash, UPDATE_HASH_LEN, data, sizeof(data), NULL, 0);

    /* Valid data should verify */
    ck_assert_int_eq(artifact_verify_chunk_hash(data, sizeof(data), hash), 0);

    /* Tamper with data; should fail */
    data[0] ^= 0xFF;
    ck_assert(artifact_verify_chunk_hash(data, sizeof(data), hash) != 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_manifest_json_roundtrip
 * --------------------------------------------------------------- */
DEFINE_TEST(test_manifest_json_roundtrip)
{
    const char *hash_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    int total_chunks = 10;
    size_t total_size = 9600;
    size_t chunk_size = 960;
    const char *version = "2.1.0";

    json_t *manifest = json_object();
    ck_assert_ptr_nonnull(manifest);

    json_object_set_new(manifest, "hash", json_string(hash_hex));
    json_object_set_new(manifest, "total_chunks", json_integer(total_chunks));
    json_object_set_new(manifest, "total_size", json_integer((json_int_t)total_size));
    json_object_set_new(manifest, "chunk_size", json_integer((json_int_t)chunk_size));
    json_object_set_new(manifest, "version", json_string(version));

    /* Read back and verify */
    ck_assert_str_eq(json_string_value(json_object_get(manifest, "hash")), hash_hex);
    ck_assert_int_eq((int)json_integer_value(json_object_get(manifest, "total_chunks")), total_chunks);
    ck_assert_int_eq((int)json_integer_value(json_object_get(manifest, "total_size")), (int)total_size);
    ck_assert_int_eq((int)json_integer_value(json_object_get(manifest, "chunk_size")), (int)chunk_size);
    ck_assert_str_eq(json_string_value(json_object_get(manifest, "version")), version);

    json_decref(manifest);
}
END_TEST_DEFINITION()

RUN_TESTS(ArtifactProc,
    test_chunk_size_calculation,
    test_download_state_tracking,
    test_per_chunk_hash_verification,
    test_manifest_json_roundtrip
)
