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

/* ---------------------------------------------------------------
 * test_chunk_base64_roundtrip (§7)
 * Encode a chunk payload and decode it back through the production
 * helpers; the bytes must survive intact for representative sizes.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_base64_roundtrip)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    /* Full-size chunk covering all 256 byte values (catches any
     * alphabet/padding mishandling). */
    uint8_t orig[ARTIFACT_CHUNK_SIZE];
    for (size_t i = 0; i < sizeof(orig); i++)
        orig[i] = (uint8_t)(i & 0xFF);

    /* Full, a partial length not divisible by 3 (exercises padding), and 1. */
    size_t sizes[] = { ARTIFACT_CHUNK_SIZE, 1000, 1 };
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        size_t len = sizes[s];
        char b64[sodium_base64_ENCODED_LEN(ARTIFACT_CHUNK_SIZE,
                                           sodium_base64_VARIANT_ORIGINAL)];
        ck_assert_int_eq(artifact_encode_chunk(orig, len, b64, sizeof(b64)), 0);

        uint8_t out[ARTIFACT_CHUNK_SIZE];
        size_t out_len = 0;
        ck_assert_int_eq(artifact_decode_chunk(b64, len, out, sizeof(out), &out_len), 0);
        ck_assert_uint_eq(out_len, len);
        ck_assert_mem_eq(out, orig, len);
    }
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_chunk_decode_rejects_length_mismatch (§7 over-read guard)
 * A decoded payload whose length disagrees with the advertised
 * expected_len must be rejected, so a bogus data_len can never drive
 * an over-read downstream.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_decode_rejects_length_mismatch)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t orig[256];
    randombytes_buf(orig, sizeof(orig));

    char b64[sodium_base64_ENCODED_LEN(256, sodium_base64_VARIANT_ORIGINAL)];
    ck_assert_int_eq(artifact_encode_chunk(orig, sizeof(orig), b64, sizeof(b64)), 0);

    uint8_t out[256];
    size_t out_len = 0;

    /* Honest length decodes. */
    ck_assert_int_eq(artifact_decode_chunk(b64, 256, out, sizeof(out), &out_len), 0);
    ck_assert_uint_eq(out_len, 256);

    /* Over/under/zero advertised lengths are all rejected. */
    ck_assert(artifact_decode_chunk(b64, 257, out, sizeof(out), &out_len) != 0);
    ck_assert(artifact_decode_chunk(b64, 255, out, sizeof(out), &out_len) != 0);
    ck_assert(artifact_decode_chunk(b64, 0,   out, sizeof(out), &out_len) != 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_chunk_decode_bounded_by_capacity (§7)
 * Decoding into a buffer smaller than the payload must fail rather
 * than overflow.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_decode_bounded_by_capacity)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t orig[200];
    randombytes_buf(orig, sizeof(orig));

    char b64[sodium_base64_ENCODED_LEN(200, sodium_base64_VARIANT_ORIGINAL)];
    ck_assert_int_eq(artifact_encode_chunk(orig, sizeof(orig), b64, sizeof(b64)), 0);

    uint8_t small[100];
    size_t out_len = 0;
    ck_assert(artifact_decode_chunk(b64, 200, small, sizeof(small), &out_len) != 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_chunk_decode_rejects_invalid_base64 (§7)
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_decode_rejects_invalid_base64)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    uint8_t out[64];
    size_t out_len = 0;
    /* '!' and '-' are outside the standard base64 alphabet. */
    ck_assert(artifact_decode_chunk("!!!not-base64!!!", 8, out, sizeof(out), &out_len) != 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_chunk_encode_rejects_small_buffer (§7)
 * An undersized output buffer must yield a graceful -1, not a
 * libsodium abort.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_encode_rejects_small_buffer)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    uint8_t orig[100];
    randombytes_buf(orig, sizeof(orig));
    char tiny[8];
    ck_assert(artifact_encode_chunk(orig, sizeof(orig), tiny, sizeof(tiny)) != 0);
}
END_TEST_DEFINITION()

RUN_TESTS(ArtifactProc,
    test_chunk_size_calculation,
    test_download_state_tracking,
    test_per_chunk_hash_verification,
    test_manifest_json_roundtrip,
    test_chunk_base64_roundtrip,
    test_chunk_decode_rejects_length_mismatch,
    test_chunk_decode_bounded_by_capacity,
    test_chunk_decode_rejects_invalid_base64,
    test_chunk_encode_rejects_small_buffer
)
