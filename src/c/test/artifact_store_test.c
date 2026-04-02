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
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "autonomous_trust/fleet/artifact_store.h"

/* ---------- helpers ---------- */

static char test_dir[256];

static void setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/at_artifact_test_%d", (int)getpid());
    mkdir(test_dir, 0755);
}

static void teardown_test_dir(void)
{
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    int ret = system(cmd);
    (void)ret;
}

static void make_test_hash(uint8_t *hash_bin, char *hash_hex)
{
    randombytes_buf(hash_bin, 32);
    sodium_bin2hex(hash_hex, 65, hash_bin, 32);
}

/* ---------------------------------------------------------------
 * test_store_init
 * --------------------------------------------------------------- */
DEFINE_TEST(test_store_init)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();

    ck_assert_ret_ok(artifact_store_init(test_dir));

    char artifacts_path[512];
    snprintf(artifacts_path, sizeof(artifacts_path), "%s/artifacts", test_dir);
    struct stat st;
    ck_assert_int_eq(stat(artifacts_path, &st), 0);
    ck_assert(S_ISDIR(st.st_mode));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_save_and_read_chunk
 * --------------------------------------------------------------- */
DEFINE_TEST(test_save_and_read_chunk)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t hash_bin[32];
    char hash_hex[65];
    make_test_hash(hash_bin, hash_hex);

    uint8_t data[64];
    randombytes_buf(data, 64);

    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, data, 64));

    uint8_t readback[64];
    size_t out_len = 0;
    ck_assert_ret_ok(artifact_store_read_chunk(hash_hex, 0, readback, sizeof(readback), &out_len));
    ck_assert_int_eq((int)out_len, 64);
    ck_assert_mem_eq(data, readback, 64);

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_has_chunk
 * --------------------------------------------------------------- */
DEFINE_TEST(test_has_chunk)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t hash_bin[32];
    char hash_hex[65];
    make_test_hash(hash_bin, hash_hex);

    ck_assert(!artifact_store_has_chunk(hash_hex, 0));

    uint8_t data[32];
    randombytes_buf(data, 32);
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, data, 32));

    ck_assert(artifact_store_has_chunk(hash_hex, 0));
    ck_assert(!artifact_store_has_chunk(hash_hex, 1));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_chunk_count
 * --------------------------------------------------------------- */
DEFINE_TEST(test_chunk_count)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t hash_bin[32];
    char hash_hex[65];
    make_test_hash(hash_bin, hash_hex);

    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 0);

    uint8_t data[16];
    randombytes_buf(data, 16);

    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, data, 16));
    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 1);

    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 1, data, 16));
    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 2);

    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 2, data, 16));
    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 3);

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_manifest_roundtrip
 * --------------------------------------------------------------- */
DEFINE_TEST(test_manifest_roundtrip)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t hash_bin[32];
    char hash_hex[65];
    make_test_hash(hash_bin, hash_hex);

    artifact_manifest_t m;
    memset(&m, 0, sizeof(m));
    strncpy(m.hash_hex, hash_hex, sizeof(m.hash_hex) - 1);
    m.total_chunks = 42;
    m.total_size = 40320;
    m.chunk_size = 960;
    strncpy(m.version, "3.1.0", sizeof(m.version) - 1);

    ck_assert_ret_ok(artifact_store_save_manifest(&m));

    artifact_manifest_t loaded;
    ck_assert_ret_ok(artifact_store_load_manifest(hash_hex, &loaded));

    ck_assert_str_eq(loaded.hash_hex, hash_hex);
    ck_assert_int_eq(loaded.total_chunks, 42);
    ck_assert_uint_eq(loaded.total_size, 40320);
    ck_assert_uint_eq(loaded.chunk_size, 960);
    ck_assert_str_eq(loaded.version, "3.1.0");

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_verify_valid
 * --------------------------------------------------------------- */
DEFINE_TEST(test_verify_valid)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    /* Build a 64-byte artifact: 2 chunks of 32 bytes */
    uint8_t artifact[64];
    randombytes_buf(artifact, 64);

    /* Compute blake2b-256 hash of the full artifact */
    uint8_t expected_hash[32];
    crypto_generichash_blake2b(expected_hash, 32, artifact, 64, NULL, 0);

    char hash_hex[65];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), expected_hash, 32);

    /* Save manifest */
    artifact_manifest_t m;
    memset(&m, 0, sizeof(m));
    strncpy(m.hash_hex, hash_hex, sizeof(m.hash_hex) - 1);
    m.total_chunks = 2;
    m.total_size = 64;
    m.chunk_size = 32;
    strncpy(m.version, "1.0.0", sizeof(m.version) - 1);
    ck_assert_ret_ok(artifact_store_save_manifest(&m));

    /* Save 2 chunks */
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, artifact, 32));
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 1, artifact + 32, 32));

    /* Before verify, has should be false */
    ck_assert(!artifact_store_has(hash_hex));

    /* Verify should succeed */
    ck_assert_ret_ok(artifact_store_verify(hash_hex, expected_hash));

    /* After verify, has should be true */
    ck_assert(artifact_store_has(hash_hex));

    /* get_path should succeed */
    char path_buf[512];
    ck_assert_ret_ok(artifact_store_get_path(hash_hex, path_buf, sizeof(path_buf)));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_verify_invalid
 * --------------------------------------------------------------- */
DEFINE_TEST(test_verify_invalid)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t artifact[64];
    randombytes_buf(artifact, 64);

    /* Compute real hash */
    uint8_t real_hash[32];
    crypto_generichash_blake2b(real_hash, 32, artifact, 64, NULL, 0);

    char hash_hex[65];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), real_hash, 32);

    /* Save manifest + chunks under the real hash_hex */
    artifact_manifest_t m;
    memset(&m, 0, sizeof(m));
    strncpy(m.hash_hex, hash_hex, sizeof(m.hash_hex) - 1);
    m.total_chunks = 2;
    m.total_size = 64;
    m.chunk_size = 32;
    strncpy(m.version, "1.0.0", sizeof(m.version) - 1);
    ck_assert_ret_ok(artifact_store_save_manifest(&m));
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, artifact, 32));
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 1, artifact + 32, 32));

    /* Create a random wrong expected hash */
    uint8_t wrong_hash[32];
    randombytes_buf(wrong_hash, 32);

    /* Verify should fail */
    ck_assert_ret_nonzero(artifact_store_verify(hash_hex, wrong_hash));

    /* has should still be false */
    ck_assert(!artifact_store_has(hash_hex));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_delete
 * --------------------------------------------------------------- */
DEFINE_TEST(test_delete)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();
    ck_assert_ret_ok(artifact_store_init(test_dir));

    uint8_t hash_bin[32];
    char hash_hex[65];
    make_test_hash(hash_bin, hash_hex);

    /* Save manifest + 1 chunk */
    artifact_manifest_t m;
    memset(&m, 0, sizeof(m));
    strncpy(m.hash_hex, hash_hex, sizeof(m.hash_hex) - 1);
    m.total_chunks = 1;
    m.total_size = 32;
    m.chunk_size = 32;
    strncpy(m.version, "1.0.0", sizeof(m.version) - 1);
    ck_assert_ret_ok(artifact_store_save_manifest(&m));

    uint8_t data[32];
    randombytes_buf(data, 32);
    ck_assert_ret_ok(artifact_store_save_chunk(hash_hex, 0, data, 32));

    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 1);

    /* Delete */
    ck_assert_ret_ok(artifact_store_delete(hash_hex));

    /* Verify everything is gone */
    ck_assert_int_eq(artifact_store_chunk_count(hash_hex), 0);
    ck_assert(!artifact_store_has_chunk(hash_hex, 0));

    artifact_manifest_t loaded;
    ck_assert_ret_nonzero(artifact_store_load_manifest(hash_hex, &loaded));

    teardown_test_dir();
}
END_TEST_DEFINITION()

RUN_TESTS(ArtifactStore,
    test_store_init,
    test_save_and_read_chunk,
    test_has_chunk,
    test_chunk_count,
    test_manifest_roundtrip,
    test_verify_valid,
    test_verify_invalid,
    test_delete
)
