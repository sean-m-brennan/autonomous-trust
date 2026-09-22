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

/** @file The durable block store, and the exact bytes both runtimes write.
 *
 *  Phase 4 P4.1. Until then no social state was persisted at all, and a block
 *  could live with that only for as long as a block did nothing. Now that it
 *  gates every inbound path, a restart silently restoring a blocked peer's
 *  reach is a moderation failure, not a cache miss.
 *
 *  WHY A GOLDEN STRING RATHER THAN A ROUND TRIP ALONE. A round trip proves the
 *  file can be re-read by the thing that wrote it, which is the weakest useful
 *  claim: two runtimes can each round-trip their own incompatible format
 *  forever. The document is a CROSS-LANGUAGE contract, so the bytes are pinned
 *  here and the identical bytes are pinned in
 *  tests/a_unit/test_social_store.py. If either side's serializer drifts —
 *  indentation, key order, number formatting, a field appearing only when set
 *  — exactly one of the two fails, and it names which.
 *
 *  WHY NOT A CONFORMANCE CASE. A live block stamps `time(NULL)`, so two
 *  runtimes blocking the same peer legitimately write different `at` values;
 *  comparing live files would be comparing clocks. What must agree is the
 *  SERIALIZATION of a given block set, which is what this fixes.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "identity/social_store.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/allocation.h"

/* Two peers, deliberately NOT in sorted order here: the writer must sort them,
 * and inserting them already-sorted would let an unsorted writer pass. The
 * timestamps differ in shape too — one integral, one fractional — because
 * number formatting is exactly the kind of thing that drifts silently between
 * a C and a Python serializer. */
#define UUID_A "0a000000-0000-4000-8000-00000000000a"
#define UUID_B "0c000000-0000-4000-8000-00000000000b"
#define AT_A 1750000001.5
#define AT_B 1750000000.0

/* Byte for byte what Python's json.dump(..., indent=2, sort_keys=True) writes
 * for the same set. No trailing newline on either side. */
static const char GOLDEN[] =
    "{\n"
    "  \"blocks\": {\n"
    "    \"" UUID_A "\": {\n"
    "      \"at\": 1750000001.5,\n"
    "      \"reason\": \"\"\n"
    "    },\n"
    "    \"" UUID_B "\": {\n"
    "      \"at\": 1750000000.0,\n"
    "      \"reason\": \"\"\n"
    "    }\n"
    "  },\n"
    "  \"version\": 1\n"
    "}";

static char g_dir[256];

static void _mkdir_tmp(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/at-social-store-%d", (int)getpid());
    mkdir(g_dir, 0755);
}

static void _rm_tmp(void)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, AT_SOCIAL_FILENAME);
    unlink(path);
    rmdir(g_dir);
}

static void _seed(map_t *blocks)
{
    ck_assert_ret_ok(map_init(blocks));
    /* B first, so a writer that preserved insertion order would emit them
     * in the wrong order and fail the golden comparison. */
    map_set(blocks, (map_key_t)UUID_B, floating_pt_dbl_data(AT_B));
    map_set(blocks, (map_key_t)UUID_A, floating_pt_dbl_data(AT_A));
}

static char *_slurp(size_t *len_out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, AT_SOCIAL_FILENAME);
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (len_out != NULL) *len_out = got;
    return buf;
}

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_the_bytes_are_what_python_writes)
{
    _mkdir_tmp();
    map_t blocks;
    _seed(&blocks);
    ck_assert_int_eq(social_store_save(&blocks, g_dir), 0);

    size_t len = 0;
    char *got = _slurp(&len);
    ck_assert_ptr_nonnull(got);
    ck_assert_str_eq(got, GOLDEN);
    ck_assert_int_eq((int)len, (int)strlen(GOLDEN));
    free(got);
    _rm_tmp();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_saved_set_loads_back_unchanged)
{
    _mkdir_tmp();
    map_t blocks;
    _seed(&blocks);
    ck_assert_int_eq(social_store_save(&blocks, g_dir), 0);

    map_t back;
    ck_assert_ret_ok(map_init(&back));
    ck_assert_int_eq(social_store_load(g_dir, &back), 0);
    ck_assert_int_eq((int)map_size(&back), 2);

    data_t *d = NULL;
    double at = 0.0;
    ck_assert_int_eq(map_get(&back, (map_key_t)UUID_A, &d), 0);
    ck_assert_ptr_nonnull(d);
    ck_assert_int_eq(data_floating_pt_dbl(d, &at), 0);
    ck_assert_double_eq_tol(at, AT_A, 1e-9);
    _rm_tmp();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_file_is_an_empty_store_not_an_error)
{
    /* The ordinary first boot. Returning an error here would make every fresh
     * node log a failure it cannot act on. */
    _mkdir_tmp();
    map_t back;
    ck_assert_ret_ok(map_init(&back));
    ck_assert_int_eq(social_store_load(g_dir, &back), 0);
    ck_assert_int_eq((int)map_size(&back), 0);
    _rm_tmp();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_corrupt_file_yields_no_blocks_rather_than_some)
{
    /* Fails toward "nobody is blocked", never toward an arbitrary subset. A
     * partial restore is the worst outcome: the operator would see some of
     * their blocks working and reasonably assume the rest were too. */
    _mkdir_tmp();
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, AT_SOCIAL_FILENAME);
    FILE *f = fopen(path, "wb");
    ck_assert_ptr_nonnull(f);
    fputs("{\"version\": 1, \"blocks\": \"not an object\"}", f);
    fclose(f);

    map_t back;
    ck_assert_ret_ok(map_init(&back));
    /* Pre-seed, so an implementation that merely failed to overwrite would be
     * caught: the store must be REPLACED, not left holding stale entries. */
    map_set(&back, (map_key_t)UUID_A, floating_pt_dbl_data(AT_A));
    ck_assert_int_eq(social_store_load(g_dir, &back), -1);
    ck_assert_int_eq((int)map_size(&back), 0);
    _rm_tmp();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unblock_is_a_delete_so_the_file_shrinks)
{
    _mkdir_tmp();
    map_t blocks;
    _seed(&blocks);
    ck_assert_int_eq(social_store_save(&blocks, g_dir), 0);
    map_remove(&blocks, (map_key_t)UUID_A);
    ck_assert_int_eq(social_store_save(&blocks, g_dir), 0);

    map_t back;
    ck_assert_ret_ok(map_init(&back));
    ck_assert_int_eq(social_store_load(g_dir, &back), 0);
    ck_assert_int_eq((int)map_size(&back), 1);
    data_t *d = NULL;
    /* Gone, not flagged: "blocked" IS the presence of the key, so nothing can
     * disagree with it and re-blocking is idempotent. */
    ck_assert(map_get(&back, (map_key_t)UUID_A, &d) != 0 || d == NULL);
    ck_assert_int_eq(map_get(&back, (map_key_t)UUID_B, &d), 0);
    _rm_tmp();
}
END_TEST_DEFINITION()

RUN_TESTS(SocialStore,
          test_the_bytes_are_what_python_writes,
          test_a_saved_set_loads_back_unchanged,
          test_no_file_is_an_empty_store_not_an_error,
          test_a_corrupt_file_yields_no_blocks_rather_than_some,
          test_an_unblock_is_a_delete_so_the_file_shrinks)
