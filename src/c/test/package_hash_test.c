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
 * @file package_hash_test.c
 * @brief The package-hash gate (identity/package_hash.h): this runtime's
 *        tagged hash, reading a Python peer's bytes-wrapped digest, and the
 *        allowlist decision. Mirrors tests/a_unit/test_package_hash.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>

#include "identity/package_hash.h"

/* What a Python node puts in slot 0 for the digest blake2b(b'stele'):
 * to_json_string wraps bytes as base64. Pinned from the Python runtime. */
static const char PY_SLOT[] =
    "{\"__type__\": \"bytes\", \"__value__\": "
    "\"OGMxYjU1NzlmYTBkZTg1ZTFhMmU4Yzg3YTI5MTk5NTgxMDNlMDIyZWZkMzU3NjEyZTNkYmFjMjUzMDJkNzk1Zg==\"}";
static const char PY_TAGGED[] =
    "py:8c1b5579fa0de85e1a2e8c87a2919958103e022efd357612e3dbac25302d795f";

DEFINE_TEST(test_own_hash_is_tagged_and_stable)
{
    const char *h = at_package_hash();
    ck_assert_int_eq((int)strlen(h), AT_PACKAGE_HASH_LEN);
    ck_assert(strncmp(h, "c:", 2) == 0);
    ck_assert_str_eq(h, at_package_hash());
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_python_slot_reads_as_py_tagged)
{
    char out[160];
    json_t *slot = json_loads(PY_SLOT, 0, NULL);
    ck_assert_ptr_nonnull(slot);
    at_package_hash_of_json(slot, out, sizeof(out));
    ck_assert_str_eq(out, PY_TAGGED);
    json_decref(slot);

    json_t *str = json_string("c:abcd");
    at_package_hash_of_json(str, out, sizeof(out));
    ck_assert_str_eq(out, "c:abcd");
    json_decref(str);

    /* Not a digest: bytes that are not hex, or another shape altogether. */
    json_t *junk = json_pack("{s:s, s:s}", "__type__", "bytes",
                             "__value__", "aGVsbG8gd29ybGQ=");
    at_package_hash_of_json(junk, out, sizeof(out));
    ck_assert_str_eq(out, "");
    json_decref(junk);
    json_t *arr = json_array();
    at_package_hash_of_json(arr, out, sizeof(out));
    ck_assert_str_eq(out, "");
    json_decref(arr);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_allowlist_decides_when_present)
{
    char root[] = "/tmp/at-pkghash-XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    char dir[300], path[400];
    snprintf(dir, sizeof(dir), "%s/etc", root);
    mkdir(dir, 0755);
    snprintf(dir, sizeof(dir), "%s/etc/at", root);
    mkdir(dir, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", root, 1);
    char why[96];

    /* No file: the gate is off, whatever is presented. */
    ck_assert(at_package_hash_admissible("", why, sizeof(why)));
    ck_assert(at_package_hash_admissible("c:feed", why, sizeof(why)));

    snprintf(path, sizeof(path), "%s/%s", dir, AT_PACKAGE_HASHES_FILE);
    json_t *doc = json_pack("{s:[s, s]}", "accepted", at_package_hash(), PY_TAGGED);
    ck_assert_int_eq(json_dump_file(doc, path, 0), 0);
    ck_assert(at_package_hash_listed(doc, PY_TAGGED));
    json_decref(doc);

    ck_assert(at_package_hash_admissible(at_package_hash(), why, sizeof(why)));
    ck_assert(at_package_hash_admissible(PY_TAGGED, why, sizeof(why)));
    why[0] = '\0';
    ck_assert(!at_package_hash_admissible("c:0000", why, sizeof(why)));
    ck_assert(strstr(why, "not on the allowlist") != NULL);
    ck_assert(!at_package_hash_admissible("", why, sizeof(why)));
    /* A prefix of a listed hash is not the hash. */
    char prefix[AT_PACKAGE_HASH_LEN];
    snprintf(prefix, sizeof(prefix), "%s", at_package_hash());
    ck_assert(!at_package_hash_admissible(prefix, why, sizeof(why)));

    unlink(path);
    rmdir(dir);
    snprintf(dir, sizeof(dir), "%s/etc", root);
    rmdir(dir);
    rmdir(root);
}
END_TEST_DEFINITION()

RUN_TESTS(PackageHash, test_own_hash_is_tagged_and_stable,
          test_a_python_slot_reads_as_py_tagged,
          test_the_allowlist_decides_when_present)
