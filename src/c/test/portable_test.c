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

#include <string.h>
#include <uuid/uuid.h>

#include "autonomous_trust/utilities/portable.h"

/* at_uuid_generate_sha1 is what Darwin builds use for every v5 UUID AT mints
 * (reputation's attestation, roster and pair ids). Its bytes must be Python's
 * uuid.uuid5 and util-linux's, or a macOS node names the same record
 * differently from everyone else. */

static void expect_uuid5(const char *ns_str, const char *name, size_t len,
                         const char *want)
{
    uuid_t ns, got;
    char got_str[37];
    ck_assert_int_eq(uuid_parse(ns_str, ns), 0);
    at_uuid_generate_sha1(got, ns, name, len);
    uuid_unparse_lower(got, got_str);
    ck_assert_str_eq(got_str, want);
}

/* Vectors from Python: uuid.uuid5(NAMESPACE_DNS, "python.org") etc. */
DEFINE_TEST(test_uuid5_matches_python)
{
    expect_uuid5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "python.org", 10,
                 "886313e1-3b8a-5372-9b90-0c9aee199e5d");
    expect_uuid5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", "", 0,
                 "1b4db7eb-4057-5ddf-91e0-36dec72071f5");
    /* 200 bytes: several SHA-1 blocks, and padding that spills into a block. */
    char long_name[200];
    memset(long_name, 'x', sizeof(long_name));
    expect_uuid5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", long_name,
                 sizeof(long_name), "cd3580b9-d244-586a-8077-74317319b48d");
}
END_TEST_DEFINITION()

/* Where util-linux is the libuuid, ours must agree with its own for every
 * name length around the SHA-1 block and padding boundaries. */
DEFINE_TEST(test_uuid5_matches_util_linux)
{
#ifdef __APPLE__
    printf("  skipped: Darwin's libuuid has no uuid_generate_sha1 to compare with\n");
#else
    uuid_t ns;
    uuid_generate(ns);
    char name[300];
    for (size_t i = 0; i < sizeof(name); i++)
        name[i] = (char)('a' + (i * 7) % 26);
    for (size_t len = 0; len <= sizeof(name); len++)
    {
        uuid_t ours, theirs;
        at_uuid_generate_sha1(ours, ns, name, len);
        uuid_generate_sha1(theirs, ns, name, len);
        ck_assert_mem_eq(ours, theirs, sizeof(uuid_t));
    }
#endif
}
END_TEST_DEFINITION()

RUN_TESTS(Portable, test_uuid5_matches_python, test_uuid5_matches_util_linux)
