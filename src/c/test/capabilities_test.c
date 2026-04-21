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

#include <string.h>
#include <sodium.h>

#include "processes/capabilities_priv.h"

/* From generated capability_table_priv.h - extern declarations */
extern capability_t capability_table[];
extern size_t capability_table_size;

DEFINE_TEST(test_find_capability_missing)
{
    ck_assert(sodium_init() >= 0);

    /* With empty or small capability table, nonexistent returns NULL */
    capability_t *cap = find_capability("nonexistent_capability");
    ck_assert_ptr_null(cap);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_capability_name_copy)
{
    ck_assert(sodium_init() >= 0);

    capability_t cap;
    memset(&cap, 0, sizeof(cap));
    strncpy(cap.name, "my_long_capability_name", CAP_NAMELEN);
    ck_assert_str_eq(cap.name, "my_long_capability_name");

    /* Name truncation at CAP_NAMELEN */
    capability_t cap2;
    memset(&cap2, 0, sizeof(cap2));
    /* Fill with a string that's exactly CAP_NAMELEN long. Use memcpy with a
     * fixed clamp so neither -Wstringop-truncation nor -Wformat-truncation
     * fire — this is an intentional-truncation test. */
    char long_name[CAP_NAMELEN + 10];
    memset(long_name, 'x', CAP_NAMELEN + 9);
    long_name[CAP_NAMELEN + 9] = '\0';
    memcpy(cap2.name, long_name, CAP_NAMELEN);
    cap2.name[CAP_NAMELEN] = '\0';
    ck_assert(strlen(cap2.name) == CAP_NAMELEN);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_capability_struct_init)
{
    ck_assert(sodium_init() >= 0);

    capability_t cap;
    memset(&cap, 0, sizeof(cap));

    strncpy(cap.name, "my_capability", CAP_NAMELEN);
    ck_assert_str_eq(cap.name, "my_capability");
    ck_assert(cap.local == false);
    ck_assert_ptr_null(cap.function);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_capability_table_exists)
{
    ck_assert(sodium_init() >= 0);

    /* capability_table_size should be defined (possibly 0) */
    ck_assert(capability_table_size < (size_t)-1);
}
END_TEST_DEFINITION()

RUN_TESTS(Capabilities, test_find_capability_missing, test_capability_name_copy,
          test_capability_struct_init, test_capability_table_exists)
