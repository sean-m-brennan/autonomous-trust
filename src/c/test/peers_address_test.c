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
 * @file peers_address_test.c
 * @brief peers_find_by_address: a CIDR suffix is stripped, a DTN EID is not.
 *
 * Cutting an EID at its first '/' turned every EID-addressed peer into "dtn:",
 * so none could be found. Python's twin is Peers.find_by_address / strip_cidr.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "identity/identity.h"
#include "identity/peers.h"

static void _peer(public_identity_t *p, const char *nick, const char *addr)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->nickname, sizeof(p->nickname), "%s", nick);
    snprintf(p->address, sizeof(p->address), "%s", addr);
    uuid_generate(p->uuid);
}

DEFINE_TEST(test_cidr_suffix_stripped)
{
    peers_t peers;
    memset(&peers, 0, sizeof(peers));
    public_identity_t a;
    _peer(&a, "a", "10.0.0.1");
    ck_assert_int_eq(peers_add(&peers, &a, -1), 0);
    const public_identity_t *got = peers_find_by_address(&peers, "10.0.0.1/24");
    ck_assert_ptr_nonnull(got);
    ck_assert_str_eq(got->nickname, "a");
    peers_free(&peers);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_kept_whole)
{
    peers_t peers;
    memset(&peers, 0, sizeof(peers));
    public_identity_t a, b;
    _peer(&a, "a", "dtn://at-aaaaaaaa/peer");
    _peer(&b, "b", "ipn:7.1");
    ck_assert_int_eq(peers_add(&peers, &a, -1), 0);
    ck_assert_int_eq(peers_add(&peers, &b, -1), 0);
    const public_identity_t *got = peers_find_by_address(&peers, "dtn://at-aaaaaaaa/peer");
    ck_assert_ptr_nonnull(got);
    ck_assert_str_eq(got->nickname, "a");
    got = peers_find_by_address(&peers, "ipn:7.1");
    ck_assert_ptr_nonnull(got);
    ck_assert_str_eq(got->nickname, "b");
    ck_assert_ptr_null(peers_find_by_address(&peers, "dtn:"));
    ck_assert_ptr_null(peers_find_by_address(&peers, "dtn://at-bbbbbbbb/peer"));
    peers_free(&peers);
}
END_TEST_DEFINITION()

RUN_TESTS(peers_address,
          test_cidr_suffix_stripped,
          test_eid_kept_whole)
