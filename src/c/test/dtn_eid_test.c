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

/**
 * @file dtn_eid_test.c
 * @brief Unit tests for network/dtn/dtn_eid.{h,c} — pure string construction,
 *        no backend or network required.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "network/dtn/dtn_eid.h"

/* A fixed UUID so the derived EID is deterministic across runs. First 4
 * bytes are what dtn_eid_from_uuid() hashes into the prefix. */
static const unsigned char FIXED_UUID[16] = {
    0xde, 0xad, 0xbe, 0xef,
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
};

DEFINE_TEST(test_eid_from_uuid_known)
{
    char eid[DTN_EID_MAX + 1] = {0};
    int n = dtn_eid_from_uuid(FIXED_UUID, eid, sizeof(eid));
    ck_assert(n > 0);
    ck_assert_str_eq(eid, "dtn://at-deadbeef/");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_from_uuid_truncates)
{
    char tiny[8] = {0};
    int n = dtn_eid_from_uuid(FIXED_UUID, tiny, sizeof(tiny));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_service_leading_slash)
{
    char eid[DTN_EID_MAX + 1] = {0};
    int n = dtn_eid_for_service("dtn://at-deadbeef/", "/peer",
                                eid, sizeof(eid));
    ck_assert(n > 0);
    /* The helper strips the service's leading '/' to avoid "//peer". */
    ck_assert_str_eq(eid, "dtn://at-deadbeef/peer");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_service_all_channel_suffixes)
{
    char eid[DTN_EID_MAX + 1] = {0};

    ck_assert(dtn_eid_for_service("dtn://at-abcd/", DTN_CHAN_PEER_SUFFIX,
                                  eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-abcd/peer");

    memset(eid, 0, sizeof(eid));
    ck_assert(dtn_eid_for_service("dtn://at-abcd/", DTN_CHAN_BCAST_SUFFIX,
                                  eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-abcd/bcast");

    memset(eid, 0, sizeof(eid));
    ck_assert(dtn_eid_for_service("dtn://at-abcd/", DTN_CHAN_GROUP_SUFFIX,
                                  eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-abcd/group");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_service_truncates)
{
    char tiny[4] = {0};
    int n = dtn_eid_for_service("dtn://at-deadbeef/", "/peer",
                                tiny, sizeof(tiny));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_group_known_hash)
{
    /* Deterministic 8-byte hash yields a stable group EID we can pin. */
    const unsigned char hash[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    char eid[DTN_EID_MAX + 1] = {0};
    int n = dtn_eid_for_group(hash, sizeof(hash), eid, sizeof(eid));
    ck_assert(n > 0);
    ck_assert_str_eq(eid, "dtn://at-group-0123456789abcdef/");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_group_rejects_short_hash)
{
    const unsigned char short_hash[4] = {0x01,0x02,0x03,0x04};
    char eid[DTN_EID_MAX + 1] = {0};
    int n = dtn_eid_for_group(short_hash, sizeof(short_hash),
                              eid, sizeof(eid));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_eid_for_group_truncates)
{
    const unsigned char hash[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    char tiny[8] = {0};
    int n = dtn_eid_for_group(hash, sizeof(hash), tiny, sizeof(tiny));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

RUN_TESTS(DTN_EID,
          test_eid_from_uuid_known,
          test_eid_from_uuid_truncates,
          test_eid_for_service_leading_slash,
          test_eid_for_service_all_channel_suffixes,
          test_eid_for_service_truncates,
          test_eid_for_group_known_hash,
          test_eid_for_group_rejects_short_hash,
          test_eid_for_group_truncates)
