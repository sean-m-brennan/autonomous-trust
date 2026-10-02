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
 * @file dtn_eid_test.c
 * @brief Unit tests for extensions/dtn/dtn_eid.{h,c} — pure string construction,
 *        no backend or network required.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "extensions/dtn/dtn_eid.h"
#include "network/net_transport.h"

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

/* ---- the transport's addressing (dtn_eid.h's pure half) ---- */

DEFINE_TEST(test_group_hash_pre_join_and_joined)
{
    unsigned char h[8];
    const uuid_t zero = {0};
    ck_assert_int_eq(dtn_group_hash(NULL, h), 0);
    ck_assert_mem_eq(h, DTN_PRE_JOIN_HASH, 8);
    ck_assert_int_eq(dtn_group_hash(zero, h), 0);
    ck_assert_mem_eq(h, "AT-boot", 8);   /* the NUL is the eighth byte */
    ck_assert_int_eq(dtn_group_hash(FIXED_UUID, h), 1);
    ck_assert_mem_eq(h, FIXED_UUID, 8);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_endpoints_in_channel_order)
{
    char eids[3][DTN_EID_MAX + 1];
    ck_assert_int_eq(dtn_endpoints(FIXED_UUID, NULL, eids), 0);
    ck_assert_str_eq(eids[NET_CHAN_PEER], "dtn://at-deadbeef/peer");
    ck_assert_str_eq(eids[NET_CHAN_BROADCAST], "dtn://at-group-41542d626f6f7400/bcast");
    ck_assert_str_eq(eids[NET_CHAN_GROUP], "dtn://at-group-41542d626f6f7400/group");
    ck_assert_int_eq(dtn_endpoints(NULL, FIXED_UUID, eids), 1);
    ck_assert_str_eq(eids[NET_CHAN_PEER], "dtn://at-local/peer");
    ck_assert_str_eq(eids[NET_CHAN_GROUP], "dtn://at-group-deadbeef00112233/group");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_channel_service_round_trip)
{
    for (int ch = 0; ch < NET_CHAN__COUNT; ch++)
        ck_assert_int_eq(dtn_service_to_channel(dtn_channel_suffix(ch)), ch);
    ck_assert_int_eq(dtn_service_to_channel("/other"), NET_CHAN__COUNT);
    ck_assert_int_eq(dtn_service_to_channel(NULL), NET_CHAN__COUNT);
    ck_assert_ptr_null(dtn_channel_suffix(NET_CHAN__COUNT));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_broadcast_eid)
{
    char eid[DTN_EID_MAX + 1] = {0};
    ck_assert(dtn_broadcast_eid(NET_CHAN_GROUP, FIXED_UUID, eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-group-deadbeef00112233/group");
    ck_assert(dtn_broadcast_eid(NET_CHAN_BROADCAST, NULL, eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-group-41542d626f6f7400/bcast");
    ck_assert_int_eq(dtn_broadcast_eid(NET_CHAN_PEER, FIXED_UUID, eid, sizeof(eid)), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_eid_resolution_order)
{
    char eid[DTN_EID_MAX + 1] = {0};
    ck_assert(dtn_peer_eid("ipn:42.1", FIXED_UUID, eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "ipn:42.1");
    ck_assert(dtn_peer_eid("10.0.0.5", FIXED_UUID, eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-deadbeef/peer");
    ck_assert(dtn_peer_eid("10.0.0.5", NULL, eid, sizeof(eid)) > 0);
    ck_assert_str_eq(eid, "dtn://at-10.0.0.5/peer");
    ck_assert_int_eq(dtn_peer_eid("", NULL, eid, sizeof(eid)), -1);
    ck_assert_int_eq(dtn_peer_eid(NULL, NULL, eid, sizeof(eid)), -1);
    char longest[114];
    memset(longest, 'a', sizeof(longest) - 1);
    longest[113] = '\0';
    ck_assert_int_eq(dtn_peer_eid(longest, NULL, eid, sizeof(eid)), 127);
    char too_long[115];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[114] = '\0';
    ck_assert_int_eq(dtn_peer_eid(too_long, NULL, eid, sizeof(eid)), -1);
}
END_TEST_DEFINITION()

RUN_TESTS(DTN_EID,
          test_group_hash_pre_join_and_joined,
          test_endpoints_in_channel_order,
          test_channel_service_round_trip,
          test_broadcast_eid,
          test_peer_eid_resolution_order,
          test_eid_from_uuid_known,
          test_eid_from_uuid_truncates,
          test_eid_for_service_leading_slash,
          test_eid_for_service_all_channel_suffixes,
          test_eid_for_service_truncates,
          test_eid_for_group_known_hash,
          test_eid_for_group_rejects_short_hash,
          test_eid_for_group_truncates)
