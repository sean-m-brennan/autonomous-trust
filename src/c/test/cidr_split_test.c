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
 * @file cidr_split_test.c
 * @brief cidr_split's output lengths, and the silence that hid them.
 *
 * cidr_split used to write with HARD-CODED lengths -- snprintf(addr,
 * IPV4_ADDR_LEN, ...) and snprintf(mask, 3, ...) -- regardless of the buffer the
 * caller supplied, even though cidr6_to_ip6_binary and both socket transports
 * pass char[IPV6_ADDR_LEN]. Measured against the unmodified library:
 *
 *   "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"
 *       addr -> "2001:0db8:85a3:"   (39 chars -> 15)
 *       mask -> "12"                (from "128")
 *   cidr6_to_ip6_binary(...)         -> rc=0, prefix=12
 *   cidr6_to_ip6_binary("fd00::1/128") -> rc=0, prefix=12
 *
 * Note the last line: a SHORT IPv6 address fits, so only the prefix was wrong,
 * and 12 passes the `> 128` family check -- the call reported SUCCESS with a /12
 * where the caller asked for /128. Nothing failed; the wrong value simply
 * propagated. The address half was equally quiet because both converters guarded
 * `inet_pton(...) < 0`, and inet_pton returns 0 (not negative) for malformed
 * input, so a truncated address was accepted too.
 *
 * The hard-coded length could NOT simply be widened: cidr4_to_ip4_binary passes a
 * 16-byte buffer, so writing IPV6_ADDR_LEN bytes would have converted a
 * truncation bug into a buffer overflow. Hence explicit out-lengths, and
 * truncation is now ENET_ADDR_TOO_LONG rather than a silent shortening.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "network/network.h"

/* 39 chars: 8 groups of 4 hex digits plus 7 colons. Comfortably past the old
 * 15-char ceiling. */
#define V6_FULL "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

/****************************
 * The lengths are the caller's
 ****************************/

DEFINE_TEST(test_ipv6_address_survives_intact)
{
    char addr[IPV6_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = V6_FULL "/128";
    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, V6_FULL);
    ck_assert_int_eq((int)strlen(addr), 39);  /* was 15 */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_three_digit_prefix_survives)
{
    /* The silent half: "128" used to come back "12". */
    char addr[IPV6_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = "fd00::1/128";
    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "fd00::1");
    ck_assert_str_eq(mask, "128");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ipv4_is_unchanged)
{
    /* The whole point of taking the length from the caller rather than widening
     * a constant: the IPv4 path keeps its 16-byte buffer and its old behaviour. */
    char addr[IPV4_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = "192.168.1.100/24";
    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "192.168.1.100");
    ck_assert_str_eq(mask, "24");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_missing_prefix_is_still_acceptable)
{
    char addr[IPV6_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = "10.0.0.1";
    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "10.0.0.1");
    ck_assert_int_eq(mask[0], 0);  /* untouched */
}
END_TEST_DEFINITION()

/****************************
 * Truncation is loud, and leaves nothing usable
 ****************************/

DEFINE_TEST(test_address_truncation_is_an_error)
{
    /* An IPv4-sized buffer handed an IPv6 address: exactly the old bug's shape,
     * now reported instead of performed. */
    char addr[IPV4_ADDR_LEN] = {0};
    char cidr[] = V6_FULL "/128";
    ck_assert_ret_nonzero(cidr_split(cidr, addr, sizeof(addr), NULL, 0));
    /* And nothing partial is left behind: a caller that ignores the return code
     * (net_proc.c's void my_address) must not use a truncated address as its
     * own -- that is a self-filter that stops matching. */
    ck_assert_int_eq(addr[0], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_prefix_truncation_is_an_error)
{
    char addr[IPV6_ADDR_LEN] = {0};
    char mask[3] = {0};  /* the old hard-coded size; cannot hold "128" */
    char cidr[] = "fd00::1/128";
    ck_assert_ret_nonzero(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_int_eq(mask[0], 0);
    ck_assert_int_eq(addr[0], 0);  /* neither half is usable alone */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_zero_length_buffers_are_refused)
{
    char addr[IPV6_ADDR_LEN] = {0};
    char cidr[] = "10.0.0.1/8";
    ck_assert_ret_nonzero(cidr_split(cidr, addr, 0, NULL, 0));
    char cidr2[] = "10.0.0.1/8";
    char mask[4] = {0};
    ck_assert_ret_nonzero(cidr_split(cidr2, addr, sizeof(addr), mask, 0));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_null_address_is_refused)
{
    char cidr[] = "10.0.0.1/8";
    ck_assert_ret_nonzero(cidr_split(cidr, NULL, 0, NULL, 0));
}
END_TEST_DEFINITION()

/****************************
 * Through the public converters
 ****************************/

DEFINE_TEST(test_v6_converter_reports_the_real_prefix)
{
    char cidr[] = V6_FULL "/128";
    uint128_t ip = 0;
    uint8_t prefix = 0;
    ck_assert_ret_ok(cidr6_to_ip6_binary(cidr, &ip, &prefix));
    ck_assert_uint_eq(prefix, 128);  /* was 12, with rc=0 */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_v6_converter_short_address_real_prefix)
{
    /* The address fits either way here, so this isolates the PREFIX defect. */
    char cidr[] = "fd00::1/128";
    uint128_t ip = 0;
    uint8_t prefix = 0;
    ck_assert_ret_ok(cidr6_to_ip6_binary(cidr, &ip, &prefix));
    ck_assert_uint_eq(prefix, 128);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_v4_converter_unchanged)
{
    char cidr[] = "10.0.0.5/24";
    uint32_t ip = 0;
    uint8_t prefix = 0;
    ck_assert_ret_ok(cidr4_to_ip4_binary(cidr, &ip, &prefix));
    ck_assert_uint_eq(prefix, 24);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_malformed_addresses_are_rejected)
{
    /* Both converters guarded `inet_pton(...) < 0`, but inet_pton returns 0 for
     * malformed input, so garbage was accepted with rc=0. Measured:
     * inet_pton(AF_INET6, "2001:0db8:85a3:") == 0. This is what kept the
     * truncation quiet, so it is pinned here alongside it. */
    uint32_t ip4 = 0;
    uint8_t p4 = 0;
    char bad4[] = "not.an.ip/24";
    ck_assert_ret_nonzero(cidr4_to_ip4_binary(bad4, &ip4, &p4));

    char partial6[] = "2001:0db8:85a3:/64";  /* what truncation used to produce */
    uint128_t ip6 = 0;
    uint8_t p6 = 0;
    ck_assert_ret_nonzero(cidr6_to_ip6_binary(partial6, &ip6, &p6));

    /* A v6 literal handed to the v4 converter must also be refused. */
    char v6_as_v4[] = V6_FULL "/128";
    ck_assert_ret_nonzero(cidr4_to_ip4_binary(v6_as_v4, &ip4, &p4));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_out_of_range_v4_prefix_is_reported_as_such)
{
    /* cidr4_to_ip4_binary's mask buffer went from 3 to 4 bytes so a 3-digit
     * prefix is REPRESENTABLE and can therefore be diagnosed: "/128" on an IPv4
     * address is an invalid mask, not an unparseable string. Either way it must
     * fail -- what matters is that it does not silently become /12. */
    char cidr[] = "10.0.0.1/128";
    uint32_t ip = 0;
    uint8_t prefix = 0;
    ck_assert_ret_nonzero(cidr4_to_ip4_binary(cidr, &ip, &prefix));
    ck_assert(prefix != 12);
}
END_TEST_DEFINITION()

RUN_TESTS(CidrSplit,
          test_ipv6_address_survives_intact,
          test_three_digit_prefix_survives,
          test_ipv4_is_unchanged,
          test_missing_prefix_is_still_acceptable,
          test_address_truncation_is_an_error,
          test_prefix_truncation_is_an_error,
          test_zero_length_buffers_are_refused,
          test_null_address_is_refused,
          test_v6_converter_reports_the_real_prefix,
          test_v6_converter_short_address_real_prefix,
          test_v4_converter_unchanged,
          test_malformed_addresses_are_rejected,
          test_out_of_range_v4_prefix_is_reported_as_such)
