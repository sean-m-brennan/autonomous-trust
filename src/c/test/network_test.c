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
#include <arpa/inet.h>

#include "network/network.h"

/*
 * Corresponds to Python test_network_network.py::TestCidr
 * and ip4_broadcast property tests in TestNetworkProperties
 */

DEFINE_TEST(test_cidr_split_ipv4)
{
    char addr[IPV4_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = "192.168.1.100/24";

    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "192.168.1.100");
    ck_assert_str_eq(mask, "24");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr_split_no_mask)
{
    char addr[IPV4_ADDR_LEN] = {0};
    char mask[4] = {0};
    char cidr[] = "10.0.0.1";

    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "10.0.0.1");
    /* mask should be empty since no /prefix */
    ck_assert_int_eq(mask[0], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr4_to_broadcast_24)
{
    char bcast[IPV4_ADDR_LEN] = {0};
    char cidr[] = "192.168.1.100/24";

    ck_assert_ret_ok(cidr4_to_broadcast(cidr, bcast));
    ck_assert_str_eq(bcast, "192.168.1.255");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr4_to_broadcast_16)
{
    char bcast[IPV4_ADDR_LEN] = {0};
    char cidr[] = "172.16.3.14/16";

    ck_assert_ret_ok(cidr4_to_broadcast(cidr, bcast));
    ck_assert_str_eq(bcast, "172.16.255.255");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr4_to_broadcast_20)
{
    char bcast[IPV4_ADDR_LEN] = {0};
    char cidr[] = "10.0.16.5/20";

    ck_assert_ret_ok(cidr4_to_broadcast(cidr, bcast));
    ck_assert_str_eq(bcast, "10.0.31.255");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ip4_binary_to_addr)
{
    /* 192.168.1.1 in network byte order */
    struct in_addr a;
    inet_pton(AF_INET, "192.168.1.1", &a);

    char addr[IPV4_ADDR_LEN] = {0};
    ck_assert_ret_ok(ip4_binary_to_addr(a.s_addr, addr));
    ck_assert_str_eq(addr, "192.168.1.1");
}
END_TEST_DEFINITION()

RUN_TESTS(Network, test_cidr_split_ipv4, test_cidr_split_no_mask,
          test_cidr4_to_broadcast_24, test_cidr4_to_broadcast_16,
          test_cidr4_to_broadcast_20, test_ip4_binary_to_addr)
