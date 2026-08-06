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
#include <jansson.h>

#include "network/network.h"

DEFINE_TEST(test_cidr_split)
{
    char cidr[] = "192.168.1.0/24";
    char addr[IPV4_ADDR_LEN] = {0};
    char mask[4] = {0};

    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "192.168.1.0");
    ck_assert_str_eq(mask, "24");

    /* Split without mask output */
    char cidr2[] = "10.0.0.1/8";
    char addr2[IPV4_ADDR_LEN] = {0};
    ck_assert_ret_ok(cidr_split(cidr2, addr2, sizeof(addr2), NULL, 0));
    ck_assert_str_eq(addr2, "10.0.0.1");

    /* NULL addr should fail */
    char cidr3[] = "10.0.0.1/8";
    ck_assert_ret_nonzero(cidr_split(cidr3, NULL, 0, NULL, 0));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr4_to_ip4_binary)
{
    char cidr[] = "192.168.1.100/24";
    uint32_t ip = 0;
    uint8_t mask = 0;

    ck_assert_ret_ok(cidr4_to_ip4_binary(cidr, &ip, &mask));
    ck_assert_uint_eq(mask, 24);
    ck_assert(ip != 0);

    /* Convert back to string to verify */
    char addr[IPV4_ADDR_LEN] = {0};
    ck_assert_ret_ok(ip4_binary_to_addr(ip, addr));
    ck_assert_str_eq(addr, "192.168.1.100");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr4_to_broadcast)
{
    char cidr[] = "192.168.1.0/24";
    char bcast[IPV4_ADDR_LEN] = {0};

    ck_assert_ret_ok(cidr4_to_broadcast(cidr, bcast));
    ck_assert_str_eq(bcast, "192.168.1.255");

    /* /16 network */
    char cidr2[] = "10.10.0.0/16";
    char bcast2[IPV4_ADDR_LEN] = {0};
    ck_assert_ret_ok(cidr4_to_broadcast(cidr2, bcast2));
    ck_assert_str_eq(bcast2, "10.10.255.255");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ip6_basic)
{
    char cidr[] = "2001:db8::1/64";
    uint128_t ip = 0;
    uint8_t mask = 0;

    ck_assert_ret_ok(cidr6_to_ip6_binary(cidr, &ip, &mask));
    ck_assert_uint_eq(mask, 64);

    char addr[IPV6_ADDR_LEN] = {0};
    ck_assert_ret_ok(ip6_binary_to_addr(ip, addr));
    /* Should contain "2001:db8" somewhere */
    ck_assert(strstr(addr, "2001:db8") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_network_json_roundtrip)
{
    network_config_t net_out;
    memset(&net_out, 0, sizeof(net_out));
    net_out.port = 27787;
    strncpy(net_out.ip4_cidr, "192.168.1.0/24", CIDR4_LEN);
    net_out.ip4_cidr[CIDR4_LEN] = '\0';
    strncpy(net_out.ip6_cidr, "2001:db8::/64", CIDR6_LEN);
    net_out.ip6_cidr[CIDR6_LEN] = '\0';
    strncpy(net_out.mcast4_addr, "239.0.0.1", IPV4_ADDR_LEN);
    net_out.mcast4_addr[IPV4_ADDR_LEN] = '\0';
    strncpy(net_out.mcast6_addr, "ff02::1", IPV6_ADDR_LEN);
    net_out.mcast6_addr[IPV6_ADDR_LEN] = '\0';
    strncpy(net_out.mac_address, "00:11:22:33:44:55", MAC_ADDR_LEN);
    net_out.mac_address[MAC_ADDR_LEN] = '\0';

    json_t *obj = NULL;
    ck_assert_ret_ok(network_to_json(&net_out, &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert(json_is_object(obj));

    /* Verify JSON content */
    ck_assert_int_eq(json_integer_value(json_object_get(obj, "port")), 27787);
    ck_assert_str_eq(json_string_value(json_object_get(obj, "typename")), "network");

    /* Roundtrip back */
    network_config_t net_in;
    memset(&net_in, 0, sizeof(net_in));
    ck_assert_ret_ok(network_from_json(obj, &net_in));

    ck_assert_int_eq(net_in.port, 27787);
    ck_assert_str_eq(net_in.ip4_cidr, "192.168.1.0/24");
    ck_assert_str_eq(net_in.ip6_cidr, "2001:db8::/64");
    ck_assert_str_eq(net_in.mcast4_addr, "239.0.0.1");
    ck_assert_str_eq(net_in.mcast6_addr, "ff02::1");
    ck_assert_str_eq(net_in.mac_address, "00:11:22:33:44:55");

    json_decref(obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cidr_split_no_mask)
{
    /* CIDR without a slash - just an address */
    char cidr[] = "10.0.0.1";
    char addr[IPV4_ADDR_LEN] = {0};
    char mask[4] = {0};

    ck_assert_ret_ok(cidr_split(cidr, addr, sizeof(addr), mask, sizeof(mask)));
    ck_assert_str_eq(addr, "10.0.0.1");
    /* mask should remain empty when no slash present */
}
END_TEST_DEFINITION()

RUN_TESTS(Network2, test_cidr_split, test_cidr4_to_ip4_binary,
          test_cidr4_to_broadcast, test_ip6_basic,
          test_network_json_roundtrip, test_cidr_split_no_mask)
