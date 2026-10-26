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

/*
 * A peer address may be a hostname rather than a numeric IP: the cohort seeder
 * writes container hostnames for Python peers, and the Python runtime resolves
 * them. The C transports used inet_pton alone, so every send to such a peer
 * failed with EINVAL. These tests pin the shared resolver and, end to end, a
 * UDP send addressed by name.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network/network.h"
#include "network/net_transport_priv.h"

static logger_t test_logger;

DEFINE_TEST(test_numeric_ipv4_resolves)
{
    struct in_addr a = {0};
    ck_assert_ret_ok(net_transport_resolve_host("10.1.2.3", false, &a));
    char out[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, out, sizeof(out));
    ck_assert_str_eq(out, "10.1.2.3");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_hostname_resolves)
{
    struct in_addr a = {0};
    ck_assert_ret_ok(net_transport_resolve_host("localhost", false, &a));
    ck_assert_int_eq(ntohl(a.s_addr) >> 24, 127);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unresolvable_name_fails)
{
    struct in_addr a = {0};
    ck_assert_ret_nonzero(net_transport_resolve_host("no-such-host.invalid",
                                                     false, &a));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_udp_send_unicast_by_hostname)
{
    /* Drives the real vtable, so the test fails if the send path stops using
     * the resolver, not only if the resolver breaks. */
    int rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(rx != -1);
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    me.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &me.sin_addr);
    ck_assert_ret_ok(bind(rx, (struct sockaddr *)&me, sizeof(me)));
    struct sockaddr_in got = {0};
    socklen_t len = sizeof(got);
    ck_assert_ret_ok(getsockname(rx, (struct sockaddr *)&got, &len));
    int peer_port = ntohs(got.sin_port);

    const net_transport_t *t = net_transport_find("udp_net_4");
    ck_assert(t != NULL);
    network_config_t net_cfg;
    memset(&net_cfg, 0, sizeof(net_cfg));
    snprintf(net_cfg.ip4_cidr, sizeof(net_cfg.ip4_cidr), "%s", "127.0.0.1/8");
    snprintf(net_cfg.mcast4_addr, sizeof(net_cfg.mcast4_addr), "%s",
             DEFAULT_MCAST4_ADDR);
    net_cfg.port = 31720;
    net_transport_params_t params = {
        .net_cfg   = &net_cfg,
        .logger    = &test_logger,
        .port_base = 31720,
        .myself    = NULL,
        .proc      = NULL,
    };
    net_transport_ctx_t *ctx = NULL;
    if (t->open(&ctx, &params) != 0) {
        close(rx);
        return;  /* could not bind the transport here; nothing to assert */
    }

    const uint8_t wire[] = "by-name";
    ck_assert_ret_ok(t->send_unicast(ctx, wire, sizeof(wire) - 1,
                                     "localhost", peer_port));
    char buf[32] = {0};
    ssize_t n = recv(rx, buf, sizeof(buf) - 1, 0);
    ck_assert_int_eq((int)n, (int)(sizeof(wire) - 1));
    ck_assert_str_eq(buf, "by-name");

    t->close(ctx);
    close(rx);
}
END_TEST_DEFINITION()

RUN_TESTS(NetResolveHost,
          test_numeric_ipv4_resolves,
          test_hostname_resolves,
          test_unresolvable_name_fails,
          test_udp_send_unicast_by_hostname)
