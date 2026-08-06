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
 * @file net_source_bind_test.c
 * @brief Source-address pinning on the outbound send paths.
 *
 * AT binds its recv sockets to the node's configured address but historically
 * left the send sockets unbound, so the kernel chose the source from the route
 * to the destination. Any node with more than one candidate source address
 * (loopback aliases, multi-homed hosts, containers on several networks) then
 * transmitted from an address its peers do not hold in their listing, and
 * attribution -- which keys on the datagram's source -- missed every frame.
 * Measured in the Python twin's 2-peer harness before the fix: 220 log lines
 * reporting the wrong source and 108 dropped frames, against 0 and 0 after.
 *
 * Two behaviours are pinned here, mirroring
 * tests/a_unit/test_network_source_bind.py on the Python side:
 *   1. the source a peer OBSERVES equals the address the node is known by, and
 *   2. pinning it cannot collide with the port the node is listening on.
 *
 * (2) is the load-bearing safety property, and it holds for a reason worth
 * stating: send sockets bind port 0 and NEVER set SO_REUSEADDR. The recv
 * sockets hold (local_addr, comm_port) WITH SO_REUSEADDR, and this kernel
 * grants a second socket that same addr:port only when both set it -- so
 * omitting it is exactly what stops autobind from handing out the listening
 * port, even with AT_COMM_PORT configured inside the ephemeral range, the one
 * arrangement where a collision is otherwise reachable. Compare
 * net_port_test.c's test_same_base_same_address_binds_silently, which pins the
 * converse hazard.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network/network.h"
#include "network/net_transport_priv.h"

static logger_t test_logger;

#define ADDR_A "127.0.0.2"
#define ADDR_B "127.0.0.3"

/* Read the kernel's ephemeral range so the collision tests can place a
 * simulated comm port INSIDE it -- the dangerous configuration. */
static int ephemeral_lo(void)
{
    FILE *fh = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
    if (fh == NULL)
        return 0;
    int lo = 0, hi = 0;
    if (fscanf(fh, "%d %d", &lo, &hi) != 2)
        lo = 0;
    fclose(fh);
    (void)hi;
    return lo;
}

/* True when the loopback aliases this test needs are bindable. */
static bool aliases_available(void)
{
    const char *addrs[] = {ADDR_A, ADDR_B};
    for (int i = 0; i < 2; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == -1)
            return false;
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        inet_pton(AF_INET, addrs[i], &a.sin_addr);
        int rc = bind(s, (struct sockaddr *)&a, sizeof(a));
        close(s);
        if (rc != 0)
            return false;
    }
    return true;
}

static int bound_port(int sock)
{
    struct sockaddr_in got = {0};
    socklen_t len = sizeof(got);
    if (getsockname(sock, (struct sockaddr *)&got, &len) != 0)
        return -1;
    return ntohs(got.sin_port);
}

static void bound_addr(int sock, char *out, size_t out_len)
{
    struct sockaddr_in got = {0};
    socklen_t len = sizeof(got);
    out[0] = '\0';
    if (getsockname(sock, (struct sockaddr *)&got, &len) != 0)
        return;
    inet_ntop(AF_INET, &got.sin_addr, out, (socklen_t)out_len);
}

/****************************
 * The helper's contract
 ****************************/

DEFINE_TEST(test_binds_requested_address_on_ephemeral_port)
{
    if (!aliases_available())
        return;  /* no loopback aliases here; nothing to assert */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(sock != -1);
    ck_assert_ret_ok(net_transport_ip_bind_source(sock, ADDR_A, AF_INET, false,
                                                  &test_logger));
    char addr[IPV4_ADDR_LEN] = {0};
    bound_addr(sock, addr, sizeof(addr));
    ck_assert_str_eq(addr, ADDR_A);
    /* The kernel picked a port; we asked for 0. */
    ck_assert(bound_port(sock) != 0);
    close(sock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_never_sets_so_reuseaddr)
{
    /* The collision guarantee. With SO_REUSEADDR the helper could bind the very
     * port the node listens on and steal its inbound datagrams. */
    if (!aliases_available())
        return;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(sock != -1);
    (void)net_transport_ip_bind_source(sock, ADDR_A, AF_INET, false,
                                       &test_logger);
    int reuse = -1;
    socklen_t len = sizeof(reuse);
    ck_assert_ret_ok(getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, &len));
    ck_assert_int_eq(reuse, 0);
    close(sock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_skips_wildcard_and_unset)
{
    /* ctx->local_addr is empty when the address could not be derived; a
     * wildcard is what an unbound socket already does. Neither is an error,
     * and neither may leave the socket bound. */
    const char *skipped[] = {NULL, "", "0.0.0.0", "::"};
    for (int i = 0; i < 4; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ck_assert(sock != -1);
        ck_assert_int_eq(net_transport_ip_bind_source(sock, skipped[i], AF_INET,
                                                      false, &test_logger), -1);
        ck_assert_int_eq(bound_port(sock), 0);  /* still unbound */
        close(sock);
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_bind_failure_is_not_fatal)
{
    /* A bad address must not take the node off the air: report failure, let the
     * caller send unbound. TEST-NET-3, guaranteed not local. */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(sock != -1);
    ck_assert_int_eq(net_transport_ip_bind_source(sock, "203.0.113.7", AF_INET,
                                                  false, &test_logger), -1);
    /* Still usable: sending is what matters more than attribution. */
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);  /* discard */
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    ssize_t sent = sendto(sock, "x", 1, 0, (struct sockaddr *)&dst, sizeof(dst));
    ck_assert(sent == 1);
    close(sock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_stream_sets_bind_address_no_port)
{
    /* TCP: pin the ADDRESS without reserving a port ahead of connect(), so the
     * per-message connect/send/close path keeps 4-tuple uniqueness instead of
     * exhausting the ephemeral range. */
#ifdef IP_BIND_ADDRESS_NO_PORT
    if (!aliases_available())
        return;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert(sock != -1);
    ck_assert_ret_ok(net_transport_ip_bind_source(sock, ADDR_A, AF_INET, true,
                                                  &test_logger));
    int opt = -1;
    socklen_t len = sizeof(opt);
    ck_assert_ret_ok(getsockopt(sock, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                                &opt, &len));
    ck_assert_int_eq(opt, 1);
    close(sock);
#endif
}
END_TEST_DEFINITION()

/****************************
 * Port-collision safety
 ****************************/

DEFINE_TEST(test_autobind_never_takes_the_listening_port)
{
    /* The dangerous arrangement: a comm port configured INSIDE the ephemeral
     * range, so autobind could plausibly select it. */
    if (!aliases_available())
        return;
    int lo = ephemeral_lo();
    if (lo <= 0)
        return;
    int comm_port_sim = lo + 1;

    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(recv_sock != -1);
    int one = 1;
    setsockopt(recv_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in held = {0};
    held.sin_family = AF_INET;
    held.sin_port = htons(comm_port_sim);
    inet_pton(AF_INET, ADDR_A, &held.sin_addr);
    if (bind(recv_sock, (struct sockaddr *)&held, sizeof(held)) != 0) {
        close(recv_sock);
        return;  /* could not reserve a port inside the range; skip */
    }

    /* Hold each socket open so autobind must keep searching. */
    enum { N = 400 };
    int socks[N];
    int made = 0;
    for (int i = 0; i < N; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == -1)
            break;
        (void)net_transport_ip_bind_source(s, ADDR_A, AF_INET, false,
                                           &test_logger);
        socks[made++] = s;
        /* Never the port this node listens on. */
        ck_assert(bound_port(s) != comm_port_sim);
    }
    for (int i = 0; i < made; i++)
        close(socks[i]);
    close(recv_sock);
    ck_assert(made > 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_explicit_collision_refused_without_reuseaddr)
{
    /* Why omitting SO_REUSEADDR is the guarantee and not merely tidy: the
     * kernel refuses the collision outright, which is what makes autobind
     * unable to produce it. */
    if (!aliases_available())
        return;
    int lo = ephemeral_lo();
    if (lo <= 0)
        return;
    int comm_port_sim = lo + 2;

    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(recv_sock != -1);
    int one = 1;
    setsockopt(recv_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in held = {0};
    held.sin_family = AF_INET;
    held.sin_port = htons(comm_port_sim);
    inet_pton(AF_INET, ADDR_A, &held.sin_addr);
    if (bind(recv_sock, (struct sockaddr *)&held, sizeof(held)) != 0) {
        close(recv_sock);
        return;
    }

    int plain = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(plain != -1);
    ck_assert_ret_nonzero(bind(plain, (struct sockaddr *)&held, sizeof(held)));
    close(plain);
    close(recv_sock);
}
END_TEST_DEFINITION()

/****************************
 * What does the PEER observe?
 ****************************/

DEFINE_TEST(test_peer_observes_our_configured_address)
{
    /* The behaviour the whole change exists for. Unbound, the receiver sees
     * some other source and attribution misses; pinned, it sees ours. */
    if (!aliases_available())
        return;
    int rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(rx != -1);
    int one = 1;
    setsockopt(rx, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    me.sin_port = 0;
    inet_pton(AF_INET, ADDR_A, &me.sin_addr);
    ck_assert_ret_ok(bind(rx, (struct sockaddr *)&me, sizeof(me)));
    int port = bound_port(rx);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, ADDR_A, &dst.sin_addr);

    char seen[IPV4_ADDR_LEN] = {0};
    struct sockaddr_in from = {0};
    socklen_t flen;
    char buf[8];

    /* (a) unbound: whatever the kernel picks for the route */
    int tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(tx != -1);
    ck_assert(sendto(tx, "x", 1, 0, (struct sockaddr *)&dst, sizeof(dst)) == 1);
    flen = sizeof(from);
    ck_assert(recvfrom(rx, buf, sizeof(buf), 0,
                       (struct sockaddr *)&from, &flen) == 1);
    inet_ntop(AF_INET, &from.sin_addr, seen, sizeof(seen));
    close(tx);
    /* Not our address -- which is precisely the attribution miss. */
    ck_assert(strcmp(seen, ADDR_B) != 0);

    /* (b) pinned: the address peers know us by */
    tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(tx != -1);
    ck_assert_ret_ok(net_transport_ip_bind_source(tx, ADDR_B, AF_INET, false,
                                                  &test_logger));
    ck_assert(sendto(tx, "x", 1, 0, (struct sockaddr *)&dst, sizeof(dst)) == 1);
    flen = sizeof(from);
    ck_assert(recvfrom(rx, buf, sizeof(buf), 0,
                       (struct sockaddr *)&from, &flen) == 1);
    inet_ntop(AF_INET, &from.sin_addr, seen, sizeof(seen));
    close(tx);
    ck_assert_str_eq(seen, ADDR_B);

    close(rx);
}
END_TEST_DEFINITION()

/****************************
 * The SEND PATH binds, not merely the helper
 ****************************/

/* Open a real UDP transport bound to `cidr`'s address on `base`, so the vtable's
 * send_unicast exercises the actual production path. net_cfg must outlive ctx. */
static const net_transport_t *open_udp(net_transport_ctx_t **out_ctx,
                                       network_config_t *net_cfg,
                                       const char *cidr, int base)
{
    const net_transport_t *t = net_transport_find("udp_net_4");
    if (t == NULL)
        return NULL;
    memset(net_cfg, 0, sizeof(*net_cfg));
    snprintf(net_cfg->ip4_cidr, sizeof(net_cfg->ip4_cidr), "%s", cidr);
    snprintf(net_cfg->mcast4_addr, sizeof(net_cfg->mcast4_addr), "%s",
             DEFAULT_MCAST4_ADDR);
    net_cfg->port = base;

    net_transport_params_t params = {
        .net_cfg   = net_cfg,
        .logger    = &test_logger,
        .port_base = base,
        .myself    = NULL,
        .proc      = NULL,
    };
    if (t->open(out_ctx, &params) != 0)
        return NULL;
    return t;
}

DEFINE_TEST(test_udp_send_unicast_carries_our_address)
{
    /* The end-to-end pin. The send functions are static, so testing the helper
     * alone would let someone delete the call from the send path with every
     * test still green -- this drives the real vtable instead. A node
     * configured on ADDR_B must be SEEN as ADDR_B by the peer it dials. */
    if (!aliases_available())
        return;

    /* Listener stands in for the peer's recv_ptp socket. */
    int rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ck_assert(rx != -1);
    int one = 1;
    setsockopt(rx, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    me.sin_port = 0;
    inet_pton(AF_INET, ADDR_A, &me.sin_addr);
    ck_assert_ret_ok(bind(rx, (struct sockaddr *)&me, sizeof(me)));
    int peer_port = bound_port(rx);

    network_config_t net_cfg;
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_udp(&ctx, &net_cfg, ADDR_B "/8", 31700);
    if (t == NULL) {
        close(rx);
        return;  /* could not bind the transport here; nothing to assert */
    }
    /* The address was cached off the same derivation the recv binds used. */
    ck_assert_str_eq(ctx->local_addr, ADDR_B);

    const uint8_t wire[] = "announce";
    ck_assert_ret_ok(t->send_unicast(ctx, wire, sizeof(wire) - 1,
                                     ADDR_A, peer_port));

    struct sockaddr_in from = {0};
    socklen_t flen = sizeof(from);
    char buf[32];
    ssize_t got = recvfrom(rx, buf, sizeof(buf), 0,
                           (struct sockaddr *)&from, &flen);
    ck_assert(got == (ssize_t)(sizeof(wire) - 1));
    char seen[IPV4_ADDR_LEN] = {0};
    inet_ntop(AF_INET, &from.sin_addr, seen, sizeof(seen));
    /* Before the fix this read 127.0.0.1 and find_by_address missed. */
    ck_assert_str_eq(seen, ADDR_B);

    t->close(ctx);
    close(rx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tcp_send_unicast_carries_our_address)
{
    /* Same pin for the other transport. tcp_send_to is static and reached only
     * via tcp_send_unicast, so this drives the vtable. Single-threaded is fine:
     * the kernel completes the handshake into the listen backlog, so
     * send_unicast returns without anyone having accepted yet. */
    if (!aliases_available())
        return;
    const net_transport_t *t = net_transport_find("tcp_net_4");
    if (t == NULL)
        return;

    /* Listener stands in for the peer's accepting socket. */
    int rx = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert(rx != -1);
    int one = 1;
    setsockopt(rx, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    me.sin_port = 0;
    inet_pton(AF_INET, ADDR_A, &me.sin_addr);
    ck_assert_ret_ok(bind(rx, (struct sockaddr *)&me, sizeof(me)));
    struct sockaddr_in got = {0};
    socklen_t glen = sizeof(got);
    ck_assert_ret_ok(getsockname(rx, (struct sockaddr *)&got, &glen));
    int peer_port = ntohs(got.sin_port);
    ck_assert_ret_ok(listen(rx, 8));

    network_config_t net_cfg;
    memset(&net_cfg, 0, sizeof(net_cfg));
    snprintf(net_cfg.ip4_cidr, sizeof(net_cfg.ip4_cidr), "%s", ADDR_B "/8");
    snprintf(net_cfg.mcast4_addr, sizeof(net_cfg.mcast4_addr), "%s",
             DEFAULT_MCAST4_ADDR);
    net_cfg.port = 31800;
    net_transport_params_t params = {
        .net_cfg   = &net_cfg,
        .logger    = &test_logger,
        .port_base = 31800,
        .myself    = NULL,
        .proc      = NULL,
    };
    net_transport_ctx_t *ctx = NULL;
    if (t->open(&ctx, &params) != 0) {
        close(rx);
        return;  /* could not bind the transport here; nothing to assert */
    }
    ck_assert_str_eq(ctx->local_addr, ADDR_B);

    const uint8_t wire[] = "announce";
    ck_assert_ret_ok(t->send_unicast(ctx, wire, sizeof(wire) - 1,
                                     ADDR_A, peer_port));

    struct sockaddr_in from = {0};
    socklen_t flen = sizeof(from);
    int conn = accept(rx, (struct sockaddr *)&from, &flen);
    ck_assert(conn != -1);
    char seen[IPV4_ADDR_LEN] = {0};
    inet_ntop(AF_INET, &from.sin_addr, seen, sizeof(seen));
    /* Before the fix this read 127.0.0.1. */
    ck_assert_str_eq(seen, ADDR_B);

    close(conn);
    t->close(ctx);
    close(rx);
}
END_TEST_DEFINITION()

RUN_TESTS(NetSourceBind,
          test_binds_requested_address_on_ephemeral_port,
          test_never_sets_so_reuseaddr,
          test_skips_wildcard_and_unset,
          test_bind_failure_is_not_fatal,
          test_stream_sets_bind_address_no_port,
          test_autobind_never_takes_the_listening_port,
          test_explicit_collision_refused_without_reuseaddr,
          test_peer_observes_our_configured_address,
          test_udp_send_unicast_carries_our_address,
          test_tcp_send_unicast_carries_our_address)
