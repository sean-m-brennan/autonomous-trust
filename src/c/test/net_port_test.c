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
 * @file net_port_test.c
 * @brief Base-port resolution and co-location of two nodes on one host.
 *
 * These assertions did not exist before. Every `.port =` in this test tree was
 * the literal 27787 (12 sites across 6 files) and network2_test.c round-trips
 * that literal, so nothing anywhere would have noticed a path that ignored the
 * configured value — which is how the config generator came to pin every
 * provisioned node to one port while the transports were already capable of
 * co-locating.
 *
 * Occupancy is probed with a socket that does NOT set SO_REUSEADDR. That is
 * deliberate: with the option set on both sockets this kernel permits two
 * binds to the identical addr:port and delivers every datagram to the LAST
 * binder (measured). A plain socket therefore reports occupancy truthfully
 * where a reuse socket would report nothing at all. See
 * test_same_base_same_address_binds_silently for that hazard, pinned.
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
#include <jansson.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "network/network.h"
#include "network/net_transport.h"
#include "config/generate.h"
#include "network/net_proc_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"

static logger_t test_logger;

/* Test seam in net_proc.c: the AT_COMM_PORT lookup is read-once-and-cached
 * (matching the other AT_* overrides), so one process needs this to exercise
 * more than one value. */
extern void net_port_resolve_reset(void);

/* Bind a plain UDP socket — no SO_REUSEADDR — purely to ask whether addr:port
 * is already taken. Returns the fd (caller closes) or -1 when occupied. */
static int probe_bind(const char *addr, int port)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = inet_addr(addr);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

static bool port_is_taken(const char *addr, int port)
{
    int s = probe_bind(addr, port);
    if (s < 0) return true;
    close(s);
    return false;
}

static void set_env_port(const char *val)
{
    if (val == NULL) unsetenv("AT_COMM_PORT");
    else setenv("AT_COMM_PORT", val, 1);
    net_port_resolve_reset();
}

/* Best-effort scratch-directory cleanup. The status is deliberately ignored:
 * these run before setup and after teardown, where a missing directory is the
 * expected case, not a failure. Consume the return value rather than casting
 * system() to void — gcc's warn_unused_result rejects a bare (void) cast. */
static void shell_cleanup(const char *cmd)
{
    int status = system(cmd);
    (void)status;
}

/* Open a UDP transport bound to `addr` on `base`. Returns the descriptor and
 * fills *out_ctx, or NULL on bind failure. net_cfg must outlive the ctx. */
static const net_transport_t *open_udp(net_transport_ctx_t **out_ctx,
                                       network_config_t *net_cfg,
                                       const char *cidr, int base)
{
    const net_transport_t *t = net_transport_find("udp_net_4");
    if (t == NULL) return NULL;
    memset(net_cfg, 0, sizeof(*net_cfg));
    snprintf(net_cfg->ip4_cidr, sizeof(net_cfg->ip4_cidr), "%s", cidr);
    snprintf(net_cfg->mcast4_addr, sizeof(net_cfg->mcast4_addr), "%s",
             DEFAULT_MCAST4_ADDR);
    net_cfg->port = base;

    net_transport_params_t params = {
        .net_cfg   = net_cfg,
        .logger    = &test_logger,
        .port_base = net_port_resolve(net_cfg->port, NULL, &test_logger),
        .myself    = NULL,
        .proc      = NULL,
    };
    if (t->open(out_ctx, &params) != 0)
        return NULL;
    return t;
}

/****************************
 * Resolution order
 ****************************/

DEFINE_TEST(test_resolve_default_when_nothing_set)
{
    set_env_port(NULL);
    net_port_source_t src = PORT_SRC_CONFIG;
    int port = net_port_resolve(0, &src, &test_logger);
    /* A single-node deployment with no knobs touched must see exactly the
     * numbers it saw before this resolver existed. */
    ck_assert_int_eq(port, 27787);
    ck_assert_int_eq(port, COMM_PORT);
    ck_assert_int_eq(src, PORT_SRC_DEFAULT);
    ck_assert_str_eq(net_port_source_name(src), "default");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_resolve_config_beats_env)
{
    set_env_port("31000");
    net_port_source_t src = PORT_SRC_DEFAULT;
    int port = net_port_resolve(28500, &src, &test_logger);
    ck_assert_int_eq(port, 28500);
    ck_assert_int_eq(src, PORT_SRC_CONFIG);
    ck_assert_str_eq(net_port_source_name(src), "config");
    set_env_port(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_resolve_env_applies_only_when_config_silent)
{
    set_env_port("31000");
    net_port_source_t src = PORT_SRC_DEFAULT;
    ck_assert_int_eq(net_port_resolve(0, &src, &test_logger), 31000);
    ck_assert_int_eq(src, PORT_SRC_ENV);
    ck_assert_str_eq(net_port_source_name(src), "AT_COMM_PORT");

    /* Bounds are usable, not merely non-crashing. */
    set_env_port("1024");
    ck_assert_int_eq(net_port_resolve(0, NULL, &test_logger), 1024);
    set_env_port("65534");
    ck_assert_int_eq(net_port_resolve(0, NULL, &test_logger), 65534);
    set_env_port(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_resolve_refuses_bad_env_and_never_yields_zero)
{
    /* Each of these must keep the default. Port 0 would ask the kernel for an
     * ephemeral port and put the node where no peer is looking — a silent
     * unreachable node is far worse than a refused override. */
    const char *bad[] = {
        "abc",      /* unparseable                      */
        "31000x",   /* trailing garbage                 */
        "",         /* present but empty                */
        "0",        /* the dangerous one                */
        "-1",       /* negative                         */
        "80",       /* privileged, unbindable unprivileged */
        "1023",     /* just below the floor             */
        "65535",    /* no room for the derived group port */
        "99999",    /* above the 16-bit space           */
        "2147483648", /* overflows long on some ABIs    */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        set_env_port(bad[i]);
        net_port_source_t src = PORT_SRC_CONFIG;
        int port = net_port_resolve(0, &src, &test_logger);
        ck_assert(port != 0);
        ck_assert_int_eq(port, COMM_PORT);
        ck_assert_int_eq(src, PORT_SRC_DEFAULT);
    }
    set_env_port(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_resolve_refuses_bad_config_and_falls_through)
{
    /* A configured value out of range must not be trusted just because it came
     * from the config layer; it falls through to the layers below. */
    set_env_port("31000");
    net_port_source_t src = PORT_SRC_CONFIG;
    ck_assert_int_eq(net_port_resolve(70000, &src, &test_logger), 31000);
    ck_assert_int_eq(src, PORT_SRC_ENV);

    set_env_port(NULL);
    ck_assert_int_eq(net_port_resolve(70000, &src, &test_logger), COMM_PORT);
    ck_assert_int_eq(src, PORT_SRC_DEFAULT);
    ck_assert_int_eq(net_port_resolve(-5, &src, &test_logger), COMM_PORT);
    ck_assert_int_eq(src, PORT_SRC_DEFAULT);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_resolved_port_always_leaves_room_for_group_port)
{
    const char *vals[] = {NULL, "1024", "31000", "65534", "65535", "abc"};
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        set_env_port(vals[i]);
        int port = net_port_resolve(0, NULL, &test_logger);
        ck_assert(port >= COMM_PORT_MIN);
        ck_assert(port <= COMM_PORT_MAX);
        ck_assert(port + 1 <= 65535);   /* the derived group port fits */
    }
    set_env_port(NULL);
}
END_TEST_DEFINITION()

/****************************
 * The configured value reaches the sockets
 ****************************/

DEFINE_TEST(test_non_default_port_reaches_every_socket)
{
    /* The assertion no test in this tree made: a config carrying a port other
     * than 27787 puts the peer socket on it and the group socket on +1, and
     * leaves the default pair alone. */
    const int base = 31500;
    ck_assert(!port_is_taken("127.0.0.1", base));
    ck_assert(!port_is_taken("127.0.0.1", base + 1));

    network_config_t net_cfg;
    net_transport_ctx_t *ctx = NULL;
    const net_transport_t *t = open_udp(&ctx, &net_cfg, "127.0.0.1/8", base);
    ck_assert(t != NULL);

    ck_assert(port_is_taken("127.0.0.1", base));
    ck_assert(port_is_taken("127.0.0.1", base + 1));
    /* And nothing landed on the compile-time default. */
    ck_assert(!port_is_taken("127.0.0.1", COMM_PORT));
    ck_assert(!port_is_taken("127.0.0.1", COMM_PORT + 1));

    t->close(ctx);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_env_port_reaches_every_socket_when_config_silent)
{
    const int base = 31600;
    set_env_port("31600");

    network_config_t net_cfg;
    net_transport_ctx_t *ctx = NULL;
    /* base 0 in the config => the resolver must supply the env value. */
    const net_transport_t *t = open_udp(&ctx, &net_cfg, "127.0.0.1/8", 0);
    ck_assert(t != NULL);
    ck_assert(port_is_taken("127.0.0.1", base));
    ck_assert(port_is_taken("127.0.0.1", base + 1));
    ck_assert(!port_is_taken("127.0.0.1", COMM_PORT));

    t->close(ctx);
    set_env_port(NULL);
}
END_TEST_DEFINITION()

/****************************
 * Two nodes, one host
 ****************************/

DEFINE_TEST(test_two_nodes_different_bases_coexist)
{
    /* This is what the whole slice is for: two C nodes on one host. */
    network_config_t cfg_a, cfg_b;
    net_transport_ctx_t *ctx_a = NULL, *ctx_b = NULL;

    const net_transport_t *ta = open_udp(&ctx_a, &cfg_a, "127.0.0.1/8", 31700);
    ck_assert(ta != NULL);
    const net_transport_t *tb = open_udp(&ctx_b, &cfg_b, "127.0.0.1/8", 31800);
    ck_assert(tb != NULL);

    /* Each holds its own pair, and the two pairs do not overlap. */
    ck_assert(port_is_taken("127.0.0.1", 31700));
    ck_assert(port_is_taken("127.0.0.1", 31701));
    ck_assert(port_is_taken("127.0.0.1", 31800));
    ck_assert(port_is_taken("127.0.0.1", 31801));

    tb->close(ctx_b);
    ta->close(ctx_a);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_two_nodes_same_base_different_addresses_coexist)
{
    /* The other co-location axis, and the one the Python diag harness already
     * uses (127.0.0.{base+i} on a shared comm_port). */
    network_config_t cfg_a, cfg_b;
    net_transport_ctx_t *ctx_a = NULL, *ctx_b = NULL;

    const net_transport_t *ta = open_udp(&ctx_a, &cfg_a, "127.0.0.2/8", 31900);
    ck_assert(ta != NULL);
    const net_transport_t *tb = open_udp(&ctx_b, &cfg_b, "127.0.0.3/8", 31900);
    ck_assert(tb != NULL);

    ck_assert(port_is_taken("127.0.0.2", 31900));
    ck_assert(port_is_taken("127.0.0.3", 31900));

    tb->close(ctx_b);
    ta->close(ctx_a);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_same_base_same_address_binds_silently)
{
    /* PINNING A KNOWN DEFECT, not endorsing it.
     *
     * Two nodes given the same base on the same address both bind and neither
     * is told. net_transport_ip.c sets SO_REUSEADDR on every bind, and with the
     * option on both sockets this kernel permits the duplicate and delivers
     * every datagram to the LAST binder — so the first node goes deaf with no
     * error anywhere. Measured, not assumed: without SO_REUSEADDR on both, the
     * second bind fails EADDRINUSE.
     *
     * This predates the port resolver and is not caused by it; the resolver is
     * what lets an operator avoid it by choosing distinct bases. Recorded in
     * ISSUES.md. If someone later makes a genuine collision loud (dropping
     * SO_REUSEADDR on the unicast sockets, or SO_REUSEPORT with an explicit
     * policy), this test is the one that should fail and be rewritten. */
    network_config_t cfg_a, cfg_b;
    net_transport_ctx_t *ctx_a = NULL, *ctx_b = NULL;

    const net_transport_t *ta = open_udp(&ctx_a, &cfg_a, "127.0.0.1/8", 32000);
    ck_assert(ta != NULL);
    const net_transport_t *tb = open_udp(&ctx_b, &cfg_b, "127.0.0.1/8", 32000);
    ck_assert(tb != NULL);   /* today: succeeds, silently */

    tb->close(ctx_b);
    ta->close(ctx_a);
}
END_TEST_DEFINITION()

/****************************
 * What the generator records
 ****************************/

DEFINE_TEST(test_generated_config_records_only_a_chosen_port)
{
    /* generate.c writes net_cfg.port only when the operator asked, which it
     * decides by asking the resolver whether the env layer supplied the value.
     * Assert that branch condition directly: it is the whole reason a
     * provisioned root no longer pins every node to 27787. */
    net_port_source_t src = PORT_SRC_CONFIG;

    set_env_port(NULL);
    net_port_resolve(0, &src, &test_logger);
    ck_assert(src != PORT_SRC_ENV);      /* => generator leaves port unset */

    set_env_port("31000");
    int asked = net_port_resolve(0, &src, &test_logger);
    ck_assert_int_eq(src, PORT_SRC_ENV);      /* => generator records 31000 */
    ck_assert_int_eq(asked, 31000);

    set_env_port("abc");
    net_port_resolve(0, &src, &test_logger);
    ck_assert(src != PORT_SRC_ENV);      /* a refused value is not "asked" */
    set_env_port(NULL);
}
END_TEST_DEFINITION()

/* Read the port out of a generated network config file, or -1 when the file
 * records none. Returns -2 if no config file was written at all. */
static int generated_port(const char *cfg_dir)
{
    static const char *names[] = {
        "network.cfg.json", "network.json", "network.cfg", "network",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cfg_dir, names[i]);
        json_error_t jerr;
        json_t *root = json_load_file(path, 0, &jerr);
        if (root == NULL) continue;
        json_t *p = json_object_get(root, "port");
        int out = (p == NULL) ? -1 : (int)json_integer_value(p);
        json_decref(root);
        return out;
    }
    return -2;
}

DEFINE_TEST(test_generator_writes_a_port_only_when_asked)
{
    /* Exercises generate_network_config() itself, not just the branch condition
     * it uses. This is the assertion that fails if the generator goes back to
     * writing COMM_PORT unconditionally — which is what pinned every
     * provisioned node to 27787 and made AT_COMM_PORT inert. */
    char dir_unset[] = "/tmp/at_netport_gen_unset";
    char dir_asked[] = "/tmp/at_netport_gen_asked";
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", dir_unset, dir_asked);
    shell_cleanup(cmd);
    ck_assert_ret_ok(mkdir(dir_unset, 0755));
    ck_assert_ret_ok(mkdir(dir_asked, 0755));

    set_env_port(NULL);
    int rc_unset = generate_network_config(dir_unset, false);

    /* Discovery needs a usable interface. If it is unavailable this test cannot
     * say anything, and must say so loudly rather than pass vacuously. */
    if (rc_unset != 0)
        fprintf(stderr, "generate_network_config failed (rc=%d): this test "
                        "cannot assert what the generator records\n", rc_unset);
    ck_assert(rc_unset == 0);
    int port_unset = generated_port(dir_unset);
    if (port_unset == -2)
        fprintf(stderr, "no network config file was written to %s\n", dir_unset);
    ck_assert(port_unset != -2);
    /* Nothing asked => nothing recorded, so the resolver's later layers apply. */
    ck_assert(port_unset == -1 || port_unset == 0);

    set_env_port("31234");
    ck_assert_ret_ok(generate_network_config(dir_asked, false));
    ck_assert_int_eq(generated_port(dir_asked), 31234);
    set_env_port(NULL);

    shell_cleanup(cmd);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_config_json_records_only_a_chosen_port)
{
    /* A config file should state only what someone actually chose. An unset
     * port is omitted rather than written as a literal 0, and a missing key
     * still reads back as unset, so the round trip is unchanged. */
    network_config_t unset = {0};
    snprintf(unset.ip4_cidr, sizeof(unset.ip4_cidr), "%s", "10.0.0.1/8");
    json_t *obj = NULL;
    ck_assert_ret_ok(network_to_json(&unset, &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert(json_object_get(obj, "port") == NULL);

    network_config_t back = {0};
    back.port = 12345;                 /* must be overwritten by the read */
    ck_assert_ret_ok(network_from_json(obj, &back));
    ck_assert_int_eq(back.port, 0);
    json_decref(obj);

    network_config_t chosen = {0};
    snprintf(chosen.ip4_cidr, sizeof(chosen.ip4_cidr), "%s", "10.0.0.1/8");
    chosen.port = 31000;
    json_t *obj2 = NULL;
    ck_assert_ret_ok(network_to_json(&chosen, &obj2));
    ck_assert_ptr_nonnull(obj2);
    json_t *p = json_object_get(obj2, "port");
    ck_assert(p != NULL);
    ck_assert_int_eq((int)json_integer_value(p), 31000);

    network_config_t back2 = {0};
    ck_assert_ret_ok(network_from_json(obj2, &back2));
    ck_assert_int_eq(back2.port, 31000);
    json_decref(obj2);
}
END_TEST_DEFINITION()

/****************************
 * PingAT / ntp are gone from C
 ****************************/

DEFINE_TEST(test_ping_at_selector_is_still_recognized)
{
    /* The selector name has to survive the deletion of the implementation:
     * the outbound drain matches on it to answer "unsupported" rather than
     * dropping the request and leaving a requester to time out. */
    ck_assert_str_eq(NET_FN_PING_AT, "ping_at");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ping_at_request_is_refused_on_its_own_selector)
{
    /* The requester gets an ANSWER, not silence. The reply deliberately rides
     * the same `ping_at` selector the requester is blocked on: a distinct
     * "unsupported" selector would be ignored by that caller, which would then
     * wait out its own timeout — the failure mode this refusal exists to avoid.
     *
     * This is local IPC (a co-process posting to process "network"), never a
     * wire path, so the assertion is on what lands in the return_to queue. */
    /* messaging binds a unix socket under <AUTONOMOUS_TRUST_ROOT>/var/at, so the
     * directory has to exist. CREATE it rather than skipping when it is absent:
     * a skipped test here would report the refusal as verified when nothing ran. */
    static char root[] = "/tmp/at_netport_msg";
    shell_cleanup("rm -rf /tmp/at_netport_msg && mkdir -p /tmp/at_netport_msg/var/at");
    ck_assert_ret_ok(setenv("AUTONOMOUS_TRUST_ROOT", root, 1));

    static char q_name[] = "netport.pingreq";
    queue_t mq;
    ck_assert_ret_ok(messaging_init(q_name, &mq));
    messaging_assign(&mq);   /* the sender needs a bound local socket */

    ck_assert_ret_ok(refuse_ping_at_unsupported("10.9.9.9", q_name, &test_logger));

    /* Poll rather than block: a missing reply must fail this test, not hang it.
     * (An AT test that hangs holds the harness's stdout pipe open.) */
    generic_msg_t recvd = {0};
    int rc = ENOMSG;
    for (int i = 0; i < 200 && rc != 0; i++) {
        rc = messaging_recv_on(&mq, &recvd, NULL, false);
        if (rc != 0) usleep(10000);
    }
    ck_assert_ret_ok(rc);
    ck_assert_int_eq(NET_MESSAGE, recvd.type);
    ck_assert_ptr_nonnull(recvd.info.net_msg.function);
    /* Same selector the requester is waiting on. */
    ck_assert_str_eq(recvd.info.net_msg.function, NET_FN_PING_AT);
    ck_assert_str_eq(recvd.info.net_msg.process, "network");
    ck_assert(!recvd.info.net_msg.encrypt);

    /* And the body says why, rather than looking like a result. */
    ck_assert_ptr_nonnull(recvd.info.net_msg.obj);
    char body[512] = {0};
    size_t n = recvd.info.net_msg.len < sizeof(body) - 1
                 ? recvd.info.net_msg.len : sizeof(body) - 1;
    memcpy(body, recvd.info.net_msg.obj, n);
    json_error_t jerr;
    json_t *parsed = json_loads(body, 0, &jerr);
    ck_assert_ptr_nonnull(parsed);
    ck_assert_str_eq(json_string_value(json_object_get(parsed, "error")),
                     "unsupported");
    /* No latency figures, no loss ratio — nothing a caller could mistake for
     * a completed PingAT. */
    ck_assert_ptr_null(json_object_get(parsed, "avg_rtt"));
    ck_assert_ptr_null(json_object_get(parsed, "loss"));
    ck_assert_str_eq(json_string_value(json_object_get(parsed, "host")),
                     "10.9.9.9");
    json_decref(parsed);

    messaging_close();
    shell_cleanup("rm -rf /tmp/at_netport_msg");
}
END_TEST_DEFINITION()

RUN_TESTS(NetPort,
          test_resolve_default_when_nothing_set,
          test_resolve_config_beats_env,
          test_resolve_env_applies_only_when_config_silent,
          test_resolve_refuses_bad_env_and_never_yields_zero,
          test_resolve_refuses_bad_config_and_falls_through,
          test_resolved_port_always_leaves_room_for_group_port,
          test_non_default_port_reaches_every_socket,
          test_env_port_reaches_every_socket_when_config_silent,
          test_two_nodes_different_bases_coexist,
          test_two_nodes_same_base_different_addresses_coexist,
          test_same_base_same_address_binds_silently,
          test_generated_config_records_only_a_chosen_port,
          test_generator_writes_a_port_only_when_asked,
          test_config_json_records_only_a_chosen_port,
          test_ping_at_selector_is_still_recognized,
          test_ping_at_request_is_refused_on_its_own_selector)
