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
 * @file hybrid_route6_test.c
 * @brief IPv6 CIDR matching in hybrid_route — kept separate from the
 *        v4/EID tests to stay under the 9-arg RUN_TESTS cap.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "network/net_transport_hybrid.h"

static void set_inner(hybrid_inner_t *in,
                      const char *kind, const char *cidr,
                      bool eid, bool is_default)
{
    memset(in, 0, sizeof(*in));
    if (kind) snprintf(in->kind,       sizeof(in->kind),       "%s", kind);
    if (cidr) snprintf(in->match_cidr, sizeof(in->match_cidr), "%s", cidr);
    in->match_eid  = eid;
    in->is_default = is_default;
}

DEFINE_TEST(test_route_ipv6_exact_and_prefix_matches)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_6", "2001:db8::/32",   false, false);
    set_inner(&cfg.inners[1], "dtn_bp",    NULL,              true,  true);

    /* Target in the 2001:db8::/32 prefix → inner 0. */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8:1234::5", NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8::1",      NULL), 0);

    /* Target outside the prefix, not EID → default (dtn). */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db9::1",      NULL), 1);
    ck_assert_int_eq(hybrid_route(&cfg, "fe80::1",          NULL), 1);

    /* EID prefix routes to DTN inner. */
    ck_assert_int_eq(hybrid_route(&cfg, "dtn://at-xyz/peer", NULL), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_ipv6_two_cidrs_picks_matching_leg)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_6", "2001:db8:a::/48", false, false);
    set_inner(&cfg.inners[1], "udp_net_6", "2001:db8:b::/48", false, false);

    /* Each leg wins its own subnet. */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8:a:1::1", NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8:b:2::2", NULL), 1);
    /* A prefix that matches neither → no default → -1. */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8:c:3::3", NULL), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_ipv6_prefix_boundaries)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 1;

    /* /128 — exact-match only. */
    set_inner(&cfg.inners[0], "udp_net_6", "fe80::1/128", false, false);
    ck_assert_int_eq(hybrid_route(&cfg, "fe80::1", NULL),  0);
    ck_assert_int_eq(hybrid_route(&cfg, "fe80::2", NULL), -1);

    /* /0 — matches any v6. */
    set_inner(&cfg.inners[0], "udp_net_6", "::/0", false, false);
    ck_assert_int_eq(hybrid_route(&cfg, "::1",              NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8::a",      NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "ff02::1",          NULL), 0);
    /* v4 target against a v6-only matcher → no match (correct isolation). */
    ck_assert_int_eq(hybrid_route(&cfg, "10.0.0.1",         NULL), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_mixed_v4_and_v6_cidrs_coexist)
{
    /* Gateway composing a v4 LAN inner, a v6 LAN inner, and a DTN
     * fallback — the hybrid must dispatch by target family. */
    hybrid_config_t cfg = {0};
    cfg.n_inners = 3;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24",     false, false);
    set_inner(&cfg.inners[1], "udp_net_6", "2001:db8::/32",   false, false);
    set_inner(&cfg.inners[2], "dtn_bp",    NULL,              true,  true);

    ck_assert_int_eq(hybrid_route(&cfg, "10.0.0.5",         NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db8:1::1",    NULL), 1);
    ck_assert_int_eq(hybrid_route(&cfg, "dtn://at-x/peer",  NULL), 2);
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.1.1",      NULL), 2);  /* default */
    ck_assert_int_eq(hybrid_route(&cfg, "fe80::2",          NULL), 2);  /* default */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_ipv6_odd_prefix_byte_boundary)
{
    /* /17 falls mid-byte: the first 16 bits must equal 2001 AND the
     * 17th bit (the HIGH bit of byte 2) must equal the CIDR's. For the
     * CIDR 2001:db80::/17, byte[2] high bit is 1 (0xdb & 0x80 == 0x80),
     * so targets whose byte[2] also has the high bit set match — and
     * anything with byte[2] < 0x80 does not. This test pins down that
     * partial-byte mask. */
    hybrid_config_t cfg = {0};
    cfg.n_inners = 1;
    set_inner(&cfg.inners[0], "udp_net_6", "2001:db80::/17", false, false);

    /* Hits: byte[2] has high bit set and first 16 bits = 2001. */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:db80::1",   NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:dbff:a::1", NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:8000::1",   NULL), 0);  /* low edge of half */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:ffff::1",   NULL), 0);  /* high edge */

    /* Misses: byte[2] < 0x80 → 17th bit is 0, different from the CIDR. */
    ck_assert_int_eq(hybrid_route(&cfg, "2001:7fff::1",   NULL), -1);
    ck_assert_int_eq(hybrid_route(&cfg, "2001:0080::1",   NULL), -1);
    /* Different first 16 bits — miss regardless of byte[2]. */
    ck_assert_int_eq(hybrid_route(&cfg, "2002:db80::1",   NULL), -1);
}
END_TEST_DEFINITION()

RUN_TESTS(Hybrid_Route_IPv6,
          test_route_ipv6_exact_and_prefix_matches,
          test_route_ipv6_two_cidrs_picks_matching_leg,
          test_route_ipv6_prefix_boundaries,
          test_route_mixed_v4_and_v6_cidrs_coexist,
          test_route_ipv6_odd_prefix_byte_boundary)
