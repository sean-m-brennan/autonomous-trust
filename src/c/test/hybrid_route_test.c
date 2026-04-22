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
 * @file hybrid_route_test.c
 * @brief Unit tests for hybrid_route() — pure matcher logic, no transports
 *        need to be opened.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "network/net_transport_hybrid.h"

/* Compact programmatic init — fills an inner slot without repeating
 * snprintf boilerplate in every test. @p cidr or @p kind may be NULL
 * to leave the corresponding field empty. */
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

/* ----- UDP+DTN gateway (typical at-over-dtn.md §4.3 shape) ----- */

DEFINE_TEST(test_route_udp_plus_dtn_local_ipv4)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24", false, false);
    set_inner(&cfg.inners[1], "dtn_bp",    NULL,          true,  true);

    /* 10.0.0.5 is in the local CIDR → udp */
    ck_assert_int_eq(hybrid_route(&cfg, "10.0.0.5", NULL), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_udp_plus_dtn_eid_targets_dtn)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24", false, false);
    set_inner(&cfg.inners[1], "dtn_bp",    NULL,          true,  true);

    ck_assert_int_eq(hybrid_route(&cfg, "dtn://at-abcd/peer", NULL), 1);
    ck_assert_int_eq(hybrid_route(&cfg, "ipn:42.1",          NULL), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_udp_plus_dtn_unknown_falls_through_to_default)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24", false, false);
    set_inner(&cfg.inners[1], "dtn_bp",    NULL,          true,  true);

    /* 192.168.x.y not in CIDR, not an EID → default (dtn) */
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.1.10", NULL), 1);
}
END_TEST_DEFINITION()

/* ----- Two IP inners on different CIDRs (multi-homed gateway) ----- */

DEFINE_TEST(test_route_two_ipv4_cidrs_picks_matching_leg)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24",   false, false);
    set_inner(&cfg.inners[1], "udp_net_4", "172.20.0.0/16", false, false);

    ck_assert_int_eq(hybrid_route(&cfg, "10.0.0.50",   NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "172.20.5.10", NULL), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_no_match_no_default_returns_neg1)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 2;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24",   false, false);
    set_inner(&cfg.inners[1], "udp_net_4", "172.20.0.0/16", false, false);

    /* Neither CIDR matches; no default → -1 */
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.1.10",    NULL), -1);
    ck_assert_int_eq(hybrid_route(&cfg, "dtn://at-x/peer", NULL), -1);
}
END_TEST_DEFINITION()

/* ----- CIDR edge cases ----- */

DEFINE_TEST(test_route_cidr_exact_edge_addresses)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 1;
    set_inner(&cfg.inners[0], "udp_net_4", "192.168.1.0/24", false, false);

    /* Network addr and broadcast addr both inside the CIDR. */
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.1.0",   NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.1.255", NULL), 0);
    /* Just outside on either side. */
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.0.255", NULL), -1);
    ck_assert_int_eq(hybrid_route(&cfg, "192.168.2.0",   NULL), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_cidr_full_slash0)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 1;
    set_inner(&cfg.inners[0], "udp_net_4", "0.0.0.0/0", false, false);

    ck_assert_int_eq(hybrid_route(&cfg, "1.2.3.4",         NULL), 0);
    ck_assert_int_eq(hybrid_route(&cfg, "255.255.255.255", NULL), 0);
    /* EIDs still not matched by a CIDR rule. */
    ck_assert_int_eq(hybrid_route(&cfg, "dtn://x/",        NULL), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_first_match_wins)
{
    hybrid_config_t cfg = {0};
    cfg.n_inners = 3;
    /* Both inners 0 and 1 would match 10.0.0.5 — inner 0 wins. */
    set_inner(&cfg.inners[0], "tcp_net_4", "10.0.0.0/24", false, false);
    set_inner(&cfg.inners[1], "udp_net_4", "10.0.0.0/8",  false, false);
    set_inner(&cfg.inners[2], "dtn_bp",    NULL,          true,  true);

    ck_assert_int_eq(hybrid_route(&cfg, "10.0.0.5",  NULL), 0);
    /* 10.99.0.1 only matches the broader /8. */
    ck_assert_int_eq(hybrid_route(&cfg, "10.99.0.1", NULL), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_route_null_inputs_safe)
{
    /* Defensive: NULL config and NULL target should return -1 cleanly. */
    ck_assert_int_eq(hybrid_route(NULL, "10.0.0.5", NULL), -1);

    hybrid_config_t cfg = {0};
    cfg.n_inners = 1;
    set_inner(&cfg.inners[0], "udp_net_4", "10.0.0.0/24", false, false);
    ck_assert_int_eq(hybrid_route(&cfg, NULL, NULL), -1);
}
END_TEST_DEFINITION()

RUN_TESTS(Hybrid_Route,
          test_route_udp_plus_dtn_local_ipv4,
          test_route_udp_plus_dtn_eid_targets_dtn,
          test_route_udp_plus_dtn_unknown_falls_through_to_default,
          test_route_two_ipv4_cidrs_picks_matching_leg,
          test_route_no_match_no_default_returns_neg1,
          test_route_cidr_exact_edge_addresses,
          test_route_cidr_full_slash0,
          test_route_first_match_wins,
          test_route_null_inputs_safe)
