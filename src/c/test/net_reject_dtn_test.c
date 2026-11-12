/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/
/* The blacklist keys on an address with its CIDR suffix stripped. A DTN
 * endpoint ID (dtn:/ipn:) keeps its slashes: they are part of the address.
 * Cutting at the first one turned every EID into "dtn:", so excluding one DTN
 * peer dropped traffic from all of them, and readmitting one readmitted all.
 * Twin of Python test_net_reject_dtn.py. */
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdbool.h>

#include "network/net_proc_priv.h"

#define DTN_A "dtn://node-a/at"
#define DTN_B "dtn://node-b/at"
#define IPN_A "ipn:7.1"
#define IPN_B "ipn:9.1"

DEFINE_TEST(test_excluding_one_dtn_peer_leaves_another_alone)
{
    net_proc_test_reset_pests();
    net_proc_test_blacklist(DTN_A);
    ck_assert(net_proc_test_is_rejected(DTN_A));
    ck_assert(!net_proc_test_is_rejected(DTN_B));
    ck_assert(!net_proc_test_is_rejected("dtn:"));
    net_proc_test_reset_pests();
}

DEFINE_TEST(test_readmitting_one_dtn_peer_leaves_another_excluded)
{
    net_proc_test_reset_pests();
    net_proc_test_blacklist(DTN_A);
    net_proc_test_blacklist(DTN_B);
    net_proc_test_readmit(DTN_A);
    ck_assert(!net_proc_test_is_rejected(DTN_A));
    ck_assert(net_proc_test_is_rejected(DTN_B));
    net_proc_test_reset_pests();
}

DEFINE_TEST(test_excluding_one_ipn_peer_leaves_another_alone)
{
    net_proc_test_reset_pests();
    net_proc_test_blacklist(IPN_A);
    ck_assert(net_proc_test_is_rejected(IPN_A));
    ck_assert(!net_proc_test_is_rejected(IPN_B));
    net_proc_test_reset_pests();
}

DEFINE_TEST(test_annoyance_from_one_dtn_peer_blacklists_only_that_peer)
{
    net_proc_test_reset_pests();
    for (int i = 0; i <= NET_ANNOY_LIMIT; i++)
        net_proc_test_track_annoy(DTN_A);
    ck_assert(net_proc_test_is_rejected(DTN_A));
    ck_assert(!net_proc_test_is_rejected(DTN_B));
    net_proc_test_reset_pests();
}

DEFINE_TEST(test_an_ip_exclusion_still_strips_the_cidr_suffix)
{
    net_proc_test_reset_pests();
    net_proc_test_blacklist("10.0.0.1/24");
    ck_assert(net_proc_test_is_rejected("10.0.0.1"));
    ck_assert(net_proc_test_is_rejected("10.0.0.1/16"));
    ck_assert(!net_proc_test_is_rejected("10.0.0.2"));
    net_proc_test_readmit("10.0.0.1");
    ck_assert(!net_proc_test_is_rejected("10.0.0.1/24"));
    net_proc_test_reset_pests();
}

RUN_TESTS(NetRejectDtn,
          test_excluding_one_dtn_peer_leaves_another_alone,
          test_readmitting_one_dtn_peer_leaves_another_excluded,
          test_excluding_one_ipn_peer_leaves_another_alone,
          test_annoyance_from_one_dtn_peer_blacklists_only_that_peer,
          test_an_ip_exclusion_still_strips_the_cidr_suffix)
