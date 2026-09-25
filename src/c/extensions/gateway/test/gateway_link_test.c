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

/* libat_gateway present after link (FEATURE_SPLIT_PLAN Phase 2): with the
 * extension linked whole, its constructor has registered the "gateway"
 * extension -- and that alone changes nothing. The "envelope" filter goes in
 * only when the node's network config sets "envelope": true, because the
 * envelope changes the wire format for the whole cohort. net_filter_test
 * asserts the converse, that a core-only binary refuses such a config. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>

#include "at_gateway.h"
#include "net_envelope.h"
#include "network/net_filter.h"
#include "network/network.h"
#include "processes/extension.h"
#include "structures/map.h"
#include "processes/processes.h"

/* What network_run does between its transport opening and its receivers
 * starting: let the extensions register, then check the config. */
static int network_start(const network_config_t *cfg)
{
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    proc.conf.data_struct = (void *)cfg;
    int rc = at_extensions_register_handlers(&proc, "network");
    if (rc != 0)
        return rc;
    return net_filters_check_config(cfg, NULL);
}

DEFINE_TEST(test_linked_but_unconfigured_installs_nothing)
{
    at_extensions_reset();
    ck_assert(at_extension_count() >= 1);

    network_config_t cfg = { .port = 27787 };
    ck_assert_int_eq(network_start(&cfg), 0);
    ck_assert(!net_filter_installed(NET_FILTER_ENVELOPE));

    /* Other processes' registration never installs it either. */
    cfg.envelope = true;
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    proc.conf.data_struct = &cfg;
    /* A real handler map: an always-on extension linked into this binary (the
     * social one in a social build) registers its verbs on "identity". */
    ck_assert_int_eq(map_create(&proc.protocol.handlers), 0);
    ck_assert_int_eq(at_extensions_register_handlers(&proc, "identity"), 0);
    ck_assert(!net_filter_installed(NET_FILTER_ENVELOPE));
    at_gateway_link();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_envelope_config_installs_filter)
{
    at_extensions_reset();
    network_config_t cfg = { .port = 27787, .envelope = true,
                             .group_forward = true, .cross_cluster = true };
    ck_assert_int_eq(network_start(&cfg), 0);
    ck_assert(net_filter_installed(NET_FILTER_ENVELOPE));

    /* A second network start in the same process keeps the one filter. */
    ck_assert_int_eq(network_start(&cfg), 0);
    ck_assert(net_filter_installed(NET_FILTER_ENVELOPE));

    /* The extension's reset empties the chain. */
    at_extensions_reset();
    ck_assert(!net_filter_installed(NET_FILTER_ENVELOPE));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_installed_filter_wraps_and_refuses_without_identity)
{
    at_extensions_reset();
    network_config_t cfg = { .port = 27787, .envelope = true };
    ck_assert_int_eq(network_start(&cfg), 0);

    uuid_t me, peer;
    memset(me, 0x11, sizeof(me));
    memset(peer, 0x22, sizeof(peer));
    const uint8_t payload[] = "inner-frame";
    const size_t plen = sizeof(payload) - 1;

    /* A PEER send gains the 36-byte header naming both ends. */
    net_send_info_t info = { .channel = NET_CHAN_PEER, .src_uuid = me, .dst_uuid = peer };
    uint8_t *out = NULL;
    size_t out_len = 0;
    ck_assert_int_eq(net_filters_outbound(&info, payload, plen, &out, &out_len), 0);
    ck_assert(out != payload);
    ck_assert_int_eq((int)out_len, (int)(NET_ENV_HEADER_LEN + plen));
    net_envelope_t env;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    ck_assert_int_eq(net_envelope_unpack(out, out_len, &env, &inner, &inner_len), 0);
    ck_assert_int_eq(env.type, NET_ENV_TYPE_PEER);
    ck_assert_mem_eq(env.src_uuid, me, 16);
    ck_assert_mem_eq(env.dst_uuid, peer, 16);
    ck_assert_int_eq((int)inner_len, (int)plen);
    ck_assert_mem_eq(inner, payload, plen);
    free(out);

    /* A broadcast carries the NIL destination. */
    uuid_t nil = {0};
    info = (net_send_info_t){ .channel = NET_CHAN_BROADCAST, .src_uuid = me };
    ck_assert_int_eq(net_filters_outbound(&info, payload, plen, &out, &out_len), 0);
    ck_assert_int_eq(net_envelope_unpack(out, out_len, &env, &inner, &inner_len), 0);
    ck_assert_int_eq(env.type, NET_ENV_TYPE_BROADCAST);
    ck_assert_mem_eq(env.dst_uuid, nil, 16);
    free(out);

    /* No identity yet: refused, where the compiled-in wrap dereferenced it. */
    info = (net_send_info_t){ .channel = NET_CHAN_PEER, .src_uuid = NULL, .dst_uuid = peer };
    out = NULL;
    ck_assert_int_eq(net_filters_outbound(&info, payload, plen, &out, &out_len), -1);
    ck_assert_ptr_null(out);

    at_extensions_reset();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_switches_without_envelope_refused)
{
    /* The library is present, but the invariant the build used to enforce
     * is now the config's: group_forward / cross_cluster need the envelope. */
    at_extensions_reset();
    network_config_t cfg = { .port = 27787, .group_forward = true };
    ck_assert_int_eq(network_start(&cfg), -1);
    cfg = (network_config_t){ .port = 27787, .cross_cluster = true };
    ck_assert_int_eq(network_start(&cfg), -1);
    ck_assert(!net_filter_installed(NET_FILTER_ENVELOPE));
}
END_TEST_DEFINITION()

RUN_TESTS(GatewayLink, test_linked_but_unconfigured_installs_nothing,
          test_envelope_config_installs_filter,
          test_installed_filter_wraps_and_refuses_without_identity,
          test_switches_without_envelope_refused)
