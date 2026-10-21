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

/* libat_dtn present after link (FEATURE_SPLIT_PLAN §5.3): with the extension
 * linked whole, its constructors have added the "dtn_bp" transport and
 * process runner the core does not name. extension_test asserts the
 * converse, that a core-only binary has neither. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "processes/processes.h"
#include "network/net_transport.h"
#include "extensions/dtn/at_dtn.h"
#include "extensions/dtn/net_transport_dtn.h"

DEFINE_TEST(test_transport_registered)
{
    const net_transport_t *t = net_transport_find("dtn_bp");
    ck_assert_ptr_nonnull(t);
    ck_assert_str_eq(t->name, "dtn_bp");
    ck_assert_ptr_nonnull(t->open);
    /* The core transports are still found beside it. */
    ck_assert_ptr_nonnull(net_transport_find("udp_net_4"));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_process_runner_registered)
{
    ck_assert(find_process("dtn_bp") == network_dtn_bp_run);
    ck_assert_str_eq(find_process_name(network_dtn_bp_run), "dtn_bp");
    ck_assert(find_process("id_proc") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_second_registration_refused)
{
    /* The table already holds DTN's entries, so a repeat is refused. */
    ck_assert_int_eq(net_transport_register(net_transport_find("dtn_bp")), -1);
    ck_assert_int_eq(process_table_append("network", "dtn_bp", network_dtn_bp_run), -1);
    at_dtn_link();
}
END_TEST_DEFINITION()

RUN_TESTS(DtnLink, test_transport_registered, test_process_runner_registered,
          test_second_registration_refused)
