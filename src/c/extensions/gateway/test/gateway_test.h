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

#ifndef GATEWAY_TEST_H
#define GATEWAY_TEST_H

/* Turn the gateway on for a test the way a node does: set "envelope" in the
 * network config and let the extension registry install the filter at
 * "network start". The tests drive handle_inbound_* directly, so this stands
 * in for network_run's at_extensions_register_handlers(proc, "network").
 * Tests run CK_NOFORK in one process; a second call finds the filter already
 * installed and leaves it. */

#include "network/net_filter.h"
#include "network/network.h"
#include "processes/extension.h"
#include "processes/processes.h"

static inline void gateway_test_enable(process_t *proc, network_config_t *cfg)
{
    cfg->envelope = true;
    proc->conf.data_struct = cfg;
    ck_assert_int_eq(at_extensions_register_handlers(proc, "network"), 0);
    ck_assert(net_filter_installed(NET_FILTER_ENVELOPE));
}

#endif /* GATEWAY_TEST_H */
