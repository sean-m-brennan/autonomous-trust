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
 * @file net_transport_registry.c
 * @brief Compile-time table of available network transports.
 *
 * To add a new transport (e.g., DTN / Bundle Protocol):
 *   1. Implement the net_transport_t vtable in net_transport_<name>.c
 *   2. Declare the `const net_transport_t` descriptor here (extern)
 *   3. Add it to the `transports[]` table below, optionally guarded by a
 *      CMake option like AT_NET_DTN
 *   4. Register the runner with the process-declaration macro in net_proc.c
 *
 * No other file needs to know about the new transport.
 */

#include <string.h>

#include "network/net_transport.h"

extern const net_transport_t udp_ip4_transport;
extern const net_transport_t udp_ip6_transport;
extern const net_transport_t tcp_ip4_transport;
extern const net_transport_t tcp_ip6_transport;
extern const net_transport_t hybrid_net_transport;
#ifdef AT_NET_DTN
extern const net_transport_t dtn_bp_transport;
#endif

static const net_transport_t *const transports[] = {
    &udp_ip4_transport,
    &udp_ip6_transport,
    &tcp_ip4_transport,
    &tcp_ip6_transport,
    &hybrid_net_transport,
#ifdef AT_NET_DTN
    &dtn_bp_transport,
#endif
};

const net_transport_t *net_transport_find(const char *name)
{
    if (name == NULL)
        return NULL;
    const size_t n = sizeof(transports) / sizeof(transports[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(transports[i]->name, name) == 0)
            return transports[i];
    }
    return NULL;
}
