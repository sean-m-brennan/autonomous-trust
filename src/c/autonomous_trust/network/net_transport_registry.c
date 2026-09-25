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
 * @brief The network transports: the core's, plus any an extension adds.
 *
 * To add a core transport:
 *   1. Implement the net_transport_t vtable in net_transport_<name>.c
 *   2. Declare the `const net_transport_t` descriptor here (extern)
 *   3. Add it to the `transports[]` table below
 *   4. Register the runner with the process-declaration macro in net_proc.c
 *
 * To add one from an extension library (as src/c/extensions/dtn/ does):
 *   1. Implement the vtable in the library
 *   2. NET_TRANSPORT_REGISTER(tag, &descriptor) in the same file
 *   3. DEFINE_PROCESS(network, <name>, ...) for its runner
 *   4. Export a link anchor, so a static link keeps the object
 *
 * No core file needs to know about an extension's transport.
 */

#include <stdio.h>
#include <string.h>

#include "network/net_transport.h"

extern const net_transport_t udp_ip4_transport;
extern const net_transport_t udp_ip6_transport;
extern const net_transport_t tcp_ip4_transport;
extern const net_transport_t tcp_ip6_transport;
extern const net_transport_t hybrid_net_transport;

static const net_transport_t *const transports[] = {
    &udp_ip4_transport,
    &udp_ip6_transport,
    &tcp_ip4_transport,
    &tcp_ip6_transport,
    &hybrid_net_transport,
};

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * utilities/msg_registry.c. */
static const net_transport_t *registered[NET_TRANSPORT_EXT_MAX];
static size_t registered_len = 0;

const net_transport_t *net_transport_find(const char *name)
{
    if (name == NULL)
        return NULL;
    const size_t n = sizeof(transports) / sizeof(transports[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(transports[i]->name, name) == 0)
            return transports[i];
    }
    for (size_t i = 0; i < registered_len; i++) {
        if (strcmp(registered[i]->name, name) == 0)
            return registered[i];
    }
    return NULL;
}

int net_transport_register(const net_transport_t *t)
{
    if (t == NULL || t->name == NULL || t->name[0] == '\0') {
        fprintf(stderr, "net_transport_register: refusing an unnamed transport\n");
        return -1;
    }
    if (net_transport_find(t->name) != NULL) {
        fprintf(stderr, "net_transport_register: refusing %s: already registered\n",
                t->name);
        return -1;
    }
    if (registered_len >= NET_TRANSPORT_EXT_MAX) {
        fprintf(stderr, "net_transport_register: refusing %s: table full (%d)\n",
                t->name, NET_TRANSPORT_EXT_MAX);
        return -1;
    }
    registered[registered_len++] = t;
    return 0;
}
