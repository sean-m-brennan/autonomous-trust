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
 * @file dtn_backend_stub.c
 * @brief No-op DTN backend — lets AT_NET_DTN=ON build without a BP library.
 *
 * Selected via -DAT_NET_DTN_BACKEND=stub. All sends succeed silently (the
 * bundle is dropped); recv always times out with ENOMSG. Useful for
 * mechanical validation of the transport scaffolding and DTN code paths
 * without linking ION or uD3TN.
 */

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "network/dtn/dtn_backend.h"

/* Frama-C: skipped — [solver-timeout] stub_init: single at_logging precondition cascade. */
static int stub_init(const dtn_endpoint_t *endpoints, size_t n_endpoints,
                     logger_t *logger)
{
    for (size_t i = 0; i < n_endpoints; i++) {
        log_info(logger, "DTN[stub]: init endpoint[%zu] eid=%s service=%s (no real BP agent)\n",
                 i,
                 endpoints[i].eid ? endpoints[i].eid : "(null)",
                 endpoints[i].service ? endpoints[i].service : "(null)");
    }
    return 0;
}

static void stub_shutdown(void) { /* no-op */ }

static int stub_send(const char *dest_eid,
                     const uint8_t *payload, size_t payload_len,
                     uint32_t lifetime_sec)
{
    (void)dest_eid; (void)payload; (void)payload_len; (void)lifetime_sec;
    return 0;  /* silently drop */
}

static int stub_recv(uint8_t **out_payload, size_t *out_len,
                     char *src_eid, size_t src_eid_len,
                     char *dest_service, size_t dest_service_len,
                     int timeout_ms)
{
    (void)out_payload; (void)out_len;
    (void)src_eid; (void)src_eid_len;
    (void)dest_service; (void)dest_service_len;
    /* Respect the caller's timeout so receiver threads don't busy-spin. */
    if (timeout_ms > 0)
        usleep((useconds_t)timeout_ms * 1000);
    return ENOMSG;
}

const dtn_backend_t dtn_backend = {
    .name     = "stub",
    .init     = stub_init,
    .shutdown = stub_shutdown,
    .send     = stub_send,
    .recv     = stub_recv,
};
