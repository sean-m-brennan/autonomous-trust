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

#ifndef DTN_BACKEND_H
#define DTN_BACKEND_H

/**
 * @file dtn_backend.h
 * @brief Abstract Bundle Protocol backend interface.
 *
 * net_transport_dtn.c talks to this interface only.  Concrete backends:
 *
 *   dtn_backend_stub.c  -- always-empty; compiles without any BP library
 *   dtn_backend_ion.c   -- NASA ION: bp_open/bp_send/bp_receive (TODO)
 *   dtn_backend_ud3tn.c -- uD3TN REST or AAP (TODO)
 *
 * Exactly one backend .c file is compiled per build; the CMake option
 * AT_NET_DTN_BACKEND selects which.  All backends provide the same
 * symbol `dtn_backend` — a `const dtn_backend_t` — so net_transport_dtn.c
 * does not need to know which is active.
 */

#include <stddef.h>
#include <stdint.h>

#include "utilities/logger.h"

/** One of the endpoints the backend should register with the BPA. */
typedef struct dtn_endpoint_s {
    const char *eid;      /**< Full EID to register, e.g. "dtn://at-abc/peer". */
    const char *service;  /**< Service suffix used for channel demux on recv,
                               e.g. "/peer", "/bcast", "/group". The backend
                               must echo this string back in @p dest_service
                               when a bundle arrives at the matching eid. */
} dtn_endpoint_t;

typedef struct dtn_backend_s {
    const char *name;  /**< "stub" | "ion" | "ud3tn" */

    /**
     * @brief Register @p n_endpoints local EIDs with the BP agent.
     *
     * The first endpoint is treated as the "primary" — it is the source
     * EID for outbound sends. Each additional endpoint is opened with
     * its own inbound reader so AT's three logical channels (peer/bcast/
     * group) can all receive.
     *
     * @return 0 on success, negative if any endpoint failed to register.
     */
    int (*init)(const dtn_endpoint_t *endpoints, size_t n_endpoints,
                logger_t *logger);

    /** Tear down the backend. */
    void (*shutdown)(void);

    /**
     * @brief Submit a bundle with @p payload to @p dest_eid.
     *
     * The source EID is the primary endpoint supplied to init().
     * @param lifetime_sec  Bundle TTL (DTN store-carry-forward window).
     * @return 0 on successful submission to local BPA, negative on failure.
     */
    int (*send)(const char *dest_eid,
                const uint8_t *payload, size_t payload_len,
                uint32_t lifetime_sec);

    /**
     * @brief Block up to @p timeout_ms for an inbound bundle on any
     *        registered endpoint.
     *
     * On success: @p *out_payload is newly-allocated (caller frees) with
     * length @p *out_len; @p src_eid is filled with the sender's EID;
     * @p dest_service is filled with the @c service string of whichever
     * registered endpoint received the bundle, so the transport can route
     * to the right AT channel.
     *
     * Returns 0 on message, ENOMSG on timeout, negative on error.
     */
    int (*recv)(uint8_t **out_payload, size_t *out_len,
                char *src_eid, size_t src_eid_len,
                char *dest_service, size_t dest_service_len,
                int timeout_ms);
} dtn_backend_t;

/** The active backend — resolved at link time by exactly one backend file. */
extern const dtn_backend_t dtn_backend;

#endif /* DTN_BACKEND_H */
