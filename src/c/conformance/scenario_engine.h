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

#ifndef AT_CONFORMANCE_SCENARIO_ENGINE_H
#define AT_CONFORMANCE_SCENARIO_ENGINE_H

/** @file Universal scenario engine for the C harness.
 *
 *  Mirror of `harness/python/scenario_engine.py`. Walks scenario steps from
 *  parsed JSON, treats each as a source step (no `in_response_to`) or an
 *  assertion step (`in_response_to: N`), captures per-participant outbox
 *  via an adapter-installed hook, and matches assertions against the
 *  captured outbox.
 *
 *  Each protocol adapter provides:
 *   - `build_inbound`: translate (from, to, function, payload) to a
 *     `generic_msg_t` ready for the protocol's handler.
 *   - `dispatch`: hand the inbound to the named participant. Typically
 *     `run_message_handlers(target->impl, queues, NET_MESSAGE, &msg)`.
 *
 *  The adapter also installs a `messaging_set_test_hook` that calls
 *  @ref sce_capture for every emitted message during dispatch.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "utilities/message.h"  /* generic_msg_t */

#define SCE_MAX_PARTICIPANTS  8
#define SCE_MAX_STEPS         64
#define SCE_MAX_CAPTURED      256
#define SCE_ID_LEN            32
#define SCE_FN_LEN            64

typedef struct sce_participant {
    char id[SCE_ID_LEN];
    char role[SCE_ID_LEN];
    void *impl;     /**< Protocol-specific (e.g. process_t * for identity). */
} sce_participant_t;

typedef struct {
    char from[SCE_ID_LEN];
    char to[SCE_ID_LEN];
    char function[SCE_FN_LEN];
} sce_captured_t;

typedef struct sce_run_ctx {
    json_t *case_data;
    sce_participant_t participants[SCE_MAX_PARTICIPANTS];
    size_t participant_count;

    /* Adapter callbacks. */
    int (*build_inbound)(struct sce_run_ctx *ctx,
                         const char *from_id,
                         const char *to_id,
                         const char *function,
                         json_t *payload,
                         generic_msg_t *out);
    int (*dispatch)(struct sce_run_ctx *ctx,
                    sce_participant_t *target,
                    generic_msg_t *inbound);

    /* Engine-managed state below — adapters should not write these. */
    sce_captured_t captured[SCE_MAX_CAPTURED];
    size_t captured_count;
    int outbox_start[SCE_MAX_STEPS];  /* -1 = step not run */
    int outbox_end[SCE_MAX_STEPS];
    char current_dispatcher[SCE_ID_LEN];
    int current_step_id;
    /* Wide enough for the longest diagnostic _drive_assertion builds: the
     * expected from->to:function triple plus a 256-byte list of what the
     * parent step's outbox actually held. */
    char err[512];
} sce_run_ctx_t;

/** Initialize internal bookkeeping (outbox indices, etc). Adapter should
 *  call this before populating participants/callbacks. */
void sce_init(sce_run_ctx_t *ctx);

/** Look up a participant by id, NULL if not found. */
sce_participant_t *sce_find_participant(sce_run_ctx_t *ctx, const char *id);

/** Append a captured outbound to the active step's outbox. Called by the
 *  adapter's messaging-hook implementation. `to_id` is the resolved
 *  participant id (or "broadcast"). Safe to call with ctx==NULL (no-op). */
void sce_capture(sce_run_ctx_t *ctx, const char *to_id, const char *function);

/** Run the scenario. Returns 0 on success, -1 on failure (ctx->err set).
 *  The case_data object must remain valid for the duration of the call. */
int sce_run(sce_run_ctx_t *ctx);

#endif /* AT_CONFORMANCE_SCENARIO_ENGINE_H */
