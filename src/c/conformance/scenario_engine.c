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

#include "scenario_engine.h"

#include <stdio.h>
#include <string.h>

void sce_init(sce_run_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < SCE_MAX_STEPS; i++) {
        ctx->outbox_start[i] = -1;
        ctx->outbox_end[i] = -1;
    }
}

sce_participant_t *sce_find_participant(sce_run_ctx_t *ctx, const char *id) {
    if (ctx == NULL || id == NULL) return NULL;
    for (size_t i = 0; i < ctx->participant_count; i++) {
        if (strcmp(ctx->participants[i].id, id) == 0) {
            return &ctx->participants[i];
        }
    }
    return NULL;
}

void sce_capture(sce_run_ctx_t *ctx, const char *to_id, const char *function) {
    if (ctx == NULL) return;
    if (ctx->captured_count >= SCE_MAX_CAPTURED) return;
    sce_captured_t *cm = &ctx->captured[ctx->captured_count++];
    snprintf(cm->from, sizeof(cm->from), "%s", ctx->current_dispatcher);
    snprintf(cm->to, sizeof(cm->to), "%s", to_id ? to_id : "");
    snprintf(cm->function, sizeof(cm->function), "%s", function ? function : "");
}

/* ------------------------------------------------------------------------- */
/* Step drivers                                                               */
/* ------------------------------------------------------------------------- */

/* Build & dispatch an inbound to all matching targets. Records outbox bounds
 * for `step_id`. `repeat` controls how many times the same inbound is
 * dispatched — 1 for normal source steps, N for replay-idempotency probes.
 * The inbound is built once and dispatched N times (matches Python's
 * scenario_engine and a real network replay's "same wire bytes redelivered"
 * semantic). Outbox bounds wrap all N deliveries' captured emissions.
 * Returns 0 on success, -1 with ctx->err on dispatch failure. */
static int _build_and_deliver(sce_run_ctx_t *ctx, int step_id,
                              const char *from, const char *to,
                              const char *function, json_t *payload,
                              int repeat) {
    generic_msg_t inbound;
    if (ctx->build_inbound(ctx, from, to, function, payload, &inbound) != 0) {
        snprintf(ctx->err, sizeof(ctx->err),
                 "step %d: build_inbound(%s) failed", step_id, function);
        return -1;
    }

    ctx->outbox_start[step_id] = (int)ctx->captured_count;
    ctx->current_step_id = step_id;

    sce_participant_t *unicast_target = NULL;
    if (strcmp(to, "broadcast") != 0) {
        unicast_target = sce_find_participant(ctx, to);
        if (unicast_target == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "step %d: unknown participant to:%s", step_id, to);
            return -1;
        }
    }

    for (int rep = 0; rep < repeat; rep++) {
        if (unicast_target == NULL) {
            /* Deliver to every participant except `from`. */
            for (size_t i = 0; i < ctx->participant_count; i++) {
                if (strcmp(ctx->participants[i].id, from) == 0) continue;
                snprintf(ctx->current_dispatcher, sizeof(ctx->current_dispatcher),
                         "%s", ctx->participants[i].id);
                ctx->dispatch(ctx, &ctx->participants[i], &inbound);
            }
        } else {
            snprintf(ctx->current_dispatcher, sizeof(ctx->current_dispatcher),
                     "%s", unicast_target->id);
            ctx->dispatch(ctx, unicast_target, &inbound);
        }
    }
    ctx->outbox_end[step_id] = (int)ctx->captured_count;
    return 0;
}

static int _drive_source(sce_run_ctx_t *ctx, json_t *step) {
    int sid = (int)json_integer_value(json_object_get(step, "id"));
    const char *from = json_string_value(json_object_get(step, "from"));
    const char *to = json_string_value(json_object_get(step, "to"));
    const char *function = json_string_value(json_object_get(step, "function"));
    json_t *payload = json_object_get(step, "payload");
    if (sid <= 0 || sid >= SCE_MAX_STEPS || from == NULL || to == NULL || function == NULL) {
        snprintf(ctx->err, sizeof(ctx->err), "source step missing required field");
        return -1;
    }
    int repeat = 1;
    json_t *rep_j = json_object_get(step, "repeat");
    if (json_is_integer(rep_j)) {
        int rv = (int)json_integer_value(rep_j);
        if (rv >= 1) repeat = rv;
    }
    return _build_and_deliver(ctx, sid, from, to, function, payload, repeat);
}

static int _drive_assertion(sce_run_ctx_t *ctx, json_t *step, int in_resp) {
    int sid = (int)json_integer_value(json_object_get(step, "id"));
    const char *from = json_string_value(json_object_get(step, "from"));
    const char *to = json_string_value(json_object_get(step, "to"));
    const char *function = json_string_value(json_object_get(step, "function"));
    if (sid <= 0 || sid >= SCE_MAX_STEPS || from == NULL || to == NULL || function == NULL) {
        snprintf(ctx->err, sizeof(ctx->err), "assertion step missing required field");
        return -1;
    }
    if (in_resp <= 0 || in_resp >= SCE_MAX_STEPS || ctx->outbox_start[in_resp] < 0) {
        snprintf(ctx->err, sizeof(ctx->err),
                 "step %d: in_response_to %d not yet run", sid, in_resp);
        return -1;
    }

    /* Match against captured emissions in the parent step's outbox. The
     * "broadcast" relaxation goes both ways: a scenario asserting "to: X"
     * also matches a captured "broadcast" (since broadcasts reach X), and
     * a scenario asserting "to: broadcast" matches any captured to_id. */
    bool match = false;
    for (int i = ctx->outbox_start[in_resp]; i < ctx->outbox_end[in_resp]; i++) {
        const sce_captured_t *cm = &ctx->captured[i];
        if (strcmp(cm->from, from) != 0) continue;
        if (strcmp(cm->function, function) != 0) continue;
        if (strcmp(to, "broadcast") == 0
            || strcmp(cm->to, to) == 0
            || strcmp(cm->to, "broadcast") == 0) {
            match = true;
            break;
        }
    }
    if (!match) {
        char captured[256] = {0};
        size_t off = 0;
        for (int i = ctx->outbox_start[in_resp];
             i < ctx->outbox_end[in_resp] && off < sizeof(captured) - 32; i++) {
            const sce_captured_t *cm = &ctx->captured[i];
            int n = snprintf(captured + off, sizeof(captured) - off,
                             "%s%s->%s:%s",
                             off == 0 ? "" : ", ",
                             cm->from, cm->to, cm->function);
            if (n < 0) break;
            /* snprintf returns the would-be length, so clamp rather than let
             * off run past the buffer and underflow the next size argument. */
            if ((size_t)n >= sizeof(captured) - off) {
                off = sizeof(captured) - 1;
                break;
            }
            off += (size_t)n;
        }
        /* Precisions bound each interpolation to its field width (ids are
         * SCE_ID_LEN, functions SCE_FN_LEN, the list is `captured` above) so
         * the whole message provably fits in ctx->err. */
        snprintf(ctx->err, sizeof(ctx->err),
                 "step %d: expected %.31s->%.31s:%.63s in response to step %d; "
                 "outbox of step %d held [%.255s]",
                 sid, from, to, function, in_resp, in_resp,
                 captured[0] ? captured : "(empty)");
        return -1;
    }

    /* Optional no_propagate: skip delivery, just mark this step as having
     * an empty outbox so future assertions can reference it. */
    json_t *no_prop = json_object_get(step, "no_propagate");
    if (json_is_true(no_prop)) {
        ctx->outbox_start[sid] = (int)ctx->captured_count;
        ctx->outbox_end[sid] = (int)ctx->captured_count;
        return 0;
    }

    /* Propagate: deliver this step's message to its `to`. The payload comes
     * from the step's own payload field (mirroring Python engine, where
     * the captured raw message is delivered; here we re-build via the
     * adapter callback for type-safety). `repeat` is meaningless on an
     * assertion step (the inbound message is whatever the source emitted,
     * once), so pin to 1. */
    return _build_and_deliver(ctx, sid, from, to, function,
                              json_object_get(step, "payload"), 1);
}

static int _check_expected_state(sce_run_ctx_t *ctx) {
    json_t *exp = json_object_get(ctx->case_data, "expected_state");
    if (!json_is_object(exp)) return 0;
    /* The engine treats expected_state as advisory unless a future hook
     * registers per-protocol checks. Keeping this stub matches Python's
     * engine, which delegates to `_check_expected_state` on the participant
     * impl when the impl exposes one. C has no equivalent yet — wire it
     * via an additional ops callback if a scenario needs it. */
    (void)ctx;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Public driver                                                              */
/* ------------------------------------------------------------------------- */

int sce_run(sce_run_ctx_t *ctx) {
    if (ctx == NULL || ctx->case_data == NULL
        || ctx->build_inbound == NULL || ctx->dispatch == NULL) {
        if (ctx != NULL)
            snprintf(ctx->err, sizeof(ctx->err), "ctx not initialized");
        return -1;
    }

    json_t *steps_j = json_object_get(ctx->case_data, "steps");
    if (!json_is_array(steps_j)) {
        snprintf(ctx->err, sizeof(ctx->err), "scenario: steps array missing");
        return -1;
    }

    size_t n = json_array_size(steps_j);
    for (size_t i = 0; i < n; i++) {
        json_t *step = json_array_get(steps_j, i);
        json_t *in_resp_j = json_object_get(step, "in_response_to");
        int rc;
        if (json_is_integer(in_resp_j)) {
            rc = _drive_assertion(ctx, step, (int)json_integer_value(in_resp_j));
        } else {
            rc = _drive_source(ctx, step);
        }
        if (rc != 0) return -1;
    }
    return _check_expected_state(ctx);
}
