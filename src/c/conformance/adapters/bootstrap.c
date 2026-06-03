/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

/** @file Bootstrap-protocol adapter (kind: scenario, protocol: bootstrap).
 *
 *  Mirrors the Python BootstrapAdapter. Builds a bootstrap_worker_t from
 *  fixtures.bootstrap (seed, ticks, pairs_target, duration_sec), ticks it the
 *  requested number of times against a peer set sized from the participant
 *  list, then asserts the per-host observable (doc/architecture/trust-tiers.md
 *  §6.5). The contract is the RNG-agnostic coverage set — all three at.*
 *  caps fired — so the C and Python selection sequences need not match.
 */

#include "bootstrap.h"

#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include "bootstrap/bootstrap_worker.h"
#include "bootstrap/bootstrap_capabilities.h"

/* Invitation sink: the conformance pin observes counts_by_cap (owned by the
 * worker), so the sink need only accept the invitation. */
static bool _always_emit(void *ctx, const char *cap_name,
                         long nonce, const char *echo_payload) {
    (void)ctx; (void)cap_name; (void)nonce; (void)echo_payload;
    return true;
}

static long _int_field(json_t *obj, const char *key, long dflt) {
    json_t *v = json_object_get(obj, key);
    return json_is_integer(v) ? (long)json_integer_value(v) : dflt;
}

static double _num_field(json_t *obj, const char *key, double dflt) {
    json_t *v = json_object_get(obj, key);
    if (json_is_real(v)) return json_real_value(v);
    if (json_is_integer(v)) return (double)json_integer_value(v);
    return dflt;
}

void at_bootstrap_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C bootstrap adapter only handles kind:scenario (got %s)",
                 c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    json_t *data = c->data;
    json_t *fixtures = json_object_get(data, "fixtures");
    json_t *bs = json_is_object(fixtures)
                     ? json_object_get(fixtures, "bootstrap") : NULL;

    long   seed         = 12345;
    long   ticks        = 30;
    long   pairs_target = 0;
    double duration_sec = 999.0;
    if (json_is_object(bs)) {
        seed         = _int_field(bs, "seed", seed);
        ticks        = _int_field(bs, "ticks", ticks);
        pairs_target = _int_field(bs, "pairs_target", 0);
        duration_sec = _num_field(bs, "duration_sec", duration_sec);
    }
    if (pairs_target == 0)
        pairs_target = ticks;

    /* Host = the participant running the worker (role new_node), else the
     * first; peers = the rest. */
    json_t *parts = json_object_get(data, "participants");
    size_t nparts = json_is_array(parts) ? json_array_size(parts) : 0;
    const char *host_id = NULL;
    for (size_t i = 0; i < nparts; i++) {
        json_t *p = json_array_get(parts, i);
        const char *role = json_string_value(json_object_get(p, "role"));
        const char *id = json_string_value(json_object_get(p, "id"));
        if (host_id == NULL && id != NULL)
            host_id = id;                 /* fallback: first participant */
        if (role != NULL && strcmp(role, "new_node") == 0 && id != NULL) {
            host_id = id;
            break;
        }
    }
    size_t peer_count = (nparts > 0) ? (nparts - 1) : 0;

    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, duration_sec, (int)pairs_target,
                                 (uint64_t)seed, false);
    for (long t = 0; t < ticks; t++)
        bootstrap_worker_tick(&w, peer_count, 0.0, _always_emit, NULL);

    int caps_fired = 0;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        if (w.counts_by_cap[i] >= 1)
            caps_fired++;

    json_t *expected_state = json_object_get(data, "expected_state");
    json_t *host_exp = (host_id != NULL && json_is_object(expected_state))
                           ? json_object_get(expected_state, host_id) : NULL;
    if (json_is_object(host_exp)) {
        json_t *want = json_object_get(host_exp, "bootstrap_caps_fired");
        if (json_is_integer(want) && caps_fired != (int)json_integer_value(want)) {
            char detail[200];
            snprintf(detail, sizeof(detail),
                     "%s: bootstrap_caps_fired=%d, expected %d "
                     "(counts h=%d t=%d e=%d)",
                     host_id ? host_id : "?", caps_fired,
                     (int)json_integer_value(want),
                     w.counts_by_cap[0], w.counts_by_cap[1], w.counts_by_cap[2]);
            at_case_result_set_fail(out, 0, "AssertionError", detail);
            return;
        }
        want = json_object_get(host_exp, "pairs_issued");
        if (json_is_integer(want) && w.pairs_issued != (int)json_integer_value(want)) {
            char detail[200];
            snprintf(detail, sizeof(detail),
                     "%s: pairs_issued=%d, expected %d",
                     host_id ? host_id : "?", w.pairs_issued,
                     (int)json_integer_value(want));
            at_case_result_set_fail(out, 0, "AssertionError", detail);
            return;
        }
    }

    at_case_result_set_pass(out, 0);
}
