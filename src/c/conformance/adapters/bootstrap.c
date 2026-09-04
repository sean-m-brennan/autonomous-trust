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

#include <math.h>
#include <stdlib.h>

#include "bootstrap/bootstrap_worker.h"
#include "bootstrap/bootstrap_capabilities.h"
#include "negotiation/task.h"          /* TASK_KWARGS_LEN */
#include "negotiation/neg_proc_priv.h" /* negotiation_score_task_result */
#include "processes/capabilities.h"    /* CAP_RESULT_LEN */

/* Invitation sink: the conformance pin observes counts_by_cap (owned by the
 * worker), so the sink need only accept the invitation. */
static bool _always_emit(void *ctx, const char *cap_name,
                         long nonce, const char *echo_payload) {
    (void)ctx; (void)cap_name; (void)nonce; (void)echo_payload;
    return true;
}

/* Addressed probe sink for the continuous phase (R+D.md §12.7). Like
 * _always_emit, it only needs to accept: the worker owns probes_by_peer /
 * probes_by_cap / probes_issued, which is what the pin reads. */
static bool _always_probe(void *ctx, const char *cap_name, size_t peer_index,
                          long nonce, const char *echo_payload) {
    (void)ctx; (void)cap_name; (void)peer_index; (void)nonce;
    (void)echo_payload;
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

/* Score the `fixtures.scored_results` rows through the production scorer and
 * check the pins (R+D.md §12.7 / §12.8). The other half of a probe: issuing a
 * known-answer challenge means nothing if the answer is not checked, and the
 * check has to agree across runtimes because both grade the same peers.
 *
 * The Python adapter builds a TaskResult per row and calls
 * automate.score_task_result; this calls negotiation_score_task_result, which
 * is where C keeps the requestor's record of what it asked. Same rules, two
 * call sites -- which is exactly the placement divergence the corpus pins
 * across.
 *
 * A numeric answer is spelled as a number in the fixture and reaches this
 * runtime as the decimal text its `report results` payload carries. */
static bool _score_results(json_t *data, json_t *rows,
                           const char *host_id, at_case_result_t *out) {
    json_t *expected_state = json_object_get(data, "expected_state");
    json_t *host_exp = (host_id != NULL && json_is_object(expected_state))
                           ? json_object_get(expected_state, host_id) : NULL;
    json_t *want_scores = json_is_object(host_exp)
        ? json_object_get(host_exp, "result_scores") : NULL;
    json_t *want_channels = json_is_object(host_exp)
        ? json_object_get(host_exp, "result_channels") : NULL;

    size_t nrows = json_array_size(rows);
    if (json_is_array(want_scores) && json_array_size(want_scores) != nrows) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "%s: %zu results scored, %zu pinned", host_id ? host_id : "?",
                 nrows, json_array_size(want_scores));
        at_case_result_set_fail(out, 0, "AssertionError", detail);
        return false;
    }

    for (size_t i = 0; i < nrows; i++) {
        json_t *row = json_array_get(rows, i);
        const char *cap = json_string_value(json_object_get(row, "capability"));
        json_t *kwargs = json_object_get(row, "kwargs");
        json_t *result = json_object_get(row, "result");

        char kwargs_json[TASK_KWARGS_LEN + 1] = {0};
        if (json_is_object(kwargs) && json_object_size(kwargs) > 0) {
            char *dumped = json_dumps(kwargs, JSON_COMPACT | JSON_SORT_KEYS);
            if (dumped != NULL) {
                snprintf(kwargs_json, sizeof(kwargs_json), "%s", dumped);
                free(dumped);
            }
        }

        /* The reply, as text. A JSON null is "no result came back", which is
         * distinct from an empty string. */
        char result_buf[CAP_RESULT_LEN + 1] = {0};
        const char *result_str = NULL;
        if (json_is_string(result)) {
            snprintf(result_buf, sizeof(result_buf), "%s",
                     json_string_value(result));
            result_str = result_buf;
        } else if (json_is_integer(result)) {
            snprintf(result_buf, sizeof(result_buf), "%lld",
                     (long long)json_integer_value(result));
            result_str = result_buf;
        } else if (json_is_real(result)) {
            snprintf(result_buf, sizeof(result_buf), "%.3f",
                     json_real_value(result));
            result_str = result_buf;
        }

        const char *channel = NULL;
        /* No subject and t=0: this scenario scores REPLIES, and the physical
         * layer (R+D.md §12.2) is inert here anyway because no physics.json is
         * configured. Passing NULL keeps that explicit rather than resting on
         * the empty model -- see the `physics` protocol for its own vectors. */
        double score = negotiation_score_task_result(
            cap, kwargs_json, result_str,
            (result_str != NULL) ? strlen(result_str) : 0,
            NULL, NULL, NULL, 0.0, 0, &channel);

        if (json_is_array(want_scores)) {
            json_t *w = json_array_get(want_scores, i);
            double want = json_is_real(w) ? json_real_value(w)
                        : (json_is_integer(w) ? (double)json_integer_value(w)
                                              : -1.0);
            if (fabs(score - want) > 1e-9) {
                char detail[240];
                snprintf(detail, sizeof(detail),
                         "%s: row %zu (%s -> %s) scored %.3f, expected %.3f",
                         host_id ? host_id : "?", i, cap ? cap : "?",
                         result_str ? result_str : "(none)", score, want);
                at_case_result_set_fail(out, 0, "AssertionError", detail);
                return false;
            }
        }
        if (json_is_array(want_channels)) {
            const char *want = json_string_value(json_array_get(want_channels, i));
            if (want != NULL && (channel == NULL || strcmp(channel, want) != 0)) {
                char detail[240];
                snprintf(detail, sizeof(detail),
                         "%s: row %zu (%s) reported channel '%s', expected '%s'",
                         host_id ? host_id : "?", i, cap ? cap : "?",
                         channel ? channel : "(none)", want);
                at_case_result_set_fail(out, 0, "AssertionError", detail);
                return false;
            }
        }
    }
    return true;
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

    /* Host = the participant the observables belong to; resolved early
     * because the scoring branch below reports against it too. */
    json_t *parts_early = json_object_get(data, "participants");
    size_t nparts_early = json_is_array(parts_early)
                              ? json_array_size(parts_early) : 0;
    const char *host_early = NULL;
    for (size_t i = 0; i < nparts_early; i++) {
        json_t *p = json_array_get(parts_early, i);
        const char *role = json_string_value(json_object_get(p, "role"));
        const char *id = json_string_value(json_object_get(p, "id"));
        if (host_early == NULL && id != NULL)
            host_early = id;
        if (role != NULL && strcmp(role, "new_node") == 0 && id != NULL) {
            host_early = id;
            break;
        }
    }

    /* Result scoring is its own trigger: a scenario carrying `scored_results`
     * is about judging replies, not about issuing probes, and the two never
     * appear together. */
    json_t *scored = json_is_object(fixtures)
        ? json_object_get(fixtures, "scored_results") : NULL;
    if (json_is_array(scored) && json_array_size(scored) > 0) {
        if (_score_results(data, scored, host_early, out))
            at_case_result_set_pass(out, 0);
        return;
    }

    long   seed         = 12345;
    long   ticks        = 30;
    long   pairs_target = 0;
    double duration_sec = 999.0;
    bool   continuous = false;
    double probe_interval_sec = 0.0;
    if (json_is_object(bs)) {
        seed         = _int_field(bs, "seed", seed);
        ticks        = _int_field(bs, "ticks", ticks);
        pairs_target = _int_field(bs, "pairs_target", 0);
        duration_sec = _num_field(bs, "duration_sec", duration_sec);
        json_t *cont = json_object_get(bs, "continuous");
        continuous = json_is_true(cont);
        probe_interval_sec = _num_field(bs, "probe_interval_sec", 0.0);
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
    /* Explicit rather than inherited from the init defaults: the window
     * scenarios must not start counting probes just because continuous
     * probing shipped. Passing a NULL probe sink is what keeps
     * bootstrap_worker_tick_all window-only. */
    w.continuous_enabled = continuous;
    w.probe_interval_sec = probe_interval_sec;
    for (long t = 0; t < ticks; t++)
        bootstrap_worker_tick_all(&w, peer_count, 0.0, _always_emit,
                                  continuous ? _always_probe : NULL, NULL);

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

        /* --- Continuous probing observables (R+D.md §12.7) --------------- */
        want = json_object_get(host_exp, "probes_issued");
        if (json_is_integer(want) && w.probes_issued != (int)json_integer_value(want)) {
            char detail[200];
            snprintf(detail, sizeof(detail),
                     "%s: probes_issued=%d, expected %d",
                     host_id ? host_id : "?", w.probes_issued,
                     (int)json_integer_value(want));
            at_case_result_set_fail(out, 0, "AssertionError", detail);
            return;
        }
        want = json_object_get(host_exp, "distinct_peers_probed");
        if (json_is_integer(want)) {
            int distinct = 0;
            size_t tracked = (peer_count < AT_PROBE_MAX_TRACKED_PEERS)
                                 ? peer_count : AT_PROBE_MAX_TRACKED_PEERS;
            for (size_t i = 0; i < tracked; i++)
                if (w.probes_by_peer[i] >= 1)
                    distinct++;
            if (distinct != (int)json_integer_value(want)) {
                char detail[200];
                snprintf(detail, sizeof(detail),
                         "%s: distinct_peers_probed=%d, expected %d",
                         host_id ? host_id : "?", distinct,
                         (int)json_integer_value(want));
                at_case_result_set_fail(out, 0, "AssertionError", detail);
                return;
            }
        }
        want = json_object_get(host_exp, "probe_caps_fired");
        if (json_is_integer(want)) {
            int fired = 0;
            for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
                if (w.probes_by_cap[i] >= 1)
                    fired++;
            if (fired != (int)json_integer_value(want)) {
                char detail[200];
                snprintf(detail, sizeof(detail),
                         "%s: probe_caps_fired=%d, expected %d "
                         "(counts h=%d t=%d e=%d)",
                         host_id ? host_id : "?", fired,
                         (int)json_integer_value(want),
                         w.probes_by_cap[0], w.probes_by_cap[1],
                         w.probes_by_cap[2]);
                at_case_result_set_fail(out, 0, "AssertionError", detail);
                return;
            }
        }
    }

    at_case_result_set_pass(out, 0);
}
