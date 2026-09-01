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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bootstrap/bootstrap_worker.h"

/* splitmix64 — a small, fast, fully-deterministic PRNG. The conformance pin
 * only requires that a seeded run cover all three caps (not that the C and
 * Python sequences match), so any reproducible uniform source suffices; this
 * one is self-contained and has no libc-global state. */
static uint64_t _rng_next(bootstrap_worker_t *w)
{
    uint64_t z = (w->rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Uniform integer in [0, n) for n > 0 (rejection-free modulo bias is
 * negligible at our magnitudes; the contract is coverage, not distribution
 * fidelity). */
static uint64_t _rng_below(bootstrap_worker_t *w, uint64_t n)
{
    return (n == 0) ? 0 : (_rng_next(w) % n);
}

static double _read_float_env(const char *name, double dflt)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return dflt;
    char *end = NULL;
    double parsed = strtod(v, &end);
    return (end != NULL && *end == '\0') ? parsed : dflt;
}

static int _read_int_env(const char *name, int dflt)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return dflt;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    return (end != NULL && *end == '\0') ? (int)parsed : dflt;
}

static int _cap_index(const char *name)
{
    if (name == NULL)
        return -1;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        if (strcmp(BOOTSTRAP_CAPABILITY_NAMES[i], name) == 0)
            return i;
    return -1;
}

static void _init_common(bootstrap_worker_t *w, double duration_sec,
                         int pairs_target, uint64_t seed, bool disabled)
{
    memset(w, 0, sizeof(*w));
    w->duration_sec = duration_sec;
    w->pairs_target = pairs_target;
    w->disabled = disabled;
    w->window_open = false;
    w->window_start_sec = 0.0;
    w->pairs_issued = 0;
    w->rng_state = seed;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++) {
        w->counts_by_cap[i] = 0;
        w->probes_by_cap[i] = 0;
        w->registered[i] = true;
    }
    /* Defaults, so the explicit-config initializer (tests, conformance) gets a
     * sane continuous phase without having to know about it. The env-reading
     * initializer overrides both below. */
    w->probe_interval_sec = AT_PROBE_DEFAULT_INTERVAL_SEC;
    w->continuous_enabled = true;
    w->probes_issued = 0;
    w->last_probe_sec = 0.0;
    w->probed_ever = false;
    /* memset above already zeroed probes_by_peer. */
}

void bootstrap_worker_init(bootstrap_worker_t *w)
{
    if (w == NULL)
        return;
    double duration = _read_float_env("AT_BOOTSTRAP_DURATION_SEC",
                                      AT_BOOTSTRAP_DEFAULT_DURATION_SEC);
    int pairs = _read_int_env("AT_BOOTSTRAP_PAIRS",
                              AT_BOOTSTRAP_DEFAULT_PAIRS_TARGET);
    const char *seed_env = getenv("AT_BOOTSTRAP_SEED");
    uint64_t seed;
    if (seed_env != NULL && seed_env[0] != '\0') {
        char *end = NULL;
        long s = strtol(seed_env, &end, 10);
        seed = (end != NULL && *end == '\0') ? (uint64_t)s
                                             : (uint64_t)time(NULL);
    } else {
        seed = (uint64_t)time(NULL);
    }
    const char *dis = getenv("AT_BOOTSTRAP_DISABLED");
    bool disabled = (dis != NULL && strcmp(dis, "1") == 0);
    _init_common(w, duration, pairs, seed, disabled);
    w->probe_interval_sec = _read_float_env("AT_PROBE_INTERVAL_SEC",
                                           AT_PROBE_DEFAULT_INTERVAL_SEC);
    const char *nocont = getenv("AT_PROBE_CONTINUOUS_DISABLED");
    w->continuous_enabled = !(nocont != NULL && strcmp(nocont, "1") == 0);
}

void bootstrap_worker_init_config(bootstrap_worker_t *w, double duration_sec,
                                  int pairs_target, uint64_t seed, bool disabled)
{
    if (w == NULL)
        return;
    _init_common(w, duration_sec, pairs_target, seed, disabled);
}

void bootstrap_worker_set_registered(bootstrap_worker_t *w, const char *name,
                                     bool registered)
{
    if (w == NULL)
        return;
    int idx = _cap_index(name);
    if (idx >= 0)
        w->registered[idx] = registered;
}

bool bootstrap_worker_try_issue_pair(bootstrap_worker_t *w, size_t peer_count,
                                     bootstrap_emit_fn emit, void *ctx)
{
    if (w == NULL || peer_count == 0)
        return false;

    int idx = (int)_rng_below(w, BOOTSTRAP_CAPABILITY_COUNT);
    const char *cap_name = BOOTSTRAP_CAPABILITY_NAMES[idx];
    if (!w->registered[idx])
        return false;

    /* Build per-cap task args, drawing from the PRNG only for the caps that
     * carry a parameter — matching Python _build_task_args (handshake nonce,
     * echo payload; time-attest takes none). */
    long nonce = 0;
    char echo_payload[32];
    const char *payload_arg = NULL;
    if (idx == 0) {                       /* at.handshake */
        nonce = (long)(1 + _rng_below(w, 1000000));
    } else if (idx == 2) {                /* at.echo-challenge */
        uint32_t r = (uint32_t)_rng_next(w);
        snprintf(echo_payload, sizeof(echo_payload), "echo:%08x", r);
        payload_arg = echo_payload;
    }

    if (emit != NULL && !emit(ctx, cap_name, nonce, payload_arg))
        return false;                     /* queue full → retry next tick */

    w->pairs_issued += 1;
    w->counts_by_cap[idx] += 1;
    return true;
}

void bootstrap_worker_tick(bootstrap_worker_t *w, size_t peer_count,
                           double now_sec, bootstrap_emit_fn emit, void *ctx)
{
    /* Window-only: no probe sink, so bootstrap_worker_tick_all stops after the
     * window exactly as this function always has. Existing callers (the seeded
     * unit tests and the conformance coverage pin) keep their behavior
     * unchanged. */
    bootstrap_worker_tick_all(w, peer_count, now_sec, emit, NULL, ctx);
}

/* ----------------------------------------------------------------------------
 * Continuous probing (R+D.md §12.7)
 * -------------------------------------------------------------------------- */

double bootstrap_ucb_bonus(int count, int total)
{
    if (count < 0)
        count = 0;
    if (total < 0)
        total = 0;
    return sqrt(2.0 * log((double)total + 2.0) / ((double)count + 1.0));
}

size_t bootstrap_worker_select_target(const bootstrap_worker_t *w,
                                     size_t peer_count)
{
    if (w == NULL || peer_count == 0)
        return 0;
    if (peer_count > AT_PROBE_MAX_TRACKED_PEERS) {
        /* No per-peer state to compare beyond the cap. Round-robin rather than
         * silently probing only the first AT_PROBE_MAX_TRACKED_PEERS peers,
         * which would leave the rest permanently unchallenged. */
        return (size_t)w->probes_issued % peer_count;
    }
    size_t best = 0;
    double best_bonus = -1.0;
    for (size_t i = 0; i < peer_count; i++) {
        double bonus = bootstrap_ucb_bonus(w->probes_by_peer[i],
                                          w->probes_issued);
        /* Strict >: ties keep the lowest index, so the result does not depend
         * on iteration direction and equal counts round-robin. */
        if (bonus > best_bonus) {
            best_bonus = bonus;
            best = i;
        }
    }
    return best;
}

const char *bootstrap_worker_select_capability(const bootstrap_worker_t *w)
{
    if (w == NULL)
        return NULL;
    /* transaction_weight is 1 for all three as registered today; read it from
     * the registration table rather than hard-coding 1, so a ladder that
     * weights them differently changes allocation with no change here. */
    bootstrap_capability_t caps[BOOTSTRAP_CAPABILITY_COUNT];
    if (register_bootstrap_capabilities(caps) != BOOTSTRAP_CAPABILITY_COUNT)
        return NULL;
    const char *best = NULL;
    double best_score = -1.0;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++) {
        if (!w->registered[i])
            continue;
        double weight = (double)caps[i].transaction_weight;
        if (weight <= 0.0)
            weight = 1.0;
        double score = weight / ((double)w->probes_by_cap[i] + 1.0);
        if (score > best_score) {
            best_score = score;
            best = BOOTSTRAP_CAPABILITY_NAMES[i];
        }
    }
    return best;
}

bool bootstrap_worker_try_issue_probe(bootstrap_worker_t *w, size_t peer_count,
                                     bootstrap_probe_emit_fn emit, void *ctx)
{
    if (w == NULL || peer_count == 0)
        return false;
    const char *cap_name = bootstrap_worker_select_capability(w);
    if (cap_name == NULL)
        return false;
    int idx = _cap_index(cap_name);
    if (idx < 0)
        return false;
    size_t target = bootstrap_worker_select_target(w, peer_count);

    /* Same per-cap argument shapes as the window path, drawing from the same
     * PRNG so a probe's challenge is as unpredictable as a bootstrap pair's --
     * a fixed nonce would let a peer precompute the one right answer. */
    long nonce = 0;
    char echo_payload[32];
    const char *payload_arg = NULL;
    if (idx == 0) {                       /* at.handshake */
        nonce = (long)(1 + _rng_below(w, 1000000));
    } else if (idx == 2) {                /* at.echo-challenge */
        uint32_t r = (uint32_t)_rng_next(w);
        snprintf(echo_payload, sizeof(echo_payload), "echo:%08x", r);
        payload_arg = echo_payload;
    }

    if (emit != NULL && !emit(ctx, cap_name, target, nonce, payload_arg))
        return false;                     /* queue full → retry next tick */

    if (target < AT_PROBE_MAX_TRACKED_PEERS)
        w->probes_by_peer[target] += 1;
    w->probes_by_cap[idx] += 1;
    w->probes_issued += 1;
    w->counts_by_cap[idx] += 1;
    return true;
}

void bootstrap_worker_tick_all(bootstrap_worker_t *w, size_t peer_count,
                               double now_sec, bootstrap_emit_fn emit,
                               bootstrap_probe_emit_fn probe_emit, void *ctx)
{
    if (w == NULL || w->disabled)
        return;
    if (!w->window_open) {
        if (peer_count > 0) {
            w->window_open = true;
            w->window_start_sec = now_sec;
        } else {
            return;
        }
    }
    double elapsed = now_sec - w->window_start_sec;
    bool window_done = (w->pairs_issued >= w->pairs_target
                        || elapsed > w->duration_sec);
    if (!window_done) {
        bootstrap_worker_try_issue_pair(w, peer_count, emit, ctx);
        return;
    }
    if (!w->continuous_enabled || probe_emit == NULL)
        return;
    /* Rate limit. The first probe after the window closes goes immediately --
     * waiting an interval to START probing serves nobody -- and every later
     * one waits probe_interval_sec. Stamp before issuing, so a full queue does
     * not turn into a retry on every tick exactly when the node is loaded. */
    if (w->probed_ever && (now_sec - w->last_probe_sec) < w->probe_interval_sec)
        return;
    w->probed_ever = true;
    w->last_probe_sec = now_sec;
    bootstrap_worker_try_issue_probe(w, peer_count, probe_emit, ctx);
}

int bootstrap_worker_count_for(const bootstrap_worker_t *w, const char *cap_name)
{
    if (w == NULL)
        return -1;
    int idx = _cap_index(cap_name);
    return (idx >= 0) ? w->counts_by_cap[idx] : -1;
}
