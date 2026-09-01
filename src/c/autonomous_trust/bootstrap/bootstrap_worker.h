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

#ifndef BOOTSTRAP_WORKER_H
#define BOOTSTRAP_WORKER_H

/** @addtogroup bootstrap
 *  @{
 *
 *  C port of `bootstrap_worker.py` (doc/architecture/trust-tiers.md §6.4).
 *  Once peers are admitted, the worker issues a fixed number of
 *  randomly-paired Task invitations against the three tier-0 bootstrap
 *  capabilities over a short post-admission window, seeding reputation from
 *  bilateral pairs.
 *
 *  Decoupling: rather than reaching into the negotiation queue directly, the
 *  worker emits each invitation through a caller-supplied ::bootstrap_emit_fn
 *  callback (the C analog of Python's `queues[CfgIds.negotiation].put`).
 *  Production wiring sends a real negotiation `start` message; the
 *  conformance adapter / unit tests pass a capturing callback. The worker
 *  owns `counts_by_cap` so the conformance pin can assert each of the three
 *  caps fired at least once over a seeded run (the RNG-agnostic contract from
 *  §6.5 — exact per-impl sequences need not match, only the coverage set).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bootstrap/bootstrap_capabilities.h"

#define AT_BOOTSTRAP_DEFAULT_DURATION_SEC 30.0
#define AT_BOOTSTRAP_DEFAULT_PAIRS_TARGET 20

/** Minimum seconds between continuous (post-window) probes (R+D.md §12.7).
 *  A rate limit, not a schedule: a probe is a real task round trip on both
 *  peers, and the point of continuing past the window is coverage over time
 *  rather than volume. Env: AT_PROBE_INTERVAL_SEC. */
#define AT_PROBE_DEFAULT_INTERVAL_SEC 60.0

/** Per-peer probe counts are tracked for this many peer indices. Beyond it the
 *  selector falls back to round-robin, which still covers every peer but stops
 *  being uncertainty-directed. See bootstrap_worker_select_target. */
#define AT_PROBE_MAX_TRACKED_PEERS 64

typedef struct {
    double   duration_sec;
    int      pairs_target;
    int      pairs_issued;
    bool     disabled;                              /* AT_BOOTSTRAP_DISABLED */
    bool     window_open;
    double   window_start_sec;
    int      counts_by_cap[BOOTSTRAP_CAPABILITY_COUNT];
    bool     registered[BOOTSTRAP_CAPABILITY_COUNT]; /* cap in own-caps list */
    uint64_t rng_state;

    /* --- Continuous probing (R+D.md §12.7) ---------------------------------
     * The window seeds reputation and stops, which applied the honeypot
     * pattern only at cold start: a peer had to misbehave inside its first 30
     * seconds to meet a known-answer check, and one that degraded later -- or
     * that behaved until it was trusted -- was never challenged again.
     *
     * The counts ARE the posterior. With no probe outcomes reaching the
     * worker, how uncertain we are about a peer is a function of how often it
     * has been challenged, which is what the UCB exploration term measures.
     * See bootstrap_ucb_bonus. */
    double   probe_interval_sec;
    bool     continuous_enabled;                    /* AT_PROBE_CONTINUOUS_DISABLED */
    int      probes_by_peer[AT_PROBE_MAX_TRACKED_PEERS];
    int      probes_by_cap[BOOTSTRAP_CAPABILITY_COUNT];
    int      probes_issued;
    double   last_probe_sec;
    bool     probed_ever;
} bootstrap_worker_t;

/** Invitation sink. Mirrors a `put` onto the negotiation queue: return true
 *  if the invitation was accepted (then the worker counts it), false if it
 *  could not be queued (queue full → retry next tick, no count). @p nonce is
 *  meaningful only for at.handshake; @p echo_payload only for
 *  at.echo-challenge (NULL otherwise). */
typedef bool (*bootstrap_emit_fn)(void *ctx, const char *cap_name,
                                  long nonce, const char *echo_payload);

/** Initialize @p w from the AT_BOOTSTRAP_* environment (DURATION_SEC, PAIRS,
 *  SEED, DISABLED), all three caps marked registered. */
void bootstrap_worker_init(bootstrap_worker_t *w);

/** Explicit-config variant for tests/scenarios that don't want to touch the
 *  environment. @p seed seeds the deterministic PRNG. */
void bootstrap_worker_init_config(bootstrap_worker_t *w, double duration_sec,
                                  int pairs_target, uint64_t seed,
                                  bool disabled);

/** Mark a bootstrap capability registered/unregistered (mirrors a cap being
 *  present/absent in the process's own-capabilities list). No-op if @p name
 *  is not a bootstrap cap. */
void bootstrap_worker_set_registered(bootstrap_worker_t *w, const char *name,
                                     bool registered);

/** Attempt to schedule one invitation against a random registered bootstrap
 *  cap. Returns true iff one was emitted (and counted). False on: no peers,
 *  selected cap unregistered, or @p emit reporting the queue full. */
bool bootstrap_worker_try_issue_pair(bootstrap_worker_t *w, size_t peer_count,
                                     bootstrap_emit_fn emit, void *ctx);

/** One main-loop pass: open the window when peers first appear, then emit a
 *  pair while the window is open and the target is unmet. @p now_sec is a
 *  monotonic seconds clock (the window-elapsed comparison uses it). */
void bootstrap_worker_tick(bootstrap_worker_t *w, size_t peer_count,
                           double now_sec, bootstrap_emit_fn emit, void *ctx);

/** Issuance count for @p cap_name, or -1 if it is not a bootstrap cap. */
int bootstrap_worker_count_for(const bootstrap_worker_t *w, const char *cap_name);

/* ----------------------------------------------------------------------------
 * Continuous probing (R+D.md §12.7)
 * -------------------------------------------------------------------------- */

/** Addressed invitation sink, for probes.
 *
 *  Separate from ::bootstrap_emit_fn because the two are different acts. A
 *  bootstrap invitation is fanned out to every capable peer; a probe is
 *  addressed to ONE. That distinction is load-bearing rather than cosmetic:
 *  fanned out, a probe is answered by whichever peer replies first (the
 *  requestor pre-seeds its result slots for all participants and forwards on
 *  the first), so a broadcast cannot express "probe THIS peer" and a slow peer
 *  is never probed at all -- which makes allocation meaningless.
 *
 *  @p peer_index is an index into the caller's peer ordering. */
typedef bool (*bootstrap_probe_emit_fn)(void *ctx, const char *cap_name,
                                        size_t peer_index, long nonce,
                                        const char *echo_payload);

/** UCB1 exploration term for an arm probed @p count times out of @p total
 *  draws: `sqrt(2 * ln(total + 2) / (count + 1))`. Mirrors Python
 *  BootstrapWorker._ucb_bonus.
 *
 *  This is §12.7's "widest posterior", read honestly for the information the
 *  worker has. A Beta posterior over a peer's quality would need the probe
 *  OUTCOMES, and those are scored on the requestor's main loop, which does not
 *  report back here. What is available is how many times each arm has been
 *  challenged, and under a count-only posterior the width is a function of
 *  exactly that. Writing it as UCB1 keeps it a standard, citable quantity.
 *
 *  `total + 2` rather than `+ 1` inside the log: at total 0 the latter is
 *  ln(1) == 0, which zeroes every arm's bonus and silently degenerates the
 *  selection to its tie-break on the very first draw. */
double bootstrap_ucb_bonus(int count, int total);

/** Index of the peer whose quality we are least sure of: argmax of
 *  @ref bootstrap_ucb_bonus over per-peer counts, tie-broken on the lowest
 *  index so the choice is reproducible. With all counts equal this is a
 *  round-robin, the right cold behavior (nothing is known, so spread).
 *
 *  For @p peer_count above @ref AT_PROBE_MAX_TRACKED_PEERS there is no
 *  per-peer state to compare, so this degrades to an explicit round-robin
 *  (`probes_issued % peer_count`) -- still full coverage, just no longer
 *  uncertainty-directed. Returns 0 when @p peer_count is 0. */
size_t bootstrap_worker_select_target(const bootstrap_worker_t *w,
                                      size_t peer_count);

/** The capability to probe with: argmax of `weight / (per-cap count + 1)`
 *  over REGISTERED caps, or NULL if none are registered.
 *
 *  Peers and capabilities are deliberately not scored the same way. For a peer
 *  we are identifying a bad arm, which is what UCB is for. For a capability
 *  there is nothing to identify -- the question is how to divide a fixed probe
 *  budget across capabilities of differing stakes -- and this rule settles at
 *  per-cap counts PROPORTIONAL to weight, which covers everything while
 *  spending more where it matters. Ranking by weight alone would probe the
 *  heaviest capability forever, leaving an adversary a single capability to
 *  answer correctly; multiplying weight by the UCB bonus allocates
 *  proportional to weight SQUARED (the bonus falls off as 1/sqrt(n)), so at a
 *  weight of 8 a light capability waits until the heavy one has 64x the
 *  probes. Mirrors Python BootstrapWorker._select_capability. */
const char *bootstrap_worker_select_capability(const bootstrap_worker_t *w);

/** Issue one directed probe. Returns true iff one was emitted (and counted).
 *  False on: no peers, no registered caps, or @p emit reporting queue-full. */
bool bootstrap_worker_try_issue_probe(bootstrap_worker_t *w, size_t peer_count,
                                     bootstrap_probe_emit_fn emit, void *ctx);

/** One main-loop pass covering BOTH phases: the bootstrap window first, then
 *  continuous probing once the window has closed (by budget or by elapsed
 *  time). @ref bootstrap_worker_tick is this with @p probe_emit NULL, i.e. the
 *  historical window-only behavior, which is what the existing seeded unit
 *  tests and the conformance coverage pin exercise. Mirrors Python
 *  BootstrapWorker._tick. */
void bootstrap_worker_tick_all(bootstrap_worker_t *w, size_t peer_count,
                               double now_sec, bootstrap_emit_fn emit,
                               bootstrap_probe_emit_fn probe_emit, void *ctx);

/** @} */

#endif /* BOOTSTRAP_WORKER_H */
