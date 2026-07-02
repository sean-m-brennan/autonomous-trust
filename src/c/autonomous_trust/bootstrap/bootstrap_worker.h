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

/** @} */

#endif /* BOOTSTRAP_WORKER_H */
