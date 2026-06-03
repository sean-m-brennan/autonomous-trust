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

#ifndef BOOTSTRAP_CAPABILITIES_H
#define BOOTSTRAP_CAPABILITIES_H

/** @addtogroup bootstrap
 *  @{
 *
 *  C port of `bootstrap_capabilities.py` — the three tier-0 AT-core
 *  bootstrap capabilities (doc/architecture/trust-tiers.md §6). They are
 *  exercised by the BootstrapWorker to seed reputation from bilateral pairs
 *  immediately after admission.
 *
 *  The server-side functions return a value (mirroring the Python
 *  value-returning `at_*` functions rather than the C
 *  `capability_function_t` void/thread_args shape); the client-side
 *  verifiers score a returned result against the expected value. Scoring
 *  constants match the Python module verbatim (0.9 success / 0.1 defection /
 *  0.5 forgivable-drift). v1 sketches: no signed-nonce / ZKP-echo strength
 *  yet (architecture doc §12).
 */

#include <stddef.h>

/* Tolerance (seconds) for at.time-attest — matches Python
 * DEFAULT_TIME_ATTEST_TOLERANCE_SEC. Wide enough to forgive routine RTT and
 * clock drift, narrow enough to catch a peer lying about its clock. */
#define AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC 0.2

#define BOOTSTRAP_CAPABILITY_COUNT 3

/* Canonical bootstrap capability names, index-stable (the worker selects by
 * index). Mirrors Python BOOTSTRAP_CAPABILITY_NAMES. */
extern const char *const BOOTSTRAP_CAPABILITY_NAMES[BOOTSTRAP_CAPABILITY_COUNT];

/* Tier metadata for a registered bootstrap capability. Mirrors the
 * required_tier=0 / transaction_weight=1 that Python's
 * register_bootstrap_capabilities applies. */
typedef struct {
    const char *name;
    int required_tier;
    int transaction_weight;
} bootstrap_capability_t;

/* ---------------------------------------------------------------
 * Server-side capability functions (executed by the responder).
 * --------------------------------------------------------------- */

/** at.handshake: receive an integer nonce, return nonce + 1. */
long at_handshake(long nonce);

/** at.time-attest: return the responder's Unix timestamp (seconds). */
double at_time_attest(void);

/** at.echo-challenge: echo @p payload verbatim. Returns a heap copy the
 *  caller must free(); NULL @p payload echoes as "". Returns NULL only on
 *  allocation failure. */
char *at_echo_challenge(const char *payload);

/* ---------------------------------------------------------------
 * Client-side verifiers (used by BootstrapWorker on the requestor).
 * --------------------------------------------------------------- */

/** 0.9 if @p result == @p sent_nonce + 1, else 0.1. */
double verify_handshake(long result, long sent_nonce);

/** Within @p tolerance of @p requestor_now → 0.9; outside (but finite) →
 *  0.5; non-finite (NaN/inf, the C analog of Python's unparseable) → 0.1. */
double verify_time_attest(double result, double requestor_now, double tolerance);

/** 0.9 iff both strings are non-NULL and byte-equal, else 0.1. */
double verify_echo(const char *result, const char *sent_payload);

/* ---------------------------------------------------------------
 * Registration.
 * --------------------------------------------------------------- */

/** Fill @p out (length BOOTSTRAP_CAPABILITY_COUNT) with the three bootstrap
 *  capabilities, each required_tier=0 / transaction_weight=1. Mirrors
 *  Python register_bootstrap_capabilities. Returns the count written, or
 *  -1 if @p out is NULL. */
int register_bootstrap_capabilities(bootstrap_capability_t *out);

/** @} */

#endif /* BOOTSTRAP_CAPABILITIES_H */
