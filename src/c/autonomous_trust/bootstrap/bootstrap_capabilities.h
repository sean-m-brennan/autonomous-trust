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

#include <stdbool.h>
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
 * Probe dispatch (R+D.md §12.7)
 * --------------------------------------------------------------- */

/** The challenge a probe was issued with, so the verifier can check the
 *  answer. Which member is meaningful depends on the capability: @p nonce for
 *  at.handshake, @p payload for at.echo-challenge, neither for at.time-attest.
 *
 *  This MUST be the requestor's own record of what it sent, never a copy read
 *  back out of the responder's reply. A known-answer check that trusts the
 *  reply's account of the challenge verifies nothing: a peer that computed the
 *  wrong answer simply reports the challenge its answer would have been right
 *  for (result 99, "nonce" 98 -- a perfect increment). Mirrors Python
 *  TaskResult.attach_requested_parameters, which stamps these from the
 *  requestor's retained Task. */
typedef struct {
    long        nonce;
    const char *payload;
} probe_challenge_t;

/** True iff @p cap_name is one of the known-answer probe capabilities.
 *  Mirrors Python is_probe_capability. */
bool is_probe_capability(const char *cap_name);

/** Tolerance (seconds) for at.time-attest, honoring
 *  AT_TIME_ATTEST_TOLERANCE_SEC and falling back to
 *  @ref AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC on unset/garbage/non-positive.
 *
 *  The override was documented in both twins from the start and read by
 *  neither. Worth knowing when tuning it: the comparison happens on the
 *  REQUESTOR at scoring time, so the measured delta includes the round trip
 *  and not just the responder's clock error. That is survivable only because
 *  an out-of-tolerance-but-finite answer scores 0.5 rather than 0.1. */
double time_attest_tolerance(void);

/** Score a probe result against the answer the requestor already knows.
 *
 *  Writes the score to @p score_out and returns true; returns false (leaving
 *  @p score_out untouched) if @p cap_name is not a probe capability, so the
 *  caller falls through to ordinary task scoring rather than grading a domain
 *  task against a nonexistent expected value. This is the boolean form of
 *  Python's "return None for a non-probe".
 *
 *  @p result_num carries the numeric answer (at.handshake, at.time-attest)
 *  and @p result_str the string answer (at.echo-challenge); the unused one is
 *  ignored. @p requestor_now is the requestor's clock for at.time-attest; pass
 *  a non-positive value to read the clock here. Per-capability argument shapes
 *  live in exactly this one place, mirroring Python verify_bootstrap_result. */
bool verify_bootstrap_result(const char *cap_name,
                             double result_num, const char *result_str,
                             const probe_challenge_t *challenge,
                             double requestor_now, double *score_out);

/* ---------------------------------------------------------------
 * Registration.
 * --------------------------------------------------------------- */

/** Fill @p out (length BOOTSTRAP_CAPABILITY_COUNT) with the three bootstrap
 *  capabilities, each required_tier=0 / transaction_weight=1. Mirrors
 *  Python register_bootstrap_capabilities. Returns the count written, or
 *  -1 if @p out is NULL. */
int register_bootstrap_capabilities(bootstrap_capability_t *out);

/** False when AT_BOOTSTRAP_DISABLED is set, in which case this node neither
 *  advertises nor answers the bootstrap capabilities. Python gates the
 *  registration call itself (automate.py); C's capability table is static, so
 *  the gate has to be read where the table is consumed
 *  (@ref build_local_capabilities) and where a job is executed. */
bool bootstrap_capabilities_enabled(void);

/* ---------------------------------------------------------------
 * Responder-side executors (::capability_result_function_t shape).
 *
 * The `at_*` functions above are the answer; these adapt them to what the
 * negotiation worker can call -- keyword arguments in as compact JSON, the
 * answer out as text -- so the three capabilities can sit in the generated
 * capability table like any other and be executed from a job.
 *
 * Text, not a typed union, because that is what crosses back in the `report
 * results` payload and what the requestor's verifier parses. Each writes at
 * most @p result_len bytes including the terminator and returns 0 on success.
 * --------------------------------------------------------------- */

/** at.handshake: reads `nonce` (absent reads as 0), writes nonce + 1. */
int at_handshake_exec(const char *kwargs_json, char *result_out,
                      size_t result_len);

/** at.time-attest: ignores its arguments, writes this node's clock as
 *  seconds with millisecond precision. */
int at_time_attest_exec(const char *kwargs_json, char *result_out,
                        size_t result_len);

/** at.echo-challenge: reads `payload` (absent reads as ""), writes it back
 *  verbatim. Returns non-zero if the token does not fit, rather than echoing
 *  a truncated one -- a truncated echo is a wrong answer, and it should read
 *  as this node failing to answer rather than as tampering. */
int at_echo_challenge_exec(const char *kwargs_json, char *result_out,
                           size_t result_len);

/** @} */

#endif /* BOOTSTRAP_CAPABILITIES_H */
