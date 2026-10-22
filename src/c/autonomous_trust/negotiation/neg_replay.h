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

#ifndef NEG_REPLAY_H
#define NEG_REPLAY_H

/**
 * @file neg_replay.h
 * @brief Replayable capabilities: the executor's half of live replication
 * (RD_12.6_LIVE_REPLICATION_PLAN.md section 3.2).
 *
 * A replayable capability (capability_t.replay) runs step by step. The
 * executor commits to the hash chain of the states it passed through
 * (`trace_root` and `trace_len` on its TaskResult) and keeps them, so that if
 * a replica disagrees it can answer a verifier's questions about any step.
 * The chain is the replication layer's (replication/bisection.h), repeated
 * here because an executor needs it whether or not the node links that
 * layer. The C half of Python `negotiation/replay.py`.
 */

#include <stdbool.h>
#include <stddef.h>

#include "processes/capabilities.h"

/** The most states a trace may hold: the bisection game's bound
 *  (AT_REPL_MAX_STEPS). */
#define NEG_REPLAY_MAX_STEPS 256

/** The largest state a replayable capability may produce, in bytes: the
 *  most a declaration's max_state_bytes may ask for. */
#define NEG_REPLAY_STATE_MAX 65536

/** blake2b hex length (TX_HASH_HEX_LEN). */
#define NEG_REPLAY_HASH_HEX_LEN 64

/** A trace: the states, each a heap string, in order. */
typedef struct
{
    char **states;
    int    n;
} neg_trace_t;

/** @brief Run @p replay over @p kwargs_json into @p trace, and write the
 *  task's answer to @p result. Returns 0, or -1 when a step fails, the
 *  computation runs past NEG_REPLAY_MAX_STEPS, or memory runs out (@p trace
 *  is then empty). Mirrors Python `run_trace`. */
int neg_replay_run(const capability_replay_t *replay, const char *kwargs_json,
                   neg_trace_t *trace, char *result, size_t result_len);

/** @brief The chain digest h_i at @p index (h_0 = H(s_0), h_i =
 *  H(h_{i-1} || s_i)), 64-hex + NUL. False for an index outside the trace. */
bool neg_trace_digest(const neg_trace_t *trace, int index,
                      char out[NEG_REPLAY_HASH_HEX_LEN + 1]);

/** @brief Free the states and empty the trace. */
void neg_trace_free(neg_trace_t *trace);

#endif /* NEG_REPLAY_H */
