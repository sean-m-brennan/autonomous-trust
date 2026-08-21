/*******************
 * Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/
/** @file
 *  Per-verb message freshness: a monotonic sender sequence plus a
 *  receiver-side high-water mark. C twin of Python `core/freshness.py`; read
 *  that module's docstring for the reasoning, and
 *  doc/architecture/security-hardening.md, "Replay resistance, per verb".
 *
 *  A signed AT message binds its content and nothing about when it was said,
 *  so a verb whose payload carries no freshness token can be captured and
 *  re-presented. Verbs that already carry one — a Paxos ballot id, a group key
 *  epoch, a chain index, an attestation nonce, a relayed query id — are
 *  unaffected and must NOT be given a second.
 *
 *  The sender stamps a monotonically increasing sequence into the payload,
 *  where the message signature already covers it (the pre-image includes
 *  base64 of the data), so a stripped sequence is an invalid message rather
 *  than an unstamped one — no pre-image change, hence no wire break for the
 *  byte-pinned corpus. The receiver keeps, per (sender, verb), the highest
 *  sequence it accepted and refuses anything at or below it.
 *
 *  Both halves are persisted. A sender that rewound its counter would have its
 *  next messages refused by peers whose marks it cannot see; a receiver that
 *  forgot its marks would accept one replay per (sender, verb) per restart.
 *
 *  ONE state per process, shared across the verbs that process emits: the
 *  marks are keyed per (sender, verb), so a shared counter is still strictly
 *  increasing within any single verb.
 *
 *  Not thread-safe; the caller serializes (each process owns its own state
 *  under that process's existing lock).
 */
#ifndef FRESHNESS_H
#define FRESHNESS_H

#include <stdbool.h>
#include <stdint.h>

#include "structures/map.h"
#include "utilities/logger.h"

/** Base name of the per-process freshness file; the process name is appended,
 *  so two processes on one node never write the same file and a counter is
 *  only advanced by the process that owns it. */
#define FRESHNESS_FILE "freshness"

/** Coalescing window for mark writes, in microseconds. A mark advance is one
 *  small atomic write, and on a busy verb that is per accepted message;
 *  bursts inside this window are written once. The residual is bounded: an
 *  unclean stop can lose up to this much mark state, costing at most one
 *  replay per (sender, verb) whose mark had not reached disk. The sender
 *  counter is NOT throttled — a rewound counter breaks liveness rather than
 *  merely narrowing a window. Mirrors Python FLUSH_INTERVAL_SECS. */
#define FRESHNESS_FLUSH_US (1000LL * 1000LL)

/** One process's freshness state. Zero-initialize, then freshness_init. */
typedef struct freshness_s
{
    char proc_name[64];
    int64_t seq;          /**< our own send counter */
    map_t marks;          /**< "sender|verb" -> integer_data(high-water) */
    map_t refusals;       /**< verb -> integer_data(count refused as stale) */
    int64_t refusals_total; /**< sum of @ref refusals; map_t has no iterator */
    bool dirty;
    int64_t last_flush_us;
    bool initialized;
} freshness_t;

/** Initialize (and load any persisted state) for @p proc_name.
 *  A missing file is the cold-start case, not an error. A corrupt file is
 *  refused loudly and left in place: "no marks" is the state an attacker would
 *  want to induce, and an operator needs to see which needs fixing. */
int freshness_init(freshness_t *fr, const char *proc_name, logger_t *logger);

/** Release the state. Flushes any pending marks first. */
void freshness_free(freshness_t *fr, logger_t *logger);

/** The next sequence to stamp on an outgoing payload.
 *  Persisted before it returns: a number that reaches a peer but not the disk
 *  is exactly the one reused after a restart and refused. Returns 0 on
 *  failure, which callers must treat as "do not send". */
int64_t freshness_stamp(freshness_t *fr, logger_t *logger);

/** True iff @p seq is fresh for (@p sender, @p verb), advancing the mark.
 *  Sequences start at 1, so 0 is the never-seen floor and any non-positive
 *  value is refused — an unstamped sender and a stripped field land on the
 *  same refusal, deliberately: there is no lenient mode
 *  (doc/architecture/reputation.md, "Quorum attestation"). */
bool freshness_accept(freshness_t *fr, const char *sender, const char *verb,
                      int64_t seq, logger_t *logger);

/** The current high-water mark for (@p sender, @p verb); 0 if never seen.
 *  For logging and tests. */
int64_t freshness_mark(freshness_t *fr, const char *sender, const char *verb);

/** How many messages this process refused as stale, for @p verb (NULL: across
 *  every verb).
 *
 *  Evidence that the guard fired, not part of its decision — nothing here is
 *  persisted or consulted by @ref freshness_accept. A refusal is otherwise
 *  invisible from outside the process: the per-sender cooldowns above these
 *  handlers suppress a second delivery on their own, so "no second response"
 *  cannot distinguish a working mark from a cooldown. This can. Read by the
 *  conformance `freshness_refusals` observable; Python mirrors it in
 *  Freshness.refusals().
 *
 *  Keyed by verb alone, unlike the marks: the sender is already in the
 *  caller's log line, and a per-verb total is what an outside observer can
 *  assert. Both refusal shapes are counted — a sequence at or below the mark
 *  (a replay) and a non-positive one (unstamped sender, or a stripped field) —
 *  because to the guard they are one decision. */
int64_t freshness_refusals(freshness_t *fr, const char *verb);

/** Force pending marks to disk (shutdown, or a test). */
void freshness_flush(freshness_t *fr, logger_t *logger);

/** Drop all in-memory state — the send counter and every mark — WITHOUT
 *  writing or re-reading the persisted file.
 *
 *  Test-only, reached through the `*_reset_state` hooks. The C process state
 *  structs are file-static singletons shared by every participant and every
 *  scenario in a run, and the state here is additionally persisted across
 *  runs — so without this, a mark left by one scenario (or by the previous
 *  invocation of a test binary) refuses the next one's first message from the
 *  "same" sender. The conformance harness compounds it by deriving
 *  participant uuids deterministically from their slugs, which makes "alice"
 *  literally the same sender in every scenario.
 *
 *  Production code MUST NOT call it: a rewound counter has its next messages
 *  refused by peers whose marks it cannot see, and forgotten marks are one
 *  replay each per (sender, verb). That is exactly why the state is persisted
 *  in the first place. */
void freshness_reset(freshness_t *fr);

#endif  /* FRESHNESS_H */
