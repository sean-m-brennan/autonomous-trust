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

#ifndef AT_CLOCK_H
#define AT_CLOCK_H

/**
 * @file clock.h
 * @brief Read the state of the system's clock discipline. Never implement it.
 *
 * AT used to carry its own NTP client on both sides. The C implementation
 * is production, so time discipline here is the job of a stock daemon
 * (chrony, ntpd, systemd-timesyncd) and AT's job is only to refuse to run
 * on a clock nobody is steering.
 *
 * The query is `ntp_adjtime(modes = 0)`, which is:
 *
 *   - unprivileged — it is a read; setting the clock needs CAP_SYS_TIME
 *   - dependency-free — no chrony socket, no client binary, no network
 *   - honest inside a container — CLOCK_REALTIME is not namespaced (a time
 *     namespace can offset only CLOCK_MONOTONIC and CLOCK_BOOTTIME), so a
 *     container reads its host's discipline state. That is also why a
 *     per-container chronyd is the wrong shape: without CAP_SYS_TIME it
 *     could not discipline anything, and with it, it would fight the host.
 *
 * The Python side mirrors this in `core/_python/network/clock.py` using the
 * same syscall, so both implementations agree on what "synced" means.
 */

#include <stdbool.h>

#include "utilities/logger.h"

/** Kernel-estimated max error, in microseconds, above which a clock is
 *  refused. NTP's own unusable distance is ~1 s (RFC 5905 MAXDIST 1.5 s);
 *  an undisciplined Linux kernel reports 16 s, so this cleanly separates
 *  "synced but imprecise" from "nobody is steering this clock". */
#define AT_CLOCK_MAX_ERROR_US 1000000L

/** Operator switch. Unset means advisory (warn once, proceed), which is what
 *  a developer machine or a test run needs; AT container images set it to 1
 *  so a production node refuses to join a cohort on an undisciplined clock. */
#define AT_CLOCK_REQUIRE_ENV "AT_REQUIRE_SYNCED_CLOCK"

/** What the kernel says about its own time discipline. */
typedef struct at_clock_state_s
{
    bool synced;           /**< A daemon is disciplining this clock. */
    bool hardware_fault;   /**< STA_CLOCKERR: the clock hardware is faulty. */
    long max_error_us;     /**< Kernel-estimated maximum error. */
    long est_error_us;     /**< Kernel-estimated expected error. */
    int status;            /**< Raw STA_* bits, for the log line. */
    bool available;        /**< False if the query itself could not be made. */
} at_clock_state_t;

/**
 * Query the kernel's clock discipline. Never fails.
 *
 * An unavailable syscall reports `synced = false` with `available = false`
 * rather than pretending the clock is fine: a check that failed open would
 * be worse than no check at all.
 */
at_clock_state_t at_clock_state(void);

/** Whether an unsynced clock is fatal here. See @ref AT_CLOCK_REQUIRE_ENV. */
bool at_clock_required(void);

/**
 * Gate startup on the host's clock discipline.
 *
 * Enforcing when AT_REQUIRE_SYNCED_CLOCK is set (AT container images set
 * it), advisory otherwise. Either way it logs which mode applied and what it
 * saw, so a start that proceeded is never ambiguous about whether the clock
 * was checked.
 *
 * @param logger      where the verdict goes; may be NULL (then stderr).
 * @param max_error_us error bound; pass 0 for @ref AT_CLOCK_MAX_ERROR_US.
 * @return 0 when the clock is acceptable or the check is advisory,
 *         -1 when enforcing and the clock is not acceptable.
 */
int at_clock_require_synced(logger_t *logger, long max_error_us);

/** Render a state for a log line. Writes at most @p len bytes including NUL. */
void at_clock_describe(const at_clock_state_t *state, char *buf, size_t len);

/* ---------------------------------------------------------------------------
 * Cohort skew: how far peers' clocks sit from ours.
 *
 * This measures and reports. It steers NOTHING. AT does not become a time
 * source for its cohort, and an offset measured here is never applied to any
 * clock — re-creating that would restore the defect for which AT's own NTP
 * client was deleted. What it buys: a node that can SEE a peer's clock
 * disagree can decline to order events against that peer, instead of trusting
 * the timestamp silently.
 *
 * Mirrors `core/_python/network/clock.py`; the estimator and the knob bounds
 * are identical on both sides on purpose.
 * See doc/architecture/cohort-clock-skew.md.
 * ------------------------------------------------------------------------- */

/** Bound past which a peer's timestamps stop being usable for ordering.
 *
 *  2 s is the pairwise implication of @ref AT_CLOCK_MAX_ERROR_US: if each of
 *  two nodes is within 1 s of true time, the pair is within 2 s of each other,
 *  so a peer beyond this is reporting something the local gate would already
 *  have refused of itself. */
#define AT_CLOCK_COHORT_SKEW_MS 2000
#define AT_CLOCK_COHORT_SKEW_MS_MIN 1
#define AT_CLOCK_COHORT_SKEW_MS_MAX 86400000

/** Operator switch, in milliseconds — matching Python's name exactly, since the
 *  point of these knobs is that one deployment setting tunes both runtimes.
 *  Milliseconds (not seconds) keeps both sides off the float-parsing path. */
#define AT_CLOCK_COHORT_SKEW_ENV "AT_MAX_COHORT_SKEW_MS"

/** One peer's clock, measured across one request/response round trip. */
typedef struct at_clock_sample_s
{
    double offset_s;  /**< Peer clock minus ours; positive = peer is ahead. */
    double delay_s;   /**< Round trip with the peer's processing time removed. */
    bool usable;      /**< False when delay < 0, i.e. the timings are impossible. */
    bool valid;       /**< False when the round trip could not be measured. */
} at_clock_sample_t;

/** The cohort view over many samples. */
typedef struct at_cohort_view_s
{
    double offset_s;      /**< Median peer offset. */
    double dispersion_s;  /**< Peak spread across usable samples. */
    size_t count;         /**< How many usable samples contributed. */
    bool valid;           /**< False when there was nothing usable to report. */
} at_cohort_view_t;

/**
 * Build a sample from the four timestamps of one round trip.
 *
 * @p t1 / @p t4 are ours (request sent, response received) and @p t2 / @p t3
 * are the peer's (request received, response sent), all wall-clock epoch
 * seconds. The arithmetic is NTP's (RFC 5905 §8), which is why @p t2 and @p t3
 * must be separate readings: their difference is the peer's processing time,
 * and subtracting it keeps a slow responder from being reported as a skewed
 * one. Python's responder cannot answer inline at all, so that gap is
 * routinely milliseconds.
 *
 * A non-finite input yields `valid = false`: a round trip that cannot be
 * measured produces no sample rather than a wrong one.
 */
at_clock_sample_t at_clock_sample_from_round_trip(double t1, double t2,
                                                  double t3, double t4);

/** True when the sample's magnitude exceeds @p bound_ms. Symmetric: a peer
 *  behind us is as unusable as one ahead. */
bool at_clock_sample_exceeds(const at_clock_sample_t *sample, long bound_ms);

/** Render a sample for a log line. Writes at most @p len bytes including NUL. */
void at_clock_sample_describe(const at_clock_sample_t *sample, const char *peer,
                              char *buf, size_t len);

/**
 * Aggregate samples into the cohort view.
 *
 * The estimator is the MEDIAN, not the mean: a minority of peers reporting
 * wild timestamps — broken, or lying — must not be able to drag the cohort
 * estimate, and a mean lets any single sample do exactly that. Even counts
 * average the two middle values, matching Python's `statistics.median` so both
 * runtimes agree to the last bit. Unusable samples are excluded.
 */
at_cohort_view_t at_clock_cohort_offset(const at_clock_sample_t *samples,
                                        size_t count);

/**
 * Resolve the skew bound: env, then compile-time default.
 *
 * Same two layers, bounds and refusal rules as the network tunables (§2.4.4) —
 * a bad value is refused with a warning and the default kept. Implemented here
 * rather than via `net_knob_resolve` because that machinery is private to the
 * network module, and utilities must not depend upward on it.
 *
 * @param logger    where a refusal is reported; may be NULL.
 * @param from_env  optional out: true when the environment supplied the value.
 */
long at_clock_max_cohort_skew_ms(logger_t *logger, bool *from_env);

#endif /* AT_CLOCK_H */
