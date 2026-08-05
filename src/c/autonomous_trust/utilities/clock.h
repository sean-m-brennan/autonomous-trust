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

#endif /* AT_CLOCK_H */
