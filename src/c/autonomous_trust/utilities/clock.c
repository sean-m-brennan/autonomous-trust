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

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/timex.h>

#include "utilities/clock.h"
#include "utilities/logger.h"

at_clock_state_t at_clock_state(void)
{
    at_clock_state_t out;
    memset(&out, 0, sizeof(out));

    struct timex tx;
    memset(&tx, 0, sizeof(tx));
    tx.modes = 0; /* read-only query */

    errno = 0;
    int rc = ntp_adjtime(&tx);
    if (rc < 0)
    {
        /* Query refused (seccomp, unusual kernel): report unavailable rather
         * than a clean clock. Failing open here would silently defeat the
         * gate on exactly the hosts least able to be trusted. */
        out.available = false;
        out.synced = false;
        out.max_error_us = -1;
        out.est_error_us = -1;
        return out;
    }

    out.available = true;
    out.status = tx.status;
    out.max_error_us = tx.maxerror;
    out.est_error_us = tx.esterror;
    out.hardware_fault = (tx.status & STA_CLOCKERR) != 0;
    /* Both conditions matter: TIME_ERROR is the documented "not synchronized"
     * return, and STA_UNSYNC is the status bit. A kernel can report one
     * without the other, so neither alone may clear the other. */
    out.synced = (rc != TIME_ERROR) && ((tx.status & STA_UNSYNC) == 0);
    return out;
}

bool at_clock_required(void)
{
    const char *val = getenv(AT_CLOCK_REQUIRE_ENV);
    if (val == NULL)
        return false;
    while (*val == ' ' || *val == '\t')
        val++;
    return strcasecmp(val, "1") == 0 || strcasecmp(val, "true") == 0 ||
           strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0;
}

void at_clock_describe(const at_clock_state_t *state, char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
    if (state == NULL)
    {
        snprintf(buf, len, "(no state)");
        return;
    }
    if (!state->available)
    {
        snprintf(buf, len, "UNAVAILABLE (ntp_adjtime query refused)");
        return;
    }
    snprintf(buf, len, "%s, max_error=%.3fs, status=0x%04x, via ntp_adjtime%s",
             state->synced ? "synced" : "UNSYNCED",
             (double)state->max_error_us / 1000000.0,
             (unsigned)state->status,
             state->hardware_fault ? ", CLOCK HARDWARE FAULT" : "");
}

int at_clock_require_synced(logger_t *logger, long max_error_us)
{
    if (max_error_us <= 0)
        max_error_us = AT_CLOCK_MAX_ERROR_US;

    at_clock_state_t state = at_clock_state();
    bool enforcing = at_clock_required();
    const char *mode = enforcing ? "enforcing" : "advisory";
    bool ok = state.synced && state.max_error_us <= max_error_us;

    char desc[192];
    at_clock_describe(&state, desc, sizeof(desc));

    if (ok)
    {
        if (logger != NULL)
            log_info(logger, "clock: %s [%s, requirement met]\n", desc, mode);
        return 0;
    }

    char why[160];
    if (!state.synced)
        snprintf(why, sizeof(why), "no NTP daemon is disciplining this clock");
    else
        snprintf(why, sizeof(why),
                 "kernel max error %.3fs exceeds the %.3fs bound",
                 (double)state.max_error_us / 1000000.0,
                 (double)max_error_us / 1000000.0);

    /* One message, both modes: the operator needs to know it is the HOST's
     * daemon that is missing — a container cannot discipline CLOCK_REALTIME. */
    if (enforcing)
    {
        if (logger != NULL)
            log_critical(logger,
                         "clock: %s -- %s. Run a stock NTP daemon (chrony, ntpd "
                         "or systemd-timesyncd) on the HOST; a container cannot "
                         "discipline CLOCK_REALTIME itself. [%s: refusing to "
                         "start]\n", desc, why, mode);
        else
            fprintf(stderr,
                    "clock: %s -- %s. Run a stock NTP daemon on the HOST. "
                    "[%s: refusing to start]\n", desc, why, mode);
        return -1;
    }
    if (logger != NULL)
        log_warn(logger,
                 "clock: %s -- %s. Run a stock NTP daemon (chrony, ntpd or "
                 "systemd-timesyncd) on the HOST; a container cannot discipline "
                 "CLOCK_REALTIME itself. [%s: continuing; set %s=1 to make this "
                 "fatal]\n", desc, why, mode, AT_CLOCK_REQUIRE_ENV);
    return 0;
}

/* --- Cohort skew ---------------------------------------------------------- *
 * Measurement only. Nothing below writes a clock, and no offset computed here
 * is ever applied to our own time. See clock.h and
 * doc/architecture/cohort-clock-skew.md.                                     */

at_clock_sample_t at_clock_sample_from_round_trip(double t1, double t2,
                                                  double t3, double t4)
{
    at_clock_sample_t out;
    memset(&out, 0, sizeof(out));

    if (!isfinite(t1) || !isfinite(t2) || !isfinite(t3) || !isfinite(t4))
        return out; /* valid = false: unmeasurable, so no sample at all */

    out.valid = true;
    out.offset_s = ((t2 - t1) + (t3 - t4)) / 2.0;
    out.delay_s = (t4 - t1) - (t3 - t2);
    /* A negative delay is arithmetically impossible, so the timestamps are
     * wrong: a clock stepped mid-exchange, or a peer stamping dishonestly.
     * Reported, never silently dropped, but it must not be aggregated. */
    out.usable = out.delay_s >= 0.0;
    return out;
}

bool at_clock_sample_exceeds(const at_clock_sample_t *sample, long bound_ms)
{
    if (sample == NULL || !sample->valid)
        return false;
    double bound_s = (double)bound_ms / 1000.0;
    double magnitude = sample->offset_s < 0.0 ? -sample->offset_s
                                              : sample->offset_s;
    return magnitude > bound_s;
}

void at_clock_sample_describe(const at_clock_sample_t *sample, const char *peer,
                              char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
    if (sample == NULL || !sample->valid)
    {
        snprintf(buf, len, "(no sample)");
        return;
    }
    snprintf(buf, len, "peer=%s offset=%+.3fs delay=%.3fs%s",
             peer != NULL ? peer : "?", sample->offset_s, sample->delay_s,
             sample->usable ? "" : " UNUSABLE(negative delay)");
}

static int _cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

at_cohort_view_t at_clock_cohort_offset(const at_clock_sample_t *samples,
                                        size_t count)
{
    at_cohort_view_t out;
    memset(&out, 0, sizeof(out));
    if (samples == NULL || count == 0)
        return out;

    double *offsets = calloc(count, sizeof(double));
    if (offsets == NULL)
        return out; /* valid = false rather than a guessed estimate */

    size_t n = 0;
    for (size_t i = 0; i < count; i++)
        if (samples[i].valid && samples[i].usable)
            offsets[n++] = samples[i].offset_s;

    if (n == 0)
    {
        free(offsets);
        return out;
    }

    qsort(offsets, n, sizeof(double), _cmp_double);
    /* Even counts average the two middle values, matching Python's
     * statistics.median exactly -- the two runtimes must not disagree here. */
    out.offset_s = (n % 2 == 1) ? offsets[n / 2]
                                : (offsets[n / 2 - 1] + offsets[n / 2]) / 2.0;
    out.dispersion_s = offsets[n - 1] - offsets[0];
    out.count = n;
    out.valid = true;
    free(offsets);
    return out;
}

long at_clock_max_cohort_skew_ms(logger_t *logger, bool *from_env)
{
    if (from_env != NULL)
        *from_env = false;
    const char *raw = getenv(AT_CLOCK_COHORT_SKEW_ENV);
    if (raw == NULL || raw[0] == '\0')
        return AT_CLOCK_COHORT_SKEW_MS;

    char *end = NULL;
    errno = 0;
    long val = strtol(raw, &end, 10);
    if (errno != 0 || end == raw || (end != NULL && *end != '\0') ||
        val < AT_CLOCK_COHORT_SKEW_MS_MIN || val > AT_CLOCK_COHORT_SKEW_MS_MAX)
    {
        /* Refused, not clamped: a value outside the range is a mistake, and
         * silently substituting a different one hides it. */
        if (logger != NULL)
            log_warn(logger,
                     "clock: refusing %s='%s' (want an integer in [%d, %d]); "
                     "using default %d\n",
                     AT_CLOCK_COHORT_SKEW_ENV, raw,
                     AT_CLOCK_COHORT_SKEW_MS_MIN, AT_CLOCK_COHORT_SKEW_MS_MAX,
                     AT_CLOCK_COHORT_SKEW_MS);
        return AT_CLOCK_COHORT_SKEW_MS;
    }
    if (from_env != NULL)
        *from_env = true;
    return val;
}
