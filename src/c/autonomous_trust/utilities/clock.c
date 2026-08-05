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
