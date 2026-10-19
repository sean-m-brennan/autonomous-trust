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

/* Windows stand-in for <sys/timex.h>: an unavailable kernel clock. */
#ifndef AT_COMPAT_SYS_TIMEX_H
#define AT_COMPAT_SYS_TIMEX_H

#include <at_win32.h>

/* Windows has no kernel NTP state to read: ntp_adjtime reports itself
 * unavailable, which utilities/clock.c treats as "clock state unknown", so only
 * a node that requires a synced clock (AT_CLOCK_REQUIRE) refuses to start. */
#define TIME_ERROR   5
#define STA_UNSYNC   0x0040
#define STA_CLOCKERR 0x1000

struct timex
{
    unsigned int modes;
    long offset, freq, maxerror, esterror;
    int  status;
    long constant, precision, tolerance;
};

static inline int ntp_adjtime(struct timex *tx)
{
    (void)tx;
    errno = ENOSYS;
    return -1;
}

#endif /* AT_COMPAT_SYS_TIMEX_H */
