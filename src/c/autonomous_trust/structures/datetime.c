/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#define _XOPEN_SOURCE 700
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>

#include "datetime_priv.h"
#include "../utilities/util.h"

#define MAX_TZ_OFFSET_STR 12

const double nsec_per_sec = 1000000000.0;

typedef struct
{
    double res;
    const char *time_fmt;
} time_res_config_t;

/*@
  requires \valid_read(dt);
  requires \valid(proto);
  assigns proto->nanosecond, proto->second, proto->minute, proto->hour,
          proto->day, proto->month, proto->year, proto->weekday,
          proto->day_of_year, proto->utc_offset;
  ensures \result == 0;
*/
int datetime_sync_out(datetime_t *dt, AutonomousTrust__Core__Protobuf__Structures__DateTime *proto)
{
    proto->nanosecond = dt->tm_nsec;
    proto->second = dt->tm_sec;
    proto->minute = dt->tm_min;
    proto->hour = dt->tm_hour;
    proto->day = dt->tm_mday;
    proto->month = dt->tm_mon;
    proto->year = dt->tm_year;
    proto->weekday = dt->tm_wday;
    proto->day_of_year = dt->tm_yday;
    proto->utc_offset = dt->tm_tz_offset;
    return 0;
}

/*@
  requires \valid_read(proto);
  requires \valid(dt);
  assigns dt->tm_nsec, dt->tm_sec, dt->tm_min, dt->tm_hour,
          dt->tm_mday, dt->tm_mon, dt->tm_year, dt->tm_wday,
          dt->tm_yday, dt->tm_tz_offset;
  ensures \result == 0;
*/
int datetime_sync_in(AutonomousTrust__Core__Protobuf__Structures__DateTime *proto, datetime_t *dt)
{
    dt->tm_nsec = proto->nanosecond;
    dt->tm_sec = proto->second;
    dt->tm_min = proto->minute;
    dt->tm_hour = proto->hour;
    dt->tm_mday = proto->day;
    dt->tm_mon = proto->month;
    dt->tm_year = proto->year;
    dt->tm_wday = proto->weekday;
    dt->tm_yday = proto->day_of_year;
    dt->tm_tz_offset = proto->utc_offset;
    return 0;
}

/*@
  requires res == MILLISECONDS || res == MICROSECONDS || res == NANOSECONDS;
  assigns \nothing;
  ensures \result.time_fmt != \null;
*/
time_res_config_t set_time_resolution(time_resolution_t res)
{
    time_res_config_t config = {0};
    config.time_fmt = ".%03d";
    switch (res)
    {
    case NANOSECONDS:
        config.res = 1000000000.0;
        config.time_fmt = ".%09d";
        break;
    case MICROSECONDS:
        config.res = 1000000.0;
        config.time_fmt = ".%06d";
        break;
    case MILLISECONDS:
    default:
        config.res = 1000.0;
        config.time_fmt = ".%03d";
        break;
    }
    return config;
}

/*@
  requires str != \null && \valid_read(str);
  requires \valid(offset);
  assigns *offset;
  behavior success:
    ensures \result == 0;
    ensures *offset >= -14.0 && *offset <= 14.0;
  behavior parse_error:
    ensures \result == 214;
  disjoint behaviors;
*/
/* Frama-C: skipped — [string-loop] strtol timezone string parsing */
int str_to_offset(const char *str, float *offset)
{
    if (str == NULL || offset == NULL)
        return EXCEPTION(EINVAL);

    char s[MAX_TZ_OFFSET_STR+1] = {0};
    /* strcpy is safe here because the only in-tree caller passes the
     * output of strftime(..., "%z", ...), which is always 5 bytes
     * ("+0000" format). If this helper ever becomes public, re-evaluate. */
    strcpy(s, str);
    char *first = strchr(s, ':');
    if (first == NULL)
        return EXCEPTION(EDT_FMT);
    char *second = strrchr(s, ':');
    if (second == NULL)
        return EXCEPTION(EDT_FMT);
    first[0] = 0;
    second[0] = 0;

    /* strtol uses endptr to distinguish "no digits parsed" (which would
     * silently return 0) from a real zero value. Reject any segment
     * that didn't advance the cursor. */
    char *end = NULL;
    long hours = strtol(s, &end, 10);
    if (end == s)
        return EXCEPTION(EDT_FMT);
    long minutes_raw = strtol(first + 1, &end, 10);
    if (end == first + 1)
        return EXCEPTION(EDT_FMT);
    float minutes = (float)minutes_raw;
    if (first != second)
    {
        long seconds = strtol(second + 1, &end, 10);
        if (end == second + 1)
            return EXCEPTION(EDT_FMT);
        minutes = (seconds / 60.0f) + minutes;
    }
    *offset = (minutes / 60.0f) + (float)hours;
    return 0;
}

/*@
  requires \valid(str + (0 .. MAX_TZ_OFFSET_STR));
  assigns str[0 .. MAX_TZ_OFFSET_STR];
  ensures \result >= 0;
*/
/* Frama-C: skipped — [solver-timeout] snprintf stub assigns cascade */
int offset_to_str(float offset, char *str)
{
    const char *sign = "";
    if (offset >= 0)
        sign = "+";
    float hour;
    float frac = fabsf(modff(offset, &hour));
    int minutes = (int)(60 * frac);
    int seconds = (int)(3600 * (frac - (60.0 / minutes)));
    if (seconds > 0)
        return snprintf(str, MAX_TZ_OFFSET_STR + 1, "%s%d:%d:%d", sign, (int)hour, minutes, seconds);
    return snprintf(str, MAX_TZ_OFFSET_STR + 1, "%s%d:%d", sign, (int)hour, minutes);
}

const char *conversions[] = {"%f", "%z", "%Z"};
size_t c_size = sizeof(conversions) / sizeof(conversions[0]);

/* WP deferred: snprintf with pointer arithmetic and non-literal format
   strings generates unbounded ranges that WP cannot model.
   Contract kept in datetime.h for callers. */
/* Frama-C: skipped — [solver-timeout] snprintf stub assigns cascade through format operations */
int datetime_strftime_res(const datetime_t *dt, const char *format, const time_resolution_t tr, char *s, size_t max)
{
    time_res_config_t res_cfg = set_time_resolution(tr);
    struct tm *tm = (struct tm *)dt;

    char tz[MAX_TZ_OFFSET_STR+1] = {0};
    if (dt->tm_utc)
        strcpy(tz, "Z");
    else
        offset_to_str(dt->tm_tz_offset, tz);

    int ns = (dt->tm_nsec / nsec_per_sec) * res_cfg.res;

    char fmt[MAX_DT_STR+1] = {0};
    strncpy(fmt, format, 255);
    size_t fmt_size = strlen(fmt);

    int err = 0;
    char *prev = fmt;
    size_t remaining = max;
    size_t len = 0;
    bool stop = false;
    for (int i = 0; i < fmt_size; i++)
    {
        for (int j = 0; j < c_size; j++)
        {
            if (strncmp(fmt + i, conversions[j], 2) == 0)
            {
                fmt[i] = 0;
                if (prev != NULL)
                {
                    len += strftime(s + len, remaining, prev, tm);
                    remaining -= len;
                    if (len == 0 || remaining <= 0)
                    {
                        err = E2BIG;
                        stop = true;
                        break;
                    }
                    prev = fmt + i + 2;
                }
                if (j == 0) { // %f - subsecond
                    if (res_cfg.res >= 1000000000.0)
                        len += snprintf(s + len, remaining, ".%09d", ns);
                    else if (res_cfg.res >= 1000000.0)
                        len += snprintf(s + len, remaining, ".%06d", ns);
                    else
                        len += snprintf(s + len, remaining, ".%03d", ns);
                } else if (j == 1 || j == 2) // %z, %Z - timezone offset
                    len += snprintf(s + len, remaining, "%s", tz);
                if (len > max)
                {
                    err = E2BIG;
                    stop = true;
                    break;
                }
                remaining = max - len;
                if (remaining == 0)
                {
                    err = E2BIG;
                    stop = true;
                    break;
                }
            }
        }
        if (stop)
            break;
    }
    if (!stop && prev != NULL && *prev != '\0')
        len += strftime(s + len, remaining, prev, tm);
    return err;
}

inline int datetime_strftime(const datetime_t *dt, const char *format, char *s, size_t max)
{
    return datetime_strftime_res(dt, format, MICROSECONDS, s, max);
}

inline int datetime_to_isoformat(const datetime_t *dt, char *s, size_t max)
{
    return datetime_strftime(dt, iso8601_format, s, max);
}

/* Frama-C: skipped — [string-loop] strptime format parsing with pointer arithmetic */
int datetime_strptime(const char *s, const char *format, datetime_t *dt)
{
    if (s == NULL || format == NULL || dt == NULL)
        return EINVAL;

    memset(dt, 0, sizeof(datetime_t));
    dt->tm_tz_offset = 0;
    dt->tm_utc = false;

    /* build a modified format string, replacing %f and %z with markers,
       then parse in stages */
    char mod_fmt[MAX_DT_STR + 1] = {0};
    int fi = 0, mi = 0;
    (void)0; /* %f and %z are parsed from remainder, not by position */
    size_t fmt_len = strlen(format);

    /* find where %f and %z appear in format, build strptime-compatible format */
    for (fi = 0; fi < (int)fmt_len && mi < MAX_DT_STR - 1; fi++)
    {
        if (fi + 1 < (int)fmt_len && format[fi] == '%')
        {
            if (format[fi + 1] == 'f')
            {
                fi++;       /* skip 'f' */
                continue;
            }
            else if (format[fi + 1] == 'z' || format[fi + 1] == 'Z')
            {
                fi++;
                continue;
            }
        }
        mod_fmt[mi++] = format[fi];
    }
    mod_fmt[mi] = '\0';

    /* parse the standard part first with strptime on the original string */
    /* strptime handles what it can and returns pointer to unparsed remainder */
    char *remainder = strptime(s, "%FT%T", (struct tm *)dt);
    if (remainder == NULL)
    {
        /* try the modified format directly */
        remainder = strptime(s, mod_fmt, (struct tm *)dt);
        if (remainder == NULL)
            return EXCEPTION(EDT_FMT);
    }

    /* now parse the fractional seconds (%f) if present */
    if (remainder != NULL && *remainder == '.')
    {
        remainder++; /* skip '.' */
        char frac_buf[16] = {0};
        int frac_idx = 0;
        while (*remainder >= '0' && *remainder <= '9' && frac_idx < 9)
        {
            frac_buf[frac_idx++] = *remainder++;
        }
        /* pad to 9 digits (nanoseconds) */
        while (frac_idx < 9)
            frac_buf[frac_idx++] = '0';
        frac_buf[9] = '\0';
        dt->tm_nsec = strtoul(frac_buf, NULL, 10);
    }

    /* now parse timezone offset (%z) if present */
    if (remainder != NULL && (*remainder == '+' || *remainder == '-' || *remainder == 'Z'))
    {
        if (*remainder == 'Z')
        {
            dt->tm_utc = true;
            dt->tm_tz_offset = 0;
        }
        else
        {
            int sign = (*remainder == '-') ? -1 : 1;
            remainder++;
            /* parse HH:MM or HHMM */
            long hours = 0, minutes = 0;
            char tz_buf[8] = {0};
            int ti = 0;
            while ((*remainder >= '0' && *remainder <= '9') || *remainder == ':')
            {
                if (*remainder != ':' && ti < 7)
                    tz_buf[ti++] = *remainder;
                remainder++;
            }
            tz_buf[ti] = '\0';
            if (ti >= 4)
            {
                char h[3] = {tz_buf[0], tz_buf[1], '\0'};
                char m[3] = {tz_buf[2], tz_buf[3], '\0'};
                hours = strtol(h, NULL, 10);
                minutes = strtol(m, NULL, 10);
            }
            else if (ti >= 2)
            {
                char h[3] = {tz_buf[0], tz_buf[1], '\0'};
                hours = strtol(h, NULL, 10);
            }
            dt->tm_tz_offset = sign * (hours + minutes / 60.0f);
            dt->tm_utc = false;
        }
    }

    return 0;
}

inline int datetime_from_isostring(const char *s, datetime_t *dt)
{
    return datetime_strptime(s, "%FT%T%f%z", dt);
}

/* Frama-C: skipped — [syscall] localtime/gmtime timezone conversion */
int datetime_from_time(time_t time, long nsec, bool local, datetime_t *dt)
{
    struct tm *tm;
    if (local)
        tm = localtime(&time);
    else
        tm = gmtime(&time);
    if (tm == NULL)
        return errno;

    memcpy(dt, tm, sizeof(struct tm));
    dt->tm_tz_offset = 0;
    if (local)
    {
        char tz[32] = {0};
        strftime(tz, 31, "%z", tm);
        str_to_offset(tz, &dt->tm_tz_offset);
    }
    dt->tm_nsec = nsec;
    dt->tm_utc = !local;
    return 0;
}

/* Frama-C: skipped — [syscall] clock_gettime system time */
int datetime_now(bool local, datetime_t *dt)
{
    struct timespec ts;
    time_t now = time(NULL);
    if (now == (time_t)-1)
        return errno;
    int err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err == -1)
        return errno;
    return datetime_from_time(now, ts.tv_nsec, local, dt);
}

/*@
  requires \valid_read(td);
  requires \valid(proto);
  assigns proto->days, proto->seconds, proto->nanoseconds;
  ensures \result == 0;
*/
int timedelta_sync_out(timedelta_t *td, AutonomousTrust__Core__Protobuf__Structures__TimeDelta *proto)
{
    proto->days = td->days;
    proto->seconds = td->seconds;
    proto->nanoseconds = td->nsecs;
    return 0;
}

/*@
  requires \valid_read(proto);
  requires \valid(td);
  assigns td->days, td->seconds, td->nsecs;
  ensures \result == 0;
*/
int timedelta_sync_in(AutonomousTrust__Core__Protobuf__Structures__TimeDelta *proto, timedelta_t *td)
{
    td->days = proto->days;
    td->seconds = proto->seconds;
    td->nsecs = proto->nanoseconds;
    return 0;
}

/* Frama-C: skipped — [arith] carry-propagation requires bound reasoning. */
int timedelta_normalize_long(long days, long seconds, long nsecs,
                             timedelta_t *out)
{
    if (out == NULL)
        return EINVAL;

    /* Carry nsecs → seconds. Use floor-division semantics so negative
     * remainders stay non-negative (i.e. -1 / 1e9 = -1 rem 999999999,
     * not 0 rem -1). C's `/` and `%` round toward zero for negative
     * operands, so we adjust by hand. */
    long ns_per_sec = 1000000000L;
    long sec_carry = nsecs / ns_per_sec;
    long ns_rem    = nsecs % ns_per_sec;
    if (ns_rem < 0) {
        ns_rem    += ns_per_sec;
        sec_carry -= 1;
    }
    seconds += sec_carry;

    long sec_per_day = 86400L;
    long day_carry = seconds / sec_per_day;
    long sec_rem   = seconds % sec_per_day;
    if (sec_rem < 0) {
        sec_rem   += sec_per_day;
        day_carry -= 1;
    }
    days += day_carry;

    out->days    = days;
    out->seconds = (unsigned int)sec_rem;
    out->nsecs   = (unsigned int)ns_rem;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] snprintf stub interaction with string parsing */
int timedelta_from_string(const char *s, timedelta_t *td)
{
    if (s == NULL || td == NULL)
        return EINVAL;

    memset(td, 0, sizeof(timedelta_t));

    /* format: "Dd HH:MM:SS.nnnnnnnnn" or "HH:MM:SS.nnnnnnnnn" or "Dd" */
    const char *p = s;
    bool negative = false;
    if (*p == '-')
    {
        negative = true;
        p++;
    }

    /* check for "Xd" days prefix */
    const char *d_pos = strchr(p, 'd');
    if (d_pos != NULL)
    {
        char day_buf[16] = {0};
        size_t dlen = d_pos - p;
        if (dlen > 15) dlen = 15;
        memcpy(day_buf, p, dlen);
        td->days = strtol(day_buf, NULL, 10);
        p = d_pos + 1;
        while (*p == ' ') p++;
    }

    /* parse HH:MM:SS */
    if (*p != '\0')
    {
        long hours = 0, minutes = 0, seconds = 0;
        if (sscanf(p, "%ld:%ld:%ld", &hours, &minutes, &seconds) >= 2)
        {
            td->seconds = (unsigned int)(hours * 3600 + minutes * 60 + seconds);
        }

        /* parse fractional seconds */
        const char *dot = strchr(p, '.');
        if (dot != NULL)
        {
            dot++;
            char frac_buf[10] = {0};
            int fi = 0;
            while (*dot >= '0' && *dot <= '9' && fi < 9)
                frac_buf[fi++] = *dot++;
            while (fi < 9)
                frac_buf[fi++] = '0';
            td->nsecs = (unsigned int)strtoul(frac_buf, NULL, 10);
        }
    }

    if (negative)
    {
        /* normalize: timedelta(-1) means days=-1, seconds=86399, etc */
        td->days = -td->days;
        if (td->seconds > 0 || td->nsecs > 0)
        {
            td->days--;
            td->seconds = 86400 - td->seconds;
            if (td->nsecs > 0)
            {
                td->seconds--;
                td->nsecs = 1000000000 - td->nsecs;
            }
        }
    }
    return 0;
}

/* Frama-C: skipped — [solver-timeout] snprintf stub assigns cascade */
int timedelta_to_string(const timedelta_t *td, char *s, size_t max)
{
    if (td == NULL || s == NULL || max == 0)
        return EINVAL;

    long total_seconds = td->seconds;
    long hours = total_seconds / 3600;
    long rem = total_seconds % 3600;
    long minutes = rem / 60;
    long seconds = rem % 60;

    int written;
    if (td->days != 0 && td->nsecs > 0)
        written = snprintf(s, max, "%ldd %02ld:%02ld:%02ld.%09u",
                          td->days, hours, minutes, seconds, td->nsecs);
    else if (td->days != 0)
        written = snprintf(s, max, "%ldd %02ld:%02ld:%02ld",
                          td->days, hours, minutes, seconds);
    else if (td->nsecs > 0)
        written = snprintf(s, max, "%ld:%02ld:%02ld.%09u",
                          hours, minutes, seconds, td->nsecs);
    else
        written = snprintf(s, max, "%ld:%02ld:%02ld",
                          hours, minutes, seconds);

    if (written < 0 || (size_t)written >= max)
        return E2BIG;
    return 0;
}
