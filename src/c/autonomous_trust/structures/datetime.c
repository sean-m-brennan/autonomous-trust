/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

time_res_config_t set_time_resolution(time_resolution_t res)
{
    time_res_config_t config = {0};
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

int str_to_offset(const char *str, float *offset)  // FIXME different sig for errors
{
    char s[MAX_TZ_OFFSET_STR+1] = {0};
    strcpy(s, str);
    char *first = strchr(s, ':');
    if (first == NULL)
        return EXCEPTION(EDT_FMT);
    char *second = strrchr(s, ':');
    if (second == NULL)
        return EXCEPTION(EDT_FMT);
    first[0] = 0;
    second[0] = 0;
    long hours = strtol(s, NULL, 10);
    float minutes = strtol(first + 1, NULL, 10);
    if (first != second)
    {
        long seconds = strtol(second + 1, NULL, 10);
        minutes = (seconds / 60.0) + minutes;
    }
    *offset = (minutes / 60.0) + hours;
    return 0;
}

int offset_to_str(float offset, char *str)
{
    const char *sign = "";
    if (offset >= 0)
        sign = "+";
    float hour;
    float frac = fabsf(modff(offset, &hour));
    int minutes = (int)(60 * frac);
    int seconds = (int)(3600 * (frac - (60.0 / minutes)));
    const char *format = "%s%d:%d";
    if (seconds > 0)
        format = "%s%d:%d:%d";
    return sprintf(str, format, sign, (int)hour, minutes, seconds);
}

const char *conversions[] = {"%f", "%z", "%Z"};
size_t c_size = sizeof(conversions) / sizeof(conversions[0]);

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
                if (j == 0) // %f - subsecond
                    len += sprintf(s + len, res_cfg.time_fmt, ns);
                else if (j == 1 || j == 2) // %z, %Z - timezone offset
                    len += sprintf(s + len, "%s", tz);
                remaining = max - len;
                if (len < 0)
                {
                    err = len;
                    stop = true;
                    break;
                }
                if (remaining <= 0)
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
    if (prev == NULL && strlen(s) == 0 && strlen(fmt) > 0)
        strftime(s, max, fmt, tm);
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

int datetime_strptime(const char *s, const char *format, datetime_t *dt)
{
    // FIXME parse %f, %z
    strptime(s, format, (struct tm *)dt); // FIXME error handling
    return 0;
}

inline int datetime_from_isostring(const char *s, datetime_t *dt)
{
    return datetime_strptime(s, "%FT%T%f%z", dt);
}

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

int timedelta_sync_out(timedelta_t *td, AutonomousTrust__Core__Protobuf__Structures__TimeDelta *proto)
{
    proto->days = td->days;
    proto->seconds = td->seconds;
    proto->nanoseconds = td->nsecs;
    return 0;
}

int timedelta_sync_in(AutonomousTrust__Core__Protobuf__Structures__TimeDelta *proto, timedelta_t *td)
{
    td->days = proto->days;
    td->seconds = proto->seconds;
    td->nsecs = proto->nanoseconds;
    return 0;
}

int timedelta_from_string(const char *s, timedelta_t *td)
{
    // FIXME
    return 0;
}

int timedelta_to_string(const timedelta_t *td, char *s, size_t max)
{
    // FIXME
    return 0;
}
