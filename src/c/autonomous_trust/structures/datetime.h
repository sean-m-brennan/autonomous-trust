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

#ifndef DATETIME_H
#define DATETIME_H

#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "utilities/exception.h"
#include "structures/datetime.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MILLISECONDS = 1,
    MICROSECONDS,
    NANOSECONDS,
} time_resolution_t;

typedef struct {
    struct tm;
    unsigned long tm_nsec;
    float tm_tz_offset;
    bool tm_utc;
    AutonomousTrust__Core__Structures__DateTime proto;
} datetime_t;

int datetime_init(datetime_t *dt);

int datetime_sync_out(datetime_t *dt);

int datetime_sync_in(datetime_t *dt);

static const char iso8601_format[] = "%FT%T%f%z";

int datetime_strftime_res(const datetime_t *dt, const char *format, const time_resolution_t tr, char *s, size_t max);

int datetime_strftime(const datetime_t *dt, const char *format, char *s, size_t max);

int datetime_to_isoformat(const datetime_t *dt, char *s, size_t max);

int datetime_strptime(const char *s, const char *format, datetime_t *dt);

int datetime_from_isostring(const char *s, datetime_t *dt);

int datetime_from_time(time_t time, long nsec, bool local, datetime_t *dt);

int datetime_now(bool local, datetime_t *dt);


typedef struct {
    long days;
    unsigned int seconds;
    unsigned int nsecs;
    AutonomousTrust__Core__Structures__TimeDelta proto;
} timedelta_t;

int timedelta_init(timedelta_t *timedelta);

int timedelta_sync_out(timedelta_t *td);

int timedelta_sync_in(timedelta_t *td);

// FIXME normalization:
// timedelta(microseconds=-1) == (days=-1, seconds=86399, ms=999999)

int timedelta_from_string(const char *s, timedelta_t *td);

int timedelta_to_string(const timedelta_t *td, char *s, size_t max);

#define EDT_FMT 214
DECLARE_ERROR(EDT_FMT, "String in incorrect format for datetime parsing")

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // DATETIME_H
