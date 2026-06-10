/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

/** @addtogroup internal_structures
 *  @{
 */

#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DT_STR 512

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
} datetime_t;

static const char iso8601_format[] = "%FT%T%f%z";

/*@ predicate valid_datetime{L}(datetime_t *dt) =
      dt != \null && \valid(dt) &&
      dt->tm_sec >= 0 && dt->tm_sec <= 60 &&
      dt->tm_min >= 0 && dt->tm_min <= 59 &&
      dt->tm_hour >= 0 && dt->tm_hour <= 23 &&
      dt->tm_mday >= 1 && dt->tm_mday <= 31 &&
      dt->tm_mon >= 0 && dt->tm_mon <= 11 &&
      dt->tm_tz_offset >= -14.0 && dt->tm_tz_offset <= 14.0;
*/

/**
 * @brief Format a datetime with explicit time resolution.
 */
/*@
  requires \valid_read(dt);
  requires \valid_read(format);
  requires max > 0;
  requires \valid(s + (0 .. max - 1));
  requires tr == MILLISECONDS || tr == MICROSECONDS || tr == NANOSECONDS;
  assigns s[0 .. max - 1];
  ensures \result == 0 || \result == E2BIG;
*/
int datetime_strftime_res(const datetime_t *dt, const char *format, const time_resolution_t tr, char *s, size_t max);

/**
 * @brief Format a datetime as a string (microsecond resolution).
 */
/*@
  requires \valid_read(dt);
  requires \valid_read(format);
  requires max > 0;
  requires \valid(s + (0 .. max - 1));
  assigns s[0 .. max - 1];
  ensures \result == 0 || \result == E2BIG;
*/
int datetime_strftime(const datetime_t *dt, const char *format, char *s, size_t max);

/**
 * @brief Format a datetime in ISO 8601 format.
 */
/*@
  requires \valid_read(dt);
  requires max > 0;
  requires \valid(s + (0 .. max - 1));
  assigns s[0 .. max - 1];
  ensures \result == 0 || \result == E2BIG;
*/
int datetime_to_isoformat(const datetime_t *dt, char *s, size_t max);

/**
 * @brief Parse a string into a datetime according to format.
 */
/*@
  requires s != \null && \valid_read(s);
  requires format != \null && \valid_read(format);
  requires dt != \null && \valid(dt);
  assigns *dt;
  ensures \result == 0 || \result == 214;
  ensures \result == 0 ==> \initialized(dt);
*/
int datetime_strptime(const char *s, const char *format, datetime_t *dt);

/**
 * @brief Parse an ISO 8601 string into a datetime.
 */
/*@
  requires s != \null && \valid_read(s);
  requires dt != \null && \valid(dt);
  assigns *dt;
  ensures \result == 0 || \result == 214;
  ensures \result == 0 ==> \initialized(dt);
*/
int datetime_from_isostring(const char *s, datetime_t *dt);

/**
 * @brief Convert a time_t and nanoseconds into a datetime.
 */
/*@
  requires dt != \null && \valid(dt);
  requires nsec >= 0 && nsec < 1000000000;
  assigns *dt;
  ensures \result == 0 || \result != 0;
*/
int datetime_from_time(time_t time, long nsec, bool local, datetime_t *dt);

/**
 * @brief Fill dt with the current date and time.
 */
/*@
  requires dt != \null && \valid(dt);
  assigns *dt;
  behavior success:
    ensures \result == 0;
    ensures \initialized(dt);
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int datetime_now(bool local, datetime_t *dt);


typedef struct {
    long days;
    unsigned int seconds;
    unsigned int nsecs;
} timedelta_t;

/*@ predicate valid_timedelta{L}(timedelta_t *td) =
      td != \null && \valid(td) &&
      td->seconds < 86400 &&
      td->nsecs < 1000000000;
*/

/**
 * @brief Normalize a (days, seconds, nsecs) triple into a canonical
 *        @ref timedelta_t with @c 0 <= seconds < 86400 and
 *        @c 0 <= nsecs < 1000000000.
 *
 * Accepts signed inputs so the caller can express intermediate values
 * outside the normalized ranges — most notably negative microseconds.
 * Python's `datetime.timedelta` normalizes the same way:
 *
 *   timedelta(microseconds=-1) → (days=-1, seconds=86399, ms=999999)
 *
 * Carry propagates from @p nsecs into @p seconds and from @p seconds
 * into @p days; sign is absorbed into @p days only.
 *
 * @param[in]  days     Day component (may be negative).
 * @param[in]  seconds  Second component (any sign / magnitude).
 * @param[in]  nsecs    Nanosecond component (any sign / magnitude).
 * @param[out] out      Receives the normalized triple.
 * @return 0 on success, non-zero on @c \null @p out.
 */
/*@
  requires out != \null && \valid(out);
  assigns *out;
  behavior success:
    ensures \result == 0;
    ensures valid_timedelta(out);
    ensures \initialized(out);
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int timedelta_normalize_long(long days, long seconds, long nsecs,
                             timedelta_t *out);

/**
 * @brief Parse a timedelta from a string ("Dd HH:MM:SS.nnnnnnnnn").
 */
/*@
  requires s != \null && \valid_read(s);
  requires td != \null && \valid(td);
  assigns *td;
  behavior success:
    ensures \result == 0;
    ensures \initialized(td);
  behavior invalid:
    assumes s == \null || td == \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int timedelta_from_string(const char *s, timedelta_t *td);

/**
 * @brief Format a timedelta into a string buffer.
 */
/*@
  requires td != \null && \valid_read(td);
  requires s != \null && max > 0;
  requires \valid(s + (0 .. max - 1));
  assigns s[0 .. max - 1];
  behavior success:
    ensures \result == 0;
    ensures (\exists integer i; 0 <= i < max && s[i] == '\0');
  behavior too_small:
    ensures \result == E2BIG;
  behavior invalid:
    assumes td == \null || s == \null || max == 0;
    ensures \result != 0;
  disjoint behaviors;
*/
int timedelta_to_string(const timedelta_t *td, char *s, size_t max);

#define EDT_FMT 214
DECLARE_ERROR(EDT_FMT, "String in incorrect format for datetime parsing")

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_structures */

#endif  // DATETIME_H
