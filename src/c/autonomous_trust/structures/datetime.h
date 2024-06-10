#ifndef DATETIME_H
#define DATETIME_H

#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "utilities/exception.h"

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

int datetime_strftime_res(const datetime_t *dt, const char *format, const time_resolution_t tr, char *s, size_t max);

int datetime_strftime(const datetime_t *dt, const char *format, char *s, size_t max);

int datetime_to_isoformat(const datetime_t *dt, char *s, size_t max);

int datetime_strptime(const char *s, const char *format, datetime_t *dt);

int datetime_from_isostring(const char *s, datetime_t *dt);

int datetime_from_time(time_t time, long nsec, bool local, datetime_t *dt);

int datetime_now(bool local, datetime_t *dt);


typedef struct {
    long days;
    long seconds;
    long nsecs;
} timedelta_t;

// FIXME normalization:
// timedelta(microseconds=-1) == (days=-1, seconds=86399, ms=999999)

int timedelta_from_string(const char *s, timedelta_t *td);

int timedelta_to_string(const timedelta_t *td, char *s, size_t max);

#define EDT_FMT 190
DECLARE_ERROR(EDT_FMT, "String in incorrect format for datetime parsing")

#endif  // DATETIME_H
