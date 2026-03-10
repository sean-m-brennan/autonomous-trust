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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <time.h>

#include "autonomous_trust/structures/datetime.h"

DEFINE_TEST(test_datetime_now)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));

    ck_assert_ret_ok(datetime_now(false, &dt));  /* UTC */
    ck_assert(dt.tm_year >= 125);  /* 2025 - 1900 */
    ck_assert(dt.tm_utc == true);

    datetime_t dt_local;
    memset(&dt_local, 0, sizeof(dt_local));
    ck_assert_ret_ok(datetime_now(true, &dt_local));
    ck_assert(dt_local.tm_year >= 125);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_from_time)
{
    /* Create datetime from known epoch: 2025-01-15 12:30:45 UTC */
    struct tm known = {0};
    known.tm_year = 125;  /* 2025 */
    known.tm_mon = 0;     /* January */
    known.tm_mday = 15;
    known.tm_hour = 12;
    known.tm_min = 30;
    known.tm_sec = 45;
    time_t t = timegm(&known);

    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    ck_assert_ret_ok(datetime_from_time(t, 123456789L, false, &dt));

    ck_assert_int_eq(dt.tm_year, 125);
    ck_assert_int_eq(dt.tm_mon, 0);
    ck_assert_int_eq(dt.tm_mday, 15);
    ck_assert_int_eq(dt.tm_hour, 12);
    ck_assert_int_eq(dt.tm_min, 30);
    ck_assert_int_eq(dt.tm_sec, 45);
    ck_assert(dt.tm_nsec == 123456789UL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_strftime)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    dt.tm_year = 125;
    dt.tm_mon = 5;   /* June */
    dt.tm_mday = 15;
    dt.tm_hour = 10;
    dt.tm_min = 30;
    dt.tm_sec = 0;
    dt.tm_utc = true;
    dt.tm_nsec = 0;

    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(datetime_strftime(&dt, "%Y-%m-%d %H:%M:%S", buf, sizeof(buf)));

    ck_assert_str_eq(buf, "2025-06-15 10:30:00");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_strftime_resolution)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    dt.tm_year = 125;
    dt.tm_mon = 0;
    dt.tm_mday = 1;
    dt.tm_hour = 0;
    dt.tm_min = 0;
    dt.tm_sec = 0;
    dt.tm_utc = true;
    dt.tm_nsec = 123456789UL;

    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(datetime_strftime_res(&dt, "%Y-%m-%d %H:%M:%S%f", MILLISECONDS, buf, sizeof(buf)));
    /* Should include millisecond fractional seconds */
    ck_assert(strlen(buf) > 19);  /* longer than "YYYY-MM-DD HH:MM:SS" */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timedelta_roundtrip)
{
    timedelta_t td = {.days = 3, .seconds = 7200, .nsecs = 500000000};
    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(timedelta_to_string(&td, buf, sizeof(buf)));
    ck_assert(strlen(buf) > 0);

    timedelta_t td2;
    memset(&td2, 0, sizeof(td2));
    ck_assert_ret_ok(timedelta_from_string(buf, &td2));
    ck_assert_int_eq(td2.days, 3);
    ck_assert_uint_eq(td2.seconds, 7200);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_isoformat)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    dt.tm_year = 125;
    dt.tm_mon = 2;   /* March */
    dt.tm_mday = 10;
    dt.tm_hour = 14;
    dt.tm_min = 30;
    dt.tm_sec = 0;
    dt.tm_utc = true;
    dt.tm_nsec = 0;

    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(datetime_to_isoformat(&dt, buf, sizeof(buf)));
    ck_assert(strlen(buf) > 0);
    /* Should contain the date portion */
    ck_assert(strstr(buf, "2025") != NULL);
    ck_assert(strstr(buf, "03") != NULL || strstr(buf, "14") != NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(DateTime, test_datetime_now, test_datetime_from_time,
          test_datetime_strftime, test_datetime_strftime_resolution,
          test_timedelta_roundtrip, test_datetime_isoformat)
