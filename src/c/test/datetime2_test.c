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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <time.h>

#include "autonomous_trust/structures/datetime.h"

DEFINE_TEST(test_datetime_strptime_basic)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));

    ck_assert_ret_ok(datetime_strptime("2025-03-15 14:30:00", "%Y-%m-%d %H:%M:%S", &dt));
    ck_assert_int_eq(dt.tm_year, 125);  /* 2025 - 1900 */
    ck_assert_int_eq(dt.tm_mon, 2);     /* March = 2 */
    ck_assert_int_eq(dt.tm_mday, 15);
    ck_assert_int_eq(dt.tm_hour, 14);
    ck_assert_int_eq(dt.tm_min, 30);
    ck_assert_int_eq(dt.tm_sec, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_isoformat_roundtrip)
{
    /* Create a known datetime */
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    dt.tm_year = 125;
    dt.tm_mon = 5;   /* June */
    dt.tm_mday = 20;
    dt.tm_hour = 8;
    dt.tm_min = 45;
    dt.tm_sec = 30;
    dt.tm_utc = true;
    dt.tm_nsec = 0;

    /* Serialize to ISO string */
    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(datetime_to_isoformat(&dt, buf, sizeof(buf)));
    ck_assert(strlen(buf) > 0);
    ck_assert(strstr(buf, "2025") != NULL);

    /* Parse it back */
    datetime_t dt2;
    memset(&dt2, 0, sizeof(dt2));
    ck_assert_ret_ok(datetime_from_isostring(buf, &dt2));
    ck_assert_int_eq(dt2.tm_year, 125);
    ck_assert_int_eq(dt2.tm_mon, 5);
    ck_assert_int_eq(dt2.tm_mday, 20);
    ck_assert_int_eq(dt2.tm_hour, 8);
    ck_assert_int_eq(dt2.tm_min, 45);
    ck_assert_int_eq(dt2.tm_sec, 30);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_from_time_local)
{
    /* Test local time variant */
    struct tm known = {0};
    known.tm_year = 125;
    known.tm_mon = 6;    /* July */
    known.tm_mday = 4;
    known.tm_hour = 12;
    known.tm_min = 0;
    known.tm_sec = 0;
    time_t t = timegm(&known);

    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    ck_assert_ret_ok(datetime_from_time(t, 0, true, &dt));  /* local */
    ck_assert(dt.tm_utc == false);
    /* Year should still be 2025 regardless of timezone */
    ck_assert_int_eq(dt.tm_year, 125);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_datetime_strftime_with_tz)
{
    datetime_t dt;
    memset(&dt, 0, sizeof(dt));
    dt.tm_year = 125;
    dt.tm_mon = 0;    /* January */
    dt.tm_mday = 1;
    dt.tm_hour = 0;
    dt.tm_min = 0;
    dt.tm_sec = 0;
    dt.tm_utc = true;
    dt.tm_nsec = 500000000UL;  /* 0.5s */

    /* Format with fractional seconds */
    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(datetime_strftime_res(&dt, "%Y-%m-%dT%H:%M:%S%f%z",
                                           NANOSECONDS, buf, sizeof(buf)));
    ck_assert(strlen(buf) > 19);
    ck_assert(strstr(buf, "2025-01-01") != NULL);
    /* Should have 'Z' for UTC timezone */
    ck_assert(strstr(buf, "Z") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timedelta_zero)
{
    timedelta_t td = {.days = 0, .seconds = 0, .nsecs = 0};
    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(timedelta_to_string(&td, buf, sizeof(buf)));
    ck_assert(strlen(buf) > 0);

    timedelta_t td2;
    memset(&td2, 0, sizeof(td2));
    ck_assert_ret_ok(timedelta_from_string(buf, &td2));
    ck_assert_int_eq(td2.days, 0);
    ck_assert_uint_eq(td2.seconds, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timedelta_large)
{
    timedelta_t td = {.days = 365, .seconds = 86399, .nsecs = 999999999};
    char buf[MAX_DT_STR] = {0};
    ck_assert_ret_ok(timedelta_to_string(&td, buf, sizeof(buf)));

    timedelta_t td2;
    memset(&td2, 0, sizeof(td2));
    ck_assert_ret_ok(timedelta_from_string(buf, &td2));
    ck_assert_int_eq(td2.days, 365);
    ck_assert_uint_eq(td2.seconds, 86399);
}
END_TEST_DEFINITION()

RUN_TESTS(DateTime2, test_datetime_strptime_basic, test_datetime_isoformat_roundtrip,
          test_datetime_from_time_local, test_datetime_strftime_with_tz,
          test_timedelta_zero, test_timedelta_large)
