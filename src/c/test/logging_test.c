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

#include <check.h>
#include "autonomous_trust/utilities/logger.h"

START_TEST(test_logging)
{
    logger_t logger;
    logger_init(&logger, DEBUG, NULL);
    log_debug(&logger, "Hello %s 1", "World");
    log_info(&logger, "Hello %s 2", "World");
    log_warn(&logger, "Hello %s 3", "World");
    log_error(&logger, "Hello %s 4", "World");
    log_critical(&logger, "Hello %s 5", "World");
    logger_init_local_time_res(&logger, WARNING, "/tmp/test.log", MICROSECONDS);
    log_debug(&logger, "Hello %s 6", "World");
    log_error(&logger, "Hello %s 7", "World");
}
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("Logging");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_logging);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
