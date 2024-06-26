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

#define DEBUG_TESTS 0

#include "test_setup.h"

DEFINE_TEST(test_logging)
{
    logger_t logger;
    logger_init(&logger, DEBUG, NULL);
    log_debug(&logger, "Hello %s 1\n", "World");
    log_info(&logger, "Hello %s 2\n", "World");
    log_warn(&logger, "Hello %s 3\n", "World");
    log_error(&logger, "Hello %s 4\n", "World");
    log_critical(&logger, "Hello %s 5\n", "World");
    logger_init_local_time_res(&logger, WARNING, "/tmp/test.log", MICROSECONDS);
    log_debug(&logger, "Hello %s 6\n", "World");
    log_error(&logger, "Hello %s 7\n", "World");
}
END_TEST_DEFINITION()

RUN_TESTS(Logging, test_logging)
