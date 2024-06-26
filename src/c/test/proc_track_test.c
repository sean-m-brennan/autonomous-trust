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

#include <stdlib.h>
#include "autonomous_trust/processes/process_tracker.h"
#include "autonomous_trust/processes/processes.h"
#include "autonomous_trust/config/configuration_priv.h"

#define DEBUG_TESTS 0

#include "test_setup.h"


int first_handle(const process_t *proc, map_t *queues, int signal)
{
    return 0;
}

int second_handle(const process_t *proc, map_t *queues, int signal)
{
    return 0;
}


DEFINE_TEST(test_process_tracker_write_config)
{
    const char *expected = "{\"typename\": \"process_tracker\", \"subsystems\": [{\"network\": \"first\"}, {\"identity\": \"second\"}]}";
    const char *filename = "proc_track_test.cfg.json";

    logger_t logger;
    ck_assert_ret_ok(logger_init(&logger, DEBUG, NULL));

    tracker_t tracker;
    ck_assert_ret_ok(tracker_init(&logger, &tracker));

    ck_assert_ret_ok(tracker_register_subsystem(&tracker, "network", "first"));
    ck_assert_ret_ok(tracker_register_subsystem(&tracker, "identity", "second"));

    config_t *cfg = find_configuration("process_tracker");
    int ret = write_config_file(cfg, &tracker, filename);
    if (ret != 0)
        log_exception(&logger);
    ck_assert_int_eq(ret, 0);

    char actual[100];
    FILE *f = fopen(filename, "r");
    ck_assert_ptr_nonnull(f);
    char *ptr = fgets(actual, 100, f);
    ck_assert_ptr_nonnull(ptr);
    fclose(f);

    ck_assert_str_eq(actual, expected);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_process_tracker_read_config)
{
    const char *config = "{\"typename\": \"process_tracker\", \"subsystems\": [{\"network\": \"first\"}, {\"identity\": \"second\"}]}";
    const char *filename = "proc_track_test.cfg.json";

    FILE *f = fopen(filename, "w");
    ck_assert_ptr_nonnull(f);
    ck_assert_ret_nonzero(fputs(config, f));
    fclose(f);

    logger_t logger;
    ck_assert_ret_ok(logger_init(&logger, DEBUG, NULL));

    tracker_t tracker;
    ck_assert_ret_ok(tracker_init(&logger, &tracker));
    int ret = read_config_file(filename, &tracker);
    if (ret != 0)
        log_exception(&logger);

    ck_assert_int_eq(2, map_size(tracker.registry));
}
END_TEST_DEFINITION()

RUN_TESTS(ProcessTracker, test_process_tracker_write_config, test_process_tracker_read_config)
