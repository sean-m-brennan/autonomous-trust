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
#include <sodium.h>
#include <jansson.h>

#include "processes/process_tracker_priv.h"
#include "utilities/exception.h"

DEFINE_TEST(test_tracker_create_free)
{
    ck_assert(sodium_init() >= 0);

    tracker_t *tracker = NULL;
    ck_assert_ret_ok(tracker_create(NULL, &tracker));
    ck_assert_ptr_nonnull(tracker);
    ck_assert_ptr_nonnull(tracker->registry);

    tracker_free(tracker);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tracker_register_subsystem)
{
    ck_assert(sodium_init() >= 0);

    tracker_t *tracker = NULL;
    ck_assert_ret_ok(tracker_create(NULL, &tracker));

    ck_assert_ret_ok(tracker_register_subsystem(tracker, "network", "udp_net_4"));
    ck_assert_ret_ok(tracker_register_subsystem(tracker, "identity", "id_proc"));

    /* Verify registry size */
    ck_assert_uint_eq(map_size(tracker->registry), 2);

    /* Verify we can look up a registered subsystem */
    data_t *val = NULL;
    char key_net[] = "network";
    ck_assert_ret_ok(map_get(tracker->registry, key_net, &val));
    char *impl = NULL;
    ck_assert_ret_ok(data_string_ptr(val, &impl));
    ck_assert_str_eq(impl, "udp_net_4");

    tracker_free(tracker);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tracker_json_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    tracker_t *tracker = NULL;
    ck_assert_ret_ok(tracker_create(NULL, &tracker));

    ck_assert_ret_ok(tracker_register_subsystem(tracker, "network", "udp_net_4"));
    ck_assert_ret_ok(tracker_register_subsystem(tracker, "reputation", "rep_proc"));

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(tracker_to_json(tracker, &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert(json_is_object(obj));

    /* Check structure */
    json_t *typename_j = json_object_get(obj, "typename");
    ck_assert_ptr_nonnull(typename_j);
    ck_assert_str_eq(json_string_value(typename_j), "process_tracker");

    json_t *subsystems = json_object_get(obj, "subsystems");
    ck_assert_ptr_nonnull(subsystems);
    ck_assert(json_is_array(subsystems));

    /* Deserialize back */
    tracker_t tracker_in;
    memset(&tracker_in, 0, sizeof(tracker_in));
    ck_assert_ret_ok(map_create(&tracker_in.registry));
    ck_assert_ret_ok(tracker_from_json(obj, &tracker_in));

    ck_assert_uint_eq(map_size(tracker_in.registry), 2);

    json_decref(obj);
    map_free(tracker_in.registry);
    tracker_free(tracker);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_find_process)
{
    ck_assert(sodium_init() >= 0);

    /* The process_table is populated by preprocessor with known entries */
    if (process_table_size > 0) {
        /* Look up the first entry */
        handler_ptr_t handler = find_process(process_table[0].name);
        ck_assert_ptr_nonnull(handler);
        ck_assert(handler == process_table[0].runner);
    }

    /* Missing process returns NULL */
    handler_ptr_t missing = find_process("nonexistent_process");
    ck_assert_ptr_null(missing);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_find_process_name)
{
    ck_assert(sodium_init() >= 0);

    /* NULL handler returns NULL */
    char *name = find_process_name(NULL);
    ck_assert_ptr_null(name);

    /* If table has entries, reverse lookup should work */
    if (process_table_size > 0) {
        char *found = find_process_name(process_table[0].runner);
        ck_assert_ptr_nonnull(found);
        ck_assert_str_eq(found, process_table[0].name);
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tracker_init_stack)
{
    ck_assert(sodium_init() >= 0);

    tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));
    ck_assert_ret_ok(tracker_init(NULL, &tracker));
    ck_assert_ptr_nonnull(tracker.registry);
    ck_assert_ptr_null(tracker.logger);

    /* Register and verify */
    ck_assert_ret_ok(tracker_register_subsystem(&tracker, "test", "test_impl"));
    ck_assert_uint_eq(map_size(tracker.registry), 1);

    map_free(tracker.registry);
}
END_TEST_DEFINITION()

RUN_TESTS(ProcTracker2, test_tracker_create_free, test_tracker_register_subsystem,
          test_tracker_json_roundtrip, test_find_process,
          test_find_process_name, test_tracker_init_stack)
