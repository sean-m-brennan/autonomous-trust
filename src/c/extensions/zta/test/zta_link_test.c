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
/* libat_zta present after link (FEATURE_SPLIT_PLAN Phase 6): with the library
 * linked whole, its constructors have registered the identity extension
 * "zta", the "zta_policy" configuration section, the zta_verify process, its
 * message types and its errors -- and none of that enforces anything until a
 * node's policy enables ZTA. extension_test asserts the converse for a
 * core-only binary. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zta/at_zta.h"
#include "config/configuration.h"
#include "identity/id_ext.h"
#include "processes/process_tracker.h"
#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/logger.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types.h"
#include "zta/x509_verifier.h"
#include "zta/zta_msg_types.h"
#include "zta/zta_verifier.h"

const char *_custom_errstr(int num);

DEFINE_TEST(test_every_registration_survived_the_link)
{
    at_zta_link();
    ck_assert(identity_ext_present("zta"));
    ck_assert_ptr_nonnull(find_configuration("zta_policy"));
    ck_assert_ptr_nonnull(find_process("zta_proc"));
    /* ...and it is a default subsystem, so a generated configuration starts it,
     * and one that lists it is not refused. */
    const char *keys[AT_SUBSYSTEM_EXT_MAX], *impls[AT_SUBSYSTEM_EXT_MAX];
    size_t n = subsystem_defaults(keys, impls, AT_SUBSYSTEM_EXT_MAX);
    bool listed = false;
    for (size_t i = 0; i < n; i++)
        listed = listed || (strcmp(keys[i], "zta_verify") == 0 && strcmp(impls[i], "zta_proc") == 0);
    ck_assert(listed);
    tracker_t tracker;
    ck_assert_int_eq(tracker_init(NULL, &tracker), 0);
    ck_assert_int_eq(tracker_register_subsystem(&tracker, "zta_verify", "zta_proc"), 0);
    ck_assert_int_eq(tracker_check_subsystem_libraries(&tracker, NULL), 0);
    tracker_free(&tracker);
    ck_assert_ptr_nonnull(at_msg_type_lookup(ZTA_REVOCATION_ALERT));
    ck_assert_ptr_nonnull(at_msg_type_lookup(ZTA_VERIFICATION_RESULT));
    ck_assert_str_eq(_custom_errstr(EX509_CALOAD), "EX509_CALOAD");
    ck_assert_str_eq(_custom_errstr(EZTA_NOCRED), "EZTA_NOCRED");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_policy_admits_and_refuses_nothing)
{
    /* A process with no zta_policy configured: the gate admits, nothing is
     * refused, nothing is proved -- a node that linked ZTA but did not turn it
     * on behaves as one without it. */
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    ck_assert_ret_ok(map_create(&proc.configs));
    public_identity_t peer;
    memset(&peer, 0, sizeof(peer));
    uint8_t key[crypto_sign_PUBLICKEYBYTES] = {0};
    ck_assert_int_eq(identity_ext_admission_gate(&proc, &peer, key), IDENTITY_EXT_ADMIT);
    ck_assert(!identity_ext_join_refused(&proc, &peer));
    ck_assert(!identity_ext_gateway_refused(&proc, "0b1c4a3e-0000-4000-8000-000000000001"));
    ck_assert(!identity_ext_operator_credential(&proc, &peer));
    ck_assert(!identity_ext_credential_anchored(&proc, &peer));
}
END_TEST_DEFINITION()

/* With the library linked, a policy that enables ZTA is one this node can
 * honour: the start is not refused. */
DEFINE_TEST(test_an_enabled_policy_starts)
{
    char dir[96];
    snprintf(dir, sizeof(dir), "/tmp/zta_link_cfg_%d", (int)getpid());
    mkdir(dir, 0700);
    char path[160];
    snprintf(path, sizeof(path), "%s/zta_policy.cfg.json", dir);
    FILE *fp = fopen(path, "w");
    ck_assert_ptr_nonnull(fp);
    fputs("{\"enabled\": true}", fp);
    fclose(fp);
    ck_assert_int_eq(identity_ext_check_config(dir, NULL), 0);
    unlink(path);
    rmdir(dir);
}
END_TEST_DEFINITION()

RUN_TESTS(ZtaLink,
          test_every_registration_survived_the_link,
          test_no_policy_admits_and_refuses_nothing,
          test_an_enabled_policy_starts)
