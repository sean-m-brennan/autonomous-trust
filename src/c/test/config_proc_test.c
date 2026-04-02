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

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "autonomous_trust/fleet/config_proc.h"
#include "autonomous_trust/fleet/update_proc.h"

/* ---------- helpers ---------- */

static char test_dir[256];

static void setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/at_config_test_%d", (int)getpid());
    mkdir(test_dir, 0755);
}

static void teardown_test_dir(void)
{
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    int ret = system(cmd);
    (void)ret;
}

static void fill_test_config_proposal(config_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));
    strncpy(prop->config_name, "network", CFG_NAME_SIZE);
    randombytes_buf(prop->content_hash, UPDATE_HASH_LEN);
    strncpy(prop->version, "1.2.0", UPDATE_VERSION_LEN);
    uuid_generate(prop->proposer_uuid);
    prop->min_proposer_reputation = 0.7;
    uuid_generate(prop->proposal_uuid);
}

/* ---------------------------------------------------------------
 * test_config_proposal_json_roundtrip
 * --------------------------------------------------------------- */
DEFINE_TEST(test_config_proposal_json_roundtrip)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    config_proposal_t orig;
    fill_test_config_proposal(&orig);

    json_t *j = config_proposal_to_json(&orig);
    ck_assert_ptr_nonnull(j);

    config_proposal_t loaded;
    ck_assert_ret_ok(config_proposal_from_json(j, &loaded));

    ck_assert_str_eq(loaded.config_name, "network");
    ck_assert_str_eq(loaded.version, "1.2.0");
    ck_assert_mem_eq(loaded.content_hash, orig.content_hash, UPDATE_HASH_LEN);

    json_decref(j);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_config_proposal_sign_verify
 * --------------------------------------------------------------- */
DEFINE_TEST(test_config_proposal_sign_verify)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    config_proposal_t prop;
    fill_test_config_proposal(&prop);

    ck_assert_ret_ok(config_proposal_sign(&prop, sk));
    ck_assert_ret_ok(config_proposal_verify(&prop, pk));

    /* Tamper with config_name — verify must fail */
    strncpy(prop.config_name, "tampered", CFG_NAME_SIZE);
    ck_assert_ret_nonzero(config_proposal_verify(&prop, pk));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_identity_guard
 * --------------------------------------------------------------- */
DEFINE_TEST(test_identity_guard)
{
    ck_assert(config_is_identity("identity"));
    ck_assert(!config_is_identity("network"));
    ck_assert(!config_is_identity("peers"));
    ck_assert(!config_is_identity("Identity"));  /* case-sensitive */
    ck_assert(!config_is_identity(""));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_config_validate_json
 * --------------------------------------------------------------- */
DEFINE_TEST(test_config_validate_json)
{
    const char *valid = "{\"typename\": \"network\", \"ip\": \"1.2.3.4\"}";
    ck_assert(config_validate_json((const uint8_t *)valid, strlen(valid)));

    const char *invalid = "not json";
    ck_assert(!config_validate_json((const uint8_t *)invalid, strlen(invalid)));

    const char *no_typename = "{\"ip\": \"1.2.3.4\"}";
    ck_assert(!config_validate_json((const uint8_t *)no_typename, strlen(no_typename)));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_backup_restore_paths
 * --------------------------------------------------------------- */
DEFINE_TEST(test_backup_restore_paths)
{
    char buf[256];
    ck_assert_ret_ok(config_backup_dir("/opt/at/var/at", buf, sizeof(buf)));
    ck_assert_str_eq(buf, "/opt/at/var/at/config_backup");
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_update_state_type_field
 * --------------------------------------------------------------- */
DEFINE_TEST(test_update_state_type_field)
{
    setup_test_dir();

    update_state_t orig;
    memset(&orig, 0, sizeof(orig));
    strncpy(orig.state, "APPLYING", sizeof(orig.state) - 1);
    strncpy(orig.type, "config", sizeof(orig.type) - 1);
    orig.attempt = 1;

    ck_assert_ret_ok(update_state_write(test_dir, &orig));

    update_state_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    ck_assert_ret_ok(update_state_read(test_dir, &loaded));
    ck_assert_str_eq(loaded.type, "config");

    teardown_test_dir();
}
END_TEST_DEFINITION()

RUN_TESTS(ConfigProc,
    test_config_proposal_json_roundtrip,
    test_config_proposal_sign_verify,
    test_identity_guard,
    test_config_validate_json,
    test_backup_restore_paths,
    test_update_state_type_field
)
