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

#include "autonomous_trust/fleet/update_proc.h"

/* ---------- helpers ---------- */

static char test_dir[256];

static void setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/at_update_test_%d", (int)getpid());
    mkdir(test_dir, 0755);
}

static void teardown_test_dir(void)
{
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    int ret = system(cmd);
    (void)ret;
}

/* ---------------------------------------------------------------
 * test_state_file_roundtrip
 * --------------------------------------------------------------- */
DEFINE_TEST(test_state_file_roundtrip)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();

    update_state_t ws;
    memset(&ws, 0, sizeof(ws));
    strncpy(ws.state, "APPLYING", sizeof(ws.state) - 1);
    strncpy(ws.version, "2.1.0", sizeof(ws.version) - 1);
    strncpy(ws.hash_hex, "abcdef0123456789", sizeof(ws.hash_hex) - 1);
    strncpy(ws.backup_path, "/opt/at/var/at/update/at_demo.backup", sizeof(ws.backup_path) - 1);
    strncpy(ws.binary_path, "/opt/at/bin/at_demo", sizeof(ws.binary_path) - 1);
    ws.timestamp = 1743600000;
    ws.attempt = 1;

    ck_assert_ret_ok(update_state_write(test_dir, &ws));

    update_state_t rs;
    memset(&rs, 0, sizeof(rs));
    ck_assert_ret_ok(update_state_read(test_dir, &rs));

    ck_assert_str_eq(rs.state, "APPLYING");
    ck_assert_str_eq(rs.version, "2.1.0");
    ck_assert_str_eq(rs.hash_hex, "abcdef0123456789");
    ck_assert_str_eq(rs.backup_path, "/opt/at/var/at/update/at_demo.backup");
    ck_assert_str_eq(rs.binary_path, "/opt/at/bin/at_demo");
    ck_assert_int_eq((int)rs.timestamp, 1743600000);
    ck_assert_int_eq(rs.attempt, 1);

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_state_file_rollback_guard
 * --------------------------------------------------------------- */
DEFINE_TEST(test_state_file_rollback_guard)
{
    update_state_t s;
    memset(&s, 0, sizeof(s));

    s.attempt = 1;
    ck_assert(!update_should_abort(&s));

    s.attempt = 2;
    ck_assert(update_should_abort(&s));

    s.attempt = 3;
    ck_assert(update_should_abort(&s));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_staging_paths
 * --------------------------------------------------------------- */
DEFINE_TEST(test_staging_paths)
{
    char buf[256];

    ck_assert_ret_ok(update_staging_dir("/opt/at/var/at", buf, sizeof(buf)));
    ck_assert_str_eq(buf, "/opt/at/var/at/update");

    ck_assert_ret_ok(update_staging_path("/opt/at/var/at", buf, sizeof(buf)));
    ck_assert_str_eq(buf, "/opt/at/var/at/update/at_demo.new");

    ck_assert_ret_ok(update_backup_path("/opt/at/var/at", buf, sizeof(buf)));
    ck_assert_str_eq(buf, "/opt/at/var/at/update/at_demo.backup");
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_state_write_creates_dir
 * --------------------------------------------------------------- */
DEFINE_TEST(test_state_write_creates_dir)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();

    update_state_t ws;
    memset(&ws, 0, sizeof(ws));
    strncpy(ws.state, "IDLE", sizeof(ws.state) - 1);
    ws.attempt = 0;

    ck_assert_ret_ok(update_state_write(test_dir, &ws));

    /* Verify <test_dir>/update/ exists */
    char update_dir[512];
    snprintf(update_dir, sizeof(update_dir), "%s/update", test_dir);
    struct stat st;
    ck_assert_int_eq(stat(update_dir, &st), 0);
    ck_assert(S_ISDIR(st.st_mode));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_state_delete
 * --------------------------------------------------------------- */
DEFINE_TEST(test_state_delete)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    setup_test_dir();

    update_state_t ws;
    memset(&ws, 0, sizeof(ws));
    strncpy(ws.state, "COMPLETE", sizeof(ws.state) - 1);
    ws.attempt = 1;

    ck_assert_ret_ok(update_state_write(test_dir, &ws));
    ck_assert(update_state_exists(test_dir));

    ck_assert_ret_ok(update_state_delete(test_dir));
    ck_assert(!update_state_exists(test_dir));

    teardown_test_dir();
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_current_binary_path
 * --------------------------------------------------------------- */
DEFINE_TEST(test_current_binary_path)
{
    char buf[512];
    ck_assert_ret_ok(update_current_binary_path(buf, sizeof(buf)));

    /* Must be non-empty */
    ck_assert(strlen(buf) > 0);

    /* Must exist on disk */
    struct stat st;
    ck_assert_int_eq(stat(buf, &st), 0);
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_selftest_crypto
 * --------------------------------------------------------------- */
DEFINE_TEST(test_selftest_crypto)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);
    ck_assert(selftest_crypto());
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_selftest_crypto_tampered
 * --------------------------------------------------------------- */
DEFINE_TEST(test_selftest_crypto_tampered)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    /* Generate two distinct keypairs */
    unsigned char pk1[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk1[crypto_sign_SECRETKEYBYTES];
    unsigned char pk2[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk1, sk1);
    crypto_sign_keypair(pk2, sk2);

    const char *msg = "autonomous_trust_selftest";
    size_t msg_len = strlen(msg);

    /* Sign with key1 */
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_int_eq(crypto_sign_detached(sig, NULL,
                     (const unsigned char *)msg, msg_len, sk1), 0);

    /* Verify with key2 — must fail (mismatch detected) */
    int result = crypto_sign_verify_detached(sig,
                     (const unsigned char *)msg, msg_len, pk2);
    ck_assert(result != 0);
}
END_TEST_DEFINITION()

RUN_TESTS(UpdateProc,
    test_state_file_roundtrip,
    test_state_file_rollback_guard,
    test_staging_paths,
    test_state_write_creates_dir,
    test_state_delete,
    test_current_binary_path,
    test_selftest_crypto,
    test_selftest_crypto_tampered
)
