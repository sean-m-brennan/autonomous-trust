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

/**
 * @file app_node_test.c
 * @brief The flat lifecycle ABI (@ref app_node.h) and the node lifecycle it
 *        wraps.
 *
 * Nothing here forks a daemon — `at_node_start` does that and no unit test can
 * follow it. What can be reached is everything that decides whether the daemon
 * would be given the right instructions, which is where the defects were:
 *
 *  1. `at_node_init` was called with a config aliasing `node->config`, and it
 *     opens by `memset`ting the node — so every argument the flat wrapper was
 *     given was discarded and replaced by a default, returning 0 throughout. The
 *     `generate_config` knob in particular did nothing at all.
 *  2. The config stores the caller's string pointers, and `at_node_shutdown`
 *     reads `app_name` — an obligation no foreign host was told about.
 *  3. A failed inbound bind was logged and ignored, so a host could hold a live
 *     daemon it could never receive from (break #4's shape again — see
 *    doc/architecture/app-peer-carrier.md).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "autonomous_trust/app_events.h"
#include "autonomous_trust/app_node.h"
#include "autonomous_trust/app_node_priv.h"
#include "autonomous_trust/node_priv.h"
#include "config/configuration.h"
#include "utilities/message.h"

/****************************
 * Roots. at_node_init creates <root>/etc/at and <root>/var/at, and the socket
 * paths live under the latter, so each test that touches either gets its own.
 ****************************/

static char test_root[] = "/tmp/at-app-node-testXXXXXX";

static void root_setup(void)
{
    static bool done = false;
    if (done) return;
    ck_assert_ptr_nonnull(mkdtemp(test_root));
    ck_assert_int_eq(setenv("AUTONOMOUS_TRUST_ROOT", test_root, 1), 0);
    done = true;
}

/* Socket paths are <root>/var/at/<queue-name>. at_node_init creates that
 * directory, but a test that binds without initialising a node needs it too, and
 * depending on another test having run first is not a dependency worth having. */
static void queue_dir_setup(void)
{
    root_setup();
    char data_dir[CFG_PATH_LEN + 1] = {0};
    ck_assert(get_data_dir(data_dir, sizeof(data_dir)) >= 0);
    ck_assert(makedirs(data_dir, 0755) == 0);
}

/* Whether `name` exists in the config directory. */
static bool cfg_dir_has(const char *name)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(dir, sizeof(dir)) < 0)
        return false;
    DIR *d = opendir(dir);
    if (d == NULL)
        return false;
    bool found = false;
    struct dirent *e;
    while (!found && (e = readdir(d)) != NULL)
        found = strcmp(e->d_name, name) == 0;
    closedir(d);
    return found;
}

/* Open descriptors, for the no-leak assertion. */
static int open_fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL)
        return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/****************************
 * Defect 1 — the arguments the wrapper was given
 ****************************/

/* The regression proper: at_node_init must survive a config that aliases the
 * node it is initialising, because the flat wrapper hands over exactly that. The
 * pre-fix reading of these six fields was
 * "at_node"/"at_to_extern"/"extern_to_at"/0/(null)/false. */
DEFINE_TEST(test_the_config_survives_an_init_that_aliases_it)
{
    root_setup();

    at_node_t node = {0};
    node.config.log_level = WARNING;
    node.config.log_file = NULL;          /* stderr; keeps the test quiet-ish */
    node.config.generate_config = false;
    node.config.app_name = "ethne";
    node.config.q_out = "app_to_at";
    node.config.q_in = "at_to_app";

    ck_assert_ret_ok(at_node_init(&node, &node.config));

    ck_assert_str_eq(node.config.app_name, "ethne");
    ck_assert_str_eq(node.config.q_in, "at_to_app");
    ck_assert_str_eq(node.config.q_out, "app_to_at");
    ck_assert_int_eq((int)node.config.log_level, (int)WARNING);
    ck_assert_int_eq((int)node.log.max_level, (int)WARNING);
    ck_assert(node.config.log_file == NULL);
}
END_TEST_DEFINITION()

/* Control on the same mechanism from the other direction: a separate config is
 * copied in, not merely pointed at, and the defaults still fill a config that
 * really is empty. */
DEFINE_TEST(test_an_empty_config_still_gets_the_documented_defaults)
{
    root_setup();

    at_node_config_t cfg = {0};
    cfg.log_level = ERROR;
    at_node_t node = {0};
    ck_assert_ret_ok(at_node_init(&node, &cfg));

    ck_assert_str_eq(node.config.app_name, "at_node");
    ck_assert_str_eq(node.config.q_in, "at_to_extern");
    ck_assert_str_eq(node.config.q_out, "extern_to_at");
    ck_assert_int_eq((int)node.config.log_level, (int)ERROR);
}
END_TEST_DEFINITION()

/* The knob that was silently dead: generate_config is what a consumer points at
 * a root with no config, and the aliasing wiped it to false. Asserted by its
 * effect, not by the field. */
DEFINE_TEST(test_generate_config_reaches_the_generator)
{
    root_setup();

    at_node_config_t cfg = {0};
    cfg.log_level = ERROR;
    cfg.app_name = "gen_probe";
    cfg.q_in = "at_to_app";
    cfg.q_out = "app_to_at";
    cfg.generate_config = true;

    /* Nothing has generated into this root yet. */
    ck_assert(!cfg_dir_has("identity.cfg.json"));

    at_node_t node = {0};
    ck_assert_ret_ok(at_node_init(&node, &cfg));

    ck_assert(node.config.generate_config);
    ck_assert(cfg_dir_has("identity.cfg.json"));
    ck_assert(cfg_dir_has("network.cfg.json"));
}
END_TEST_DEFINITION()

/****************************
 * Defect 2 — the strings
 ****************************/

/* A foreign host builds its arguments as temporaries. The handle's config must
 * point at its own copies, or at_node_shutdown's log of app_name reads freed
 * memory. Scribbling the source is the only way to tell a copy from a pointer. */
DEFINE_TEST(test_the_strings_are_copied_not_borrowed)
{
    char app_name[] = "ethne";
    char q_in[] = "at_to_app";
    char q_out[] = "app_to_at";
    char log_file[] = "/tmp/at-app-node-test.log";

    at_app_node_strings_t owned;
    at_node_config_t cfg;
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, app_name, q_in,
                                              q_out, INFO, false, log_file));

    /* The caller's storage goes away — as a Rust CString temporary would. */
    memset(app_name, 'x', sizeof(app_name) - 1);
    memset(q_in, 'x', sizeof(q_in) - 1);
    memset(q_out, 'x', sizeof(q_out) - 1);
    memset(log_file, 'x', sizeof(log_file) - 1);

    ck_assert_str_eq(cfg.app_name, "ethne");
    ck_assert_str_eq(cfg.q_in, "at_to_app");
    ck_assert_str_eq(cfg.q_out, "app_to_at");
    ck_assert_str_eq(cfg.log_file, "/tmp/at-app-node-test.log");
    ck_assert_int_eq((int)cfg.log_level, (int)INFO);
    ck_assert(!cfg.generate_config);
    /* Not a knob the wrapper offers: run_autonomous_trust discards it, and a
     * foreign host never calls at_node_run. */
    ck_assert(cfg.capabilities == NULL);
    ck_assert_uint_eq(cfg.max_iterations, 0);
}
END_TEST_DEFINITION()

/* NULL log_file means stderr, and must not become a pointer to an empty
 * string — logger_init switches on the NULL. */
DEFINE_TEST(test_no_log_file_stays_a_null_not_an_empty_string)
{
    at_app_node_strings_t owned;
    at_node_config_t cfg;
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, "ethne", "in",
                                              "out", DEBUG, true, NULL));
    ck_assert(cfg.log_file == NULL);
    ck_assert(cfg.generate_config);
}
END_TEST_DEFINITION()

/****************************
 * What the wrapper refuses
 ****************************/

DEFINE_TEST(test_a_missing_name_is_refused)
{
    /* Through the public entry point: all of these must return before anything
     * is forked or bound. */
    ck_assert_ptr_null(at_app_node_start(NULL, "in", "out", INFO, false, NULL));
    ck_assert_ptr_null(at_app_node_start("", "in", "out", INFO, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", NULL, "out", INFO, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", "", "out", INFO, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", "in", NULL, INFO, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", "in", "", INFO, false, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_one_name_for_both_directions_is_refused)
{
    /* The two directions are separate sockets; sharing a name has the daemon
     * receiving its own output. */
    ck_assert_ptr_null(at_app_node_start("app", "q", "q", INFO, false, NULL));

    /* Control: the same call with distinct names gets past validation — it
     * reaches build_config and returns 0 there. */
    at_app_node_strings_t owned;
    at_node_config_t cfg;
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, "app", "q", "q2",
                                              INFO, false, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_log_level_off_the_scale_is_refused)
{
    /* Rejected, not clamped: 0 is what the aliasing bug produced, and the
     * wrapper used to validate the level and then hand the daemon a zero. */
    ck_assert_ptr_null(at_app_node_start("app", "in", "out", 0, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", "in", "out", -1, false, NULL));
    ck_assert_ptr_null(at_app_node_start("app", "in", "out",
                                         (int)CRITICAL + 1, false, NULL));

    /* Controls: both ends of the scale are accepted. */
    at_app_node_strings_t owned;
    at_node_config_t cfg;
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, "app", "in", "out",
                                              (int)DEBUG, false, NULL));
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, "app", "in", "out",
                                              (int)CRITICAL, false, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_name_longer_than_the_messaging_layer_keeps_is_refused)
{
    char long_name[MSG_KEY_LEN + 8];
    memset(long_name, 'q', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    at_app_node_strings_t owned;
    at_node_config_t cfg;
    /* messaging_init keeps MSG_KEY_LEN - 1 bytes of a queue name. Truncating
     * silently would leave the app bound to a name the daemon does not send to. */
    ck_assert_ret_nonzero(at_app_node_build_config(&cfg, &owned, "app",
                                                   long_name, "out", INFO,
                                                   false, NULL));
    ck_assert_ret_nonzero(at_app_node_build_config(&cfg, &owned, "app", "in",
                                                   long_name, INFO, false,
                                                   NULL));
    ck_assert_ret_nonzero(at_app_node_build_config(&cfg, &owned, long_name,
                                                   "in", "out", INFO, false,
                                                   NULL));
    ck_assert_ptr_null(at_app_node_start("app", long_name, "out", INFO, false,
                                         NULL));

    /* Boundary control: the longest name that does survive messaging_init is
     * accepted, and arrives whole. */
    char max_name[MSG_KEY_LEN];
    memset(max_name, 'q', sizeof(max_name) - 1);
    max_name[sizeof(max_name) - 1] = '\0';
    ck_assert_ret_ok(at_app_node_build_config(&cfg, &owned, "app", max_name,
                                              "out", INFO, false, NULL));
    ck_assert_str_eq(cfg.q_in, max_name);

    /* Same rule for the log path, at the length logger_init keeps. */
    char long_path[MAX_FILENAME + 8];
    memset(long_path, 'p', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    ck_assert_ret_nonzero(at_app_node_build_config(&cfg, &owned, "app", "in",
                                                   "out", INFO, false,
                                                   long_path));

    /* And the other flat entry point agrees. Two consumers of one carrier
     * disagreeing about what a name means is the same failure by a longer
     * route: the reader would bind the truncation, the node the whole name. */
    queue_dir_setup();
    ck_assert_ptr_null(at_app_events_open(long_name));
    ck_assert_ptr_null(at_app_events_open(""));

    /* Control, and the roster half: a real reader binds the short name, then
     * refuses to send a pull to an over-long q_out — a name the daemon does not
     * receive on. */
    at_app_events_t *ev = at_app_events_open("events_reader");
    ck_assert_ptr_nonnull(ev);
    ck_assert_ret_nonzero(at_app_events_request_roster(ev, long_name));
    at_app_events_close(ev);
    messaging_assign(NULL);   /* at_app_events_open assigned a queue now gone */
}
END_TEST_DEFINITION()

/****************************
 * Defect 3 — a bind failure is fatal
 ****************************/

/* at_node_start's non-forking half. A directory sitting on the socket path is
 * the cheapest deterministic bind failure: messaging_init's unlink of the path
 * fails with EISDIR. This used to be logged and ignored, and start returned 0. */
DEFINE_TEST(test_an_inbound_queue_that_cannot_bind_fails_the_bind)
{
    root_setup();

    at_node_config_t cfg = {0};
    cfg.log_level = CRITICAL;   /* the failure path logs; keep it quiet */
    cfg.app_name = "bind_probe";
    cfg.q_in = "blocked_queue";
    cfg.q_out = "app_to_at";

    at_node_t node = {0};
    ck_assert_ret_ok(at_node_init(&node, &cfg));

    char data_dir[CFG_PATH_LEN + 1] = {0};
    ck_assert(get_data_dir(data_dir, sizeof(data_dir)) >= 0);
    char blocked[CFG_PATH_LEN + 64];
    snprintf(blocked, sizeof(blocked), "%s/%s", data_dir, cfg.q_in);
    ck_assert_int_eq(mkdir(blocked, 0700), 0);

    int fds_before = open_fd_count();
    ck_assert(fds_before > 0);

    ck_assert_ret_nonzero(at_node_bind_inbound(&node));
    /* No half-open socket left behind, and no descriptor leaked. */
    ck_assert_int_eq(node.app_queue.fd, -1);
    ck_assert_int_eq(open_fd_count(), fds_before);
    /* The blocking directory is still there: the failure path must not unlink a
     * path it may not own. */
    struct stat st;
    ck_assert_int_eq(stat(blocked, &st), 0);
    ck_assert(S_ISDIR(st.st_mode));

    /* Control: the same node binds a name nothing is sitting on. */
    node.config.q_in = "clear_queue";
    ck_assert_ret_ok(at_node_bind_inbound(&node));
    ck_assert(node.app_queue.fd >= 0);
    ck_assert_str_eq(node.app_queue.key, "clear_queue");

    messaging_qclose(&node.app_queue);
    /* The assigned queue is process-global and this one is a local. */
    messaging_assign(NULL);
    ck_assert_int_eq(rmdir(blocked), 0);
}
END_TEST_DEFINITION()

/* The name that gets bound is q_in, not app_name — break #4 itself. The
 * fallback to app_name is for a caller that only ever sends. */
DEFINE_TEST(test_the_bound_name_is_q_in_and_falls_back_to_app_name)
{
    root_setup();

    at_node_config_t cfg = {0};
    cfg.log_level = CRITICAL;
    cfg.app_name = "sender_only";
    cfg.q_in = "inbound_queue";
    cfg.q_out = "app_to_at";

    at_node_t node = {0};
    ck_assert_ret_ok(at_node_init(&node, &cfg));
    ck_assert_ret_ok(at_node_bind_inbound(&node));
    ck_assert_str_eq(node.app_queue.key, "inbound_queue");
    messaging_qclose(&node.app_queue);

    /* An empty q_in is the fallback case, not a failure. at_node_init's own
     * default would have supplied "at_to_extern" for a NULL, so set it after. */
    node.config.q_in = "";
    ck_assert_ret_ok(at_node_bind_inbound(&node));
    ck_assert_str_eq(node.app_queue.key, "sender_only");

    messaging_qclose(&node.app_queue);
    messaging_assign(NULL);
}
END_TEST_DEFINITION()

/****************************
 * The handle's own contract
 ****************************/

DEFINE_TEST(test_a_null_handle_is_harmless)
{
    /* A foreign host holds NULL whenever start failed, and asks these three
     * things of it. None may crash. */
    ck_assert(!at_app_node_alive(NULL));
    ck_assert_int_eq(at_app_node_pid(NULL), 0);
    ck_assert(!at_app_node_ready(NULL));
    ck_assert(!at_app_node_wait_ready(NULL, 50));
    at_app_node_stop(NULL);
}
END_TEST_DEFINITION()

/****************************
 * Readiness — the other half of alive
 ****************************/

/* `alive` and `ready` were one question and are two. Measured on a cold node:
 * at_app_node_start returns after ~2 ms, alive is true immediately, and the
 * daemon's inbound queue does not exist for another ~210 ms. Everything a host
 * sends in that window goes nowhere. This cannot fork a daemon (the test suite
 * must not), so it exercises the predicate against a queue it binds itself —
 * which is the same question `ready` asks about the daemon's. */

DEFINE_TEST(test_readiness_is_about_a_bound_queue_not_a_live_process)
{
    queue_dir_setup();

    /* Nothing bound under this name: not ready, however alive anyone is. */
    ck_assert(!messaging_bound("_ready_probe_q"));

    queue_t q;
    ck_assert_ret_ok(messaging_init("_ready_probe_q", &q));
    ck_assert(messaging_bound("_ready_probe_q"));

    messaging_qclose(&q);
    ck_assert(!messaging_bound("_ready_probe_q"));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wait_ready_does_not_wait_out_the_timeout_for_nothing)
{
    queue_dir_setup();

    /* A NULL handle is the shape a host holds when start failed; waiting on it
     * must return at once rather than sleeping the whole timeout. Timing is the
     * assertion, since the point of the bound is that it is not paid when the
     * answer is already known. */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ck_assert(!at_app_node_wait_ready(NULL, 2000));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    ck_assert(ms < 500);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_roster_pull_says_not_ready_rather_than_just_failing)
{
    queue_dir_setup();

    at_app_events_t *ev = at_app_events_open("_roster_ready_in");
    ck_assert_ptr_nonnull(ev);

    /* Nobody has bound the outbound name, which on a cold daemon is the ORDINARY
     * case for the first ~210 ms. It used to be indistinguishable from a genuine
     * send failure, so a caller could only guess whether to retry. */
    ck_assert_int_eq(at_app_events_request_roster(ev, "_roster_ready_out"),
                     AT_APP_NOT_READY);

    /* A real failure keeps reporting -1, so the two remain distinguishable. */
    ck_assert_int_eq(at_app_events_request_roster(ev, ""), -1);
    ck_assert_int_eq(at_app_events_request_roster(NULL, "_roster_ready_out"), -1);

    /* Bind the far end and the pull goes through. */
    queue_t far;
    ck_assert_ret_ok(messaging_init("_roster_ready_out", &far));
    ck_assert_int_eq(at_app_events_request_roster(ev, "_roster_ready_out"), 0);

    messaging_qclose(&far);
    at_app_events_close(ev);
}
END_TEST_DEFINITION()

RUN_TESTS(App_Node,
          test_the_config_survives_an_init_that_aliases_it,
          test_an_empty_config_still_gets_the_documented_defaults,
          test_generate_config_reaches_the_generator,
          test_the_strings_are_copied_not_borrowed,
          test_no_log_file_stays_a_null_not_an_empty_string,
          test_a_missing_name_is_refused,
          test_one_name_for_both_directions_is_refused,
          test_a_log_level_off_the_scale_is_refused,
          test_a_name_longer_than_the_messaging_layer_keeps_is_refused,
          test_an_inbound_queue_that_cannot_bind_fails_the_bind,
          test_the_bound_name_is_q_in_and_falls_back_to_app_name,
          test_a_null_handle_is_harmless,
          test_readiness_is_about_a_bound_queue_not_a_live_process,
          test_wait_ready_does_not_wait_out_the_timeout_for_nothing,
          test_a_roster_pull_says_not_ready_rather_than_just_failing)
