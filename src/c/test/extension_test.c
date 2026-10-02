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

/* The extension registry (processes/extension.h, FEATURE_SPLIT_PLAN Phase 0):
 * refusals, the per-registration gate, per-process dispatch, and first
 * contact -- the first real client -- appearing exactly when enabled. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config/configuration.h"
#include "processes/processes.h"
#include "processes/extension.h"
#include "config/generate.h"
#include "processes/capabilities.h"
#include "processes/process_tracker.h"
#include "structures/map.h"
#include "identity/id_proc_priv.h"
#ifdef AT_FIRST_CONTACT_ENABLED   /* linked with libat_first_contact */
#include "first_contact/first_contact.h"
#endif
#include "identity/id_ext.h"
#include "network/net_transport.h"
#include "utilities/exception.h"

static int gate_reads = 0;
static bool gate_open = false;
static int registered_on_identity = 0;
static int registered_elsewhere = 0;
static int resets = 0;

static bool test_gate(void) { gate_reads++; return gate_open; }
static int test_register(process_t *proc, const char *proc_name)
{
    (void)proc;
    if (strcmp(proc_name, "identity") == 0) registered_on_identity++;
    else registered_elsewhere++;
    return 0;
}
static void test_reset(void) { resets++; }

static const at_extension_t test_ext = {
    .name = "test_ext", .enabled = test_gate,
    .register_handlers = test_register, .reset = test_reset,
};

static bool has_handler(process_t *proc, char *verb)
{
    data_t *d = NULL;
    return map_get(proc->protocol.handlers, verb, &d) == 0 && d != NULL;
}

DEFINE_TEST(test_registration_refusals)
{
    static const at_extension_t unnamed = { .name = "" };
    ck_assert_int_eq(at_extension_register(NULL), -1);
    ck_assert_int_eq(at_extension_register(&unnamed), -1);
    size_t before = at_extension_count();
    ck_assert_int_eq(at_extension_register(&test_ext), 0);
    ck_assert_int_eq(at_extension_register(&test_ext), -1);   /* duplicate name */
    ck_assert_int_eq((int)at_extension_count(), (int)before + 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gate_is_reread_and_dispatch_is_per_process)
{
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    /* A real handler map: an always-on extension linked into this binary (the
     * social one in a social build) registers its verbs on "identity" too. */
    ck_assert_int_eq(map_create(&proc.protocol.handlers), 0);
    gate_reads = registered_on_identity = registered_elsewhere = 0;

    gate_open = false;
    ck_assert_int_eq(at_extensions_register_handlers(&proc, "identity"), 0);
    ck_assert_int_eq(registered_on_identity, 0);
    /* Flipped between calls, as the conformance harness flips AT_FIRST_CONTACT:
     * a cached gate would miss it. */
    gate_open = true;
    ck_assert_int_eq(at_extensions_register_handlers(&proc, "identity"), 0);
    ck_assert_int_eq(at_extensions_register_handlers(&proc, "reputation"), 0);
    ck_assert_int_eq(registered_on_identity, 1);
    ck_assert_int_eq(registered_elsewhere, 1);
    ck_assert_int_eq(gate_reads, 3);

    resets = 0;
    at_extensions_reset();
    ck_assert_int_eq(resets, 1);
}
END_TEST_DEFINITION()

#ifdef AT_FIRST_CONTACT_ENABLED
DEFINE_TEST(test_first_contact_registers_exactly_when_enabled)
{
    char root[] = "/tmp/at-extension-testXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    setenv("AUTONOMOUS_TRUST_ROOT", root, 1);
    gate_open = false;   /* keep the test extension out of the way */

    for (int on = 0; on <= 1; on++)
    {
        if (on) setenv(AT_FIRST_CONTACT_ENV, "1", 1);
        else unsetenv(AT_FIRST_CONTACT_ENV);
        at_extensions_reset();

        process_t proc;
        memset(&proc, 0, sizeof(proc));
        snprintf(proc.name, sizeof(proc.name), "identity");
        pthread_rwlock_init(&proc.protocol.peers_rwlock, NULL);
        ck_assert_int_eq(map_create(&proc.protocol.handlers), 0);
        ck_assert_int_eq(identity_register_handlers(&proc), 0);
        ck_assert_int_eq((int)has_handler(&proc, ID_FC_HELLO), on);
        ck_assert_int_eq((int)has_handler(&proc, ID_FC_HELLO_ACK), on);
        /* Linked, so asking for it is honoured, not refused -- and so is a
         * relay, since first contact brings rendezvous with it. */
        ck_assert_int_eq(identity_ext_check_env(NULL), 0);
        setenv("AT_USE_RELAY", "198.51.100.1:27790", 1);
        ck_assert_int_eq(identity_ext_check_env(NULL), 0);
        unsetenv("AT_USE_RELAY");
        pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    }
    unsetenv(AT_FIRST_CONTACT_ENV);
    at_extensions_reset();
}
END_TEST_DEFINITION()
#else
DEFINE_TEST(test_first_contact_registers_exactly_when_enabled)
{
    /* Without libat_first_contact the core carries no handshake: the run-time
     * switch alone registers nothing... */
    char root[] = "/tmp/at-extension-testXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    setenv("AUTONOMOUS_TRUST_ROOT", root, 1);
    gate_open = false;
    setenv("AT_FIRST_CONTACT", "1", 1);
    at_extensions_reset();
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    snprintf(proc.name, sizeof(proc.name), "identity");
    pthread_rwlock_init(&proc.protocol.peers_rwlock, NULL);
    ck_assert_int_eq(map_create(&proc.protocol.handlers), 0);
    ck_assert_int_eq(identity_register_handlers(&proc), 0);
    ck_assert(!has_handler(&proc, (char *)"first_contact_hello"));
    ck_assert(!has_handler(&proc, (char *)"first_contact_hello_ack"));
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    /* ...so a node asked for it refuses to start rather than run without it;
     * switched off, it asks for nothing. */
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    setenv("AT_FIRST_CONTACT", "0", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), 0);
    unsetenv("AT_FIRST_CONTACT");
    /* Nor does this binary link rendezvous: a relay asked for is refused, and
     * a switch set off declares nothing. */
    setenv("AT_USE_RELAY", "198.51.100.1:27790", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    unsetenv("AT_USE_RELAY");
    setenv("AT_RELAY", "1", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    setenv("AT_RELAY", "0", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), 0);
    unsetenv("AT_RELAY");
    setenv("AT_RELAY_SEED_FALLBACK", "on", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    unsetenv("AT_RELAY_SEED_FALLBACK");
    at_extensions_reset();
}
END_TEST_DEFINITION()
#endif

/* Transports (network/net_transport.h): the core names none from an
 * extension, and a registered one is found beside the core's. This binary
 * links the core alone, so DTN -- now libat_dtn -- must be absent. */
DEFINE_TEST(test_transport_registration)
{
    ck_assert_ptr_nonnull(net_transport_find("udp_net_4"));
    ck_assert_ptr_null(net_transport_find("dtn_bp"));

    static const net_transport_t probe = { .name = "probe_net" };
    ck_assert_int_eq(net_transport_register(&probe), 0);
    ck_assert_ptr_eq(net_transport_find("probe_net"), &probe);

    static const net_transport_t unnamed = { .name = NULL };
    static const net_transport_t empty = { .name = "" };
    static const net_transport_t shadow = { .name = "udp_net_4" };
    ck_assert_int_eq(net_transport_register(NULL), -1);
    ck_assert_int_eq(net_transport_register(&unnamed), -1);
    ck_assert_int_eq(net_transport_register(&empty), -1);
    ck_assert_int_eq(net_transport_register(&probe), -1);   /* duplicate */
    ck_assert_int_eq(net_transport_register(&shadow), -1);  /* core name */
    ck_assert(net_transport_find("udp_net_4") != &shadow);

    static net_transport_t fill[NET_TRANSPORT_EXT_MAX];
    static char names[NET_TRANSPORT_EXT_MAX][16];
    int accepted = 0;
    for (int i = 0; i < NET_TRANSPORT_EXT_MAX; i++)
    {
        snprintf(names[i], sizeof(names[i]), "fill_%d", i);
        fill[i].name = names[i];
        if (net_transport_register(&fill[i]) == 0) accepted++;
    }
    /* probe took one slot, so the last fill is refused: the table is full. */
    ck_assert_int_eq(accepted, NET_TRANSPORT_EXT_MAX - 1);
    ck_assert_ptr_null(net_transport_find(names[NET_TRANSPORT_EXT_MAX - 1]));
    ck_assert_ptr_nonnull(net_transport_find(names[0]));
}
END_TEST_DEFINITION()

/* Processes (process_tracker.h): DEFINE_PROCESS appends into the free
 * slots the generated table leaves, and refuses rather than overflows. */
static int probe_runner(process_t *proc, array_t *queues, char *signal, logger_t *logger)
{
    return 0;
}

DEFINE_TEST(test_process_table_append)
{
    const size_t before = process_table_size;
    ck_assert_ptr_null(find_process("dtn_bp"));   /* core alone: no DTN */

    ck_assert_int_eq(process_table_append("probe", "probe_proc", probe_runner), 0);
    ck_assert_int_eq((int)process_table_size, (int)before + 1);
    ck_assert(find_process("probe_proc") == probe_runner);
    ck_assert_str_eq(find_process_name(probe_runner), "probe_proc");

    ck_assert_int_eq(process_table_append("probe", NULL, probe_runner), -1);
    ck_assert_int_eq(process_table_append("probe", "", probe_runner), -1);
    ck_assert_int_eq(process_table_append("probe", "no_runner", NULL), -1);
    ck_assert_int_eq(process_table_append("probe", "probe_proc", probe_runner), -1);
    ck_assert_int_eq(process_table_append("identity", "id_proc", probe_runner), -1);

    static char names[AT_PROCESS_EXT_MAX][16];
    int accepted = 0;
    for (int i = 0; i < AT_PROCESS_EXT_MAX; i++)
    {
        snprintf(names[i], sizeof(names[i]), "fill_proc_%d", i);
        if (process_table_append("probe", names[i], probe_runner) == 0) accepted++;
    }
    /* probe_proc took one slot, so the last fill is refused, not written. */
    ck_assert_int_eq(accepted, AT_PROCESS_EXT_MAX - 1);
    ck_assert_int_eq((int)process_table_size, (int)before + AT_PROCESS_EXT_MAX);
}
END_TEST_DEFINITION()


/* A cfg dir holding zta_policy.cfg.json with @p body; returns its path. */
static const char *_zta_cfg_dir(const char *tag, const char *body)
{
    static char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/at_ext_cfg_%s_%d", tag, (int)getpid());
    mkdir(dir, 0700);
    char path[192];
    snprintf(path, sizeof(path), "%s/zta_policy.cfg.json", dir);
    FILE *fp = fopen(path, "w");
    if (body != NULL && fp != NULL)
        fputs(body, fp);
    if (fp != NULL)
        fclose(fp);
    if (body == NULL)
        unlink(path);
    return dir;
}

/* A core-only binary has no ZTA: a policy that turns it on refuses the start,
 * one that does not (or none) is fine (FEATURE_SPLIT_PLAN Phase 6). */
DEFINE_TEST(test_core_only_refuses_an_enabled_zta_policy)
{
    ck_assert(!identity_ext_present("zta"));
    ck_assert_int_eq(identity_ext_check_config(_zta_cfg_dir("on", "{\"enabled\": true}"), NULL), -1);
    ck_assert_int_eq(identity_ext_check_config(_zta_cfg_dir("off", "{\"enabled\": false}"), NULL), 0);
    ck_assert_int_eq(identity_ext_check_config(_zta_cfg_dir("none", NULL), NULL), 0);
    ck_assert_int_eq(identity_ext_check_config(_zta_cfg_dir("junk", "not json"), NULL), 0);
    /* The policy's loader is the library's: the section is not registered. */
    ck_assert_ptr_null(find_configuration("zta_policy"));
}
END_TEST_DEFINITION()

static int probe_from_json(const json_t *obj, void *data) { (void)obj; (void)data; return 0; }

/* The configuration and error tables take an extension's entries the way the
 * process table does: bounds-checked, never written past their end
 * (FEATURE_SPLIT_PLAN §3.3, Phase 6). */
DEFINE_TEST(test_configuration_and_error_table_append)
{
    const size_t before = configuration_table_size;
    static int probe_struct;
    ck_assert_int_eq(configuration_table_append("probe_section", NULL, probe_from_json,
                                                sizeof(probe_struct), &probe_struct), 0);
    ck_assert_int_eq((int)configuration_table_size, (int)before + 1);
    config_t *found = find_configuration("probe_section");
    ck_assert_ptr_nonnull(found);
    ck_assert(found->from_json == probe_from_json);
    ck_assert_int_eq((int)found->data_len, (int)sizeof(probe_struct));
    ck_assert_int_eq(configuration_table_append("probe_section", NULL, probe_from_json,
                                                0, NULL), -1);
    ck_assert_int_eq(configuration_table_append(NULL, NULL, probe_from_json, 0, NULL), -1);
    ck_assert_int_eq(configuration_table_append("", NULL, probe_from_json, 0, NULL), -1);
    ck_assert_int_eq(configuration_table_append("no_parser", NULL, NULL, 0, NULL), -1);
    ck_assert_int_eq(configuration_table_append("identity", NULL, probe_from_json, 0, NULL), -1);
    static char names[AT_CONFIG_EXT_MAX + 1][24];
    int accepted = 0, refused = 0;
    for (int i = 0; i < AT_CONFIG_EXT_MAX + 1; i++)
    {
        snprintf(names[i], sizeof(names[i]), "fill_section_%d", i);
        if (configuration_table_append(names[i], NULL, probe_from_json, 0, NULL) == 0)
            accepted++;
        else
            refused++;
    }
    /* The table filled and refused the rest: never written past its end. */
    ck_assert(refused >= 1);
    ck_assert_int_eq((int)configuration_table_size, (int)before + 1 + accepted);

    const size_t e_before = error_table_size;
    ck_assert_int_eq(error_table_append(9001, "EPROBE", "a probe error"), 0);
    ck_assert_int_eq((int)error_table_size, (int)e_before + 1);
    ck_assert_int_eq(error_table_append(9001, "EPROBE_AGAIN", "same number"), -1);
    /* The same error again is one error, not two. */
    ck_assert_int_eq(error_table_append(9001, "EPROBE", "a probe error"), 0);
    ck_assert_int_eq((int)error_table_size, (int)e_before + 1);
    ck_assert_int_eq(error_table_append(9002, NULL, "unnamed"), -1);
    int e_accepted = 0, e_refused = 0;
    for (int i = 0; i < 200; i++)
    {
        if (error_table_append(9100 + i, "EFILL", "fill") == 0)
            e_accepted++;
        else
            e_refused++;
    }
    ck_assert(e_refused >= 1);
    ck_assert_int_eq((int)error_table_size, (int)e_before + 1 + e_accepted);
    ck_assert(error_table_size <= 128);
}
END_TEST_DEFINITION()

/* A core-only binary (this one links the core alone) has no social feature:
 * no identity extension named "social", none of its verbs on identity, and a
 * node told to publish a position or profile refuses to start rather than
 * publish nothing. libat_social's social_link_test asserts the converse. */
DEFINE_TEST(test_core_only_has_no_social_and_refuses_its_declarations)
{
    ck_assert(!identity_ext_present("social"));

    process_t proc;
    memset(&proc, 0, sizeof(proc));
    ck_assert_int_eq(map_create(&proc.protocol.handlers), 0);
    ck_assert_int_eq(identity_register_handlers(&proc), 0);
    static const char *const social_verbs[] = {
        "peer_position_query", "peer_profile_query", "peer_dm", "peer_post",
        "peer_cosign_request", "app_block", "app_publish_post",
    };
    for (size_t i = 0; i < sizeof(social_verbs) / sizeof(*social_verbs); i++) {
        data_t *h = NULL;
        ck_assert(map_get(proc.protocol.handlers, (map_key_t)social_verbs[i], &h) != 0);
    }
    /* Core verbs are still there. */
    data_t *h = NULL;
    ck_assert_int_eq(map_get(proc.protocol.handlers, (map_key_t)"app_peer_standing", &h), 0);

    unsetenv("AT_OWN_GEOHASH");
    unsetenv("AT_OWN_PROFILE");
    ck_assert_int_eq(identity_ext_check_env(NULL), 0);
    setenv("AT_OWN_PROFILE", "{\"display_name\": \"x\"}", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    setenv("AT_OWN_PROFILE", "", 1);          /* empty is undeclared */
    ck_assert_int_eq(identity_ext_check_env(NULL), 0);
    unsetenv("AT_OWN_PROFILE");
    setenv("AT_OWN_GEOHASH", "9q8yy", 1);
    ck_assert_int_eq(identity_ext_check_env(NULL), -1);
    unsetenv("AT_OWN_GEOHASH");
}
END_TEST_DEFINITION()


/* A core-only binary has no fleet and no data-source service: no process, no
 * default subsystem, nothing of theirs in the configuration it generates, and
 * a configuration that starts one of their subsystems refuses the start
 * (FEATURE_SPLIT_PLAN Phase 8). Also the two load-time registries the move
 * needed: default subsystems and capabilities. */
DEFINE_TEST(test_core_only_has_no_fleet_and_refuses_its_subsystems)
{
    static const char *const feature[][2] = {
        { "fleet", "fleet_proc" }, { "artifact", "artifact_proc" },
        { "update", "update_proc" }, { "config", "config_proc" },
        { "data-source", "data_source_proc" },
    };
    for (size_t i = 0; i < sizeof(feature) / sizeof(feature[0]); i++)
        ck_assert_ptr_null(find_process(feature[i][1]));
    ck_assert_uint_eq(subsystem_defaults(NULL, NULL, AT_SUBSYSTEM_EXT_MAX), 0);
    ck_assert_ptr_null(find_capability("data"));

    /* The generated configuration starts the core's subsystems only. */
    char dir[] = "/tmp/at_ext_subsysXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(dir));
    ck_assert_int_eq(generate_subsystems_config(dir), 0);
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", dir, default_tracker_filename);
    FILE *fp = fopen(path, "r");
    ck_assert_ptr_nonnull(fp);
    char text[4096] = {0};
    size_t n = fread(text, 1, sizeof(text) - 1, fp);
    fclose(fp);
    unlink(path);
    rmdir(dir);
    ck_assert(n > 0);
    ck_assert(strstr(text, "id_proc") != NULL);
    for (size_t i = 0; i < sizeof(feature) / sizeof(feature[0]); i++)
        ck_assert(strstr(text, feature[i][1]) == NULL);

    /* Configured anyway: refused, one line per subsystem. An unknown runner
     * that is no feature's is not this check's to refuse. */
    tracker_t tracker;
    ck_assert_int_eq(tracker_init(NULL, &tracker), 0);
    ck_assert_int_eq(tracker_register_subsystem(&tracker, "identity", "id_proc"), 0);
    ck_assert_int_eq(tracker_register_subsystem(&tracker, "mystery", "no_such_proc"), 0);
    ck_assert_int_eq(tracker_check_subsystem_libraries(&tracker, NULL), 0);
    ck_assert_int_eq(tracker_register_subsystem(&tracker, "data-source", "data_source_proc"), 0);
    ck_assert_int_eq(tracker_check_subsystem_libraries(&tracker, NULL), -1);
    tracker_free(&tracker);
    ck_assert_int_eq(tracker_init(NULL, &tracker), 0);
    ck_assert_int_eq(tracker_register_subsystem(&tracker, "fleet", "fleet_proc"), 0);
    ck_assert_int_eq(tracker_check_subsystem_libraries(&tracker, NULL), -1);
    tracker_free(&tracker);

    /* The default-subsystem registry refuses what process_table_append does. */
    ck_assert_int_eq(subsystem_default_register(NULL, "x_proc"), -1);
    ck_assert_int_eq(subsystem_default_register("x", ""), -1);
    ck_assert_int_eq(subsystem_default_register("probe-sub", "probe_proc"), 0);
    ck_assert_int_eq(subsystem_default_register("probe-sub", "probe_proc"), -1);
    const char *keys[AT_SUBSYSTEM_EXT_MAX], *impls[AT_SUBSYSTEM_EXT_MAX];
    ck_assert_uint_eq(subsystem_defaults(keys, impls, AT_SUBSYSTEM_EXT_MAX), 1);
    ck_assert_str_eq(keys[0], "probe-sub");
    ck_assert_str_eq(impls[0], "probe_proc");
    static char sub_names[AT_SUBSYSTEM_EXT_MAX][16];
    int accepted = 0;
    for (int i = 0; i < AT_SUBSYSTEM_EXT_MAX; i++) {
        snprintf(sub_names[i], sizeof(sub_names[i]), "fill-sub-%d", i);
        if (subsystem_default_register(sub_names[i], "probe_proc") == 0)
            accepted++;
    }
    ck_assert_int_eq(accepted, AT_SUBSYSTEM_EXT_MAX - 1);   /* probe-sub took one */

    /* A capability added at load is found like a generated one. */
    ck_assert_int_eq(capability_table_append("probe_cap", NULL, NULL), 0);
    capability_t *cap = find_capability("probe_cap");
    ck_assert_ptr_nonnull(cap);
    ck_assert(cap->local);
    ck_assert_int_eq(capability_table_append("probe_cap", NULL, NULL), -1);
    ck_assert_int_eq(capability_table_append(NULL, NULL, NULL), -1);
    ck_assert_int_eq(capability_table_append("", NULL, NULL), -1);
}
END_TEST_DEFINITION()

RUN_TESTS(Extension, test_registration_refusals,
          test_gate_is_reread_and_dispatch_is_per_process,
          test_first_contact_registers_exactly_when_enabled,
          test_transport_registration,
          test_process_table_append,
          test_configuration_and_error_table_append,
          test_core_only_refuses_an_enabled_zta_policy,
          test_core_only_has_no_social_and_refuses_its_declarations,
          test_core_only_has_no_fleet_and_refuses_its_subsystems)
