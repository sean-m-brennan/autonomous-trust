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

#include "processes/processes.h"
#include "processes/extension.h"
#include "structures/map.h"
#include "identity/id_proc_priv.h"
#include "identity/first_contact.h"
#include "identity/id_ext.h"
#include "network/net_transport.h"

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
        pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    }
    unsetenv(AT_FIRST_CONTACT_ENV);
    at_extensions_reset();
}
END_TEST_DEFINITION()

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

RUN_TESTS(Extension, test_registration_refusals,
          test_gate_is_reread_and_dispatch_is_per_process,
          test_first_contact_registers_exactly_when_enabled,
          test_transport_registration,
          test_process_table_append,
          test_core_only_has_no_social_and_refuses_its_declarations)
