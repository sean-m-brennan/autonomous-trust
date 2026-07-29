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
 * @file app_events_test.c
 * @brief The AT -> app peer carrier and the daemon routing it rides on.
 *
 * Regression cover for five independent breaks that together meant the
 * app-facing stream carried nothing at all (see
 * doc/architecture/app-peer-carrier.md):
 *
 *  1. no process produced peer data for it;
 *  2. two of three app-bound arms had no reachable producer ("main" was not
 *     a bound queue name);
 *  3. the drain batched app-bound messages into an array it then discarded,
 *     sending the loop's last-received message instead;
 *  4. the app bound its own `app_name` while the daemon sent to `q_in`;
 *  5. the drain queued a pointer to the message's `info` union and read it
 *     back as a whole generic_msg_t, so it switched on the first eight
 *     PAYLOAD bytes rather than on the type tag.
 *
 * No real IPC: assertions read the messaging test hook, which captures each
 * send's target queue and payload.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "autonomous_trust/at_route_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "structures/array.h"
#include "structures/data.h"
#include "processes/processes.h"
#include "identity/id_proc_priv.h"
#include "reputation/rep_proc_priv.h"
#include "autonomous_trust/app_events.h"

#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>

/****************************
 * Send-capture hook
 ****************************/

#define MAX_CAPTURED 16

typedef struct {
    char key[MSG_KEY_LEN + 1];
    long type;
    generic_msg_t msg;
} captured_t;

static captured_t captured[MAX_CAPTURED];
static int num_captured;
static int hook_fail_next;   /* when >0, the next N sends report EAGAIN */

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (hook_fail_next > 0) {
        hook_fail_next--;
        return EAGAIN;
    }
    if (num_captured < MAX_CAPTURED) {
        captured_t *c = &captured[num_captured++];
        snprintf(c->key, sizeof(c->key), "%s", key == NULL ? "" : key);
        c->type = (long)type;
        if (msg != NULL)
            memcpy(&c->msg, msg, sizeof(*msg));
    }
    return 0;
}

static void capture_reset(void)
{
    memset(captured, 0, sizeof(captured));
    num_captured = 0;
    hook_fail_next = 0;
    messaging_set_test_hook(_capture_hook);
}

static void capture_done(void)
{
    messaging_set_test_hook(NULL);
}

static int count_to(const char *key)
{
    int n = 0;
    for (int i = 0; i < num_captured; i++)
        if (strcmp(captured[i].key, key) == 0) n++;
    return n;
}

static int count_type(long type)
{
    int n = 0;
    for (int i = 0; i < num_captured; i++)
        if (captured[i].type == type) n++;
    return n;
}

/****************************
 * Break #3 — the drain built a batch and discarded it
 ****************************/

DEFINE_TEST(test_drain_sends_every_app_bound_message)
{
    capture_reset();

    array_t unhandled = {0};
    ck_assert_int_eq(array_init(&unhandled), 0);

    /* Two app-bound messages accumulate in one drain. Both must go out.
     * Distinct payloads so we can tell them apart on the far side — the
     * pre-fix code sent ONE message twice as often as it sent two. */
    generic_msg_t first = {0}, second = {0};
    first.type = UPDATE_ACCEPTED;
    first.info.update_accepted.accept_count = 11;
    second.type = UPDATE_ACCEPTED;
    second.info.update_accepted.accept_count = 22;
    ck_assert_int_eq(at_route_queue_msg(&unhandled, &first), 0);
    ck_assert_int_eq(at_route_queue_msg(&unhandled, &second), 0);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    ck_assert_int_eq(sent, 2);
    ck_assert_int_eq(count_to("app_q"), 2);
    /* FIFO, and both distinct payloads survived. */
    ck_assert_int_eq(captured[0].msg.info.update_accepted.accept_count, 11);
    ck_assert_int_eq(captured[1].msg.info.update_accepted.accept_count, 22);

    /* The drain empties the array whatever it sends. */
    ck_assert_int_eq((int)array_size(&unhandled), 0);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * Break #5 — routing must read the type tag, not the payload
 ****************************/

DEFINE_TEST(test_drain_routes_on_the_type_tag_not_the_payload)
{
    capture_reset();

    array_t unhandled = {0};
    array_init(&unhandled);

    /* An app-bound message whose leading payload bytes deliberately spell a
     * DIFFERENT valid message type. Pre-fix the drain queued &msg.info and
     * read it back as a generic_msg_t*, so ->type landed on exactly these
     * bytes and this message was misrouted to the reputation process. */
    generic_msg_t msg = {0};
    msg.type = UPDATE_ACCEPTED;
    long decoy = TASK_RESULT;
    memcpy(msg.info.update_accepted.proposal_uuid, &decoy, sizeof(decoy));
    ck_assert_int_eq(at_route_queue_msg(&unhandled, &msg), 0);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    /* Routed as what it IS, not as what its payload happens to spell. */
    ck_assert_int_eq(sent, 1);
    ck_assert_int_eq(count_to("app_q"), 1);
    ck_assert_int_eq(count_to("reputation"), 0);
    ck_assert_int_eq(captured[0].type, UPDATE_ACCEPTED);

    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_drain_forwards_sibling_traffic_by_type)
{
    capture_reset();

    array_t unhandled = {0};
    array_init(&unhandled);
    generic_msg_t res = {0}, stat = {0};
    res.type = TASK_RESULT;
    stat.type = TASK_STATUS;
    at_route_queue_msg(&unhandled, &res);
    at_route_queue_msg(&unhandled, &stat);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    /* Neither is app-bound. */
    ck_assert_int_eq(sent, 0);
    ck_assert_int_eq(count_to("app_q"), 0);
    ck_assert_int_eq(count_to("reputation"), 1);
    ck_assert_int_eq(count_to("negotiation"), 1);
    ck_assert_int_eq((int)array_size(&unhandled), 0);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * The carrier types are app-bound
 ****************************/

DEFINE_TEST(test_carrier_types_reach_the_app_queue)
{
    capture_reset();

    array_t unhandled = {0};
    array_init(&unhandled);

    generic_msg_t obs = {0};
    obs.type = PEER_OBSERVED;
    obs.info.peer_observed.rank = 7;
    obs.info.peer_observed.operator_bound = true;
    obs.info.peer_observed.operator_attested_at = 1721800000.0;
    for (int i = 0; i < 32; i++)
        obs.info.peer_observed.signing_pubkey[i] = (uint8_t)(0x40 + i);

    generic_msg_t rep = {0};
    rep.type = PEER_REPUTATION;
    rep.info.peer_reputation.score = 0.73;
    rep.info.peer_reputation.rated = true;

    at_route_queue_msg(&unhandled, &obs);
    at_route_queue_msg(&unhandled, &rep);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    ck_assert_int_eq(sent, 2);
    ck_assert_int_eq(count_type(PEER_OBSERVED), 1);
    ck_assert_int_eq(count_type(PEER_REPUTATION), 1);

    /* Every field survives the hop intact. */
    ck_assert_int_eq(captured[0].msg.info.peer_observed.rank, 7);
    ck_assert(captured[0].msg.info.peer_observed.operator_bound);
    ck_assert_double_eq_tol(
        captured[0].msg.info.peer_observed.operator_attested_at,
        1721800000.0, 1e-6);
    ck_assert_int_eq(captured[0].msg.info.peer_observed.signing_pubkey[0], 0x40);
    ck_assert_int_eq(captured[0].msg.info.peer_observed.signing_pubkey[31], 0x5F);
    ck_assert(captured[1].msg.info.peer_reputation.rated);
    ck_assert_double_eq_tol(captured[1].msg.info.peer_reputation.score,
                            0.73, 1e-9);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * The carrier types round-trip the IPC serializer
 ****************************/

DEFINE_TEST(test_carrier_types_round_trip_proto)
{
    /* message_size must know both types, or the queue cannot size them. */
    ck_assert_int_eq((int)message_size(PEER_OBSERVED),
                     (int)sizeof(peer_observed_msg_t));
    ck_assert_int_eq((int)message_size(PEER_REPUTATION),
                     (int)sizeof(peer_reputation_msg_t));

    /* The round trip below also pins the string tag both ways: the serializer
     * writes the type as a `type_url` string and the parser maps it back, so
     * a type missing from either table fails here. */
    generic_msg_t out = {0};
    out.type = PEER_OBSERVED;
    out.size = sizeof(peer_observed_msg_t);
    out.info.peer_observed.rank = -3;
    out.info.peer_observed.operator_bound = false;
    out.info.peer_observed.operator_attested_at = 0.0;
    for (int i = 0; i < 32; i++)
        out.info.peer_observed.signing_pubkey[i] = (uint8_t)(0xF0 - i);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_int_eq(generic_msg_to_proto(&out, &data, &data_len), 0);

    generic_msg_t back = {0};
    ck_assert_int_eq(proto_to_generic_msg(data, data_len, &back), 0);
    ck_assert_int_eq((int)back.type, (int)PEER_OBSERVED);
    ck_assert_int_eq(back.info.peer_observed.rank, -3);
    ck_assert(!back.info.peer_observed.operator_bound);
    ck_assert_int_eq(back.info.peer_observed.signing_pubkey[0], 0xF0);
    ck_assert_int_eq(back.info.peer_observed.signing_pubkey[31], 0xD1);

    generic_msg_t rep = {0};
    rep.type = PEER_REPUTATION;
    rep.size = sizeof(peer_reputation_msg_t);
    rep.info.peer_reputation.score = 0.0;
    rep.info.peer_reputation.rated = false;
    void *rdata = NULL;
    size_t rlen = 0;
    ck_assert_int_eq(generic_msg_to_proto(&rep, &rdata, &rlen), 0);
    generic_msg_t rback = {0};
    ck_assert_int_eq(proto_to_generic_msg(rdata, rlen, &rback), 0);
    /* NEGATIVE CONTROL 2: an unrated peer stays unrated across the hop. A
     * consumer must not be able to read 0.0 as a real, earned score. */
    ck_assert(!rback.info.peer_reputation.rated);
}
END_TEST_DEFINITION()

/****************************
 * Negative control 5 — an unroutable type must not be forwarded
 ****************************/

DEFINE_TEST(test_drain_drops_unroutable_type_without_sending)
{
    capture_reset();

    array_t unhandled = {0};
    array_init(&unhandled);
    generic_msg_t sig = {0};
    sig.type = SIGNAL;   /* never app-bound, never forwarded */
    at_route_queue_msg(&unhandled, &sig);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    ck_assert_int_eq(sent, 0);
    ck_assert_int_eq(num_captured, 0);
    /* Still drained — an unroutable message must not wedge the loop. */
    ck_assert_int_eq((int)array_size(&unhandled), 0);

    /* NEGATIVE CONTROL 1, the other way an app-bound message goes nowhere:
     * no app has bound a queue yet. Dropped, loop keeps running, and the app
     * recovers what it missed with a roster pull once it attaches. */
    generic_msg_t obs = {0};
    obs.type = PEER_OBSERVED;
    at_route_queue_msg(&unhandled, &obs);
    ck_assert_int_eq(at_route_internal_msgs(&unhandled, NULL, NULL), 0);
    ck_assert_int_eq(num_captured, 0);
    ck_assert_int_eq((int)array_size(&unhandled), 0);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * Negative control 4 — a failing (EAGAIN) send must not crash or wedge
 ****************************/

DEFINE_TEST(test_drain_survives_send_failure)
{
    capture_reset();
    hook_fail_next = 1;   /* the outward send reports EAGAIN */

    array_t unhandled = {0};
    array_init(&unhandled);
    generic_msg_t a = {0}, b = {0};
    a.type = PEER_OBSERVED;
    b.type = PEER_OBSERVED;
    at_route_queue_msg(&unhandled, &a);
    at_route_queue_msg(&unhandled, &b);

    int sent = at_route_internal_msgs(&unhandled, "app_q", NULL);

    /* The failure is reported honestly rather than counted, and it does not
     * abandon the rest of the batch. */
    ck_assert_int_eq(sent, 1);
    ck_assert_int_eq((int)array_size(&unhandled), 0);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * Inbound routing — the app's surface is exactly one verb
 ****************************/

DEFINE_TEST(test_extern_msg_routes_inbound_types)
{
    capture_reset();

    generic_msg_t task = {0};
    task.type = TASK;
    ck_assert_int_eq(at_route_extern_msg(&task, NULL), 0);
    ck_assert_int_eq(count_to("negotiation"), 1);

    generic_msg_t prop = {0};
    prop.type = UPDATE_PROPOSAL;
    ck_assert_int_eq(at_route_extern_msg(&prop, NULL), 0);
    ck_assert_int_eq(count_to("fleet"), 1);

    /* An app may not inject arbitrary internal traffic. */
    generic_msg_t bogus = {0};
    bogus.type = GROUP;
    ck_assert_int_eq(at_route_extern_msg(&bogus, NULL), -1);
    ck_assert_int_eq(count_type(GROUP), 0);

    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_roster_request_reaches_both_carrier_halves)
{
    capture_reset();

    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    req.info.net_msg.function = (char *)AT_APP_ROSTER_REQUEST;

    ck_assert_int_eq(at_route_extern_msg(&req, NULL), 0);

    /* Identity holds the peer facts, reputation the scores — both answer,
     * and each copy is addressed to its own process so dispatch matches. */
    ck_assert_int_eq(count_to("identity"), 1);
    ck_assert_int_eq(count_to("reputation"), 1);
    for (int i = 0; i < num_captured; i++)
        ck_assert_str_eq(captured[i].msg.info.net_msg.process, captured[i].key);

    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_extern_net_msg_verb_is_allowlisted)
{
    capture_reset();

    /* NEGATIVE CONTROL: any other local verb must be refused. Forwarding a
     * net_msg to whatever process it names would hand an app AT's entire
     * internal verb surface — tier_update, slash proposals, everything. */
    generic_msg_t evil = {0};
    evil.type = NET_MESSAGE;
    evil.info.net_msg.function = (char *)"tier_update";
    snprintf(evil.info.net_msg.process, sizeof(evil.info.net_msg.process),
             "identity");

    ck_assert_int_eq(at_route_extern_msg(&evil, NULL), -1);
    ck_assert_int_eq(num_captured, 0);

    /* A net_msg with no function at all is refused too, not dereferenced. */
    generic_msg_t empty = {0};
    empty.type = NET_MESSAGE;
    empty.info.net_msg.function = NULL;
    ck_assert_int_eq(at_route_extern_msg(&empty, NULL), -1);
    ck_assert_int_eq(num_captured, 0);

    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * The emitters — break #1: nothing produced peer data at all
 ****************************/

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

/* A process with @p n peers in its table, as both real processes hold them. */
static void proc_with_peers(process_t *proc, size_t n, uint8_t seed)
{
    memset(proc, 0, sizeof(*proc));
    snprintf(proc->name, sizeof(proc->name), "identity");
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    for (size_t i = 0; i < n && i < DEFAULT_MAX_PEERS; i++) {
        uuid_fill(proc->protocol.peers[i].uuid, (uint8_t)(seed + 0x10 * i));
        for (size_t k = 0; k < crypto_sign_PUBLICKEYBYTES; k++)
            proc->protocol.peers[i].signature.public[k] = (uint8_t)(seed + i + k);
    }
    proc->protocol.num_peers = n;
}

DEFINE_TEST(test_identity_emits_one_observation_per_peer)
{
    capture_reset();

    process_t proc;
    proc_with_peers(&proc, 3, 0x20);

    int n = identity_emit_all_peers(&proc);

    ck_assert_int_eq(n, 3);
    ck_assert_int_eq(count_type(PEER_OBSERVED), 3);
    /* Emitted to the daemon's own queue — a sub-process does not know the
     * app's queue name, so the main loop owns the outward hop. */
    ck_assert_int_eq(count_to(AT_MAIN_QUEUE), 3);
    /* The peer's real signing key crosses, not a zeroed placeholder. */
    ck_assert_int_eq(captured[0].msg.info.peer_observed.signing_pubkey[0], 0x20);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_roster_pull_with_no_peers_emits_nothing)
{
    capture_reset();

    process_t proc;
    proc_with_peers(&proc, 0, 0x30);

    /* NEGATIVE CONTROL 6: an empty roster is a real answer, not an event. */
    ck_assert_int_eq(identity_emit_all_peers(&proc), 0);
    ck_assert_int_eq(num_captured, 0);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unverified_operator_suppresses_the_attendance_stamp)
{
    capture_reset();

    process_t proc;
    proc_with_peers(&proc, 2, 0x40);
    /* Peer 0: a verified guardian, present recently. */
    proc.protocol.peers[0].operator_bound = true;
    proc.protocol.peers[0].operator_attested_at = 1721800000.0;
    /* Peer 1: NEGATIVE CONTROL 3 — claims an attendance stamp but its
     * operator credential never verified, so operator_bound is false. */
    proc.protocol.peers[1].operator_bound = false;
    proc.protocol.peers[1].operator_attested_at = 1721800000.0;

    ck_assert_int_eq(identity_emit_all_peers(&proc), 2);

    ck_assert(captured[0].msg.info.peer_observed.operator_bound);
    ck_assert_double_eq_tol(
        captured[0].msg.info.peer_observed.operator_attested_at,
        1721800000.0, 1e-6);

    /* The unverified peer's stamp is NOT forwarded: an attendance claim from
     * a node whose operator credential never verified attests to nothing, and
     * a consumer receiving it would have to know to distrust it. */
    ck_assert(!captured[1].msg.info.peer_observed.operator_bound);
    ck_assert_double_eq_tol(
        captured[1].msg.info.peer_observed.operator_attested_at, 0.0, 1e-9);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    capture_done();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_pull_reports_unrated_peers_as_unrated)
{
    capture_reset();

    process_t proc;
    proc_with_peers(&proc, 2, 0x50);
    snprintf(proc.name, sizeof(proc.name), "reputation");

    /* Peer 0 has an actual rating; peer 1 has never been scored. */
    reputation_install_peer_reputation(proc.protocol.peers[0].uuid, 0.62);

    int n = reputation_emit_all(&proc);

    ck_assert_int_eq(n, 2);
    ck_assert_int_eq(count_type(PEER_REPUTATION), 2);

    ck_assert(captured[0].msg.info.peer_reputation.rated);
    ck_assert_double_eq_tol(captured[0].msg.info.peer_reputation.score,
                            0.62, 1e-6);

    /* THE point of the pull: an unrated peer is reported, and reported AS
     * unrated. AT's own PREREP_NEUTRAL placeholder is a value a peer can
     * genuinely earn, so a bare number could not carry this distinction. */
    ck_assert(!captured[1].msg.info.peer_reputation.rated);
    ck_assert_double_eq_tol(captured[1].msg.info.peer_reputation.score,
                            0.0, 1e-9);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    capture_done();
}
END_TEST_DEFINITION()

/****************************
 * The verb dispatches — the one link between routing and the emitters.
 *
 * at_route_extern_msg forwards the request and the emitters answer it, but
 * nothing else pins that the registered function STRING actually reaches the
 * handler: a typo in either registration would leave a request silently
 * unhandled, with both halves' tests still green.
 ****************************/

DEFINE_TEST(test_roster_verb_dispatches_to_the_registered_handlers)
{
    capture_reset();

    /* The identity half. */
    process_t idp;
    proc_with_peers(&idp, 2, 0x60);
    ck_assert_int_eq(map_create(&idp.protocol.handlers), 0);
    /* The REAL registration, so a typo in either the verb constant or the
     * registration call fails here rather than at runtime. */
    ck_assert_int_eq(identity_register_handlers(&idp), 0);

    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "%s", idp.name);
    req.info.net_msg.function = (char *)AT_APP_ROSTER_REQUEST;

    ck_assert(run_message_handlers(&idp, NULL, NET_MESSAGE, &req));
    /* Dispatched, and the handler emitted one observation per peer. */
    ck_assert_int_eq(count_type(PEER_OBSERVED), 2);

    pthread_rwlock_destroy(&idp.protocol.peers_rwlock);
    capture_done();
}
END_TEST_DEFINITION()

/* Unix-socket paths are <AUTONOMOUS_TRUST_ROOT>/var/at/<queue-name>, so a
 * bare test has to provide a root that exists before it can bind one. */
static void socket_root_setup(void)
{
    static char root[] = "/tmp/at-app-events-testXXXXXX";
    static bool done = false;
    if (done) return;
    ck_assert_ptr_nonnull(mkdtemp(root));
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/var", root);
    ck_assert_int_eq(mkdir(dir, 0700), 0);
    snprintf(dir, sizeof(dir), "%s/var/at", root);
    ck_assert_int_eq(mkdir(dir, 0700), 0);
    ck_assert_int_eq(setenv("AUTONOMOUS_TRUST_ROOT", root, 1), 0);
    done = true;
}

/****************************
 * Break #4 — end to end over REAL sockets, no test hook.
 *
 * The only assertion here that could have caught break #4: the app must bind
 * the same name the daemon sends to. Everything above runs on the capture
 * hook, which cannot see a queue-name mismatch because it never touches a
 * socket.
 ****************************/

DEFINE_TEST(test_carrier_crosses_a_real_socket_to_the_app)
{
    /* No capture hook: this is the real transport. */
    messaging_set_test_hook(NULL);
    socket_root_setup();

    /* The app binds the AT -> app queue, exactly as at_node_start now does. */
    at_app_events_t *ev = at_app_events_open("test_at_to_app");
    ck_assert_ptr_nonnull(ev);

    /* Stand in for the daemon's outward hop: the drain sending to q_out. */
    array_t unhandled = {0};
    array_init(&unhandled);

    generic_msg_t obs = {0};
    obs.type = PEER_OBSERVED;
    obs.info.peer_observed.rank = 4;
    obs.info.peer_observed.operator_bound = true;
    obs.info.peer_observed.operator_attested_at = 1721800123.0;
    uuid_fill(obs.info.peer_observed.peer_uuid, 0x70);
    for (size_t k = 0; k < crypto_sign_PUBLICKEYBYTES; k++)
        obs.info.peer_observed.signing_pubkey[k] = (uint8_t)(0x80 + k);

    generic_msg_t rep = {0};
    rep.type = PEER_REPUTATION;
    uuid_fill(rep.info.peer_reputation.peer_uuid, 0x70);
    rep.info.peer_reputation.score = 0.91;
    rep.info.peer_reputation.rated = true;

    /* An unrated peer, to prove rated=false survives the real hop too. */
    generic_msg_t unrated = {0};
    unrated.type = PEER_REPUTATION;
    uuid_fill(unrated.info.peer_reputation.peer_uuid, 0x90);
    unrated.info.peer_reputation.score = 0.0;
    unrated.info.peer_reputation.rated = false;

    at_route_queue_msg(&unhandled, &obs);
    at_route_queue_msg(&unhandled, &rep);
    at_route_queue_msg(&unhandled, &unrated);

    int sent = at_route_internal_msgs(&unhandled, "test_at_to_app", NULL);
    ck_assert_int_eq(sent, 3);

    /* And the app receives them, decoded through the flat ABI. */
    at_app_event_t batch[8];
    memset(batch, 0, sizeof(batch));
    int n = at_app_events_poll(ev, batch, 8);
    ck_assert_int_eq(n, 3);

    ck_assert_int_eq((int)batch[0].kind, (int)AT_APP_EVENT_PEER_OBSERVED);
    ck_assert_int_eq(batch[0].data.peer.rank, 4);
    ck_assert(batch[0].data.peer.operator_bound);
    ck_assert_double_eq_tol(batch[0].data.peer.operator_attested_at,
                            1721800123.0, 1e-6);
    ck_assert_int_eq(batch[0].data.peer.signing_pubkey[0], 0x80);
    ck_assert_int_eq(batch[0].data.peer.signing_pubkey[31], 0x9F);
    ck_assert_int_eq(batch[0].data.peer.peer_uuid[0], 0x70);

    ck_assert_int_eq((int)batch[1].kind, (int)AT_APP_EVENT_PEER_REPUTATION);
    ck_assert(batch[1].data.reputation.rated);
    ck_assert_double_eq_tol(batch[1].data.reputation.score, 0.91, 1e-9);

    ck_assert_int_eq((int)batch[2].kind, (int)AT_APP_EVENT_PEER_REPUTATION);
    ck_assert(!batch[2].data.reputation.rated);

    /* A second poll on a drained queue is empty, not an error. */
    ck_assert_int_eq(at_app_events_poll(ev, batch, 8), 0);

    at_app_events_close(ev);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_app_bound_to_the_wrong_name_receives_nothing)
{
    messaging_set_test_hook(NULL);
    socket_root_setup();

    /* NEGATIVE CONTROL: this is break #4 exactly — the app binds one name
     * while the daemon sends to another. Nothing arrives, and nothing
     * reports an error either, which is why it went unnoticed. */
    at_app_events_t *ev = at_app_events_open("test_app_name_mismatch");
    ck_assert_ptr_nonnull(ev);

    array_t unhandled = {0};
    array_init(&unhandled);
    generic_msg_t obs = {0};
    obs.type = PEER_OBSERVED;
    at_route_queue_msg(&unhandled, &obs);

    /* The daemon sends to the queue name it was configured with... */
    at_route_internal_msgs(&unhandled, "test_at_to_app_other", NULL);

    /* ...and the app, bound elsewhere, sees nothing. */
    at_app_event_t batch[4];
    ck_assert_int_eq(at_app_events_poll(ev, batch, 4), 0);

    at_app_events_close(ev);
}
END_TEST_DEFINITION()

RUN_TESTS(App_Events,
          test_drain_sends_every_app_bound_message,
          test_drain_routes_on_the_type_tag_not_the_payload,
          test_drain_forwards_sibling_traffic_by_type,
          test_carrier_types_reach_the_app_queue,
          test_carrier_types_round_trip_proto,
          test_drain_drops_unroutable_type_without_sending,
          test_drain_survives_send_failure,
          test_extern_msg_routes_inbound_types,
          test_roster_request_reaches_both_carrier_halves,
          test_extern_net_msg_verb_is_allowlisted,
          test_identity_emits_one_observation_per_peer,
          test_identity_roster_pull_with_no_peers_emits_nothing,
          test_unverified_operator_suppresses_the_attendance_stamp,
          test_reputation_pull_reports_unrated_peers_as_unrated,
          test_roster_verb_dispatches_to_the_registered_handlers,
          test_carrier_crosses_a_real_socket_to_the_app,
          test_app_bound_to_the_wrong_name_receives_nothing)
