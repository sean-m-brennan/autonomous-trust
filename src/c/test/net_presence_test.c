/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/

/** @file Local soft-absence (doc/architecture/peer-presence.md).
 *
 *  The network process's presence tracker: when a peer counts as absent, when
 *  this node owes the group a heartbeat, and the PEER_PRESENCE hand-off to the
 *  sibling processes and the app. Times are passed in, so nothing here sleeps.
 *  Mirrors tests/a_unit/test_peer_presence.py.
 */

#define DEBUG_TESTS 1

#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "app_events.h"
#include "config/configuration.h"
#include "utilities/util.h"
#include "network/net_presence.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"

#define T0 1000000.0

static void _roster(uuid_t *r, size_t n)
{
    for (size_t i = 0; i < n; i++)
        uuid_generate(r[i]);
}

DEFINE_TEST(test_a_peer_is_absent_only_after_the_threshold)
{
    net_presence_configure(30.0, 90.0);
    uuid_t r[2];
    _roster(r, 2);
    net_presence_change_t ch[4];
    size_t n = 99;

    /* Joining the roster starts the grace: nobody is absent yet. */
    (void)net_presence_tick(r, 2, T0, ch, 4, &n);
    ck_assert_uint_eq(n, 0);

    net_presence_heard(r[1], T0 + 60.0);
    (void)net_presence_tick(r, 2, T0 + 90.0, ch, 4, &n);
    ck_assert_uint_eq(n, 0);                 /* exactly the threshold: present */

    (void)net_presence_tick(r, 2, T0 + 91.0, ch, 4, &n);
    ck_assert_uint_eq(n, 1);                 /* r[0]: never heard, grace over */
    ck_assert(uuid_compare(ch[0].peer_uuid, r[0]) == 0);
    ck_assert(!ch[0].present);
    ck_assert_double_eq_tol(ch[0].last_heard, 0.0, 1e-9);

    /* A transition is reported once, not on every tick. */
    (void)net_presence_tick(r, 2, T0 + 92.0, ch, 4, &n);
    ck_assert_uint_eq(n, 0);

    (void)net_presence_tick(r, 2, T0 + 151.0, ch, 4, &n);
    ck_assert_uint_eq(n, 1);                 /* r[1]: 91 s since it was heard */
    ck_assert(uuid_compare(ch[0].peer_uuid, r[1]) == 0);
    ck_assert_double_eq_tol(ch[0].last_heard, T0 + 60.0, 1e-6);

    /* Any frame brings a peer back, on the next tick. */
    net_presence_heard(r[0], T0 + 152.0);
    (void)net_presence_tick(r, 2, T0 + 153.0, ch, 4, &n);
    ck_assert_uint_eq(n, 1);
    ck_assert(uuid_compare(ch[0].peer_uuid, r[0]) == 0);
    ck_assert(ch[0].present);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_frame_from_a_stranger_is_not_evidence)
{
    net_presence_configure(30.0, 90.0);
    uuid_t r, stranger;
    _roster(&r, 1);
    uuid_generate(stranger);
    (void)net_presence_tick(&r, 1, T0, NULL, 0, NULL);
    net_presence_heard(stranger, T0 + 10.0);
    net_presence_change_t row[2];
    uuid_t both[2];
    uuid_copy(both[0], r);
    uuid_copy(both[1], stranger);
    /* The stranger joins the roster later; what it sent before does not count. */
    ck_assert_uint_eq(net_presence_snapshot(both, 2, row, 2), 2);
    ck_assert_double_eq_tol(row[1].last_heard, 0.0, 1e-9);
    ck_assert(row[1].present);               /* unknown reads present */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_heartbeat_is_owed_only_after_silence_toward_someone)
{
    net_presence_configure(30.0, 90.0);
    uuid_t r[2];
    _roster(r, 2);
    ck_assert(!net_presence_tick(r, 2, T0, NULL, 0, NULL));
    ck_assert(!net_presence_tick(r, 2, T0 + 29.0, NULL, 0, NULL));

    /* Talking to one member says nothing to the other. */
    net_presence_sent(r[0], T0 + 29.0);
    ck_assert(net_presence_tick(r, 2, T0 + 30.0, NULL, 0, NULL));

    /* A group frame reaches everyone. */
    net_presence_sent(NULL, T0 + 30.0);
    ck_assert(!net_presence_tick(r, 2, T0 + 59.0, NULL, 0, NULL));
    ck_assert(net_presence_tick(r, 2, T0 + 60.0, NULL, 0, NULL));

    /* A busy node never owes one. */
    for (int s = 60; s < 200; s += 10) {
        net_presence_sent(NULL, T0 + s);
        ck_assert(!net_presence_tick(r, 2, T0 + s + 5.0, NULL, 0, NULL));
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_peer_off_the_roster_is_forgotten)
{
    net_presence_configure(30.0, 90.0);
    uuid_t r[2];
    _roster(r, 2);
    net_presence_change_t ch[2];
    size_t n = 0;
    (void)net_presence_tick(r, 2, T0, ch, 2, &n);
    (void)net_presence_tick(r, 1, T0 + 200.0, ch, 2, &n);   /* r[1] left */
    ck_assert_uint_eq(n, 1);                                /* only r[0] */
    /* Back on the roster, it starts a fresh grace rather than being absent. */
    (void)net_presence_tick(r, 2, T0 + 201.0, ch, 2, &n);
    ck_assert_uint_eq(n, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_thresholds_keep_absent_above_the_heartbeat)
{
    net_presence_configure(60.0, 10.0);
    ck_assert_double_eq_tol(net_presence_absent_sec(), 60.0, 1e-9);
    net_presence_configure(-1.0, 0.0);
    ck_assert_double_eq_tol(net_presence_heartbeat_sec(),
                            NET_PRESENCE_HEARTBEAT_DEFAULT_SEC, 1e-9);
    ck_assert_double_eq_tol(net_presence_absent_sec(),
                            NET_PRESENCE_ABSENT_DEFAULT_SEC, 1e-9);
    setenv("AT_PRESENCE_HEARTBEAT_SEC", "5", 1);
    setenv("AT_PRESENCE_ABSENT_SEC", "nonsense", 1);
    net_presence_init();
    ck_assert_double_eq_tol(net_presence_heartbeat_sec(), 5.0, 1e-9);
    ck_assert_double_eq_tol(net_presence_absent_sec(),
                            NET_PRESENCE_ABSENT_DEFAULT_SEC, 1e-9);
    unsetenv("AT_PRESENCE_HEARTBEAT_SEC");
    unsetenv("AT_PRESENCE_ABSENT_SEC");
    net_presence_init();
}
END_TEST_DEFINITION()

/* A sibling records the flag beside the peer it names, and keeps it beside
 * that peer when an earlier one is removed. */
DEFINE_TEST(test_a_sibling_marks_the_named_peer_absent)
{
    process_t *proc = calloc(1, sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    for (int i = 0; i < 3; i++) {
        generic_msg_t peer = {0};
        peer.type = PEER;
        uuid_generate(peer.info.peer.uuid);
        ck_assert(run_message_handlers(proc, NULL, PEER, &peer));
    }
    generic_msg_t pres = {0};
    pres.type = PEER_PRESENCE;
    memcpy(pres.info.peer_presence.peer_uuid, proc->protocol.peers[2].uuid,
           sizeof(uuid_t));
    pres.info.peer_presence.present = false;
    ck_assert(run_message_handlers(proc, NULL, PEER_PRESENCE, &pres));
    ck_assert(!proc->protocol.peer_absent[0]);
    ck_assert(!proc->protocol.peer_absent[1]);
    ck_assert(proc->protocol.peer_absent[2]);

    ck_assert(processes_remove_peer(proc, proc->protocol.peers[0].uuid));
    ck_assert_uint_eq(proc->protocol.num_peers, 2);
    ck_assert(!proc->protocol.peer_absent[0]);
    ck_assert(proc->protocol.peer_absent[1]);   /* moved with its peer */
    ck_assert(!proc->protocol.peer_absent[2]);  /* vacated slot cleared */

    pres.info.peer_presence.present = true;
    ck_assert(run_message_handlers(proc, NULL, PEER_PRESENCE, &pres));
    ck_assert(!proc->protocol.peer_absent[1]);
    pthread_rwlock_destroy(&proc->protocol.peers_rwlock);
    free(proc);
}
END_TEST_DEFINITION()

/* The app hears it as AT_APP_EVENT_PEER_PRESENCE, through the real IPC
 * serializer and the flat decoder. */
DEFINE_TEST(test_the_app_decodes_a_presence_event)
{
    char root[] = "/tmp/at_presence_XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    ck_assert_int_eq(setenv("AUTONOMOUS_TRUST_ROOT", root, 1), 0);
    char data_dir[CFG_PATH_LEN + 1] = {0};
    ck_assert(get_data_dir(data_dir, sizeof(data_dir)) >= 0);
    ck_assert(makedirs(data_dir, 0755) == 0);
    at_app_events_t *ev = at_app_events_open("presence_q");
    ck_assert_ptr_nonnull(ev);
    generic_msg_t msg = {0};
    msg.type = PEER_PRESENCE;
    msg.size = sizeof(peer_presence_msg_t);
    uuid_generate(msg.info.peer_presence.peer_uuid);
    msg.info.peer_presence.present = false;
    msg.info.peer_presence.last_heard = T0 + 0.5;
    ck_assert_int_eq(messaging_send("presence_q", PEER_PRESENCE, &msg, false), 0);

    at_app_event_t out[2];
    int n = at_app_events_poll(ev, out, 2);
    ck_assert_int_eq(n, 1);
    ck_assert_int_eq(out[0].kind, AT_APP_EVENT_PEER_PRESENCE);
    ck_assert_mem_eq(out[0].data.presence.peer_uuid,
                     msg.info.peer_presence.peer_uuid, AT_APP_UUID_LEN);
    ck_assert(!out[0].data.presence.present);
    ck_assert_double_eq_tol(out[0].data.presence.last_heard, T0 + 0.5, 1e-6);
    at_app_events_close(ev);
    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

RUN_TESTS(NetPresence,
          test_a_peer_is_absent_only_after_the_threshold,
          test_a_frame_from_a_stranger_is_not_evidence,
          test_a_heartbeat_is_owed_only_after_silence_toward_someone,
          test_a_peer_off_the_roster_is_forgotten,
          test_the_thresholds_keep_absent_above_the_heartbeat,
          test_a_sibling_marks_the_named_peer_absent,
          test_the_app_decodes_a_presence_event)
