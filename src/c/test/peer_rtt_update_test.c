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
 * @file peer_rtt_update_test.c
 * @brief PEER_RTT_UPDATE propagation (at-over-dtn §4.3 B-followup).
 *
 * Drives run_message_handlers() with a PEER_RTT_UPDATE message and
 * asserts that the target peer's peer_rtt_ms[] slot is updated. No real
 * IPC: we populate process.protocol.peers[] directly, hand a crafted
 * generic_msg_t to the dispatcher, and read back the protocol state.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"
#include "identity/identity.h"

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void proc_init_with_peers(process_t *proc,
                                 uuid_t *uuids, size_t n)
{
    memset(proc, 0, sizeof(*proc));
    snprintf(proc->name, sizeof(proc->name), "testproc");
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    for (size_t i = 0; i < n && i < DEFAULT_MAX_PEERS; i++) {
        memcpy(proc->protocol.peers[i].uuid, uuids[i], 16);
        snprintf(proc->protocol.peers[i].nickname,
                 sizeof(proc->protocol.peers[i].nickname),
                 "peer-%zu", i);
        proc->protocol.peer_rtt_ms[i] = 0;
    }
    proc->protocol.num_peers = n;
}

static int read_rtt_ms(const process_t *proc, const uuid_t target)
{
    peers_read_lock(proc);
    int found = -1;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (memcmp(proc->protocol.peers[i].uuid, target, 16) == 0) {
            found = proc->protocol.peer_rtt_ms[i];
            break;
        }
    }
    peers_read_unlock(proc);
    return found;
}

DEFINE_TEST(test_rtt_update_matches_peer_by_uuid)
{
    uuid_t peers[3];
    uuid_fill(peers[0], 0x10);
    uuid_fill(peers[1], 0x20);
    uuid_fill(peers[2], 0x30);
    const uint8_t *A = peers[0], *B = peers[1], *C = peers[2];

    process_t proc;
    proc_init_with_peers(&proc, peers, 3);

    /* Middle peer receives a 750ms rtt update — DTN-class link. */
    generic_msg_t msg = {0};
    msg.type = PEER_RTT_UPDATE;
    msg.size = sizeof(peer_rtt_update_msg_t);
    memcpy(msg.info.peer_rtt_update.peer_uuid, B, 16);
    msg.info.peer_rtt_update.rtt_ms = 750;

    ck_assert_int_eq((int)run_message_handlers(&proc, NULL, PEER_RTT_UPDATE, &msg), 1);

    /* B updated; A and C untouched. */
    ck_assert_int_eq(read_rtt_ms(&proc, A), 0);
    ck_assert_int_eq(read_rtt_ms(&proc, B), 750);
    ck_assert_int_eq(read_rtt_ms(&proc, C), 0);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rtt_update_overwrites_previous_value)
{
    uuid_t peers[1];
    uuid_fill(peers[0], 0x40);
    const uint8_t *A = peers[0];

    process_t proc;
    proc_init_with_peers(&proc, peers, 1);
    proc.protocol.peer_rtt_ms[0] = 50;   /* pre-existing LAN-class value */

    generic_msg_t msg = {0};
    msg.type = PEER_RTT_UPDATE;
    memcpy(msg.info.peer_rtt_update.peer_uuid, A, 16);
    msg.info.peer_rtt_update.rtt_ms = 1200;

    run_message_handlers(&proc, NULL, PEER_RTT_UPDATE, &msg);

    /* Fresher estimate wins. */
    ck_assert_int_eq(read_rtt_ms(&proc, A), 1200);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rtt_update_unknown_peer_is_dropped)
{
    uuid_t peers[1];
    uuid_fill(peers[0], 0x50);
    uuid_t UNKNOWN;
    uuid_fill(UNKNOWN, 0x51);
    const uint8_t *KNOWN = peers[0];

    process_t proc;
    proc_init_with_peers(&proc, peers, 1);

    generic_msg_t msg = {0};
    msg.type = PEER_RTT_UPDATE;
    memcpy(msg.info.peer_rtt_update.peer_uuid, UNKNOWN, 16);
    msg.info.peer_rtt_update.rtt_ms = 999;

    /* Returns true regardless — caller's "handled" contract is satisfied
     * whether or not a match was found. The log-and-drop is observable
     * only through the debug log; we assert no side effects. */
    ck_assert_int_eq((int)run_message_handlers(&proc, NULL, PEER_RTT_UPDATE, &msg), 1);

    /* KNOWN peer's rtt must remain 0 — didn't get the update meant for
     * UNKNOWN. */
    ck_assert_int_eq(read_rtt_ms(&proc, KNOWN), 0);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rtt_update_negative_clamped_at_handler)
{
    /* The handler itself does NOT clamp — it just stores what net_proc
     * gave it. net_proc's link_class_ms returns int and is conventioned
     * to report 0 for unknown; negative should not happen in practice,
     * but if it does we preserve it so diagnostic tools see the anomaly.
     * This test pins down that behavior. */
    uuid_t peers[1];
    uuid_fill(peers[0], 0x60);
    const uint8_t *A = peers[0];

    process_t proc;
    proc_init_with_peers(&proc, peers, 1);

    generic_msg_t msg = {0};
    msg.type = PEER_RTT_UPDATE;
    memcpy(msg.info.peer_rtt_update.peer_uuid, A, 16);
    msg.info.peer_rtt_update.rtt_ms = -1;

    run_message_handlers(&proc, NULL, PEER_RTT_UPDATE, &msg);
    ck_assert_int_eq(read_rtt_ms(&proc, A), -1);

    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

RUN_TESTS(Peer_Rtt_Update,
          test_rtt_update_matches_peer_by_uuid,
          test_rtt_update_overwrites_previous_value,
          test_rtt_update_unknown_peer_is_dropped,
          test_rtt_update_negative_clamped_at_handler)
