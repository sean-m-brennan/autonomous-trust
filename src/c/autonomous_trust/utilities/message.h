/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef MESSAGE_H
#define MESSAGE_H

/** @addtogroup public_api
 *  @{
 */

#include <stdbool.h>
#include <sys/socket.h>

#include "structures/map.h"
#include "msg_types.h"

#define MSG_KEY_LEN PROC_NAME_LEN

/**
 * @brief IPC queue name of the daemon's own main loop.
 *
 * The loop binds this (@ref run_autonomous_trust) and sibling processes send
 * to it — anything app-bound has to pass through the loop, which owns the
 * app's queue name. One spelling, in one place, because a second spelling is
 * exactly what silently swallowed negotiation's task results: they were sent
 * to `"main"`, a name nothing ever binds.
 */
#define AT_MAIN_QUEUE "AutonomousTrust"

/**
 * @brief App → AT local-only verb: re-emit the current peer view.
 *
 * Carried as a @ref NET_MESSAGE `function` rather than as its own message
 * type, following the established local-only-verb pattern (`tier_update`,
 * `attest_trigger`, `local_rep_query`): typed messages dispatch through a
 * single shared switch that cannot reach process-specific code, whereas a
 * function string dispatches to whichever process registered it.
 *
 * One of a small, explicit allowlist of verbs the daemon accepts from an app,
 * each forwarded to a fixed set of processes — an app must not be able to
 * inject arbitrary internal verbs at an arbitrary process.
 */
#define AT_APP_ROSTER_REQUEST "app_roster_request"

/**
 * @brief App → AT local-only verb: set (or clear) THIS node's own opt-in coarse
 * position, so the identity process can answer peers' directed position queries.
 *
 * The payload is the operator's chosen geohash bucket, or empty to opt out
 * (clears it). STRICTLY OPT-IN: absent this verb, `own_geohash` stays empty and
 * the node advertises and answers nothing geographic. Forwarded only to the
 * identity process. Second (and only other) verb on the app→AT allowlist.
 */
#define AT_APP_SET_POSITION "app_set_position"

/* App→AT: set/replace THIS node's opt-in agora.profile (Increment 3). The
 * payload is the profile object itself; empty clears it (opt out). Forwarded
 * only to the identity process. Third verb on the app→AT allowlist. */
#define AT_APP_SET_PROFILE "app_set_profile"

/* App→AT: request an explicit connection to a peer (Increment 5). The payload
 * is {"peer": "<uuid_str>"}; identity sets our edge to pending_out and sends a
 * directed encrypted peer_connection_request to that peer. Forwarded only to
 * the identity process. Fourth verb on the app→AT allowlist. */
#define AT_APP_CONNECT_REQUEST "app_connect_request"

/* App→AT: respond to an inbound connection request (Increment 5). The payload
 * is {"peer": "<uuid_str>", "accept": <bool>}; identity sets our edge to
 * connected/declined and sends a directed encrypted, SIGNED
 * peer_connection_response. Forwarded only to the identity process. Fifth verb
 * on the app→AT allowlist. */
#define AT_APP_CONNECT_RESPOND "app_connect_respond"

#define DEFAULT_MAX_MSG_SIZE 1024
/* MAX_MSG_SIZE is configurable at runtime via messaging_set_max_size() */
#define MAX_MSG_SIZE (messaging_max_size())

/*@
  assigns \nothing;
  ensures \result >= DEFAULT_MAX_MSG_SIZE || \result > 0;
*/
size_t messaging_max_size(void);

/*@
  requires size > 0;
  assigns \nothing;
*/
void messaging_set_max_size(size_t size);

typedef struct
{
    int fd;
    char key[MSG_KEY_LEN+1];
} queue_t;

/**
 * @brief Initialize a message queue
 *
 * @param id A message queue id
 * @param queue Queue object
 * @return int Success or error
 */
/*@
  requires id != \null && \valid_read(id);
  requires \valid(queue);
  assigns queue->key[0 .. MSG_KEY_LEN - 1], queue->fd;
  behavior success:
    ensures \result == 0;
    ensures queue->fd >= 0;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int messaging_init(const char *id, queue_t *queue);

/**
 * @brief Is a queue with this key actually bound — i.e. is somebody listening?
 *
 * The readiness question a host needs and could not previously ask. A forked
 * daemon exists long before its message loop binds anything: measured, about
 * **170-210 ms** separate `at_app_node_start` returning from the daemon's inbound
 * queue appearing, and for that whole window the process is alive and nothing
 * sent to it arrives. `at_app_node_alive` truthfully reports a running process
 * and says nothing about reachability; this answers the other half.
 *
 * Probes with `connect` on a throwaway datagram socket rather than checking that
 * the socket file exists, because a daemon that died leaves the file behind and a
 * file check would call that ready. Sends nothing; has no effect on a listener.
 *
 * @param key Queue name.
 * @return true if a socket is bound at that key's path.
 */
/*@
  requires key != \null && \valid_read(key);
  assigns \nothing;
*/
bool messaging_bound(const char *key);

/**
 * @brief Identify the queue that belong to this process.
 *
 * @param queue Queue object
 */
/*@
  requires queue == \null || \valid(queue);
  assigns \nothing;
*/
void messaging_assign(queue_t *queue);

/**
 * @brief Receive a message from a specific queue (usually external)
 *
 * @param queue Queue object
 * @param msg Generic message
 * @param their_addr Sender's info
 * @param blocking
 * @return int
 */
/*@
  requires \valid(q);
  requires q->fd > 0;
  requires \valid(msg);
  requires their_addr == \null || \valid(their_addr);
  assigns msg->type, msg->size, msg->info;
  behavior success:
    ensures \result == 0;
  behavior no_message:
    ensures \result == ENOMSG;
  behavior error:
    ensures \result == -1;
  disjoint behaviors;
*/
int messaging_recv_on(queue_t *q, generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking);

/**
 * @brief Receive a message from the assigned queue
 *
 * @param data
 * @param their_addr
 * @param blocking
 * @return int
 */
/*@
  requires \valid(data);
  requires their_addr == \null || \valid(their_addr);
  assigns data->type, data->size, data->info;
  behavior no_queue:
    ensures \result == -1;
  behavior success:
    ensures \result == 0;
  behavior no_message:
    ensures \result == ENOMSG;
  disjoint behaviors;
*/
int messaging_recv_from(generic_msg_t *data, struct sockaddr_storage *their_addr, bool blocking);

/**
 * @brief 
 * 
 */
#define messaging_recv(data) messaging_recv_from(data, NULL, false)

/*@
  requires \valid(q);
  requires q->fd > 0;
  requires \valid(msg_type);
  requires \valid(sig);
  assigns *msg_type, sig->descr[0 .. SIGNAL_LEN], sig->sig;
  behavior success:
    ensures \result == 0;
    ensures *msg_type == SIGNAL;
  behavior wrong_type:
    ensures \result == -2;
  behavior recv_error:
    ensures \result != 0 && \result != -2;
  disjoint behaviors;
*/
int signal_recv(queue_t *q, long *msg_type, signal_t * sig);

/**
 * @brief Send a message internally
 *
 * @param queue_id
 * @param type
 * @param msg
 * @return int
 */
/*@
  requires key != \null && \valid_read(key);
  requires \valid(msg);
  assigns \nothing;
  behavior no_queue:
    ensures \result == -1;
  behavior success:
    ensures \result == 0;
  behavior would_block:
    ensures \result == EAGAIN;
  behavior error:
    ensures \result == -1;
  disjoint behaviors no_queue, success, would_block;
*/
int messaging_send(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking);

/**
 * @brief Test-mode hook: callback invoked instead of the real socket write.
 *
 * Set via @ref messaging_set_test_hook. While installed, every
 * @ref messaging_send call invokes the hook with the (key, type, msg)
 * triple and returns the hook's return value. The real Unix-socket
 * datagram write is bypassed entirely.
 *
 * Used by the conformance harness to capture per-participant outboxes
 * without a real transport. Set to NULL to restore production behavior.
 *
 * Call ordering: messaging_send checks the hook BEFORE generic_msg_to_proto,
 * so hook implementations see the in-memory @ref generic_msg_t directly.
 */
typedef int (*messaging_test_hook_t)(const char *key,
                                     const message_type_t type,
                                     generic_msg_t *msg,
                                     bool blocking);

/** Install a test-mode hook (or pass NULL to clear). Not thread-safe;
 *  install before starting any harness dispatch and clear after. */
void messaging_set_test_hook(messaging_test_hook_t hook);

/**
 * @brief Close a specific message queue and remove its socket file.
 *
 * @param queue
 */
/*@
  requires queue == \null || \valid(queue);
  behavior null_queue:
    assumes queue == \null;
    assigns \nothing;
  behavior valid_queue:
    assumes queue != \null;
    assigns queue->fd;
  disjoint behaviors;
*/
void messaging_qclose(queue_t *queue);

/**
 * @brief Close the process's assigned message queue.
 *
 */
/*@
  assigns \nothing;
*/
void messaging_close();

#define EMSG_NOCONN 204
DECLARE_ERROR(EMSG_NOCONN, "Attempting to send/recv without a queue (see message_assign())");


/** @} */ /* end of public_api */

#endif  // MESSAGE_H
