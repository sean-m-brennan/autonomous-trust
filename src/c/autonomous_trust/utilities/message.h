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
#include <sys/stat.h>   /* dev_t / ino_t: the bound socket's identity */

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

#ifdef AT_SOCIAL_ENABLED
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

/* App→AT: send a directed text message to a peer (Increment 6). The payload is
 * {"peer": "<uuid_str>", "text": "<body>"}; identity sends a directed encrypted
 * peer_dm carrying {text, seq, ts} to that peer. The app echoes the outgoing
 * message locally (the core does not echo it back). Forwarded only to the
 * identity process. Sixth verb on the app→AT allowlist. */
#define AT_APP_SEND_DM "app_send_dm"

/* App→AT: publish a feed post to the local group (Increment 7). The payload is
 * {"body": "<body>", "tier": <int 0..4>}; identity signs the post with this
 * node's Ed25519 key, group-encrypts it and multicasts it on the group channel.
 * The app echoes the outgoing post locally (the core does not echo it back).
 * Forwarded only to the identity process. Seventh verb on the app→AT allowlist. */
#define AT_APP_PUBLISH_POST "app_publish_post"

/* App→AT: react to a feed post (Increment 8). The payload is {"author":
 * "<uuid_str>", "post_id": "<hex>"}; identity sends a directed encrypted
 * peer_reaction {post_id, seq, ts} to the post's author. The reaction is the
 * return signal a fire-and-forget post otherwise lacks, so both the reactor and
 * the author submit a reputation score for the same post-derived task and the
 * engagement accrues. Forwarded only to the identity process. Eighth verb on the
 * app→AT allowlist. */
#define AT_APP_REACT_POST "app_react_post"

/* App→AT: locally block a peer (Increment 8). The payload is {"peer":
 * "<uuid_str>"}; identity clamps that peer's effective trust tier to 0 for THIS
 * node only. Purely local: no reputation transaction and nothing on the wire
 * (unlike a decline). Forwarded only to the identity process. Ninth verb on the
 * app→AT allowlist. */
#define AT_APP_BLOCK "app_block"

/* App→AT: pull a FRESH operator-attendance attestation from a peer NOW (Phase 2,
 * presence). The payload is {"peer": "<uuid_str>"}; identity issues a
 * nonce-fresh operator_attest_query to that peer and, on the response, updates
 * the peer's operator_attested_at and re-emits peer_observed. Forwarded only to
 * the identity process. Tenth verb on the app→AT allowlist. */
#define AT_APP_REQUEST_ATTEND "app_request_attend"

/* App→AT: set (or clear) THIS node's opt-in EXACT position (Phase 2, private
 * proximity). The payload is {"lat": <deg>, "lon": <deg>} or empty to opt out.
 * STORED LOCAL-ONLY and NEVER advertised — it feeds only the pairwise, encrypted
 * distance-band probe with CONNECTED peers (it is never read by any query
 * handler). Forwarded only to the identity process. Eleventh verb on the
 * app→AT allowlist. */
#define AT_APP_SET_EXACT_POSITION "app_set_exact_position"

/* App→AT: run a private-proximity probe against a CONNECTED peer (Phase 2). The
 * payload is {"peer": "<uuid_str>"}; identity derives multi-resolution grid tags
 * keyed by the pairwise box secret and exchanges them so both sides learn only a
 * coarse distance BAND (near/mid/far), never coordinates. Forwarded only to the
 * identity process. Twelfth verb on the app→AT allowlist. */
#define AT_APP_REQUEST_PROXIMITY "app_request_proximity"

/* App→AT: publish (or re-publish) THIS node's OWN business page (Phase 3 P3.2).
 * The payload is {"polity": "<did>", "bundle": "<opaque ethne json>", "seq": <int>};
 * identity signs the canonical ad with this node's Ed25519 key, marks it as the
 * business's own (satisfaction AT_BUSINESS_SAT_SELF), group-encrypts it and
 * multicasts it. The bundle is opaque to the core — it is the app that proves
 * polity-root → envoy → page. Forwarded only to the identity process.
 * Thirteenth verb on the app→AT allowlist. */
#define AT_APP_ADVERTISE_BUSINESS "app_advertise_business"

/* App→AT: declare, update or clear THIS node's CUSTOMER edge to a business
 * (Phase 3 P3.2). The payload is {"polity": "<did>", "satisfaction": <0..4>,
 * "bundle": "<opaque ethne json>", "seq": <int>}, or {"polity": "<did>",
 * "satisfaction": -1} to clear it. A customer edge is what authorizes this node
 * to CARRY the page: on set, identity caches the bundle and advertises it in the
 * FIRST PERSON (signed by us, with our satisfaction); on clear, this node simply
 * goes quiet about that business — an unhappy customer publishes nothing
 * negative, so silence is the only negative signal. Forwarded only to the
 * identity process. Fourteenth verb on the app→AT allowlist. */
#define AT_APP_SET_CUSTOMER "app_set_customer"

/* App→AT: ask named peers to co-sign one staff-roll or guardianship record
 * (Phase 3 P3.3). The payload is {"peers": ["<uuid_str>", …], "record":
 * "membership"|"guardian", "op": "<act>", "polity": "<did>", "cid": "<b3:hex>",
 * "bytes": "<canonical cbor as hex>"}; identity sends each named peer a directed
 * ENCRYPTED peer_cosign_request. The KEYS NEVER TRAVEL — the record does, and
 * each signer signs it where their key already lives.
 *
 * The core carries the bytes and verifies nothing about them: it holds no Ethne,
 * just as it holds no verifier for a page bundle. It does bound and shape-check
 * the ask, and it deliberately carries NO description — what the record commits
 * to is derived on the signer's own node from these bytes, so the asking node
 * cannot choose both what you sign and what you are told you are signing.
 * Forwarded only to the identity process. Fifteenth verb on the app→AT
 * allowlist. */
#define AT_APP_REQUEST_COSIGN "app_request_cosign"

/* App→AT: return this node's detached signature over an exchange a peer is
 * authoring (Phase 3 P3.3). The payload is {"peer": "<uuid_str>", "cid":
 * "<b3:hex>", "signer": "<did:key>", "sig": "<hex>"}; identity sends the
 * requester a directed ENCRYPTED peer_cosign_sig. The signature is checked
 * against the payload by the ASSEMBLING node, which is the only one holding it.
 * Forwarded only to the identity process. Sixteenth verb on the app→AT
 * allowlist. */
#define AT_APP_RETURN_COSIGN "app_return_cosign"

/* App→AT: publish a business POST — the polity speaking (Phase 3 P3.4). The
 * payload is {"polity": "<did>", "bundle": "<opaque ethne {post,delegation}>",
 * "seq": <int>}; identity signs the canonical post with this node's Ed25519
 * key, group-encrypts it and multicasts it, and inbound copies are relayed a
 * bounded number of hops.
 *
 * The bundle is opaque to the core, exactly as a page bundle is: the ENVOY
 * signature inside it is what makes these the business's words, and only the
 * app can check it. Being on the roll — or running this verb at all — confers
 * nothing. Forwarded only to the identity process. Seventeenth verb on the
 * app→AT allowlist. */
#define AT_APP_PUBLISH_BUSINESS_POST "app_publish_business_post"
#endif /* AT_SOCIAL_ENABLED */

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
    /* WHICH socket file this queue actually bound, so that closing it can
     * remove ITS OWN entry and no one else's. messaging_init unlinks before it
     * binds — that is how a queue survives the crash of whoever held the name
     * last — but it also means a LIVE holder can have the name taken out from
     * under it. When that holder then closed, the old unconditional
     * unlink(key) deleted the path the NEW owner was listening on: the new
     * process kept polling a socket with no name while every sender got
     * ENOENT, with nothing bound anywhere. Zero when the post-bind stat
     * failed, in which case close falls back to the unconditional unlink. */
    dev_t bound_dev;
    ino_t bound_ino;
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
