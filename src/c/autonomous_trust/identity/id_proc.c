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

#include <stdarg.h>
#include <string.h>
#include <pthread.h>

#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "structures/data_priv.h"
#include "network/net_message.h"
#include "peers.h"
#include "id_proc_priv.h"

DEFINE_ERROR(EID_NOQ, "Required process queue missing");

/****************************
 * Protocol function names (must match Python IdentityProtocol)
 ****************************/

static const char *ID_ANNOUNCE    = "request_access";
static const char *ID_ACCEPT      = "access_granted";
static const char *ID_HISTORY     = "full_history";
static const char *ID_DIFF        = "history_diff";
static const char *ID_PROPOSE     = "propose_peer";
static const char *ID_VOTE        = "vote_on_peer";
static const char *ID_CONFIRM     = "peer_accepted";
static const char *ID_UPDATE      = "group_key_update";

/****************************
 * Internal helpers
 ****************************/

static int _remember_activity(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    /* Update proc configs with latest data; broadcast to all other processes */
    size_t qsize = array_size(queues);
    for (size_t i = 0; i < qsize; i++)
    {
        data_t *name_val = NULL;
        if (array_get(queues, (int)i, &name_val) != 0)
            continue;
        char *qname = NULL;
        if (data_string_ptr(name_val, &qname) != 0)
            continue;
        if (strcmp(qname, proc->name) == 0)
            continue;
        messaging_send(qname, msg->type, msg, false);
    }
    return 0;
}

/****************************
 * Handler: welcoming_committee (request_access)
 * Phase 3 only. Receives broadcast from new peer wanting to join.
 ****************************/

static bool handle_welcoming_committee(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received access request from %s\n",
             nmsg->from_whom.fullname);

    /* Validate the new identity */
    if (nmsg->from_whom.fullname[0] == '\0')
    {
        log_warn(proc->logger, "Identity: rejecting empty identity\n");
        return true;
    }

    /* Check if already a peer */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, nmsg->from_whom.uuid) == 0)
        {
            log_debug(proc->logger, "Identity: peer %s already known\n",
                      nmsg->from_whom.fullname);
            return true;
        }
    }

    /* Propose this peer to existing group members for voting */
    generic_msg_t propose_msg = {0};
    propose_msg.type = NET_MESSAGE;
    strncpy(propose_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    propose_msg.info.net_msg.function = (char *)ID_PROPOSE;
    /* Attach the new peer's identity as data */
    memcpy(&propose_msg.info.net_msg.from_whom, &nmsg->from_whom, sizeof(public_identity_t));
    propose_msg.info.net_msg.encrypt = true;

    /* Send proposal to each existing peer via network */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        memcpy(&propose_msg.info.net_msg.to_whom, &proc->protocol.peers[i],
               sizeof(public_identity_t));
        messaging_send("network", NET_MESSAGE, &propose_msg, false);
    }

    log_info(proc->logger, "Identity: proposed peer %s for voting\n",
             nmsg->from_whom.fullname);
    return true;
}

/****************************
 * Handler: handle_acceptance (access_granted)
 * Phase 2+. Receives acceptance from an existing peer.
 ****************************/

static bool handle_acceptance(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase < 2)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: access granted by %s\n",
             nmsg->from_whom.fullname);

    /* Add the accepting peer to our peer list */
    if (proc->protocol.num_peers < MAX_PEERS)
    {
        memcpy(&((process_t *)proc)->protocol.peers[proc->protocol.num_peers],
               &nmsg->from_whom, sizeof(public_identity_t));
        ((process_t *)proc)->protocol.num_peers++;

        /* Broadcast peer update to all local processes */
        generic_msg_t peer_msg = {0};
        peer_msg.type = PEER;
        memcpy(&peer_msg.info.peer, &nmsg->from_whom, sizeof(public_identity_t));
        _remember_activity(proc, queues, &peer_msg);
    }

    return true;
}

/****************************
 * Handler: receive_history (full_history)
 * Receives full history + group from established peer.
 ****************************/

static bool handle_receive_history(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received history from %s\n",
             nmsg->from_whom.fullname);

    /* Store the history data for choose_group to process */
    /* The history payload is in nmsg->obj / nmsg->len */
    /* In full implementation, this would be deserialized and stored */

    return true;
}

/****************************
 * Handler: handle_vote_on_peer (propose_peer)
 * Phase 3 only. Receives a peer proposal for voting.
 ****************************/

static bool handle_vote_on_peer(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received peer proposal from %s\n",
             nmsg->from_whom.fullname);

    /* Create signed vote proof for the proposed peer */
    /* In full implementation, uses identity_sign() to create proof */
    /* For now, auto-approve and send vote back */

    generic_msg_t vote_msg = {0};
    vote_msg.type = NET_MESSAGE;
    strncpy(vote_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    vote_msg.info.net_msg.function = (char *)ID_VOTE;
    memcpy(&vote_msg.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    vote_msg.info.net_msg.encrypt = true;
    /* Attach approval proof data */
    /* vote_msg.info.net_msg.obj = proof_data; */

    messaging_send("network", NET_MESSAGE, &vote_msg, false);

    return true;
}

/****************************
 * Handler: count_vote (vote_on_peer)
 * Phase 3 only. Receives and counts votes on proposed peers.
 ****************************/

static bool handle_count_vote(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received vote from %s\n",
              nmsg->from_whom.fullname);

    /* Verify the vote signature */
    /* In full implementation:
     * 1. Verify signature using nmsg->from_whom's public key
     * 2. Verify the agreement proof
     * 3. Record the vote in the vote collection
     * 4. If enough votes collected, trigger _peer_accepted()
     */

    return true;
}

/****************************
 * Handler: handle_confirm_peer (peer_accepted)
 * Phase 3 only. Receives confirmation that a peer was accepted.
 ****************************/

static bool handle_confirm_peer(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: peer acceptance confirmed from %s\n",
             nmsg->from_whom.fullname);

    /* Add confirmed peer to our peer list */
    /* In full implementation:
     * 1. Extract confirmed peer identity from message data
     * 2. Add to peers list
     * 3. Update peer capabilities
     * 4. Broadcast peer update to local processes
     */

    return true;
}

/****************************
 * Handler: handle_history_diff (history_diff)
 * Phase 3 only. Receives and merges history diffs.
 ****************************/

static bool handle_history_diff(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received history diff from %s\n",
              nmsg->from_whom.fullname);

    /* In full implementation:
     * 1. Deserialize step list from message data
     * 2. Call step_dag_ingest_branch() to import
     * 3. Validate the branch
     * 4. Merge into main branch
     */

    return true;
}

/****************************
 * Handler: handle_group_update (group_key_update)
 * Phase 3 only. Receives group address list updates.
 ****************************/

static bool handle_group_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received group update from %s\n",
             nmsg->from_whom.fullname);

    /* In full implementation:
     * 1. Deserialize new group data from message
     * 2. Compare with current group (check if newer)
     * 3. If newer, update self.group
     * 4. Broadcast group update to local processes
     */

    generic_msg_t group_msg = {0};
    group_msg.type = GROUP;
    memcpy(&group_msg.info.group, &proc->protocol.group, sizeof(group_t));
    _remember_activity(proc, queues, &group_msg);

    return true;
}

/****************************
 * Pre-loop: acquire capabilities and announce
 ****************************/

static int _acquire_capabilities(const process_t *proc, directory_t *queues)
{
    /* Wait for capabilities from other processes */
    /* In full implementation, this blocks until the network process
     * reports back with available capabilities */
    return 0;
}

static int _announce_identity(const process_t *proc, directory_t *queues)
{
    data_t net = STRING_DATA("network");
    if (!array_contains(queues, &net))
        return EXCEPTION(EID_NOQ);

    /* Build announcement: identity + package_hash + capabilities */
    generic_msg_t buf = {0};
    buf.type = NET_MESSAGE;
    strncpy(buf.info.net_msg.process, "identity", PROC_NAME_LEN);
    buf.info.net_msg.function = (char *)ID_ANNOUNCE;
    buf.info.net_msg.encrypt = false; /* Broadcast is unencrypted */

    /* Get own identity from config */
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0)
    {
        void *ident = NULL;
        if (data_object_ptr(id_dat, &ident) == 0)
        {
            public_identity_t *pub = NULL;
            identity_publish((const identity_t *)ident, &pub);
            if (pub != NULL)
            {
                memcpy(&buf.info.net_msg.from_whom, pub, sizeof(public_identity_t));
                smrt_deref(pub);
            }
        }
    }

    /* Set broadcast recipient */
    strncpy(buf.info.net_msg.return_to, "identity", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &buf, false);
    log_info(proc->logger, "Identity: announced self to network\n");
    return 0;
}

/****************************
 * Identity process main entry
 ****************************/

int identity_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    /* Register protocol handlers */
    process_register_handler(proc, (char *)ID_ANNOUNCE, (handler_ptr_t)handle_welcoming_committee);
    process_register_handler(proc, (char *)ID_ACCEPT,   (handler_ptr_t)handle_acceptance);
    process_register_handler(proc, (char *)ID_HISTORY,  (handler_ptr_t)handle_receive_history);
    process_register_handler(proc, (char *)ID_DIFF,     (handler_ptr_t)handle_history_diff);
    process_register_handler(proc, (char *)ID_PROPOSE,  (handler_ptr_t)handle_vote_on_peer);
    process_register_handler(proc, (char *)ID_VOTE,     (handler_ptr_t)handle_count_vote);
    process_register_handler(proc, (char *)ID_CONFIRM,  (handler_ptr_t)handle_confirm_peer);
    process_register_handler(proc, (char *)ID_UPDATE,   (handler_ptr_t)handle_group_update);

    /* Phase 0→1: Acquire capabilities */
    _acquire_capabilities(proc, queues);
    proc->protocol.phase = 1;

    /* Phase 1→2: Announce identity */
    _announce_identity(proc, queues);
    proc->protocol.phase = 2;

    /* Phase 2→3 transition happens in choose_group (async) */
    /* For now, set to phase 3 after announcement */
    proc->protocol.phase = 3;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(identity, id_proc, identity_run);
