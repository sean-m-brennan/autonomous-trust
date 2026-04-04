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

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
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

#define MAJORITY(n) (((n) / 2) + 1)

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
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    array_t histories;
    map_t peer_potentials;
    map_t vote_collection;
    bool choosing_group;
    pthread_mutex_t lock;
    bool initialized;
} id_state;

static void _ensure_id_init(void)
{
    if (!id_state.initialized)
    {
        array_init(&id_state.histories);
        map_init(&id_state.peer_potentials);
        map_init(&id_state.vote_collection);
        id_state.choosing_group = false;
        pthread_mutex_init(&id_state.lock, NULL);
        id_state.initialized = true;
    }
}

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
 * Helper: _add_peer
 * Adds a new peer to the process's peer list and broadcasts to local processes.
 ****************************/

static int _add_peer(process_t *proc, directory_t *queues, const public_identity_t *new_peer)
{
    if (proc->protocol.num_peers >= MAX_PEERS)
        return -1;
    memcpy(&((process_t *)proc)->protocol.peers[proc->protocol.num_peers],
           new_peer, sizeof(public_identity_t));
    ((process_t *)proc)->protocol.num_peers++;
    generic_msg_t peer_msg = {0};
    peer_msg.type = PEER;
    memcpy(&peer_msg.info.peer, new_peer, sizeof(public_identity_t));
    _remember_activity(proc, queues, &peer_msg);
    return 0;
}

/****************************
 * Helper: _peer_accepted
 * Sends ID_CONFIRM to existing group members and ID_ACCEPT to the new peer,
 * then adds the peer to our list.
 ****************************/

static int _peer_accepted(process_t *proc, directory_t *queues, const public_identity_t *new_peer)
{
    /* Send ID_CONFIRM to existing group members with new_peer identity in JSON payload */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t confirm = {0};
        confirm.type = NET_MESSAGE;
        strncpy(confirm.info.net_msg.process, "identity", PROC_NAME_LEN);
        confirm.info.net_msg.function = (char *)ID_CONFIRM;
        confirm.info.net_msg.encrypt = true;
        memcpy(&confirm.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        json_t *peer_json = json_object();
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(new_peer->uuid, uuid_str);
        json_object_set_new(peer_json, "uuid", json_string(uuid_str));
        json_object_set_new(peer_json, "fullname", json_string(new_peer->fullname));
        net_msg_pack_json(&confirm.info.net_msg, peer_json);
        json_decref(peer_json);
        messaging_send("network", NET_MESSAGE, &confirm, false);
    }
    /* Send ID_ACCEPT to the new peer */
    generic_msg_t accept = {0};
    accept.type = NET_MESSAGE;
    strncpy(accept.info.net_msg.process, "identity", PROC_NAME_LEN);
    accept.info.net_msg.function = (char *)ID_ACCEPT;
    accept.info.net_msg.encrypt = false;
    memcpy(&accept.info.net_msg.to_whom, new_peer, sizeof(public_identity_t));
    messaging_send("network", NET_MESSAGE, &accept, false);
    return _add_peer(proc, queues, new_peer);
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

    /* Check if already a peer.  If so, re-send access_granted in case the
     * peer restarted and lost its in-memory peer list (it still holds the
     * same identity/keys, but needs us to re-acknowledge it). */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, nmsg->from_whom.uuid) == 0)
        {
            log_info(proc->logger, "Identity: peer %s already known, re-sending access_granted\n",
                     nmsg->from_whom.fullname);
            generic_msg_t accept = {0};
            accept.type = NET_MESSAGE;
            strncpy(accept.info.net_msg.process, "identity", PROC_NAME_LEN);
            accept.info.net_msg.function = (char *)ID_ACCEPT;
            accept.info.net_msg.encrypt = false;
            memcpy(&accept.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
            messaging_send("network", NET_MESSAGE, &accept, false);
            return true;
        }
    }

    /* Bootstrap: auto-accept when no existing peers (no one to vote) */
    if (proc->protocol.num_peers == 0)
    {
        log_info(proc->logger, "Identity: bootstrap — auto-accepting first peer %s\n",
                 nmsg->from_whom.fullname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom);
        return true;
    }

    /* Store proposed peer in potentials and self-vote before sending proposals */
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, uuid_str);

    pthread_mutex_lock(&id_state.lock);
    public_identity_t *potential = smrt_create(sizeof(public_identity_t));
    if (potential != NULL)
    {
        memcpy(potential, &nmsg->from_whom, sizeof(public_identity_t));
        data_t *pot_dat = object_ptr_data(potential, sizeof(public_identity_t));
        map_set(&id_state.peer_potentials, uuid_str, pot_dat);
    }
    /* Proposer self-vote: count as 1 */
    data_t *self_vote = integer_data(1);
    map_set(&id_state.vote_collection, uuid_str, self_vote);
    pthread_mutex_unlock(&id_state.lock);

    /* Propose this peer to existing group members for voting.
     * Carry proposed peer identity in JSON payload (not from_whom)
     * because encrypted messages overwrite from_whom with the sender. */
    json_t *proposal_json = json_object();
    json_object_set_new(proposal_json, "uuid", json_string(uuid_str));
    json_object_set_new(proposal_json, "fullname", json_string(nmsg->from_whom.fullname));
    json_object_set_new(proposal_json, "address", json_string(nmsg->from_whom.address));

    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t propose_msg = {0};
        propose_msg.type = NET_MESSAGE;
        strncpy(propose_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
        propose_msg.info.net_msg.function = (char *)ID_PROPOSE;
        propose_msg.info.net_msg.encrypt = true;
        memcpy(&propose_msg.info.net_msg.to_whom, &proc->protocol.peers[i],
               sizeof(public_identity_t));
        net_msg_pack_json(&propose_msg.info.net_msg, proposal_json);
        messaging_send("network", NET_MESSAGE, &propose_msg, false);
    }
    json_decref(proposal_json);

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

    /* Check if already a peer (bootstrap auto-accept may have already added them) */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, nmsg->from_whom.uuid) == 0)
        {
            log_debug(proc->logger, "Identity: peer already known, skipping duplicate add\n");
            return true;
        }
    }

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
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received history from %s\n",
             nmsg->from_whom.fullname);

    /* Unpack JSON payload and store for group selection */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_receive_history: no JSON payload\n");
        return true;
    }

    pthread_mutex_lock(&id_state.lock);
    /* Store the history JSON blob in the histories array for later processing */
    data_t *hist_dat = object_ptr_data(payload, sizeof(json_t));
    array_append(&id_state.histories, hist_dat);
    pthread_mutex_unlock(&id_state.lock);

    log_debug(proc->logger, "Identity: stored history from %s\n", nmsg->from_whom.fullname);
    return true;
}

/****************************
 * Handler: handle_vote_on_peer (propose_peer)
 * Phase 3 only. Receives a peer proposal for voting.
 ****************************/

static bool handle_vote_on_peer(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;

    /* Extract proposed peer identity from JSON payload (not from_whom,
     * which gets overwritten by decryption with the sender's identity) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_vote_on_peer: no JSON payload\n");
        return true;
    }

    const char *proposed_uuid_raw = json_string_value(json_object_get(payload, "uuid"));
    if (proposed_uuid_raw == NULL)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_vote_on_peer: missing uuid\n");
        return true;
    }

    char proposed_uuid[UUID_STRING_LEN + 1];
    strncpy(proposed_uuid, proposed_uuid_raw, UUID_STRING_LEN);
    proposed_uuid[UUID_STRING_LEN] = '\0';
    json_decref(payload);

    log_info(proc->logger, "Identity: received peer proposal for %s\n", proposed_uuid);

    /* Pack approval vote */
    json_t *vote_json = json_object();
    json_object_set_new(vote_json, "uuid", json_string(proposed_uuid));
    json_object_set_new(vote_json, "approved", json_true());

    /* Send vote back to the proposer (from_whom = sender after decryption) */
    generic_msg_t vote_msg = {0};
    vote_msg.type = NET_MESSAGE;
    strncpy(vote_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    vote_msg.info.net_msg.function = (char *)ID_VOTE;
    memcpy(&vote_msg.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    vote_msg.info.net_msg.encrypt = true;
    net_msg_pack_json(&vote_msg.info.net_msg, vote_json);
    json_decref(vote_json);

    messaging_send("network", NET_MESSAGE, &vote_msg, false);

    log_debug(proc->logger, "Identity: sent approval vote for %s\n", proposed_uuid);
    return true;
}

/****************************
 * Handler: count_vote (vote_on_peer)
 * Phase 3 only. Receives and counts votes on proposed peers.
 ****************************/

static bool handle_count_vote(process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received vote from %s\n",
              nmsg->from_whom.fullname);

    /* Unpack JSON payload to get the proposed peer UUID and approval flag */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_count_vote: no JSON payload\n");
        return true;
    }

    json_t *j_uuid     = json_object_get(payload, "uuid");
    json_t *j_approved = json_object_get(payload, "approved");

    if (!j_uuid || !j_approved)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_count_vote: missing JSON fields\n");
        return true;
    }

    const char *peer_uuid_raw = json_string_value(j_uuid);
    bool approved = json_is_true(j_approved);

    if (!approved || peer_uuid_raw == NULL)
    {
        json_decref(payload);
        log_debug(proc->logger, "Identity: vote not approved, skipping\n");
        return true;
    }

    /* Copy UUID before freeing JSON payload */
    char uuid_key[UUID_STRING_LEN + 2];
    strncpy(uuid_key, peer_uuid_raw, sizeof(uuid_key) - 1);
    uuid_key[sizeof(uuid_key) - 1] = '\0';
    json_decref(payload);

    data_t *count_dat = NULL;
    int count = 0;
    if (map_get(&id_state.vote_collection, uuid_key, &count_dat) == 0)
        data_integer(count_dat, &count);
    count += 1;
    data_t *new_count_dat = integer_data(count);
    map_set(&id_state.vote_collection, uuid_key, new_count_dat);

    size_t num_peers = proc->protocol.num_peers;

    pthread_mutex_unlock(&id_state.lock);

    log_debug(proc->logger, "Identity: vote count for %s: %d (need %d)\n",
              uuid_key, count, MAJORITY(num_peers));

    /* If majority reached, accept the peer */
    if (count >= MAJORITY(num_peers))
    {
        /* Find the proposed peer in peer_potentials */
        pthread_mutex_lock(&id_state.lock);
        data_t *peer_dat = NULL;
        map_get(&id_state.peer_potentials, uuid_key, &peer_dat);
        public_identity_t *new_peer = NULL;
        if (peer_dat != NULL)
            data_object_ptr(peer_dat, (void **)&new_peer);
        pthread_mutex_unlock(&id_state.lock);

        if (new_peer != NULL)
        {
            log_info(proc->logger, "Identity: majority vote reached for %s, accepting peer\n",
                     uuid_key);
            _peer_accepted(proc, queues, new_peer);
        }
        else
        {
            log_warn(proc->logger, "Identity: majority reached but peer %s not in potentials\n",
                     uuid_key);
        }
    }

    return true;
}

/****************************
 * Handler: handle_confirm_peer (peer_accepted)
 * Phase 3 only. Receives confirmation that a peer was accepted.
 ****************************/

static bool handle_confirm_peer(process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: peer acceptance confirmed from %s\n",
             nmsg->from_whom.fullname);

    /* Unpack peer identity from JSON payload (uuid + fullname) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_confirm_peer: no JSON payload\n");
        return true;
    }

    json_t *j_uuid     = json_object_get(payload, "uuid");
    json_t *j_fullname = json_object_get(payload, "fullname");

    if (!j_uuid || !j_fullname)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_confirm_peer: missing JSON fields\n");
        return true;
    }

    const char *uuid_str  = json_string_value(j_uuid);
    const char *fullname  = json_string_value(j_fullname);

    /* Reconstruct public_identity_t from JSON fields */
    public_identity_t new_peer;
    memset(&new_peer, 0, sizeof(public_identity_t));
    if (uuid_str != NULL)
        uuid_parse(uuid_str, new_peer.uuid);
    if (fullname != NULL)
        strncpy(new_peer.fullname, fullname, NAME_LEN);

    json_decref(payload);

    log_info(proc->logger, "Identity: confirmed peer %s (%s)\n", fullname, uuid_str);
    _add_peer(proc, queues, &new_peer);

    return true;
}

/****************************
 * Handler: handle_history_diff (history_diff)
 * Phase 3 only. Receives and logs history diffs.
 ****************************/

static bool handle_history_diff(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received history diff from %s\n",
              nmsg->from_whom.fullname);

    /* Unpack JSON step list from payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_history_diff: no JSON payload\n");
        return true;
    }

    /* Log what was received — DAG merge requires DAG infrastructure */
    size_t step_count = 0;
    if (json_is_array(payload))
        step_count = json_array_size(payload);
    else if (json_is_object(payload))
        step_count = 1;

    log_info(proc->logger,
             "Identity: received %zu history diff step(s) from %s (DAG merge pending infrastructure)\n",
             step_count, nmsg->from_whom.fullname);

    json_decref(payload);
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

    /* Unpack group JSON from payload */
    json_t *payload = NULL;
    bool updated = false;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL)
    {
        /* Extract address count from incoming payload to compare with current group */
        json_t *j_address = json_object_get(payload, "address");
        const char *incoming_addr = j_address ? json_string_value(j_address) : NULL;

        /* Compare: if incoming has a non-empty address and current group address differs,
         * treat as newer/replacement and update */
        if (incoming_addr != NULL && incoming_addr[0] != '\0' &&
            strcmp(incoming_addr, proc->protocol.group.address) != 0)
        {
            /* Update group address from incoming payload */
            strncpy(((process_t *)proc)->protocol.group.address, incoming_addr, ADDR_LEN);
            updated = true;
            log_info(proc->logger, "Identity: group address updated to %s\n", incoming_addr);
        }

        json_decref(payload);
    }

    if (!updated)
        log_debug(proc->logger, "Identity: group update: no change needed\n");

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
    int timeout_ms = 10000;
    int elapsed = 0;
    while (elapsed < timeout_ms)
    {
        generic_msg_t buf = {0};
        int err = messaging_recv(&buf);
        if (err == 0)
            run_message_handlers((process_t *)proc, queues, buf.type, &buf);
        if (proc->protocol.peer_capabilities != NULL)
            break;
        usleep(100000);
        elapsed += 100;
    }
    return 0;
}

static int _build_announcement(const process_t *proc, generic_msg_t *buf)
{
    memset(buf, 0, sizeof(generic_msg_t));
    buf->type = NET_MESSAGE;
    strncpy(buf->info.net_msg.process, "identity", PROC_NAME_LEN);
    buf->info.net_msg.function = (char *)ID_ANNOUNCE;
    buf->info.net_msg.encrypt = false; /* Broadcast is unencrypted */

    /* Get own identity from config */
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0)
    {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 && id_cfg->data_struct != NULL)
        {
            public_identity_t *pub = NULL;
            identity_publish((const identity_t *)id_cfg->data_struct, &pub);
            if (pub != NULL)
            {
                memcpy(&buf->info.net_msg.from_whom, pub, sizeof(public_identity_t));
                smrt_deref(pub);
            }
        }
    }

    /* Set broadcast recipient (to_whom empty = broadcast) */
    strncpy(buf->info.net_msg.return_to, "identity", PROC_NAME_LEN);
    return 0;
}

static int _announce_identity(const process_t *proc, directory_t *queues)
{
    data_t net = STRING_DATA("network");
    if (!array_contains(queues, &net))
        return EXCEPTION(EID_NOQ);

    generic_msg_t buf = {0};
    _build_announcement(proc, &buf);

    /* Retry until network process IPC socket is ready */
    int ret = -1;
    for (int attempt = 0; attempt < 20; attempt++)
    {
        ret = messaging_send("network", NET_MESSAGE, &buf, false);
        if (ret == 0)
            break;
        log_debug(proc->logger, "Identity: network not ready, retrying (%d)...\n", attempt);
        usleep(100000); /* 100ms */
    }

    if (ret != 0)
    {
        log_error(proc->logger, "Identity: failed to send announcement to network\n");
        return ret;
    }

    log_info(proc->logger, "Identity: announced self to network\n");
    return 0;
}

/****************************
 * Identity process main entry
 ****************************/

int identity_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_id_init();

    /* Daemonize first so messaging is available for pre-loop activity */
    process_ctx_t pctx = {0};
    int err = process_setup(proc, signal, logger, &pctx);
    if (err != 0)
        return err;

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

    /* Identity-specific loop: re-announce periodically until peers found */
    generic_msg_t announce_buf = {0};
    _build_announcement(proc, &announce_buf);
    int announce_interval = 10; /* re-announce every 10 cadence cycles (~5s) */
    int cycle = 0;

    while (keep_running(proc, &pctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        /* Periodic re-announcement until we have peers */
        if (proc->protocol.num_peers == 0 && ++cycle >= announce_interval)
        {
            cycle = 0;
            messaging_send("network", NET_MESSAGE, &announce_buf, false);
            log_debug(logger, "Identity: re-announcing (no peers yet)\n");
        }

        generic_msg_t buf = {0};
        err = messaging_recv(&buf);
        if (err == -1 || err == ENOMSG)
            continue;
        if (!run_message_handlers(proc, queues, buf.type, &buf))
        {
            log_debug(logger, "Identity: unhandled message type %ld\n", buf.type);
        }
    }

    if (pctx.fd1 > 0)
        close(pctx.fd1);
    if (pctx.fd2 > 0)
        close(pctx.fd2);
    return 0;
}
DECLARE_PROCESS(identity, id_proc, identity_run);
