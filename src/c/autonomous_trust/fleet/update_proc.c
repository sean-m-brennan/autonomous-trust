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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "processes/processes.h"
#include "fleet/update_proc.h"
#include "fleet/artifact_proc.h"
#include "fleet/artifact_store.h"
#include "config/configuration.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"

#define EUPDATE 280
DEFINE_ERROR(EUPDATE, "Update process error");


/* ------------------------------------------------------------------ */
/* Module state                                                        */
/* ------------------------------------------------------------------ */

static char update_data_dir[256] = {0};


/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/**
 * copy_file - stream copy src to dst via 4096-byte buffer.
 * Sets dst to mode 0755 after copy.  Returns 0 on success, -1 on error.
 */
static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in)
        return -1;

    FILE *out = fopen(dst, "wb");
    if (!out)
    {
        fclose(in);
        return -1;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (fwrite(buf, 1, n, out) != n)
        {
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    int read_err = ferror(in);
    fclose(in);
    fclose(out);

    if (read_err)
        return -1;

    chmod(dst, 0755);
    return 0;
}

/**
 * ensure_staging_dir - create <update_data_dir>/update/ if it does not exist.
 */
static int ensure_staging_dir(void)
{
    char dir[256];
    if (update_staging_dir(update_data_dir, dir, sizeof(dir)) != 0)
        return -1;

    struct stat st;
    if (stat(dir, &st) != 0)
    {
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            return -1;
    }
    return 0;
}

/**
 * broadcast_status - send update status to all known peers.
 */
static void broadcast_status(const process_t *proc,
                             const char *hash_hex,
                             const char *version,
                             const char *status,
                             const char *detail)
{
    json_t *base = json_object();
    json_object_set_new(base, "hash", json_string(hash_hex));
    json_object_set_new(base, "version", json_string(version));
    json_object_set_new(base, "status", json_string(status));
    json_object_set_new(base, "detail", json_string(detail));

    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        json_t *copy = json_deep_copy(base);

        generic_msg_t out = {0};
        out.type = NET_MESSAGE;
        net_msg_t *nmsg = &out.info.net_msg;
        strncpy(nmsg->process, "update", PROC_NAME_LEN);
        nmsg->function = (char *)UPDATE_PROTO_STATUS;
        nmsg->encrypt = true;
        memcpy(&nmsg->to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(nmsg->return_to, "update", PROC_NAME_LEN);

        if (net_msg_pack_json(nmsg, copy) != 0)
        {
            json_decref(copy);
            continue;
        }
        json_decref(copy);
        messaging_send("network", NET_MESSAGE, &out, false);
    }
    json_decref(base);
}

/**
 * stage_and_apply - stage artifact, back up current binary, swap, restart.
 *
 * On success this function does not return (execl replaces the process).
 * Returns -1 on error.
 */
static int stage_and_apply(const process_t *proc,
                           const char *artifact_path,
                           const char *hash_hex,
                           const char *version)
{
    if (ensure_staging_dir() != 0)
        return -1;

    char staging_path[256];
    char backup_path[256];
    char binary_path[256];

    if (update_staging_path(update_data_dir, staging_path, sizeof(staging_path)) != 0)
        return -1;
    if (update_backup_path(update_data_dir, backup_path, sizeof(backup_path)) != 0)
        return -1;
    if (update_current_binary_path(binary_path, sizeof(binary_path)) != 0)
        return -1;

    /* Copy artifact to staging location */
    if (copy_file(artifact_path, staging_path) != 0)
        return -1;

    /* Back up the current binary */
    if (copy_file(binary_path, backup_path) != 0)
    {
        unlink(staging_path);
        return -1;
    }

    /* Point of no return: atomic rename of staged binary over current */
    if (rename(staging_path, binary_path) != 0)
    {
        unlink(staging_path);
        return -1;
    }

    /* Write persistent state so post-restart health check knows what happened */
    update_state_t state;
    memset(&state, 0, sizeof(state));
    strncpy(state.state, "APPLYING", sizeof(state.state) - 1);
    strncpy(state.version, version, sizeof(state.version) - 1);
    strncpy(state.hash_hex, hash_hex, sizeof(state.hash_hex) - 1);
    strncpy(state.backup_path, backup_path, sizeof(state.backup_path) - 1);
    strncpy(state.binary_path, binary_path, sizeof(state.binary_path) - 1);
    state.timestamp = (long)time(NULL);
    state.attempt = 1;

    if (update_state_write(update_data_dir, &state) != 0)
    {
        /* Undo the binary swap */
        rename(backup_path, binary_path);
        return -1;
    }

    /* Restart the service — replaces this process image */
    execl("/usr/bin/sudo", "sudo", "systemctl", "restart", "autonomous-trust", NULL);

    /* If execl returns, something went wrong */
    return -1;
}

/**
 * rollback - restore backup binary and restart.
 */
static void rollback(const process_t *proc, update_state_t *state)
{
    copy_file(state->backup_path, state->binary_path);

    strncpy(state->state, "ROLLBACK", sizeof(state->state) - 1);
    state->state[sizeof(state->state) - 1] = '\0';
    state->attempt++;

    update_state_write(update_data_dir, state);

    broadcast_status(proc, state->hash_hex, state->version, "failed",
                     "health check failed, rolling back");

    execl("/usr/bin/sudo", "sudo", "systemctl", "restart", "autonomous-trust", NULL);
}

/**
 * run_health_check - post-restart verification of binary health.
 * On success: cleans up state file and backup, broadcasts success.
 * On failure: triggers rollback.
 */
static void run_health_check(const process_t *proc, update_state_t *state)
{
    char cfg_dir[CFG_PATH_LEN];
    if (get_cfg_dir(cfg_dir) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root != NULL)
            snprintf(cfg_dir, sizeof(cfg_dir), "%s/etc/at", root);
        else
            snprintf(cfg_dir, sizeof(cfg_dir), "/tmp/at_cfg");
    }

    /* Basic self-tests */
    if (!selftest_identity(cfg_dir) ||
        !selftest_crypto() ||
        !selftest_config(cfg_dir))
    {
        rollback(proc, state);
        return;  /* only reached if execl fails */
    }

    /* Peer handshake test: try to reach at least one peer */
    bool handshake_ok = false;
    if (proc->protocol.num_peers == 0)
    {
        handshake_ok = true;  /* no peers to test — consider OK */
    }
    else
    {
        size_t max = proc->protocol.num_peers;
        if (max > UPDATE_HANDSHAKE_MAX_PEERS)
            max = UPDATE_HANDSHAKE_MAX_PEERS;

        for (size_t i = 0; i < max; i++)
        {
            json_t *ping = json_object();
            json_object_set_new(ping, "type", json_string("health_check"));

            generic_msg_t out = {0};
            out.type = NET_MESSAGE;
            net_msg_t *nmsg = &out.info.net_msg;
            strncpy(nmsg->process, "update", PROC_NAME_LEN);
            nmsg->function = (char *)UPDATE_PROTO_STATUS;
            nmsg->encrypt = true;
            memcpy(&nmsg->to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            strncpy(nmsg->return_to, "update", PROC_NAME_LEN);

            if (net_msg_pack_json(nmsg, ping) == 0)
            {
                if (messaging_send("network", NET_MESSAGE, &out, false) == 0)
                {
                    handshake_ok = true;
                    json_decref(ping);
                    break;
                }
            }
            json_decref(ping);
        }
    }

    if (!handshake_ok)
    {
        rollback(proc, state);
        return;  /* only reached if execl fails */
    }

    /* All checks passed */
    update_state_delete(update_data_dir);
    unlink(state->backup_path);

    broadcast_status(proc, state->hash_hex, state->version, "success",
                     "update applied and verified");
}


/* ------------------------------------------------------------------ */
/* Protocol handlers                                                   */
/* ------------------------------------------------------------------ */

/**
 * handle_artifact_ready - an artifact download completed and is ready for install.
 */
static bool handle_artifact_ready(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Update: handle_artifact_ready: failed to unpack JSON\n");
        return false;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    json_t *j_path = json_object_get(payload, "path");
    json_t *j_version = json_object_get(payload, "version");

    if (!j_hash || !j_path || !j_version)
    {
        json_decref(payload);
        log_error(proc->logger, "Update: handle_artifact_ready: missing fields\n");
        return false;
    }

    const char *hash_hex = json_string_value(j_hash);
    const char *artifact_path = json_string_value(j_path);
    const char *version = json_string_value(j_version);

    log_info(proc->logger, "Update: artifact ready hash=%s version=%s path=%s\n",
             hash_hex, version, artifact_path);

    int rc = stage_and_apply(proc, artifact_path, hash_hex, version);

    /* If we get here, stage_and_apply failed (execl didn't happen) */
    if (rc != 0)
    {
        log_error(proc->logger, "Update: stage_and_apply failed for %s\n", hash_hex);
        broadcast_status(proc, hash_hex, version, "failed",
                         "staging or binary swap failed");
    }

    json_decref(payload);
    return (rc == 0);
}

/**
 * handle_update_status - receive a peer's update status broadcast (informational).
 */
static bool handle_update_status(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_info(proc->logger, "Update: status from %s (no payload)\n",
                 nmsg->from_whom.fullname);
        return true;
    }

    const char *status = json_string_value(json_object_get(payload, "status"));
    const char *version = json_string_value(json_object_get(payload, "version"));
    const char *detail = json_string_value(json_object_get(payload, "detail"));

    log_info(proc->logger, "Update: peer %s status=%s version=%s detail=%s\n",
             nmsg->from_whom.fullname,
             status  ? status  : "?",
             version ? version : "?",
             detail  ? detail  : "?");

    json_decref(payload);
    return true;
}


/* ------------------------------------------------------------------ */
/* Process entry point                                                 */
/* ------------------------------------------------------------------ */

int update_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    /* Determine data directory */
    char data_dir[CFG_PATH_LEN];
    if (get_data_dir(data_dir) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root != NULL)
            snprintf(data_dir, sizeof(data_dir), "%s/var/at", root);
        else
            snprintf(data_dir, sizeof(data_dir), "/tmp/at_update");
    }
    strncpy(update_data_dir, data_dir, sizeof(update_data_dir) - 1);

    /* Check for pending update state file */
    if (update_state_exists(update_data_dir))
    {
        update_state_t state;
        if (update_state_read(update_data_dir, &state) == 0)
        {
            if (update_should_abort(&state))
            {
                /* Loop prevention: rollback already happened */
                log_info(logger, "Update: rollback completed (attempt %d), returning to IDLE\n",
                         state.attempt);
                update_state_delete(update_data_dir);
            }
            else if (strcmp(state.state, "APPLYING") == 0 ||
                     strcmp(state.state, "ROLLBACK") == 0)
            {
                run_health_check(proc, &state);
            }
            else
            {
                log_info(logger, "Update: cleaning up unexpected state '%s'\n", state.state);
                update_state_delete(update_data_dir);
            }
        }
    }

    /* Register handlers */
    process_register_handler(proc, (char *)ARTIFACT_PROTO_READY,
                             (handler_ptr_t)handle_artifact_ready);
    process_register_handler(proc, (char *)UPDATE_PROTO_STATUS,
                             (handler_ptr_t)handle_update_status);

    proc->protocol.phase = 1;
    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(update, update_proc, update_run);
