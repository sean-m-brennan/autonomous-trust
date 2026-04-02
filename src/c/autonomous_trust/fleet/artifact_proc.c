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

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sodium.h>

#include "processes/processes.h"
#include "fleet/artifact_proc.h"
#include "fleet/artifact_store.h"
#include "structures/map.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"

#define EARTIFACT 270
DEFINE_ERROR(EARTIFACT, "Artifact transfer error");


/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    map_t active_downloads;   /* hash_hex -> download_state_t* */
    bool initialized;
    pthread_mutex_t lock;
} artifact_state;

static void _ensure_init(void)
{
    if (!artifact_state.initialized)
    {
        map_init(&artifact_state.active_downloads);
        pthread_mutex_init(&artifact_state.lock, NULL);
        artifact_state.initialized = true;
    }
}


/****************************
 * Helper: send_to_peer
 * Send a JSON message via the network process.
 ****************************/

static int send_to_peer(const process_t *proc, const char *function,
                        json_t *payload, const public_identity_t *peer)
{
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    net_msg_t *nmsg = &out.info.net_msg;
    strncpy(nmsg->process, "artifact", PROC_NAME_LEN);
    nmsg->function = (char *)function;
    memcpy(&nmsg->to_whom, peer, sizeof(public_identity_t));
    nmsg->encrypt = true;
    strncpy(nmsg->return_to, "artifact", PROC_NAME_LEN);

    if (net_msg_pack_json(nmsg, payload) != 0)
    {
        json_decref(payload);
        return -1;
    }
    json_decref(payload);
    return messaging_send("network", NET_MESSAGE, &out, false);
}


/****************************
 * Handler: handle_artifact_request
 * A peer asks us for an artifact we may have.
 ****************************/

static bool handle_artifact_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Artifact: request from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Artifact: handle_artifact_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    if (!j_hash)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: handle_artifact_request: missing hash\n");
        return false;
    }

    const char *hash_hex = json_string_value(j_hash);
    if (!hash_hex)
    {
        json_decref(payload);
        return false;
    }

    if (artifact_store_has(hash_hex))
    {
        /* Load manifest and send it back */
        artifact_manifest_t manifest;
        if (artifact_store_load_manifest(hash_hex, &manifest) != 0)
        {
            json_decref(payload);
            log_error(proc->logger, "Artifact: failed to load manifest for %s\n", hash_hex);
            return false;
        }

        json_t *resp = json_object();
        json_object_set_new(resp, "hash", json_string(hash_hex));
        json_object_set_new(resp, "total_chunks", json_integer(manifest.total_chunks));
        json_object_set_new(resp, "total_size", json_integer((json_int_t)manifest.total_size));
        json_object_set_new(resp, "chunk_size", json_integer((json_int_t)manifest.chunk_size));
        json_object_set_new(resp, "version", json_string(manifest.version));

        json_decref(payload);
        send_to_peer(proc, ARTIFACT_PROTO_MANIFEST, resp, &nmsg->from_whom);
    }
    else
    {
        log_debug(proc->logger, "Artifact: we don't have artifact %s\n", hash_hex);
        json_decref(payload);
    }

    return true;
}


/****************************
 * Handler: handle_artifact_manifest
 * We received manifest info for a requested artifact.
 ****************************/

static bool handle_artifact_manifest(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Artifact: manifest from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Artifact: handle_artifact_manifest: failed to unpack JSON\n");
        return false;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    json_t *j_total_chunks = json_object_get(payload, "total_chunks");
    json_t *j_total_size = json_object_get(payload, "total_size");
    json_t *j_chunk_size = json_object_get(payload, "chunk_size");
    json_t *j_version = json_object_get(payload, "version");

    if (!j_hash || !j_total_chunks || !j_total_size || !j_chunk_size || !j_version)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: handle_artifact_manifest: missing fields\n");
        return false;
    }

    const char *hash_hex = json_string_value(j_hash);
    int total_chunks = (int)json_integer_value(j_total_chunks);
    size_t total_size = (size_t)json_integer_value(j_total_size);
    size_t chunk_size = (size_t)json_integer_value(j_chunk_size);
    const char *version = json_string_value(j_version);

    /* Save manifest to disk */
    artifact_manifest_t manifest;
    memset(&manifest, 0, sizeof(manifest));
    strncpy(manifest.hash_hex, hash_hex, sizeof(manifest.hash_hex) - 1);
    manifest.total_chunks = total_chunks;
    manifest.total_size = total_size;
    manifest.chunk_size = chunk_size;
    strncpy(manifest.version, version, sizeof(manifest.version) - 1);

    if (artifact_store_save_manifest(&manifest) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to save manifest for %s\n", hash_hex);
        return false;
    }

    /* Decode hash_hex to binary */
    uint8_t expected_hash[UPDATE_HASH_LEN];
    size_t bin_len = 0;
    if (sodium_hex2bin(expected_hash, UPDATE_HASH_LEN,
                       hash_hex, strlen(hash_hex),
                       NULL, &bin_len, NULL) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to decode hash hex\n");
        return false;
    }

    /* Create download state */
    download_state_t *state = calloc(1, sizeof(download_state_t));
    if (!state)
    {
        json_decref(payload);
        return false;
    }

    artifact_download_state_init(state, hash_hex, total_chunks, expected_hash, version);

    /* Store in active_downloads map */
    pthread_mutex_lock(&artifact_state.lock);
    data_t *dat = object_ptr_data(state, sizeof(download_state_t));
    map_set(&artifact_state.active_downloads, (char *)hash_hex, dat);
    pthread_mutex_unlock(&artifact_state.lock);

    json_decref(payload);

    /* Request first chunk */
    json_t *req = json_object();
    json_object_set_new(req, "hash", json_string(hash_hex));
    json_object_set_new(req, "chunk_index", json_integer(0));
    send_to_peer(proc, ARTIFACT_PROTO_CHUNK_REQ, req, &nmsg->from_whom);

    return true;
}


/****************************
 * Handler: handle_chunk_request
 * A peer wants a specific chunk from us.
 ****************************/

static bool handle_chunk_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Artifact: handle_chunk_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    json_t *j_chunk_index = json_object_get(payload, "chunk_index");

    if (!j_hash || !j_chunk_index)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: handle_chunk_request: missing fields\n");
        return false;
    }

    const char *hash_hex = json_string_value(j_hash);
    int chunk_index = (int)json_integer_value(j_chunk_index);

    /* Read chunk from store */
    uint8_t chunk_buf[ARTIFACT_CHUNK_SIZE];
    size_t chunk_len = 0;
    if (artifact_store_read_chunk(hash_hex, chunk_index, chunk_buf, sizeof(chunk_buf), &chunk_len) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to read chunk %d for %s\n", chunk_index, hash_hex);
        return false;
    }

    /* Compute per-chunk blake2b hash */
    uint8_t chunk_hash[UPDATE_HASH_LEN];
    crypto_generichash_blake2b(chunk_hash, UPDATE_HASH_LEN, chunk_buf, chunk_len, NULL, 0);

    /* Hex-encode chunk data and chunk_hash */
    char data_hex[ARTIFACT_CHUNK_SIZE * 2 + 1];
    sodium_bin2hex(data_hex, sizeof(data_hex), chunk_buf, chunk_len);

    char chunk_hash_hex[UPDATE_HASH_LEN * 2 + 1];
    sodium_bin2hex(chunk_hash_hex, sizeof(chunk_hash_hex), chunk_hash, UPDATE_HASH_LEN);

    /* Build response */
    json_t *resp = json_object();
    json_object_set_new(resp, "hash", json_string(hash_hex));
    json_object_set_new(resp, "chunk_index", json_integer(chunk_index));
    json_object_set_new(resp, "data", json_string(data_hex));
    json_object_set_new(resp, "chunk_hash", json_string(chunk_hash_hex));
    json_object_set_new(resp, "data_len", json_integer((json_int_t)chunk_len));

    json_decref(payload);
    send_to_peer(proc, ARTIFACT_PROTO_CHUNK, resp, &nmsg->from_whom);

    return true;
}


/****************************
 * Handler: handle_chunk_response
 * We received a chunk for an in-progress download.
 ****************************/

static bool handle_chunk_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Artifact: handle_chunk_response: failed to unpack JSON\n");
        return false;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    json_t *j_chunk_index = json_object_get(payload, "chunk_index");
    json_t *j_data = json_object_get(payload, "data");
    json_t *j_chunk_hash = json_object_get(payload, "chunk_hash");
    json_t *j_data_len = json_object_get(payload, "data_len");

    if (!j_hash || !j_chunk_index || !j_data || !j_chunk_hash || !j_data_len)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: handle_chunk_response: missing fields\n");
        return false;
    }

    const char *hash_hex = json_string_value(j_hash);
    int chunk_index = (int)json_integer_value(j_chunk_index);
    const char *data_hex = json_string_value(j_data);
    const char *chunk_hash_hex = json_string_value(j_chunk_hash);
    size_t data_len = (size_t)json_integer_value(j_data_len);

    /* Decode hex data */
    uint8_t data_buf[ARTIFACT_CHUNK_SIZE];
    size_t bin_len = 0;
    if (sodium_hex2bin(data_buf, sizeof(data_buf),
                       data_hex, strlen(data_hex),
                       NULL, &bin_len, NULL) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to decode chunk data hex\n");
        return false;
    }

    /* Decode chunk hash */
    uint8_t chunk_hash[UPDATE_HASH_LEN];
    size_t hash_bin_len = 0;
    if (sodium_hex2bin(chunk_hash, UPDATE_HASH_LEN,
                       chunk_hash_hex, strlen(chunk_hash_hex),
                       NULL, &hash_bin_len, NULL) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to decode chunk hash hex\n");
        return false;
    }

    /* Verify per-chunk hash */
    if (artifact_verify_chunk_hash(data_buf, data_len, chunk_hash) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: chunk %d hash mismatch for %s\n", chunk_index, hash_hex);
        return false;
    }

    /* Save chunk to store */
    if (artifact_store_save_chunk(hash_hex, chunk_index, data_buf, data_len) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Artifact: failed to save chunk %d for %s\n", chunk_index, hash_hex);
        return false;
    }

    /* Update download state */
    pthread_mutex_lock(&artifact_state.lock);

    data_t *state_dat = NULL;
    download_state_t *state = NULL;
    if (map_get(&artifact_state.active_downloads, (char *)hash_hex, &state_dat) == 0 && state_dat != NULL)
    {
        ptr_t ptr = NULL;
        data_object_ptr(state_dat, &ptr);
        state = (download_state_t *)ptr;
    }

    if (!state)
    {
        pthread_mutex_unlock(&artifact_state.lock);
        json_decref(payload);
        log_error(proc->logger, "Artifact: no active download for %s\n", hash_hex);
        return false;
    }

    bool complete = artifact_download_state_record(state);

    if (complete)
    {
        /* Verify full artifact hash */
        int verify_ok = (artifact_store_verify(hash_hex, state->expected_hash) == 0);

        char version[UPDATE_VERSION_LEN + 1];
        strncpy(version, state->version, sizeof(version) - 1);
        version[sizeof(version) - 1] = '\0';

        /* Remove from active downloads and free state */
        map_remove(&artifact_state.active_downloads, (char *)hash_hex);
        free(state);

        pthread_mutex_unlock(&artifact_state.lock);
        json_decref(payload);

        /* Send ARTIFACT_PROTO_COMPLETE to source peer */
        json_t *comp = json_object();
        json_object_set_new(comp, "hash", json_string(hash_hex));
        json_object_set_new(comp, "verified", json_boolean(verify_ok));
        send_to_peer(proc, ARTIFACT_PROTO_COMPLETE, comp, &nmsg->from_whom);

        /* Send ARTIFACT_PROTO_READY to fleet process internally */
        char path_buf[256];
        artifact_store_get_path(hash_hex, path_buf, sizeof(path_buf));

        json_t *ready = json_object();
        json_object_set_new(ready, "hash", json_string(hash_hex));
        json_object_set_new(ready, "path", json_string(path_buf));
        json_object_set_new(ready, "version", json_string(version));

        generic_msg_t ready_msg = {0};
        ready_msg.type = NET_MESSAGE;
        net_msg_t *rnmsg = &ready_msg.info.net_msg;
        strncpy(rnmsg->process, "artifact", PROC_NAME_LEN);
        rnmsg->function = (char *)ARTIFACT_PROTO_READY;
        strncpy(rnmsg->return_to, "artifact", PROC_NAME_LEN);

        if (net_msg_pack_json(rnmsg, ready) == 0)
        {
            messaging_send("update", NET_MESSAGE, &ready_msg, false);
        }
        json_decref(ready);

        log_info(proc->logger, "Artifact: download complete for %s, verified=%d\n",
                 hash_hex, verify_ok);
    }
    else
    {
        /* Find next missing chunk */
        int next_chunk = chunk_index + 1;
        int total = state->total_chunks;
        pthread_mutex_unlock(&artifact_state.lock);
        json_decref(payload);

        while (next_chunk < total && artifact_store_has_chunk(hash_hex, next_chunk))
        {
            next_chunk++;
        }

        if (next_chunk < total)
        {
            json_t *req = json_object();
            json_object_set_new(req, "hash", json_string(hash_hex));
            json_object_set_new(req, "chunk_index", json_integer(next_chunk));
            send_to_peer(proc, ARTIFACT_PROTO_CHUNK_REQ, req, &nmsg->from_whom);
        }
    }

    return true;
}


/****************************
 * Handler: handle_artifact_complete
 * Informational: a peer finished downloading an artifact from us.
 ****************************/

static bool handle_artifact_complete(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_info(proc->logger, "Artifact: complete notification from %s\n", nmsg->from_whom.fullname);
        return true;
    }

    json_t *j_hash = json_object_get(payload, "hash");
    const char *hash_hex = j_hash ? json_string_value(j_hash) : "unknown";

    log_info(proc->logger, "Artifact: peer %s completed download of %s\n",
             nmsg->from_whom.fullname, hash_hex);

    json_decref(payload);
    return true;
}


/****************************
 * Artifact process main entry
 ****************************/

int artifact_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    /* Initialize artifact store */
    const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
    char data_dir[256];
    if (root != NULL)
        snprintf(data_dir, sizeof(data_dir), "%s/var/at", root);
    else
        snprintf(data_dir, sizeof(data_dir), "/tmp/at_artifacts");

    if (artifact_store_init(data_dir) != 0)
    {
        log_error(logger, "Artifact: failed to initialize store at %s\n", data_dir);
        return -1;
    }

    /* Register protocol handlers */
    process_register_handler(proc, (char *)ARTIFACT_PROTO_REQUEST,   (handler_ptr_t)handle_artifact_request);
    process_register_handler(proc, (char *)ARTIFACT_PROTO_MANIFEST,  (handler_ptr_t)handle_artifact_manifest);
    process_register_handler(proc, (char *)ARTIFACT_PROTO_CHUNK_REQ, (handler_ptr_t)handle_chunk_request);
    process_register_handler(proc, (char *)ARTIFACT_PROTO_CHUNK,     (handler_ptr_t)handle_chunk_response);
    process_register_handler(proc, (char *)ARTIFACT_PROTO_COMPLETE,  (handler_ptr_t)handle_artifact_complete);

    proc->protocol.phase = 1;
    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(artifact, artifact_proc, artifact_run);
