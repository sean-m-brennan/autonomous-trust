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
 * fleet_ops.c — high-level fleet operations for host applications.
 *
 * Unlike fleet_helpers.c (which is pure/dependency-free for unit testing),
 * this file uses the full messaging, artifact store, and network infrastructure.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sodium.h>
#include <jansson.h>
#include <uuid/uuid.h>

#include "fleet/update_proposal.h"
#include "fleet/fleet_proc.h"
#include "fleet/artifact_store.h"
#include "fleet/artifact_proc.h"
#include "config/configuration.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "network/net_message.h"


/* Frama-C: skipped — [solver-timeout] artifact_store + logging preconditions */
int fleet_store_artifact(const char *file_path, const char *version,
                         logger_t *logger,
                         uint8_t *hash_out, char *hash_hex_out)
{
    char data_dir[CFG_PATH_LEN + 1];
    get_data_dir(data_dir, sizeof(data_dir));
    artifact_store_init(data_dir);

    FILE *f = fopen(file_path, "rb");
    if (!f)
    {
        if (logger)
            log_error(logger, "fleet_store_artifact: cannot open %s\n", file_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(fsize);
    if (!data || fread(data, 1, fsize, f) != (size_t)fsize)
    {
        free(data);
        fclose(f);
        if (logger)
            log_error(logger, "fleet_store_artifact: read failed for %s\n", file_path);
        return -1;
    }
    fclose(f);

    /* Hash */
    crypto_generichash_blake2b(hash_out, UPDATE_HASH_LEN, data, fsize, NULL, 0);
    sodium_bin2hex(hash_hex_out, UPDATE_HASH_LEN * 2 + 1, hash_out, UPDATE_HASH_LEN);

    if (logger)
        log_info(logger, "fleet_store_artifact: hash=%s (%ld bytes)\n",
                 hash_hex_out, fsize);

    /* Store as chunks */
    artifact_manifest_t manifest;
    memset(&manifest, 0, sizeof(manifest));
    strncpy(manifest.hash_hex, hash_hex_out, sizeof(manifest.hash_hex) - 1);
    manifest.total_size = fsize;
    manifest.chunk_size = ARTIFACT_CHUNK_SIZE;
    manifest.total_chunks = (int)((fsize + ARTIFACT_CHUNK_SIZE - 1) / ARTIFACT_CHUNK_SIZE);
    strncpy(manifest.version, version ? version : "0.0.0",
            sizeof(manifest.version) - 1);
    artifact_store_save_manifest(&manifest);

    for (int i = 0; i < manifest.total_chunks; i++)
    {
        size_t offset = (size_t)i * ARTIFACT_CHUNK_SIZE;
        size_t chunk_len = ARTIFACT_CHUNK_SIZE;
        if (offset + chunk_len > (size_t)fsize)
            chunk_len = (size_t)fsize - offset;
        artifact_store_save_chunk(hash_hex_out, i, data + offset, chunk_len);
    }
    artifact_store_verify(hash_hex_out, hash_out);
    free(data);

    if (logger)
        log_info(logger, "fleet_store_artifact: stored %d chunks\n",
                 manifest.total_chunks);
    return 0;
}

int fleet_propose_update(const uint8_t *artifact_hash, const char *version,
                         const char *target_arch,
                         const uint8_t *signing_pk, const uint8_t *signing_sk,
                         logger_t *logger)
{
    update_proposal_t prop;
    memset(&prop, 0, sizeof(prop));
    strncpy(prop.version, version ? version : "0.0.0", UPDATE_VERSION_LEN);
    memcpy(prop.artifact_hash, artifact_hash, UPDATE_HASH_LEN);
    strncpy(prop.target_arch, target_arch ? target_arch : "unknown", UPDATE_ARCH_LEN);
    prop.min_proposer_reputation = 0.0;
    uuid_generate(prop.proposal_uuid);

    memcpy(prop.signer_uuid, prop.proposal_uuid, sizeof(uuid_t));
    if (update_proposal_sign(&prop, signing_sk) != 0)
    {
        if (logger)
            log_error(logger, "fleet_propose_update: signing failed\n");
        return -1;
    }

    json_t *prop_json = update_proposal_to_json(&prop);
    if (!prop_json)
        return -1;

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    net_msg_t *nmsg = &msg.info.net_msg;
    strncpy(nmsg->process, "fleet", PROC_NAME_LEN);
    nmsg->function = FLEET_PROTO_PROPOSE;
    strncpy(nmsg->return_to, "fleet", PROC_NAME_LEN);
    memcpy(nmsg->from_whom.signature.public, signing_pk,
           crypto_sign_PUBLICKEYBYTES);
    sodium_bin2hex((char *)nmsg->from_whom.signature.public_hex,
                   crypto_sign_PUBLICKEYBYTES * 2 + 1,
                   signing_pk, crypto_sign_PUBLICKEYBYTES);

    if (net_msg_pack_json(nmsg, prop_json) != 0)
    {
        json_decref(prop_json);
        return -1;
    }
    json_decref(prop_json);

    int rc = messaging_send("fleet", NET_MESSAGE, &msg, false);
    if (rc != 0)
    {
        if (logger)
            log_error(logger, "fleet_propose_update: send failed\n");
        return -1;
    }

    if (logger)
        log_info(logger, "fleet_propose_update: proposal submitted\n");
    return 0;
}
