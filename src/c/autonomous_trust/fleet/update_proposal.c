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

#include "fleet/update_proposal.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

/* Frama-C: skipped — [serialization] jansson JSON serialization */
json_t *update_proposal_to_json(const update_proposal_t *prop)
{
    json_t *obj = json_object();
    if (!obj) return NULL;

    json_object_set_new(obj, "version", json_string(prop->version));

    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), prop->artifact_hash, UPDATE_HASH_LEN);
    json_object_set_new(obj, "artifact_hash", json_string(hash_hex));

    char signer_str[37];
    uuid_unparse_lower(prop->signer_uuid, signer_str);
    json_object_set_new(obj, "signer_uuid", json_string(signer_str));

    json_object_set_new(obj, "target_arch", json_string(prop->target_arch));
    json_object_set_new(obj, "min_proposer_reputation", json_real(prop->min_proposer_reputation));

    char proposal_str[37];
    uuid_unparse_lower(prop->proposal_uuid, proposal_str);
    json_object_set_new(obj, "proposal_uuid", json_string(proposal_str));

    char sig_hex[UPDATE_SIG_LEN * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), prop->signature, UPDATE_SIG_LEN);
    json_object_set_new(obj, "signature", json_string(sig_hex));

    return obj;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int update_proposal_from_json(const json_t *json, update_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));

    const char *version = json_string_value(json_object_get(json, "version"));
    const char *hash_hex = json_string_value(json_object_get(json, "artifact_hash"));
    const char *signer_str = json_string_value(json_object_get(json, "signer_uuid"));
    const char *arch = json_string_value(json_object_get(json, "target_arch"));
    json_t *j_rep = json_object_get(json, "min_proposer_reputation");
    const char *proposal_str = json_string_value(json_object_get(json, "proposal_uuid"));
    const char *sig_hex = json_string_value(json_object_get(json, "signature"));

    if (!version || !hash_hex || !signer_str || !arch || !j_rep || !proposal_str || !sig_hex)
        return -1;

    strncpy(prop->version, version, UPDATE_VERSION_LEN);
    strncpy(prop->target_arch, arch, UPDATE_ARCH_LEN);
    prop->min_proposer_reputation = json_real_value(j_rep);

    if (sodium_hex2bin(prop->artifact_hash, UPDATE_HASH_LEN,
                       hash_hex, strlen(hash_hex), NULL, NULL, NULL) != 0)
        return -1;

    if (uuid_parse(signer_str, prop->signer_uuid) != 0)
        return -1;

    if (uuid_parse(proposal_str, prop->proposal_uuid) != 0)
        return -1;

    if (sodium_hex2bin(prop->signature, UPDATE_SIG_LEN,
                       sig_hex, strlen(sig_hex), NULL, NULL, NULL) != 0)
        return -1;

    return 0;
}

/* Frama-C: skipped — [solver-timeout] crypto signature preconditions */
static size_t build_signable(const update_proposal_t *prop, uint8_t *buf, size_t buflen)
{
    size_t offset = 0;
    size_t vlen = strlen(prop->version);

    if (offset + vlen > buflen) return 0;
    memcpy(buf + offset, prop->version, vlen);
    offset += vlen;

    if (offset + UPDATE_HASH_LEN > buflen) return 0;
    memcpy(buf + offset, prop->artifact_hash, UPDATE_HASH_LEN);
    offset += UPDATE_HASH_LEN;

    size_t alen = strlen(prop->target_arch);
    if (offset + alen > buflen) return 0;
    memcpy(buf + offset, prop->target_arch, alen);
    offset += alen;

    return offset;
}

/* Frama-C: skipped — [solver-timeout] libsodium sign preconditions */
int update_proposal_sign(update_proposal_t *prop, const uint8_t *sk)
{
    uint8_t msg[256];
    size_t msg_len = build_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    unsigned long long sig_len;
    return crypto_sign_detached(prop->signature, &sig_len, msg, msg_len, sk);
}

/* Frama-C: skipped — [solver-timeout] libsodium verify preconditions */
int update_proposal_verify(const update_proposal_t *prop, const uint8_t *pk)
{
    uint8_t msg[256];
    size_t msg_len = build_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    return crypto_sign_verify_detached(prop->signature, msg, msg_len, pk);
}
