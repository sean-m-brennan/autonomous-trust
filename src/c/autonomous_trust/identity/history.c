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
#include <stdio.h>

#include <sodium.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "history.h"
#include "identity_priv.h"
#include "../utilities/allocation.h"

/* IdentityObj blob interface implementations */

static int _identity_obj_designation(const merkle_blob_t *blob, uint8_t **out, size_t *out_len)
{
    const identity_obj_t *obj = (const identity_obj_t *)blob;
    if (obj == NULL || obj->identity == NULL)
        return EINVAL;

    char uuid_str[37];
    uuid_unparse_lower(obj->identity->uuid, uuid_str);

    /* originator + uuid + fullname + public_key */
    size_t orig_len = strlen(obj->originator_uuid);
    size_t uuid_len = strlen(uuid_str);
    size_t name_len = strlen(obj->identity->fullname);
    size_t key_len = crypto_sign_PUBLICKEYBYTES;
    size_t total = orig_len + uuid_len + name_len + key_len;

    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return ENOMEM;

    size_t offset = 0;
    memcpy(buf + offset, obj->originator_uuid, orig_len);
    offset += orig_len;
    memcpy(buf + offset, uuid_str, uuid_len);
    offset += uuid_len;
    memcpy(buf + offset, obj->identity->fullname, name_len);
    offset += name_len;
    memcpy(buf + offset, obj->identity->signature.public, key_len);

    *out = buf;
    *out_len = total;
    return 0;
}

static int _identity_obj_get_hash(const merkle_blob_t *blob, const uint8_t *nonce,
                                   size_t nonce_len, uint8_t *hash_out)
{
    uint8_t *designation = NULL;
    size_t designation_len = 0;
    int err = _identity_obj_designation(blob, &designation, &designation_len);
    if (err != 0)
        return err;

    size_t total = designation_len + nonce_len;
    uint8_t *combined = malloc(total);
    if (combined == NULL)
    {
        free(designation);
        return ENOMEM;
    }
    memcpy(combined, designation, designation_len);
    if (nonce != NULL && nonce_len > 0)
        memcpy(combined + designation_len, nonce, nonce_len);

    int ret = merkle_hash(combined, total, hash_out);
    free(designation);
    free(combined);
    return ret;
}

/*@
  requires identity != \null && \valid(identity);
  requires \valid(obj);
  allocates *obj;
  behavior success:
    ensures \result == 0;
    ensures *obj != \null;
  behavior null_args:
    assumes identity == \null || obj == \null;
    ensures \result == EINVAL;
  behavior oom:
    ensures \result == ENOMEM;
  disjoint behaviors null_args, success;
*/
int identity_obj_create(public_identity_t *identity, const char *originator_uuid,
                        identity_obj_t **obj)
{
    if (identity == NULL || obj == NULL)
        return EINVAL;

    identity_obj_t *o = calloc(1, sizeof(identity_obj_t));
    if (o == NULL)
        return ENOMEM;

    o->identity = identity;
    if (originator_uuid != NULL)
        strncpy(o->originator_uuid, originator_uuid, MERKLE_UUID_LEN - 1);

    /* set up blob interface */
    uuid_unparse_lower(identity->uuid, o->base.uuid);
    if (originator_uuid != NULL)
        strncpy(o->base.originator, originator_uuid, MERKLE_UUID_LEN - 1);
    o->base.designation = _identity_obj_designation;
    o->base.get_hash = _identity_obj_get_hash;
    o->base.user_data = identity;

    *obj = o;
    return 0;
}

int identity_obj_designation(const identity_obj_t *obj, uint8_t **out, size_t *out_len)
{
    return _identity_obj_designation((const merkle_blob_t *)obj, out, out_len);
}

/*@
  requires obj == \null || \valid(obj);
  frees obj;
*/
void identity_obj_free(identity_obj_t *obj)
{
    if (obj != NULL)
        free(obj);
}

/*@
  requires \valid(history);
  allocates *history;
  behavior success:
    ensures \result == 0;
    ensures *history != \null;
  behavior null_out:
    assumes history == \null;
    ensures \result == EINVAL;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors null_out, success;
*/
int identity_history_create(agreement_voter_t *myself,
                            peers_t *peers,
                            logger_t *logger,
                            int timeout,
                            identity_history_t **history)
{
    (void)myself; // TODO: use for voter registration
    if (history == NULL)
        return EINVAL;

    identity_history_t *h = calloc(1, sizeof(identity_history_t));
    if (h == NULL)
        return ENOMEM;

    int err = dag_init(&h->dag);
    if (err != 0)
    {
        free(h);
        return err;
    }

    err = merkle_tree_create(&h->merkle);
    if (err != 0)
    {
        dag_free(&h->dag);
        free(h);
        return err;
    }

    h->peers = peers;
    h->logger = logger;
    h->timeout = timeout;

    err = array_create(&h->blacklist);
    if (err != 0)
    {
        merkle_tree_free(h->merkle);
        dag_free(&h->dag);
        free(h);
        return err;
    }

    *history = h;
    return 0;
}

/*@
  requires history == \null || \valid(history);
  requires who == \null || \valid(who);
  behavior null_args:
    assumes history == \null || who == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && who != \null;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int identity_history_insert_peer(identity_history_t *history,
                                 public_identity_t *who)
{
    if (history == NULL || who == NULL)
        return EINVAL;

    /* create identity blob */
    char orig_uuid[MERKLE_UUID_LEN] = {0};
    if (history->merkle->has_root_digest)
    {
        /* use current root digest as originator for tracking */
        snprintf(orig_uuid, sizeof(orig_uuid), "merkle-root");
    }

    identity_obj_t *obj = NULL;
    int err = identity_obj_create(who, orig_uuid, &obj);
    if (err != 0)
        return err;

    /* insert into merkle tree */
    err = merkle_insert(history->merkle, (merkle_blob_t *)obj);
    if (err != 0)
        return err;

    /* add step to DAG */
    uint8_t root_digest[MERKLE_DIGEST_LEN];
    merkle_root_digest(history->merkle, root_digest);

    linked_step_t *step = NULL;
    err = linked_step_create(NULL, root_digest, &step);
    if (err != 0)
        return err;

    return dag_add_step(&history->dag, step, NULL);
}

/*@
  requires history == \null || \valid(history);
  requires item == \null || \valid(item);
  requires \valid(proof_out);
  requires \valid(proof_len);
  behavior null_args:
    assumes history == \null || item == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && item != \null;
    ensures \result == 0 ==> *proof_out != \null && *proof_len >= 0;
  disjoint behaviors;
*/
int identity_history_prove_existence(identity_history_t *history,
                                     merkle_blob_t *item,
                                     merkle_proof_step_t **proof_out,
                                     int *proof_len)
{
    if (history == NULL || item == NULL)
        return EINVAL;
    return merkle_inclusion_proof(history->merkle, item, proof_out, proof_len);
}

/*@
  requires history == \null || \valid(history);
  requires item == \null || \valid(item);
  requires proof_len >= 0;
  requires proof_len == 0 || \valid(proof + (0 .. proof_len - 1));
  behavior null_args:
    assumes history == \null || item == \null;
    ensures \result == \false;
  behavior valid_args:
    assumes history != \null && item != \null;
    ensures \result == \true || \result == \false;
  disjoint behaviors;
  complete behaviors;
*/
bool identity_history_verify_existence(identity_history_t *history,
                                       merkle_blob_t *item,
                                       merkle_proof_step_t *proof,
                                       int proof_len)
{
    if (history == NULL || item == NULL)
        return false;
    return merkle_audit(history->merkle, item, proof, proof_len);
}

/* JSON serialization helpers for wire-compatible history exchange */

static json_t *linked_step_to_json(const linked_step_t *step)
{
    if (step == NULL)
        return NULL;

    json_t *obj = json_object();
    if (obj == NULL)
        return NULL;

    json_object_set_new(obj, "uuid", json_string(step->uuid));

    char ts_buf[MAX_DT_STR];
    if (datetime_to_isoformat(&step->timestamp, ts_buf, sizeof(ts_buf)) == 0)
        json_object_set_new(obj, "timestamp", json_string(ts_buf));

    /* payload is a merkle root digest (MERKLE_DIGEST_LEN bytes) */
    if (step->payload != NULL)
    {
        size_t hex_len = MERKLE_DIGEST_LEN * 2 + 1;
        char *hex = malloc(hex_len);
        if (hex != NULL)
        {
            hexlify((const unsigned char *)step->payload, MERKLE_DIGEST_LEN,
                    (unsigned char *)hex);
            hex[MERKLE_DIGEST_LEN * 2] = '\0';
            json_object_set_new(obj, "payload", json_string(hex));
            free(hex);
        }
    }

    return obj;
}

static int linked_step_from_json(const json_t *obj, linked_step_t **step_out)
{
    if (obj == NULL || step_out == NULL)
        return EINVAL;

    const char *uuid_str = json_string_value(json_object_get(obj, "uuid"));
    if (uuid_str == NULL)
        return EINVAL;

    linked_step_t *step = NULL;
    int err = linked_step_create(uuid_str, NULL, &step);
    if (err != 0)
        return err;

    const char *ts_str = json_string_value(json_object_get(obj, "timestamp"));
    if (ts_str != NULL)
        datetime_from_isostring(ts_str, &step->timestamp);

    const char *payload_hex = json_string_value(json_object_get(obj, "payload"));
    if (payload_hex != NULL)
    {
        uint8_t *digest = malloc(MERKLE_DIGEST_LEN);
        if (digest != NULL)
        {
            unhexlify((const unsigned char *)payload_hex,
                      MERKLE_DIGEST_LEN * 2, digest);
            step->payload = digest;
        }
    }

    *step_out = step;
    return 0;
}

/*@
  requires history == \null || \valid(history);
  requires signer == \null || \valid(signer);
  requires wire_out == \null || \valid(wire_out);
  requires wire_len == \null || \valid(wire_len);
  allocates *wire_out;
  behavior null_args:
    assumes history == \null || signer == \null ||
            wire_out == \null || wire_len == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && signer != \null &&
            wire_out != \null && wire_len != \null;
    ensures \result == 0 ==> *wire_out != \null && *wire_len > 0;
  disjoint behaviors;
*/
int identity_history_share(identity_history_t *history,
                           const identity_t *signer,
                           uint8_t **wire_out, size_t *wire_len)
{
    if (history == NULL || signer == NULL || wire_out == NULL || wire_len == NULL)
        return EINVAL;

    array_t *steps = NULL;
    int err = dag_recite(&history->dag, NULL, NULL, &steps);
    if (err != 0)
        return err;

    /* serialize steps to JSON array */
    json_t *arr = json_array();
    if (arr == NULL)
    {
        array_free(steps);
        return ENOMEM;
    }

    int idx;
    data_t *val;
    array_for_each(steps, idx, val)
        ptr_t ptr = NULL;
        if (data_object_ptr(val, &ptr) == 0 && ptr != NULL)
        {
            json_t *step_json = linked_step_to_json((const linked_step_t *)ptr);
            if (step_json != NULL)
                json_array_append_new(arr, step_json);
        }
    array_end_for_each

    char *json_str = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    array_free(steps);
    if (json_str == NULL)
        return ENOMEM;

    /* sign the JSON payload */
    size_t json_len = strlen(json_str);
    size_t signed_len = crypto_sign_BYTES + json_len;
    uint8_t *signed_buf = malloc(signed_len);
    if (signed_buf == NULL)
    {
        free(json_str);
        return ENOMEM;
    }

    unsigned long long actual_len = 0;
    if (crypto_sign(signed_buf, &actual_len,
                    (const uint8_t *)json_str, json_len,
                    signer->signature.private) != 0)
    {
        free(json_str);
        free(signed_buf);
        return -1;
    }
    free(json_str);

    *wire_out = signed_buf;
    *wire_len = (size_t)actual_len;
    return 0;
}

/*@
  requires history == \null || \valid(history);
  requires sender == \null || \valid(sender);
  requires wire == \null || \valid_read(wire + (0 .. wire_len - 1));
  behavior null_args:
    assumes history == \null || sender == \null ||
            wire == \null || wire_len == 0;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && sender != \null &&
            wire != \null && wire_len > 0;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int identity_history_hear(identity_history_t *history,
                          const public_identity_t *sender,
                          const uint8_t *wire, size_t wire_len)
{
    if (history == NULL || sender == NULL || wire == NULL || wire_len == 0)
        return EINVAL;

    /* verify signature and extract JSON payload */
    size_t json_max = wire_len;
    uint8_t *json_buf = malloc(json_max);
    if (json_buf == NULL)
        return ENOMEM;

    unsigned long long json_len = 0;
    if (crypto_sign_open(json_buf, &json_len, wire, wire_len,
                         sender->signature.public) != 0)
    {
        free(json_buf);
        return -1;  /* signature verification failed */
    }

    /* parse JSON array back to linked steps */
    json_error_t jerr;
    json_t *arr = json_loadb((const char *)json_buf, (size_t)json_len, 0, &jerr);
    free(json_buf);
    if (arr == NULL || !json_is_array(arr))
    {
        if (arr != NULL)
            json_decref(arr);
        return EINVAL;
    }

    size_t count = json_array_size(arr);
    if (count == 0)
    {
        json_decref(arr);
        return 0;
    }

    linked_step_t **steps = calloc(count, sizeof(linked_step_t *));
    if (steps == NULL)
    {
        json_decref(arr);
        return ENOMEM;
    }

    for (size_t i = 0; i < count; i++)
    {
        int err = linked_step_from_json(json_array_get(arr, i), &steps[i]);
        if (err != 0)
        {
            for (size_t j = 0; j < i; j++)
                linked_step_free(steps[j]);
            free(steps);
            json_decref(arr);
            return err;
        }
    }
    json_decref(arr);

    /* rebuild parent chain (recite outputs head-to-root order) */
    for (size_t i = 0; i + 1 < count; i++)
        steps[i]->parent = steps[i + 1];

    char name_out[32];
    int err = dag_ingest_branch(&history->dag, steps, count, NULL,
                                name_out, sizeof(name_out));
    free(steps);
    if (err != 0)
        return err;

    /* merge into main */
    return dag_merge(&history->dag, name_out, NULL, false);
}

/*@
  requires history == \null || \valid(history);
  behavior null_history:
    assumes history == \null;
    assigns \nothing;
  behavior valid_history:
    assumes history != \null;
    frees history;
  disjoint behaviors;
  complete behaviors;
*/
void identity_history_free(identity_history_t *history)
{
    if (history == NULL)
        return;
    dag_free(&history->dag);
    if (history->merkle != NULL)
        merkle_tree_free(history->merkle);
    if (history->agreement != NULL)
        agreement_protocol_free(history->agreement);
    if (history->blacklist != NULL)
        array_free(history->blacklist);
    free(history);
}

int identity_history_by_authority_create(public_identity_t *myself,
                                         peers_t *peers,
                                         logger_t *logger,
                                         int timeout,
                                         int threshold_rank,
                                         identity_history_t **history)
{
    agreement_voter_t voter = {0};
    uuid_unparse_lower(myself->uuid, voter.uuid);
    voter.rank = 0;

    int err = identity_history_create(&voter, peers, logger, timeout, history);
    if (err != 0)
        return err;

    err = agreement_by_authority_create(&voter, NULL, 0, threshold_rank, &(*history)->agreement);
    return err;
}

int identity_history_by_stake_create(public_identity_t *myself,
                                     peers_t *peers,
                                     logger_t *logger,
                                     int timeout,
                                     double (*get_stake)(agreement_voter_t *),
                                     identity_history_t **history)
{
    agreement_voter_t voter = {0};
    uuid_unparse_lower(myself->uuid, voter.uuid);
    voter.rank = 0;

    int err = identity_history_create(&voter, peers, logger, timeout, history);
    if (err != 0)
        return err;

    err = agreement_by_stake_create(&voter, NULL, 0, get_stake, &(*history)->agreement);
    return err;
}

int identity_history_by_work_create(public_identity_t *myself,
                                    peers_t *peers,
                                    logger_t *logger,
                                    int timeout,
                                    int difficulty,
                                    identity_history_t **history)
{
    agreement_voter_t voter = {0};
    uuid_unparse_lower(myself->uuid, voter.uuid);
    voter.rank = 0;

    int err = identity_history_create(&voter, peers, logger, timeout, history);
    if (err != 0)
        return err;

    err = agreement_by_work_create(&voter, NULL, 0, difficulty, &(*history)->agreement);
    return err;
}
