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

#include <time.h>

#include "history.h"
#include "identity_priv.h"
#include "../utilities/allocation.h"
#include "../utilities/logger.h"

/* IdentityObj blob interface implementations */

/* Frama-C: skipped —
 * [alloc-pattern] _identity_obj_designation: 12 at_memcpy + uuid_unparse + strnlen
 * cascade through blob-designation assembly.
 */
static int _identity_obj_designation(const merkle_blob_t *blob, uint8_t **out, size_t *out_len)
{
    const identity_obj_t *obj = (const identity_obj_t *)blob;
    if (obj == NULL || obj->identity == NULL)
        return EINVAL;

    char uuid_str[37];
    uuid_unparse_lower(obj->identity->uuid, uuid_str);

    /* originator + uuid + nickname + public_key.  Use strnlen throughout
     * so a wire-sourced identity that lacks a NUL terminator cannot walk
     * past the field and read adjacent memory. */
    size_t orig_len = strnlen(obj->originator_uuid, MERKLE_UUID_LEN);
    size_t uuid_len = strnlen(uuid_str, sizeof(uuid_str));
    size_t name_len = strnlen(obj->identity->nickname, NAME_LEN + 1);
    if (orig_len >= MERKLE_UUID_LEN || uuid_len >= sizeof(uuid_str) ||
        name_len > NAME_LEN)
        return EINVAL;
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
    memcpy(buf + offset, obj->identity->nickname, name_len);
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

/* Frama-C: skipped —
 * [string-loop] identity_obj_create: strncpy preconditions cascade into success/oom
 * ensures; same pattern as names.c/random_name.
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
    {
        strncpy(o->originator_uuid, originator_uuid, MERKLE_UUID_LEN - 1);
        o->originator_uuid[MERKLE_UUID_LEN - 1] = '\0';
    }

    /* set up blob interface */
    uuid_unparse_lower(identity->uuid, o->base.uuid);
    if (originator_uuid != NULL)
    {
        strncpy(o->base.originator, originator_uuid, MERKLE_UUID_LEN - 1);
        o->base.originator[MERKLE_UUID_LEN - 1] = '\0';
    }
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

void identity_obj_free(identity_obj_t *obj)
{
    if (obj != NULL)
        free(obj);
}

/* C13: branch validator for IdentityHistory — parity with Python
 * IdentityHistory._validate (history/history.py:155-168). Walks the
 * branch and rejects backdating: a child step must have a strictly
 * later timestamp than its parent. dag_recite returns the branch
 * head-first, so when iterating index i we are looking at a
 * progressively older step, and the immediately-prior index i-1 is
 * the newer (child) entry. Backdating is therefore
 *   prev->timestamp <= cur->timestamp
 * (the newer node has a non-strictly-greater timestamp). Mirrors
 * the Python `steps[i-1].timestamp >= steps[i].timestamp` test
 * over the root-first branch_list.
 *
 * NB: Python's check skips entries with `timestamp is None`; the C
 * representation never carries a NULL timestamp (datetime_t is
 * value-typed), so the gate degenerates to an unconditional
 * comparison. */
static bool _identity_history_validate_branch(step_dag_t *dag,
                                              const char *branch,
                                              void *ctx)
{
    identity_history_t *h = (identity_history_t *)ctx;
    array_t *steps = NULL;
    if (dag_recite(dag, branch, NULL, &steps) != 0 || steps == NULL)
    {
        if (h != NULL)
            log_error(h->logger, "IdentityHistory: branch %s not found\n",
                      branch);
        return false;
    }

    size_t n = array_size(steps);
    bool ok = true;
    for (size_t i = 1; i < n; i++)
    {
        data_t *prev_d = NULL;
        data_t *cur_d = NULL;
        if (array_get(steps, (int)(i - 1), &prev_d) != 0 || prev_d == NULL ||
            array_get(steps, (int)i,       &cur_d)  != 0 || cur_d  == NULL)
            continue;
        ptr_t prev_p = NULL;
        ptr_t cur_p  = NULL;
        if (data_object_ptr(prev_d, &prev_p) != 0 ||
            data_object_ptr(cur_d,  &cur_p)  != 0)
            continue;
        const linked_step_t *prev = (const linked_step_t *)prev_p;
        const linked_step_t *cur  = (const linked_step_t *)cur_p;
        time_t prev_t = mktime((struct tm *)&prev->timestamp);
        time_t cur_t  = mktime((struct tm *)&cur->timestamp);
        if (prev_t <= cur_t)
        {
            if (h != NULL)
                log_error(h->logger,
                          "IdentityHistory: backdating at step %zu of branch %s\n",
                          i, branch);
            ok = false;
            break;
        }
    }
    array_free(steps);
    return ok;
}

/* Frama-C: skipped —
 * [solver-timeout] identity_history_create: dag_init + success ensures (smrt_ptr
 * allocation cascade).
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
    /* Install the IdentityHistory-specific branch validator (C13).
     * The ctx is the owning history struct so the validator can log
     * via the same logger as the rest of identity_history_*. */
    dag_set_validator(&h->dag, _identity_history_validate_branch, h);

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

int identity_history_prove_existence(identity_history_t *history,
                                     merkle_blob_t *item,
                                     merkle_proof_step_t **proof_out,
                                     int *proof_len)
{
    if (history == NULL || item == NULL)
        return EINVAL;
    return merkle_inclusion_proof(history->merkle, item, proof_out, proof_len);
}

bool identity_history_verify_existence(identity_history_t *history,
                                       merkle_blob_t *item,
                                       merkle_proof_step_t *proof,
                                       int proof_len)
{
    if (history == NULL || item == NULL)
        return false;
    return merkle_audit(history->merkle, item, proof, proof_len);
}

/* JSON serialization helpers for wire-compatible history exchange.
 * Exported so id_proc.c can build/parse the 3-tuple history payload
 * (`[group, [steps], [peers]]`) that mirrors Python idprocess.py:498-513.
 * Declared in history.h. */

/* Frama-C: skipped — linked_step_to_json / linked_step_from_json: jansson + hexlify cascades. */
json_t *linked_step_to_json(const linked_step_t *step)
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
        char hex[MERKLE_DIGEST_LEN * 2 + 1];
        hexlify((const unsigned char *)step->payload, MERKLE_DIGEST_LEN,
                (unsigned char *)hex);
        hex[MERKLE_DIGEST_LEN * 2] = '\0';
        json_object_set_new(obj, "payload", json_string(hex));
    }

    return obj;
}

/* Frama-C: skipped — linked_step_to_json / linked_step_from_json: jansson + hexlify cascades. */
int linked_step_from_json(const json_t *obj, linked_step_t **step_out)
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

/* Frama-C: skipped — [serialization] identity_history_hear: dag_ingest_branch + json_decref. */
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

    /* C12: dag_catch_up performs ingest + diff + recite + validate
     * + merge in one shot, matching Python StepDAG.catch_up
     * (dag.py:287-297). The validator installed at create time
     * (_identity_history_validate_branch) decides whether the merge
     * actually happens; on rejection the branch stays in the DAG
     * unmerged. We discard the branch_diff here — the wire layer
     * does not surface it to the caller. */
    int err = dag_catch_up(&history->dag, steps, count, NULL);
    free(steps);
    return err;
}

/* Frama-C: skipped —
 * [recursive-ds] identity_history_free: composite destructor cascades through
 * agreement_protocol_free + merkle_tree_free + dag_free + array_free; 4 consecutive
 * free-valid preconditions time out.
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

/****************************
 * Blacklist + identity-aware prove/verify wrappers
 *
 * Mirrors Python's PoA/PoS prove() overrides (poa.py:37-42,
 * pos.py:35-40) and IdentityHistory.verify_object (history.py:170-213).
 * These sit on top of the protocol-generic agreement_* primitives,
 * which intentionally remain blacklist- and identity-blind.
 ****************************/

int identity_history_blacklist_add(identity_history_t *history,
                                   const uuid_t uuid,
                                   const char *address)
{
    if (history == NULL || history->blacklist == NULL)
        return EINVAL;
    if (uuid == NULL && (address == NULL || address[0] == '\0'))
        return EINVAL;

    identity_blacklist_entry_t *entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
        return ENOMEM;
    if (uuid != NULL) {
        uuid_copy(entry->uuid, uuid);
        entry->uuid_set = true;
    }
    if (address != NULL) {
        strncpy(entry->address, address, ADDR_LEN);
        entry->address[ADDR_LEN] = '\0';
    }
    data_t *dat = object_ptr_data(entry, sizeof(*entry));
    if (dat == NULL) {
        free(entry);
        return ENOMEM;
    }
    return array_append(history->blacklist, dat);
}

bool identity_history_is_blacklisted(const identity_history_t *history,
                                     const uuid_t uuid,
                                     const char *address)
{
    if (history == NULL || history->blacklist == NULL)
        return false;
    size_t n = array_size(history->blacklist);
    for (size_t i = 0; i < n; i++) {
        data_t *dat = NULL;
        if (array_get(history->blacklist, (int)i, &dat) != 0 || dat == NULL)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(dat, &ptr) != 0 || ptr == NULL)
            continue;
        const identity_blacklist_entry_t *e =
            (const identity_blacklist_entry_t *)ptr;
        if (uuid != NULL && e->uuid_set &&
            uuid_compare((unsigned char *)e->uuid, (unsigned char *)uuid) == 0)
            return true;
        if (address != NULL && address[0] != '\0' &&
            e->address[0] != '\0' &&
            strncmp(e->address, address, ADDR_LEN) == 0)
            return true;
    }
    return false;
}

int identity_history_prove(identity_history_t *history,
                           merkle_blob_t *blob,
                           agreement_proof_t **proof_out)
{
    if (history == NULL || blob == NULL || proof_out == NULL)
        return EINVAL;
    *proof_out = NULL;

    /* The blob carries an identity_obj_t whose `.identity` field is the
     * subject of the proof. Skip the blacklist check if the blob is not
     * an identity_obj_t (no .identity present) — defensive, matches
     * Python's failure-to-find-attrs path. */
    const identity_obj_t *idobj = (const identity_obj_t *)blob;
    if (idobj != NULL && idobj->identity != NULL) {
        if (identity_history_is_blacklisted(history,
                                            idobj->identity->uuid,
                                            idobj->identity->address)) {
            if (history->logger != NULL)
                log_debug(history->logger,
                          "identity_history_prove: rejecting blacklisted "
                          "identity %s\n", idobj->identity->nickname);
            return EACCES;
        }
    }
    return agreement_prove(history->agreement, blob, proof_out);
}

bool identity_history_verify_object(identity_history_t *history,
                                    merkle_blob_t *blob,
                                    agreement_proof_t *proof,
                                    const uint8_t *sig, size_t sig_len)
{
    if (history == NULL || blob == NULL)
        return false;

    /* Shape check: blob must carry a non-null identity with at least
     * uuid + nickname + signature populated. Mirrors Python's
     * IdentityObj.validate() (history.py:55-69). The C identity_obj_t
     * stores `identity` as a pointer; null or zero-nickname rejects. */
    const identity_obj_t *idobj = (const identity_obj_t *)blob;
    if (idobj->identity == NULL) {
        if (history->logger != NULL)
            log_debug(history->logger, "verify_object: no identity\n");
        return false;
    }
    if (idobj->identity->nickname[0] == '\0') {
        if (history->logger != NULL)
            log_debug(history->logger, "verify_object: identity has no nickname\n");
        return false;
    }
    /* Signature key presence: the ed25519 public key is a fixed-size
     * array, but a freshly-zeroed identity would have an all-zero key.
     * Reject that as the C analog of Python's `identity.signature is None`. */
    bool key_nonzero = false;
    for (size_t i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
        if (idobj->identity->signature.public[i] != 0) {
            key_nonzero = true;
            break;
        }
    }
    if (!key_nonzero) {
        if (history->logger != NULL)
            log_debug(history->logger, "verify_object: identity has no signature key\n");
        return false;
    }

    /* Signature check is optional — Python skips it when sig/proof are
     * None. The sig buffer here is the libsodium combined form
     * (signature || message), matching how identity_sign produces it. */
    if (sig != NULL && sig_len > 0 && proof != NULL) {
        if (history->peers == NULL) {
            if (history->logger != NULL)
                log_warn(history->logger,
                         "verify_object: no peers list, cannot locate voter\n");
            return false;
        }
        uuid_t voter_uuid;
        if (uuid_parse(proof->uuid, voter_uuid) != 0) {
            if (history->logger != NULL)
                log_warn(history->logger,
                         "verify_object: bad voter uuid %s\n", proof->uuid);
            return false;
        }
        const public_identity_t *voter =
            peers_find_by_uuid(history->peers, voter_uuid);
        if (voter == NULL) {
            if (history->logger != NULL)
                log_warn(history->logger,
                         "verify_object: unknown voter %s\n", proof->uuid);
            return false;
        }
        /* crypto_sign_open recovers the message from the combined buffer
         * and validates the signature in one shot; non-zero return means
         * the signature failed verification (Python's BadSignatureError). */
        unsigned char *recovered = malloc(sig_len);
        if (recovered == NULL)
            return false;
        unsigned long long recovered_len = 0;
        int rc = crypto_sign_open(recovered, &recovered_len,
                                  sig, sig_len, voter->signature.public);
        free(recovered);
        if (rc != 0) {
            if (history->logger != NULL)
                log_warn(history->logger,
                         "verify_object: signature verification failed\n");
            return false;
        }
    }

    /* Divergence detection (ISSUES.md §3.2): the proof commits the voter to a
     * specific view of the candidate via its digest. Recompute the blob's hash
     * — with the proof's nonce, so PoW's mined digest also matches — and reject
     * a proof whose digest disagrees: that voter is voting on a conflicting
     * history view of this blob. get_hash is byte-identical Python<->C (pinned
     * by pow-cross-language-byte-pin), so this is interop-safe. Enforced only
     * when a digest is present (empty-digest proofs fall through, matching
     * prior behavior). Mirrors Python IdentityHistory.verify_object. */
    if (proof != NULL && proof->digest != NULL && proof->digest_len > 0 &&
        blob->get_hash != NULL) {
        uint8_t computed[MERKLE_DIGEST_LEN];
        if (blob->get_hash(blob, proof->nonce, proof->nonce_len, computed) == 0) {
            if (proof->digest_len != MERKLE_DIGEST_LEN ||
                memcmp(proof->digest, computed, MERKLE_DIGEST_LEN) != 0) {
                if (history->logger != NULL)
                    log_warn(history->logger, "verify_object: divergent history "
                             "view — proof digest mismatch\n");
                return false;
            }
        }
    }
    return true;
}

bool identity_history_verify(identity_history_t *history,
                             merkle_blob_t *blob,
                             agreement_proof_t *proof,
                             const uint8_t *sig, size_t sig_len)
{
    if (history == NULL || history->agreement == NULL)
        return false;
    if (!identity_history_verify_object(history, blob, proof, sig, sig_len))
        return false;
    return agreement_verify(history->agreement, blob, proof, sig, sig_len);
}
