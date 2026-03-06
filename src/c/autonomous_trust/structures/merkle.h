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

#ifndef MERKLE_H
#define MERKLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#include "array.h"
#include "map.h"
#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MERKLE_DIGEST_LEN crypto_generichash_BYTES
#define MERKLE_UUID_LEN 37

/* Abstract blob interface - user provides these via function pointers */
typedef struct merkle_blob_s merkle_blob_t;

typedef int (*blob_designation_fn)(const merkle_blob_t *blob, uint8_t **out, size_t *out_len);
typedef int (*blob_get_hash_fn)(const merkle_blob_t *blob, const uint8_t *nonce, size_t nonce_len,
                                uint8_t *hash_out);

struct merkle_blob_s {
    char uuid[MERKLE_UUID_LEN];
    char originator[MERKLE_UUID_LEN];
    blob_designation_fn designation;
    blob_get_hash_fn get_hash;
    void *user_data;
};

typedef struct {
    uint8_t digest[MERKLE_DIGEST_LEN];
    merkle_blob_t *blob;    /* only for leaves */
    int left;               /* index in node array, -1 if none */
    int right;              /* index in node array, -1 if none */
    int parent;             /* index in node array, -1 if root */
} merkle_node_t;

typedef struct {
    merkle_node_t *nodes;
    int node_count;
    int node_capacity;
    int root;               /* index of root node */
    array_t *blobs;         /* list of merkle_blob_t* */
    uint8_t root_digest[MERKLE_DIGEST_LEN];
    bool has_root_digest;
} merkle_tree_t;

typedef struct {
    uint8_t left[MERKLE_DIGEST_LEN];
    uint8_t right[MERKLE_DIGEST_LEN];
    bool has_left;
    bool has_right;
} merkle_proof_step_t;

int merkle_hash(const uint8_t *data, size_t data_len, uint8_t *hash_out);

int merkle_tree_create(merkle_tree_t **tree);

int merkle_insert(merkle_tree_t *tree, merkle_blob_t *blob);

int merkle_delete(merkle_tree_t *tree, merkle_blob_t *blob);

int merkle_merge(merkle_tree_t *tree, merkle_tree_t *other);

int merkle_root_digest(merkle_tree_t *tree, uint8_t *digest_out);

int merkle_inclusion_proof(merkle_tree_t *tree, merkle_blob_t *blob,
                           merkle_proof_step_t **proof_out, int *proof_len);

bool merkle_audit(merkle_tree_t *tree, merkle_blob_t *blob,
                  merkle_proof_step_t *proof, int proof_len);

bool merkle_consistent(merkle_tree_t *tree, int other_size,
                       const uint8_t *other_root_digest);

void merkle_tree_free(merkle_tree_t *tree);

#define EMRKL_NOTFOUND 222
DECLARE_ERROR(EMRKL_NOTFOUND, "Blob not found in Merkle tree");

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MERKLE_H
