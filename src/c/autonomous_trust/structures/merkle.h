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

#include <uuid/uuid.h>
#include <sodium.h>

#include "utilities/exception.h"
#include "utilities/allocation.h"

/**
 * @brief Hash output size: BLAKE2b default (32 bytes).
 */
#define MERKLE_HASH_LEN crypto_generichash_blake2b_BYTES

/**
 * @brief Abstract blob interface: designation bytes → hash.
 * @details User provides a function to extract "designation" bytes from their object.
 */
typedef struct {
    uuid_t uuid;
    uuid_t originator;
    void *user_data;
    /** Returns pointer to designation bytes and sets *len. Pointer must remain valid. */
    const uint8_t *(*designation)(void *user_data, size_t *len);
} merkle_blob_t;

/**
 * @brief Opaque Merkle node.
 */
typedef struct merkleNode merkle_node_t;

/**
 * @brief Opaque Merkle tree.
 */
typedef struct merkleTree merkle_tree_t;

/**
 * @brief Proof step: sibling digests at each tree level.
 */
typedef struct {
    bool is_left;  /**< True if sibling is on the left */
    uint8_t sibling_digest[MERKLE_HASH_LEN];
} merkle_proof_step_t;

/**
 * @brief Inclusion proof: chain of sibling digests from leaf to root.
 */
typedef struct {
    merkle_proof_step_t *steps;
    size_t count;
} merkle_proof_t;

/**
 * @brief Compute BLAKE2b hash of input bytes.
 */
int merkle_hash(const uint8_t *input, size_t input_len,
                uint8_t output[MERKLE_HASH_LEN]);

/**
 * @brief Compute hash of a blob with optional nonce.
 */
int merkle_blob_hash(const merkle_blob_t *blob, const uint8_t *nonce, size_t nonce_len,
                     uint8_t output[MERKLE_HASH_LEN]);

/**
 * @brief Create a new Merkle tree.
 */
int merkle_tree_create(merkle_tree_t **tree_ptr);

/**
 * @brief Insert a blob into the tree. Triggers rehash.
 * @return 0 on success, -1 on error
 */
int merkle_tree_insert(merkle_tree_t *tree, merkle_blob_t *blob);

/**
 * @brief Delete a blob from the tree. Triggers rehash.
 */
int merkle_tree_delete(merkle_tree_t *tree, const merkle_blob_t *blob);

/**
 * @brief Merge another tree's blobs into this tree.
 */
int merkle_tree_merge(merkle_tree_t *tree, merkle_tree_t *other);

/**
 * @brief Get the root digest (NULL if tree is empty).
 */
const uint8_t *merkle_tree_root_digest(const merkle_tree_t *tree);

/**
 * @brief Number of blobs in the tree.
 */
size_t merkle_tree_size(const merkle_tree_t *tree);

/**
 * @brief Generate inclusion proof for a blob.
 * @param tree The tree
 * @param blob The blob to prove
 * @param proof Output proof (caller must free proof->steps)
 * @return 0 on success, -1 if not found
 */
int merkle_inclusion_proof(const merkle_tree_t *tree, const merkle_blob_t *blob,
                           merkle_proof_t *proof);

/**
 * @brief Audit: verify blob is in tree using proof chain.
 * @param root_digest Expected root digest to verify against
 * @param blob The blob
 * @param proof The inclusion proof
 * @return true if verified
 */
bool merkle_audit(const uint8_t root_digest[MERKLE_HASH_LEN],
                  const merkle_blob_t *blob, const merkle_proof_t *proof);

/**
 * @brief Check if blob is in tree (via audit).
 */
bool merkle_tree_contains(const merkle_tree_t *tree, const merkle_blob_t *blob);

/**
 * @brief Free a proof.
 */
void merkle_proof_free(merkle_proof_t *proof);

/**
 * @brief Free the Merkle tree and all internal structures (not blob user_data).
 */
void merkle_tree_free(merkle_tree_t *tree);


#define EMRK_DUP 222
DECLARE_ERROR(EMRK_DUP, "Duplicate blob insertion in Merkle tree");

#define EMRK_NOTFOUND 223
DECLARE_ERROR(EMRK_NOTFOUND, "Blob not found in Merkle tree");

#endif // MERKLE_H
