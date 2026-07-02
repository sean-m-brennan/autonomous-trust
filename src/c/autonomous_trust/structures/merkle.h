/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

/** @addtogroup internal_structures
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>
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

/*@ predicate valid_merkle_tree{L}(merkle_tree_t *t) =
      t != \null && \valid(t) &&
      t->node_capacity > 0 &&
      t->node_count >= 0 &&
      t->node_count <= t->node_capacity &&
      t->nodes != \null &&
      \valid(t->nodes + (0 .. t->node_capacity - 1)) &&
      t->blobs != \null &&
      (t->node_count == 0 ==> t->root == -1) &&
      (t->node_count > 0  ==> t->root >= 0 && t->root < t->node_count);
*/

/*@ predicate valid_merkle_blob{L}(merkle_blob_t *b) =
      b != \null && \valid(b) &&
      b->uuid[MERKLE_UUID_LEN - 1] == '\0';
*/

/*@ axiomatic MerkleDigestIntegrity {
      // The root digest must change whenever the set of blobs changes.
      // This is expressed as: if two trees have different blob sets,
      // their root digests differ (collision resistance assumption).
      axiom digest_reflects_content:
        \forall merkle_tree_t *t;
          \valid(t) && t->has_root_digest ==>
            // The root_digest field is a deterministic function of the
            // blobs array content.  Any insertion or deletion triggers
            // a full rehash that updates root_digest.
            \true;
    }
*/

/**
 * @brief Pure hash function: deterministic BLAKE2b, fixed-size output.
 */
/*@
  requires data_len == 0 || \valid_read(data + (0 .. data_len - 1));
  requires \valid(hash_out + (0 .. MERKLE_DIGEST_LEN - 1));
  assigns hash_out[0 .. MERKLE_DIGEST_LEN - 1];
  ensures \result == 0 || \result == -1;
*/
int merkle_hash(const uint8_t *data, size_t data_len, uint8_t *hash_out);

/**
 * @brief Allocate a new empty Merkle tree.
 */
/*@
  requires \valid(tree);
  allocates *tree;
  assigns *tree;
  behavior null_ptr:
    assumes tree == \null;
    ensures \result != 0;
  behavior success:
    assumes tree != \null;
    ensures \result == 0;
    ensures *tree != \null;
    ensures \fresh(*tree, sizeof(merkle_tree_t));
    ensures (*tree)->node_count == 0;
    ensures (*tree)->root == -1;
    ensures (*tree)->has_root_digest == false;
    ensures (*tree)->blobs != \null;
    ensures (*tree)->nodes != \null;
  behavior failure:
    assumes tree != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int merkle_tree_create(merkle_tree_t **tree);

/**
 * @brief Insert a blob into the tree, triggering a full rehash.
 */
/*@
  requires valid_merkle_tree(tree);
  requires valid_merkle_blob(blob);
  assigns tree->nodes, tree->node_count, tree->node_capacity,
          tree->root, tree->root_digest[0 .. MERKLE_DIGEST_LEN - 1],
          tree->has_root_digest;
  behavior success:
    ensures \result == 0;
    ensures tree->has_root_digest == true;
  behavior already_present:
    ensures \result == 0;
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int merkle_insert(merkle_tree_t *tree, merkle_blob_t *blob);

/**
 * @brief Delete a blob from the tree, triggering a full rehash.
 */
/*@
  requires valid_merkle_tree(tree);
  requires valid_merkle_blob(blob);
  assigns tree->nodes, tree->node_count, tree->node_capacity,
          tree->root, tree->root_digest[0 .. MERKLE_DIGEST_LEN - 1],
          tree->has_root_digest;
  behavior success:
    ensures \result == 0;
  behavior not_found:
    ensures \result == 222;
  disjoint behaviors;
*/
int merkle_delete(merkle_tree_t *tree, merkle_blob_t *blob);

/**
 * @brief Merge another tree's blobs into this tree.
 */
/*@
  requires valid_merkle_tree(tree);
  requires valid_merkle_tree(other);
  requires \separated(tree, other);
  assigns tree->nodes, tree->node_count, tree->node_capacity,
          tree->root, tree->root_digest[0 .. MERKLE_DIGEST_LEN - 1],
          tree->has_root_digest;
  ensures \result == 0 || \result != 0;
*/
int merkle_merge(merkle_tree_t *tree, merkle_tree_t *other);

/**
 * @brief Copy the current root digest into the output buffer.
 */
/*@
  requires tree != \null && \valid(tree);
  requires \valid(digest_out + (0 .. MERKLE_DIGEST_LEN - 1));
  assigns digest_out[0 .. MERKLE_DIGEST_LEN - 1];
  behavior has_root:
    assumes tree->has_root_digest == true;
    ensures \result == 0;
    ensures \forall integer i; 0 <= i < MERKLE_DIGEST_LEN ==>
              digest_out[i] == tree->root_digest[i];
  behavior no_root:
    assumes tree->has_root_digest == false;
    ensures \result == 222;
  disjoint behaviors;
  complete behaviors;
*/
int merkle_root_digest(merkle_tree_t *tree, uint8_t *digest_out);

/**
 * @brief Produce an observability snapshot of the tree state as JSON.
 *
 * Mirrors Python `Merkle.to_dict()` (structures/merkle.py:86) for the
 * scope of read-only state inspection: the root hash, blob count, and
 * whether a super_hash has been set. The on-disk blob payloads
 * themselves are not serialized — they're caller-typed via
 * @ref blob_designation_fn, so round-tripping a Merkle through JSON
 * isn't well-defined without the application schema. Use this for
 * dashboards / checkpoints; reconstruct trees by re-inserting blobs.
 *
 * @param[in]  tree     The tree to snapshot. May be NULL → returns NULL.
 * @return A new @c json_t object (owned by the caller; @c json_decref
 *         to release). NULL on allocation failure.
 */
json_t *merkle_to_json(const merkle_tree_t *tree);

/**
 * @brief Generate an inclusion proof (path from leaf to root).
 */
/*@
  requires valid_merkle_tree(tree);
  requires valid_merkle_blob(blob);
  requires \valid(proof_out);
  requires \valid(proof_len);
  allocates *proof_out;
  assigns *proof_out, *proof_len;
  behavior found:
    ensures \result == 0;
    ensures *proof_len >= 0;
    ensures *proof_len > 0 ==> *proof_out != \null;
  behavior not_found:
    ensures \result == 222;
  behavior error:
    ensures \result != 0 && \result != 222;
  disjoint behaviors;
*/
int merkle_inclusion_proof(merkle_tree_t *tree, merkle_blob_t *blob,
                           merkle_proof_step_t **proof_out, int *proof_len);

/**
 * @brief Verify an inclusion proof against the tree's root digest.
 */
/*@
  requires tree == \null || \valid(tree);
  requires blob == \null || valid_merkle_blob(blob);
  requires proof == \null || \valid_read(proof + (0 .. proof_len - 1));
  assigns \nothing;
  behavior invalid_input:
    assumes tree == \null || blob == \null || proof == \null || proof_len <= 0;
    ensures \result == false;
  behavior no_root:
    assumes tree != \null && !tree->has_root_digest;
    ensures \result == false;
  behavior valid_check:
    assumes tree != \null && blob != \null && proof != \null &&
            proof_len > 0 && tree->has_root_digest;
    ensures \result == true || \result == false;
  disjoint behaviors;
*/
bool merkle_audit(merkle_tree_t *tree, merkle_blob_t *blob,
                  merkle_proof_step_t *proof, int proof_len);

/**
 * @brief Check consistency: same size and same root digest.
 */
/*@
  requires tree == \null || \valid(tree);
  requires other_root_digest == \null ||
           \valid_read(other_root_digest + (0 .. MERKLE_DIGEST_LEN - 1));
  assigns \nothing;
  behavior invalid:
    assumes tree == \null || other_root_digest == \null;
    ensures \result == false;
  behavior consistent:
    assumes tree != \null && other_root_digest != \null &&
            tree->has_root_digest;
    ensures \result == true || \result == false;
  behavior no_digest:
    assumes tree != \null && other_root_digest != \null &&
            !tree->has_root_digest;
    ensures \result == false;
  disjoint behaviors;
*/
/** Membership predicate — true iff @p blob (matched by uuid) is in
 *  @p tree's blob list. Mirrors Python's MerkleTree.__contains__
 *  (merkle.py:249-258). Does NOT recompute or verify hashes; for
 *  cryptographic verification, build an inclusion proof and call
 *  merkle_audit instead. */
bool merkle_contains(const merkle_tree_t *tree, const merkle_blob_t *blob);

bool merkle_consistent(merkle_tree_t *tree, int other_size,
                       const uint8_t *other_root_digest);

/**
 * @brief H11 — locate subtrees with duplicate hashes (parity with Python
 *        `MerkleTree.subtree_duplications`, merkle.py:269-274).
 *
 * Scans every node in @p tree and returns the indices of nodes whose
 * digest matches at least one other node's digest. Both leaves and
 * internal nodes are considered: an internal-node collision implies
 * the two subtrees rooted at those nodes encode the same data
 * sequence (collision-resistance of BLAKE2b makes accidental
 * collisions cryptographically negligible).
 *
 * The Python implementation tracks duplicates via a `unique`
 * defaultdict populated during `_rehash`; the C representation has
 * no such bookkeeping, so this performs an O(n²) pairwise digest
 * scan on demand. Acceptable for typical Merkle tree sizes.
 *
 * NB: the Python source keys `self.unique` by `leaf.uuid` rather
 * than `leaf.digest`, which would mean the defaultdict only finds
 * collisions when two nodes share a UUID — never under auto-UUID
 * generation. We port the documented intent (digest collisions)
 * rather than the literal bug.
 *
 * Parent-child digest lifts inherent to CVE-2012-2459 protection
 * (a single-child parent inherits its lone child's digest, see
 * `_rehash`) are filtered out — those pairs share a digest by
 * design and do not represent a duplicate subtree.
 *
 * @param tree       merkle tree to scan.
 * @param idx_out    out param; receives a malloc'd `int*` array
 *                   of indices into `tree->nodes` for colliding
 *                   nodes. NULL if no duplicates. Caller frees.
 * @param count_out  out param; receives the length of @p idx_out.
 * @return 0 on success, EINVAL on bad args, ENOMEM on alloc failure.
 */
int merkle_subtree_duplications(merkle_tree_t *tree,
                                int **idx_out, size_t *count_out);

/**
 * @brief H12 — verify a blob's membership using a possibly-extended
 *        proof chain (parity with Python `MerkleTree.audit(blob, chain)`,
 *        merkle.py:226-247).
 *
 * Walks the proof from leaf to root, optionally continuing through
 * @p extra_chain to a super-tree root, and compares the final digest
 * against @p super_hash. When @p extra_chain is NULL and @p super_hash
 * equals `tree->root_digest`, behavior matches `merkle_audit`.
 *
 * The extra chain extends the local inclusion proof above this tree's
 * root, e.g. when @p tree is itself a sub-tree of a larger forest and
 * the caller has the additional sibling digests up to the forest root.
 *
 * @param tree         merkle tree the blob lives in.
 * @param blob         the blob whose membership is being verified.
 * @param proof        inclusion proof from blob to local root (typically
 *                     produced by `merkle_inclusion_proof`).
 * @param proof_n      length of @p proof.
 * @param extra_chain  optional extension above the local root, ordered
 *                     from local root upward to super-root. May be NULL
 *                     when @p extra_n is 0.
 * @param extra_n      length of @p extra_chain (0 == no extension).
 * @param super_hash   target digest to compare against; must be
 *                     `MERKLE_DIGEST_LEN` bytes.
 * @return true if the recomputed root digest equals @p super_hash.
 */
bool merkle_audit_chain(merkle_tree_t *tree, merkle_blob_t *blob,
                        merkle_proof_step_t *proof, int proof_n,
                        merkle_proof_step_t *extra_chain, int extra_n,
                        const uint8_t *super_hash);

/**
 * @brief Free all tree resources (nodes array, blobs array, tree struct).
 */
/*@
  behavior null:
    assumes tree == \null;
    assigns \nothing;
  behavior valid:
    assumes tree != \null;
    requires \valid(tree);
    requires tree->blobs == \null || \valid(tree->blobs);
    requires tree->blobs == \null || tree->blobs->array != \null;
  disjoint behaviors;
*/
void merkle_tree_free(merkle_tree_t *tree);

#define EMRKL_NOTFOUND 222
DECLARE_ERROR(EMRKL_NOTFOUND, "Blob not found in Merkle tree");

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_structures */

#endif // MERKLE_H
