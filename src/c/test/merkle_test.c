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
#include <sodium.h>

#include "autonomous_trust/structures/merkle.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

/* test blob implementation */
static int _test_get_hash(const merkle_blob_t *blob, const uint8_t *nonce,
                          size_t nonce_len, uint8_t *hash_out)
{
    /* hash the uuid + nonce */
    size_t uuid_len = strlen(blob->uuid);
    size_t total = uuid_len + nonce_len;
    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return -1;
    memcpy(buf, blob->uuid, uuid_len);
    if (nonce != NULL && nonce_len > 0)
        memcpy(buf + uuid_len, nonce, nonce_len);
    int ret = merkle_hash(buf, total, hash_out);
    free(buf);
    return ret;
}

static merkle_blob_t *make_test_blob(const char *uuid)
{
    merkle_blob_t *blob = malloc(sizeof(merkle_blob_t));
    memset(blob, 0, sizeof(merkle_blob_t));
    strncpy(blob->uuid, uuid, MERKLE_UUID_LEN - 1);
    strncpy(blob->originator, "test-orig", MERKLE_UUID_LEN - 1);
    blob->get_hash = _test_get_hash;
    blob->designation = NULL;
    blob->user_data = NULL;
    return blob;
}

DEFINE_TEST(test_merkle_hash)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_assert(0);

    uint8_t data[] = "hello merkle";
    uint8_t hash1[MERKLE_DIGEST_LEN];
    uint8_t hash2[MERKLE_DIGEST_LEN];

    ck_assert_ret_ok(merkle_hash(data, sizeof(data) - 1, hash1));
    ck_assert_ret_ok(merkle_hash(data, sizeof(data) - 1, hash2));
    ck_assert_mem_eq(hash1, hash2, MERKLE_DIGEST_LEN);

    /* different data gives different hash */
    uint8_t data2[] = "hello merkle2";
    ck_assert_ret_ok(merkle_hash(data2, sizeof(data2) - 1, hash2));
    ck_assert(memcmp(hash1, hash2, MERKLE_DIGEST_LEN) != 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_insert)
{
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));
    ck_assert_ptr_nonnull(tree);

    uint8_t root1[MERKLE_DIGEST_LEN];
    memset(root1, 0, MERKLE_DIGEST_LEN);

    merkle_blob_t *blob1 = make_test_blob("blob-1");
    ck_assert_ret_ok(merkle_insert(tree, blob1));

    ck_assert(tree->has_root_digest);
    uint8_t digest1[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree, digest1));

    /* inserting another blob changes root */
    merkle_blob_t *blob2 = make_test_blob("blob-2");
    ck_assert_ret_ok(merkle_insert(tree, blob2));

    uint8_t digest2[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree, digest2));
    ck_assert(memcmp(digest1, digest2, MERKLE_DIGEST_LEN) != 0);

    merkle_tree_free(tree);
    free(blob1);
    free(blob2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_delete)
{
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    merkle_blob_t *blob1 = make_test_blob("del-1");
    merkle_blob_t *blob2 = make_test_blob("del-2");
    ck_assert_ret_ok(merkle_insert(tree, blob1));
    ck_assert_ret_ok(merkle_insert(tree, blob2));

    uint8_t digest_before[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree, digest_before));

    ck_assert_ret_ok(merkle_delete(tree, blob2));

    uint8_t digest_after[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree, digest_after));
    ck_assert(memcmp(digest_before, digest_after, MERKLE_DIGEST_LEN) != 0);

    merkle_tree_free(tree);
    free(blob1);
    free(blob2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_proof_audit)
{
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    merkle_blob_t *blob1 = make_test_blob("proof-1");
    merkle_blob_t *blob2 = make_test_blob("proof-2");
    merkle_blob_t *blob3 = make_test_blob("proof-3");

    ck_assert_ret_ok(merkle_insert(tree, blob1));
    ck_assert_ret_ok(merkle_insert(tree, blob2));
    ck_assert_ret_ok(merkle_insert(tree, blob3));

    /* get inclusion proof for blob2 */
    merkle_proof_step_t *proof = NULL;
    int proof_len = 0;
    ck_assert_ret_ok(merkle_inclusion_proof(tree, blob2, &proof, &proof_len));
    ck_assert_ptr_nonnull(proof);
    ck_assert(proof_len > 0);

    /* audit should verify */
    ck_assert(merkle_audit(tree, blob2, proof, proof_len));

    free(proof);
    merkle_tree_free(tree);
    free(blob1);
    free(blob2);
    free(blob3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_merge)
{
    merkle_tree_t *tree1 = NULL;
    merkle_tree_t *tree2 = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree1));
    ck_assert_ret_ok(merkle_tree_create(&tree2));

    merkle_blob_t *blob1 = make_test_blob("merge-1");
    merkle_blob_t *blob2 = make_test_blob("merge-2");
    merkle_blob_t *blob3 = make_test_blob("merge-3");

    ck_assert_ret_ok(merkle_insert(tree1, blob1));
    ck_assert_ret_ok(merkle_insert(tree2, blob2));
    ck_assert_ret_ok(merkle_insert(tree2, blob3));

    ck_assert_ret_ok(merkle_merge(tree1, tree2));

    /* tree1 now has 3 blobs */
    ck_assert(tree1->has_root_digest);

    merkle_tree_free(tree1);
    merkle_tree_free(tree2);
    free(blob1);
    free(blob2);
    free(blob3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_consistent)
{
    merkle_tree_t *tree1 = NULL;
    merkle_tree_t *tree2 = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree1));
    ck_assert_ret_ok(merkle_tree_create(&tree2));

    merkle_blob_t *blob1 = make_test_blob("cons-1");
    merkle_blob_t *blob2 = make_test_blob("cons-2");

    ck_assert_ret_ok(merkle_insert(tree1, blob1));
    ck_assert_ret_ok(merkle_insert(tree1, blob2));
    ck_assert_ret_ok(merkle_insert(tree2, blob1));
    ck_assert_ret_ok(merkle_insert(tree2, blob2));

    uint8_t digest2[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree2, digest2));

    ck_assert(merkle_consistent(tree1, 2, digest2));

    /* different tree should not be consistent */
    merkle_blob_t *blob3 = make_test_blob("cons-3");
    ck_assert_ret_ok(merkle_insert(tree2, blob3));
    uint8_t digest3[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree2, digest3));
    ck_assert(!merkle_consistent(tree1, 3, digest3));

    merkle_tree_free(tree1);
    merkle_tree_free(tree2);
    free(blob1);
    free(blob2);
    free(blob3);
}
END_TEST_DEFINITION()

/* H11: a fresh tree of unique blobs has no duplicate subtrees. */
DEFINE_TEST(test_merkle_subtree_duplications_none)
{
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    merkle_blob_t *blob1 = make_test_blob("dup-a");
    merkle_blob_t *blob2 = make_test_blob("dup-b");
    merkle_blob_t *blob3 = make_test_blob("dup-c");
    ck_assert_ret_ok(merkle_insert(tree, blob1));
    ck_assert_ret_ok(merkle_insert(tree, blob2));
    ck_assert_ret_ok(merkle_insert(tree, blob3));

    int *idx = NULL;
    size_t count = (size_t)-1;
    ck_assert_ret_ok(merkle_subtree_duplications(tree, &idx, &count));
    ck_assert_int_eq((int)count, 0);
    ck_assert_ptr_null(idx);

    merkle_tree_free(tree);
    free(blob1);
    free(blob2);
    free(blob3);
}
END_TEST_DEFINITION()

/* H12: merkle_audit_chain with no extra chain and super_hash =
 * root_digest is equivalent to merkle_audit (true result). */
DEFINE_TEST(test_merkle_audit_chain_equivalent)
{
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    merkle_blob_t *blob1 = make_test_blob("chain-1");
    merkle_blob_t *blob2 = make_test_blob("chain-2");
    merkle_blob_t *blob3 = make_test_blob("chain-3");
    ck_assert_ret_ok(merkle_insert(tree, blob1));
    ck_assert_ret_ok(merkle_insert(tree, blob2));
    ck_assert_ret_ok(merkle_insert(tree, blob3));

    merkle_proof_step_t *proof = NULL;
    int proof_len = 0;
    ck_assert_ret_ok(merkle_inclusion_proof(tree, blob2, &proof, &proof_len));

    uint8_t root[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(tree, root));

    /* No extra chain: pass-through must match merkle_audit. */
    ck_assert(merkle_audit_chain(tree, blob2, proof, proof_len,
                                 NULL, 0, root));
    /* Mismatched super_hash must reject. */
    uint8_t bogus[MERKLE_DIGEST_LEN] = {0};
    ck_assert(!merkle_audit_chain(tree, blob2, proof, proof_len,
                                  NULL, 0, bogus));

    free(proof);
    merkle_tree_free(tree);
    free(blob1);
    free(blob2);
    free(blob3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_to_json_snapshot)
{
    /* Empty tree → root_digest is null and counts are zero. */
    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    json_t *snap0 = merkle_to_json(tree);
    ck_assert_ptr_nonnull(snap0);
    ck_assert(json_is_null(json_object_get(snap0, "root_digest")));
    ck_assert_int_eq((int)json_integer_value(json_object_get(snap0, "blob_count")), 0);
    ck_assert_int_eq((int)json_integer_value(json_object_get(snap0, "node_count")), 0);
    json_decref(snap0);

    /* After one insert: root_digest is a 64-hex-char string,
     * blob_count == 1, node_count > 0. */
    merkle_blob_t *blob1 = make_test_blob("snap-1");
    ck_assert_ret_ok(merkle_insert(tree, blob1));

    json_t *snap1 = merkle_to_json(tree);
    ck_assert_ptr_nonnull(snap1);
    const char *hex = json_string_value(json_object_get(snap1, "root_digest"));
    ck_assert_ptr_nonnull(hex);
    ck_assert_int_eq((int)strlen(hex), MERKLE_DIGEST_LEN * 2);
    ck_assert_int_eq((int)json_integer_value(json_object_get(snap1, "blob_count")), 1);
    ck_assert(json_integer_value(json_object_get(snap1, "node_count")) > 0);
    json_decref(snap1);

    /* NULL input → NULL out. */
    ck_assert_ptr_null(merkle_to_json(NULL));

    merkle_tree_free(tree);
    free(blob1);
}
END_TEST_DEFINITION()

RUN_TESTS(merkle, test_merkle_hash, test_merkle_insert, test_merkle_delete,
          test_merkle_proof_audit, test_merkle_merge, test_merkle_consistent,
          test_merkle_subtree_duplications_none,
          test_merkle_audit_chain_equivalent,
          test_merkle_to_json_snapshot)
