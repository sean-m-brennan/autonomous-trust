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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "structures/merkle.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

/* Test blob designation function */
static const uint8_t *test_designation(void *user_data, size_t *len)
{
    const char *s = (const char *)user_data;
    *len = strlen(s);
    return (const uint8_t *)s;
}

static merkle_blob_t make_test_blob(const char *name, uuid_t uuid)
{
    merkle_blob_t blob;
    memset(&blob, 0, sizeof(blob));
    uuid_copy(blob.uuid, uuid);
    uuid_copy(blob.originator, uuid);
    blob.user_data = (void *)name;
    blob.designation = test_designation;
    return blob;
}

DEFINE_TEST(test_merkle_hash)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    uint8_t hash1[MERKLE_HASH_LEN];
    uint8_t hash2[MERKLE_HASH_LEN];

    ck_assert_ret_ok(merkle_hash((const uint8_t *)"hello", 5, hash1));
    ck_assert_ret_ok(merkle_hash((const uint8_t *)"hello", 5, hash2));

    /* Same input → same hash */
    ck_assert_int_eq(memcmp(hash1, hash2, MERKLE_HASH_LEN), 0);

    /* Different input → different hash */
    ck_assert_ret_ok(merkle_hash((const uint8_t *)"world", 5, hash2));
    ck_assert_int_ne(memcmp(hash1, hash2, MERKLE_HASH_LEN), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_tree_create)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));
    ck_assert_ptr_nonnull(tree);
    ck_assert_int_eq(merkle_tree_size(tree), 0);
    ck_assert_ptr_null(merkle_tree_root_digest(tree));

    merkle_tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_insert_and_contains)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    uuid_t u1, u2, u3;
    uuid_generate(u1);
    uuid_generate(u2);
    uuid_generate(u3);

    merkle_blob_t blob1 = make_test_blob("alice", u1);
    merkle_blob_t blob2 = make_test_blob("bob", u2);
    merkle_blob_t blob3 = make_test_blob("charlie", u3);

    ck_assert_ret_ok(merkle_tree_insert(tree, &blob1));
    ck_assert_int_eq(merkle_tree_size(tree), 1);
    ck_assert_ptr_nonnull(merkle_tree_root_digest(tree));

    ck_assert_ret_ok(merkle_tree_insert(tree, &blob2));
    ck_assert_int_eq(merkle_tree_size(tree), 2);

    ck_assert_ret_ok(merkle_tree_insert(tree, &blob3));
    ck_assert_int_eq(merkle_tree_size(tree), 3);

    /* Contains checks */
    ck_assert(merkle_tree_contains(tree, &blob1));
    ck_assert(merkle_tree_contains(tree, &blob2));
    ck_assert(merkle_tree_contains(tree, &blob3));

    /* Unknown blob */
    uuid_t u4;
    uuid_generate(u4);
    merkle_blob_t blob4 = make_test_blob("dave", u4);
    ck_assert(!merkle_tree_contains(tree, &blob4));

    merkle_tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_inclusion_proof)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    uuid_t u1, u2, u3, u4;
    uuid_generate(u1);
    uuid_generate(u2);
    uuid_generate(u3);
    uuid_generate(u4);

    merkle_blob_t blobs[4] = {
        make_test_blob("alpha", u1),
        make_test_blob("beta", u2),
        make_test_blob("gamma", u3),
        make_test_blob("delta", u4),
    };

    for (int i = 0; i < 4; i++)
        ck_assert_ret_ok(merkle_tree_insert(tree, &blobs[i]));

    const uint8_t *root = merkle_tree_root_digest(tree);
    ck_assert_ptr_nonnull(root);

    /* Verify proof for each blob */
    for (int i = 0; i < 4; i++)
    {
        merkle_proof_t proof = {0};
        ck_assert_ret_ok(merkle_inclusion_proof(tree, &blobs[i], &proof));
        ck_assert(merkle_audit(root, &blobs[i], &proof));
        merkle_proof_free(&proof);
    }

    /* Proof for unknown blob should fail */
    uuid_t u5;
    uuid_generate(u5);
    merkle_blob_t unknown = make_test_blob("unknown", u5);
    merkle_proof_t bad_proof = {0};
    ck_assert_ret_nonzero(merkle_inclusion_proof(tree, &unknown, &bad_proof));

    merkle_tree_free(tree);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_merkle_delete)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    merkle_tree_t *tree = NULL;
    ck_assert_ret_ok(merkle_tree_create(&tree));

    uuid_t u1, u2;
    uuid_generate(u1);
    uuid_generate(u2);
    merkle_blob_t b1 = make_test_blob("one", u1);
    merkle_blob_t b2 = make_test_blob("two", u2);

    ck_assert_ret_ok(merkle_tree_insert(tree, &b1));
    ck_assert_ret_ok(merkle_tree_insert(tree, &b2));
    ck_assert_int_eq(merkle_tree_size(tree), 2);

    ck_assert_ret_ok(merkle_tree_delete(tree, &b1));
    ck_assert_int_eq(merkle_tree_size(tree), 1);
    ck_assert(!merkle_tree_contains(tree, &b1));
    ck_assert(merkle_tree_contains(tree, &b2));

    merkle_tree_free(tree);
}

RUN_TESTS(Merkle, test_merkle_hash, test_merkle_tree_create,
          test_merkle_insert_and_contains, test_merkle_inclusion_proof,
          test_merkle_delete)
