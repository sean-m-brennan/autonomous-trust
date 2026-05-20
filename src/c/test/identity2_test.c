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
#include <pthread.h>
#include <sodium.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"

DEFINE_TEST(test_peers_max_count_default)
{
    ck_assert(sodium_init() >= 0);

    /* Default value should be DEFAULT_MAX_PEERS */
    ck_assert_uint_eq(peers_max_count(), DEFAULT_MAX_PEERS);
    ck_assert_uint_eq(MAX_PEERS, DEFAULT_MAX_PEERS);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peers_set_max_count)
{
    ck_assert(sodium_init() >= 0);

    /* Set to a smaller value */
    peers_set_max_count(64);
    ck_assert_uint_eq(peers_max_count(), 64);
    ck_assert_uint_eq(MAX_PEERS, 64);

    /* Cannot exceed DEFAULT_MAX_PEERS */
    peers_set_max_count(DEFAULT_MAX_PEERS + 100);
    ck_assert_uint_eq(peers_max_count(), 64);  /* unchanged */

    /* Cannot set to 0 */
    peers_set_max_count(0);
    ck_assert_uint_eq(peers_max_count(), 64);  /* unchanged */

    /* Restore default */
    peers_set_max_count(DEFAULT_MAX_PEERS);
    ck_assert_uint_eq(peers_max_count(), DEFAULT_MAX_PEERS);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "10.0.0.99";
    char name[] = "Proto Node";
    char nick[] = "PN";
    char pet[] = "proto-n";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, pet, &ident));

    /* Publish to public identity */
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));

    /* Serialize public identity to protobuf */
    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(peer_to_proto(pub, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    /* Deserialize from protobuf */
    public_identity_t pub2;
    memset(&pub2, 0, sizeof(public_identity_t));
    ck_assert_ret_ok(proto_to_peer((uint8_t *)data, data_len, &pub2));

    /* Verify all fields survive roundtrip */
    ck_assert_str_eq(pub2.address, "10.0.0.99");
    ck_assert_str_eq(pub2.fullname, "Proto Node");
    ck_assert_str_eq(pub2.nickname, "PN");
    ck_assert_str_eq(pub2.petname, "proto-n");
    ck_assert_mem_eq(pub2.uuid, uuid, sizeof(uuid_t));

    free(data);
    smrt_deref(pub);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_json_nickname_petname)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "192.168.0.1";
    char name[] = "Full Name";
    char nick[] = "Nicky";
    char pet[] = "my-pet";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, pet, &ident));

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(identity_to_json(ident, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Verify nickname and petname in JSON */
    const char *j_nick = json_string_value(json_object_get(obj, "nickname"));
    const char *j_pet = json_string_value(json_object_get(obj, "petname"));
    ck_assert_ptr_nonnull(j_nick);
    ck_assert_ptr_nonnull(j_pet);
    ck_assert_str_eq(j_nick, "Nicky");
    ck_assert_str_eq(j_pet, "my-pet");

    /* Deserialize and verify */
    identity_t ident2;
    memset(&ident2, 0, sizeof(identity_t));
    ck_assert_ret_ok(identity_from_json(obj, &ident2));
    ck_assert_str_eq(ident2.nickname, "Nicky");
    ck_assert_str_eq(ident2.petname, "my-pet");
    ck_assert_str_eq(ident2.fullname, "Full Name");
    ck_assert_str_eq(ident2.address, "192.168.0.1");

    json_decref(obj);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_create_null_names)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "10.0.0.1";
    char name[] = "Just Name";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, NULL, NULL, &ident));
    ck_assert_ptr_nonnull(ident);

    /* nickname and petname should be empty strings when NULL passed */
    ck_assert_str_eq(ident->nickname, "");
    ck_assert_str_eq(ident->petname, "");
    ck_assert_str_eq(ident->fullname, "Just Name");

    identity_free(ident);
}
END_TEST_DEFINITION()

/* Regression for id_proc.c:522 — handle_count_vote used to do an
 * unsynchronised read-modify-write of id_state.vote_collection AND call
 * pthread_mutex_unlock without a matching lock (see BUGS.md C6).  The fix
 * hoists the critical section into vote_collection_increment(), which takes
 * id_state.lock internally.  This test spawns N threads that each call the
 * helper M times for the same uuid_key; the final count must equal N*M
 * exactly.  Under the original unsynchronised code, concurrent
 * read-modify-writes would lose updates and the final count would be < N*M. */

typedef struct {
    const char *uuid_key;
    int iterations;
} _c6_ctx_t;

static void *_c6_voter(void *arg)
{
    _c6_ctx_t *c = (_c6_ctx_t *)arg;
    for (int i = 0; i < c->iterations; i++)
        (void)vote_collection_increment(c->uuid_key);
    return NULL;
}

DEFINE_TEST(test_vote_collection_increment_is_race_free)
{
    /* Warm-up: first-time id_state initialisation is not itself serialised
     * (see _ensure_id_init), so call from the main thread once before
     * spawning to avoid racing the init path.  A distinct uuid is used so
     * the target key still starts at zero. */
    (void)vote_collection_increment("c6-warmup-xxxx-xxxx-xxxx-xxxxxxxxxxxx");

    const char *uuid_key = "c6-test-aaaa-bbbb-cccc-dddddddddddd";

    enum { NTHREADS = 8, ITERS = 256 };
    pthread_t threads[NTHREADS];
    _c6_ctx_t ctx = { uuid_key, ITERS };

    for (int i = 0; i < NTHREADS; i++)
        ck_assert_int_eq(pthread_create(&threads[i], NULL, _c6_voter, &ctx), 0);
    for (int i = 0; i < NTHREADS; i++)
        ck_assert_int_eq(pthread_join(threads[i], NULL), 0);

    int final_count = 0;
    ck_assert_ret_ok(vote_collection_get(uuid_key, &final_count));
    ck_assert_int_eq(final_count, NTHREADS * ITERS);
}
END_TEST_DEFINITION()

RUN_TESTS(Identity2, test_peers_max_count_default, test_peers_set_max_count,
          test_identity_proto_roundtrip, test_identity_json_nickname_petname,
          test_identity_create_null_names,
          test_vote_collection_increment_is_race_free)
