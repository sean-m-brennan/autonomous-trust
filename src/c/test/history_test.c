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
#include <uuid/uuid.h>

#include "autonomous_trust/identity/history.h"
#include "autonomous_trust/identity/identity.h"
#include "autonomous_trust/identity/identity_priv.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

static public_identity_t *make_test_peer(const char *name)
{
    public_identity_t *peer = malloc(sizeof(public_identity_t));
    memset(peer, 0, sizeof(public_identity_t));
    uuid_generate(peer->uuid);
    strncpy(peer->nickname, name, NAME_LEN);
    strncpy(peer->address, "127.0.0.1", ADDR_LEN);
    /* generate signing keypair */
    crypto_sign_keypair(peer->signature.public, peer->signature.private);
    sodium_bin2hex((char *)peer->signature.public_hex,
                   sizeof(peer->signature.public_hex),
                   peer->signature.public,
                   crypto_sign_PUBLICKEYBYTES);
    return peer;
}

DEFINE_TEST(test_identity_obj_create)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_assert(0);

    public_identity_t *peer = make_test_peer("Alice");
    identity_obj_t *obj = NULL;
    ck_assert_ret_ok(identity_obj_create(peer, "orig-uuid-1234", &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert_str_eq(obj->originator_uuid, "orig-uuid-1234");
    ck_assert(obj->base.get_hash != NULL);

    /* get designation bytes */
    uint8_t *desig = NULL;
    size_t desig_len = 0;
    ck_assert_ret_ok(identity_obj_designation(obj, &desig, &desig_len));
    ck_assert_ptr_nonnull(desig);
    ck_assert(desig_len > 0);
    free(desig);

    /* can compute hash */
    uint8_t hash[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(obj->base.get_hash(&obj->base, NULL, 0, hash));

    identity_obj_free(obj);
    free(peer);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_history_create_and_insert)
{
    public_identity_t *me = make_test_peer("Self");
    peers_t peers;
    memset(&peers, 0, sizeof(peers_t));

    agreement_voter_t voter = {.rank = 1};
    char uuid_str[37];
    uuid_unparse_lower(me->uuid, uuid_str);
    strncpy(voter.uuid, uuid_str, AGREEMENT_UUID_LEN - 1);
    voter.uuid[AGREEMENT_UUID_LEN - 1] = '\0';

    logger_t logger = {0};

    identity_history_t *history = NULL;
    ck_assert_ret_ok(identity_history_create(&voter, &peers, &logger, 0, &history));
    ck_assert_ptr_nonnull(history);

    /* insert a peer */
    public_identity_t *bob = make_test_peer("Bob");
    ck_assert_ret_ok(identity_history_insert_peer(history, bob));

    /* merkle tree should now have entries */
    ck_assert(history->merkle->has_root_digest);

    identity_history_free(history);
    free(me);
    free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_history_share_hear)
{
    /* create a full identity for signing */
    identity_t *signer = NULL;
    ck_assert_ret_ok(identity_create(NULL, "127.0.0.1", "Sharer",
                                     "sharer", &signer));

    peers_t peers;
    memset(&peers, 0, sizeof(peers_t));

    agreement_voter_t voter = {.rank = 1};
    char uuid_str[37];
    uuid_unparse_lower(signer->uuid, uuid_str);
    strncpy(voter.uuid, uuid_str, AGREEMENT_UUID_LEN - 1);
    voter.uuid[AGREEMENT_UUID_LEN - 1] = '\0';

    logger_t logger = {0};
    identity_history_t *history = NULL;
    ck_assert_ret_ok(identity_history_create(&voter, &peers, &logger, 0, &history));

    public_identity_t *p1 = make_test_peer("Peer1");
    public_identity_t *p2 = make_test_peer("Peer2");
    ck_assert_ret_ok(identity_history_insert_peer(history, p1));
    ck_assert_ret_ok(identity_history_insert_peer(history, p2));

    /* share the history as a signed wire buffer */
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(identity_history_share(history, signer, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);
    ck_assert(wire_len > 0);

    /* create a second history to receive into */
    identity_history_t *receiver = NULL;
    ck_assert_ret_ok(identity_history_create(&voter, &peers, &logger, 0, &receiver));

    /* hear should verify signature and ingest */
    public_identity_t *pub = (public_identity_t *)signer;
    ck_assert_ret_ok(identity_history_hear(receiver, pub, wire, wire_len));

    free(wire);
    identity_history_free(receiver);
    identity_history_free(history);
    smrt_deref(signer);
    free(p1);
    free(p2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_history_merkle_changes)
{
    public_identity_t *me = make_test_peer("Root");
    peers_t peers;
    memset(&peers, 0, sizeof(peers_t));

    agreement_voter_t voter = {.rank = 1};
    char uuid_str[37];
    uuid_unparse_lower(me->uuid, uuid_str);
    strncpy(voter.uuid, uuid_str, AGREEMENT_UUID_LEN - 1);
    voter.uuid[AGREEMENT_UUID_LEN - 1] = '\0';

    logger_t logger = {0};
    identity_history_t *history = NULL;
    ck_assert_ret_ok(identity_history_create(&voter, &peers, &logger, 0, &history));

    /* insert first peer - get digest */
    public_identity_t *p1 = make_test_peer("First");
    ck_assert_ret_ok(identity_history_insert_peer(history, p1));
    uint8_t digest1[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(history->merkle, digest1));

    /* insert second peer - digest should change */
    public_identity_t *p2 = make_test_peer("Second");
    ck_assert_ret_ok(identity_history_insert_peer(history, p2));
    uint8_t digest2[MERKLE_DIGEST_LEN];
    ck_assert_ret_ok(merkle_root_digest(history->merkle, digest2));

    ck_assert(memcmp(digest1, digest2, MERKLE_DIGEST_LEN) != 0);

    identity_history_free(history);
    free(me);
    free(p1);
    free(p2);
}
END_TEST_DEFINITION()

RUN_TESTS(history, test_identity_obj_create,
          test_identity_history_create_and_insert,
          test_identity_history_share_hear,
          test_identity_history_merkle_changes)
