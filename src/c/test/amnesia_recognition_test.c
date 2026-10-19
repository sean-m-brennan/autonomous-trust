/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/

/* Recognizing a returning node (doc/architecture/identity-protocol.md,
 * "Amnesia"). The welcoming committee used to readmit any uuid already in
 * peers[], by uuid alone, and hand it the group key with no vote: a
 * first-contact direct peer, or anyone presenting a known uuid under keys of
 * their own. Now only a group MEMBER presenting the keys it is known by is
 * readmitted; a known uuid under new keys is refused; any other peer goes to
 * the vote, where duplicate detection lets a recorded contact through. */
#define DEBUG_TESTS 1

#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/id_ext.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "structures/array.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"
#include "utilities/util.h"

static char ID_ANNOUNCE_FN[] = "request_access";
static char ID_PROPOSE_FN[]  = "propose_peer";
static char NET_NAME[]       = "network";
static char ID_NAME[]        = "identity";

/* What the identity process handed the network process, by function. */
static size_t g_histories, g_proposals, g_votes;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type != NET_MESSAGE || key == NULL || strcmp(key, NET_NAME) != 0
        || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, "full_history") == 0)
        g_histories++;
    else if (strcmp(fn, "propose_peer") == 0)
        g_proposals++;
    else if (strcmp(fn, "vote_on_peer") == 0)
        g_votes++;
    return 0;
}

/* A stand-in for first contact's address book: the one uuid it holds. */
static char g_contact[UUID_STRING_LEN + 1];

static bool _test_is_contact(const process_t *proc, const char *uuid_str)
{
    (void)proc;
    return g_contact[0] != '\0' && strcmp(uuid_str, g_contact) == 0;
}

static const identity_ext_t test_contacts_ext = {
    .name = "test_contacts",
    .is_contact = _test_is_contact,
};

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    static bool registered = false;
    if (!registered) {
        ck_assert_int_eq(identity_ext_register(&test_contacts_ext), 0);
        registered = true;
    }
    identity_reset_state();
    g_histories = g_proposals = g_votes = 0;
    g_contact[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    identity_set_synchronous_dispatch(false);
    messaging_set_test_hook(NULL);
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    return ident;
}

/* An identity process holding a keyed group with self as its only member. */
static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    char self_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid);
    group_add_address(&proc->protocol.group, self_uuid, self->address);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    return proc;
}

static void _publish(const identity_t *who, public_identity_t *out)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(who, &pub));
    memcpy(out, pub, sizeof(*out));
    smrt_deref(pub);
}

/* Hold @p who in peers[], as a first-contact admission would. */
static void _add_peer(process_t *proc, const identity_t *who)
{
    _publish(who, &proc->protocol.peers[proc->protocol.num_peers++]);
}

/* ...and in the group address map too: a member. */
static void _add_member(process_t *proc, const identity_t *who)
{
    _add_peer(proc, who);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    group_add_address(&proc->protocol.group, u, who->address);
}

static bool _is_member(process_t *proc, const identity_t *who)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    data_t *v = NULL;
    return map_get(&proc->protocol.group.address_map, u, &v) == 0;
}

static string_t _member_address(process_t *proc, const identity_t *who)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    data_t *v = NULL;
    string_t addr = NULL;
    if (map_get(&proc->protocol.group.address_map, u, &v) == 0)
        (void)data_string_ptr(v, &addr);
    return addr;
}

static directory_t *_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    return queues;
}

/* Dispatch a request_access from @p from (as published), unencrypted, with
 * the empty payload an untargeted request carries in the harness. */
static void _dispatch_request(process_t *proc, const public_identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ANNOUNCE_FN;
    memcpy(&msg.info.net_msg.from_whom, from, sizeof(*from));
    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
}

/* Dispatch a propose_peer naming @p candidate, from @p proposer. */
static void _dispatch_proposal(process_t *proc, const identity_t *proposer,
                               const identity_t *candidate)
{
    public_identity_t cand;
    _publish(candidate, &cand);
    json_t *body = NULL;
    ck_assert_ret_ok(public_identity_to_json(&cand, &body));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_PROPOSE_FN;
    msg.info.net_msg.verified = true;
    _publish(proposer, &msg.info.net_msg.from_whom);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
    net_msg_free_obj(&msg.info.net_msg);
}

/* A member that lost its state comes back with the keys we know: readmitted
 * on recognition, no vote. */
DEFINE_TEST(test_a_returning_member_is_readmitted_without_a_vote)
{
    _begin();
    identity_t *me = _mk_identity("guard", "10.0.0.1");
    identity_t *mem = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, mem);

    public_identity_t from;
    _publish(mem, &from);
    _dispatch_request(proc, &from);

    ck_assert_uint_eq(g_histories, 1);
    ck_assert_uint_eq(g_proposals, 0);
    _end();
}
END_TEST_DEFINITION()

/* THE HOLE. A peer that is not a member -- a first-contact direct peer -- is
 * not readmitted: it is proposed, and no group key leaves until the vote. */
DEFINE_TEST(test_a_peer_that_is_not_a_member_goes_to_the_vote)
{
    _begin();
    identity_t *me = _mk_identity("guard", "10.0.0.1");
    identity_t *other = _mk_identity("other", "10.0.0.3");
    identity_t *contact = _mk_identity("contact", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, other);       /* so the request is not a bootstrap */
    _add_peer(proc, contact);

    public_identity_t from;
    _publish(contact, &from);
    _dispatch_request(proc, &from);

    ck_assert_uint_eq(g_histories, 0);
    ck_assert(g_proposals >= 1);        /* one unicast per peer */
    ck_assert(!_is_member(proc, contact));
    _end();
}
END_TEST_DEFINITION()

/* A member's uuid under keys we have never seen is refused outright: neither
 * readmitted (C used to encrypt the key to whatever keys came with the
 * request) nor proposed. */
DEFINE_TEST(test_a_known_uuid_under_new_keys_is_refused)
{
    _begin();
    identity_t *me = _mk_identity("guard", "10.0.0.1");
    identity_t *mem = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, mem);

    public_identity_t from;
    _publish(mem, &from);
    crypto_sign_keypair(from.signature.public, from.signature.private);
    hexlify(from.signature.public, crypto_sign_PUBLICKEYBYTES,
            from.signature.public_hex);
    crypto_box_keypair(from.encryptor.public, from.encryptor.private);
    hexlify(from.encryptor.public, crypto_box_PUBLICKEYBYTES,
            from.encryptor.public_hex);
    _dispatch_request(proc, &from);

    ck_assert_uint_eq(g_histories, 0);
    ck_assert_uint_eq(g_proposals, 0);
    _end();
}
END_TEST_DEFINITION()

/* Address is not part of recognition: a member that moved networks is
 * readmitted, and its new address replaces the old one. */
DEFINE_TEST(test_a_member_that_moved_is_readmitted_at_its_new_address)
{
    _begin();
    identity_t *me = _mk_identity("guard", "10.0.0.1");
    identity_t *mem = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, mem);

    public_identity_t from;
    _publish(mem, &from);
    at_strlcpy(from.address, "10.0.77.9", sizeof(from.address));
    _dispatch_request(proc, &from);

    ck_assert_uint_eq(g_histories, 1);
    ck_assert_uint_eq(g_proposals, 0);
    ck_assert_str_eq(_member_address(proc, mem), "10.0.77.9");
    ck_assert_str_eq(proc->protocol.peers[0].address, "10.0.77.9");
    _end();
}
END_TEST_DEFINITION()

/* Duplicate detection: a recorded contact in peers[], with the keys it is
 * known by, is voted on; the same peer without the contact record collides. */
DEFINE_TEST(test_a_recorded_contact_is_voted_on)
{
    _begin();
    identity_set_synchronous_dispatch(true);
    identity_t *me = _mk_identity("voter", "10.0.0.1");
    identity_t *proposer = _mk_identity("proposer", "10.0.0.4");
    identity_t *contact = _mk_identity("contact", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, proposer);
    _add_peer(proc, contact);

    _dispatch_proposal(proc, proposer, contact);
    ck_assert_uint_eq(g_votes, 0);          /* not a contact: a collision */

    uuid_unparse_lower(contact->uuid, g_contact);
    _dispatch_proposal(proc, proposer, contact);
    ck_assert_uint_eq(g_votes, 1);
    _end();
}
END_TEST_DEFINITION()

/* ...but only as the keyholder it is known as, and only while not a member. */
DEFINE_TEST(test_a_contact_is_exempt_only_with_its_keys_and_as_a_non_member)
{
    _begin();
    identity_set_synchronous_dispatch(true);
    identity_t *me = _mk_identity("voter", "10.0.0.1");
    identity_t *proposer = _mk_identity("proposer", "10.0.0.4");
    identity_t *contact = _mk_identity("contact", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, proposer);
    _add_peer(proc, contact);
    uuid_unparse_lower(contact->uuid, g_contact);

    /* Same uuid, other keys: a different keyholder claiming the contact. */
    identity_t *impostor = NULL;
    ck_assert_ret_ok(identity_create(&contact->uuid, contact->address, "contact",
                                     "contact", &impostor));
    _dispatch_proposal(proc, proposer, impostor);
    ck_assert_uint_eq(g_votes, 0);

    /* Already a member: nothing to vote on. */
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(contact->uuid, u);
    group_add_address(&proc->protocol.group, u, contact->address);
    _dispatch_proposal(proc, proposer, contact);
    ck_assert_uint_eq(g_votes, 0);
    _end();
}
END_TEST_DEFINITION()

/* A contact the vote admits was in peers[] before it was a member, so the
 * admission must still put it in the group (and the key follow), though
 * _add_peer has nothing to add. */
DEFINE_TEST(test_a_contact_the_vote_admits_becomes_a_member)
{
    _begin();
    identity_t *me = _mk_identity("guard", "10.0.0.1");
    identity_t *contact = _mk_identity("contact", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, contact);
    directory_t *queues = _queues();

    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(contact, &pub));
    identity_arm_pending_vote(pub, 2, -1.0);   /* both of the two: a majority */
    identity_periodic_vote_collection(proc, queues);

    ck_assert_uint_eq(g_histories, 1);
    ck_assert(_is_member(proc, contact));
    ck_assert_uint_eq(proc->protocol.num_peers, 1);   /* not listed twice */

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(AmnesiaRecognition,
          test_a_contact_the_vote_admits_becomes_a_member,
          test_a_returning_member_is_readmitted_without_a_vote,
          test_a_peer_that_is_not_a_member_goes_to_the_vote,
          test_a_known_uuid_under_new_keys_is_refused,
          test_a_member_that_moved_is_readmitted_at_its_new_address,
          test_a_recorded_contact_is_voted_on,
          test_a_contact_is_exempt_only_with_its_keys_and_as_a_non_member)
