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

/** @file A catch-up reply too large for one datagram goes as pages.
 *
 *  Partition cohort part-3629127 (2026-10-14, ISSUES §2.67): the whole
 *  resident window a `latest update` carries came to 104 KB once commit and
 *  placement certificates rode on every entry, and the UDP transport cut each
 *  reply to 65,507 bytes. The island that had been behind never caught up. A
 *  window over the page size now goes as {page, of, head, chain} pages, and the
 *  receiver handles the window only once every page of one head from one
 *  sender is in.
 *
 *  The conformance harness resets the reputation state before every step, so
 *  assembly across pages is pinned here (and in Python's test_update_pages.py).
 *  Dispatch follows rep_quorum_test.c.
 */

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
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char LATEST_UPDATE_FN[] = "latest update";
static char UPDATE_NEEDED_FN[] = "update needed";

#define ENTRIES 20
#define MAX_SENT 64

/* Every `latest update` this node sent, parsed. */
static json_t *g_sent[MAX_SENT];
static size_t g_num_sent;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, LATEST_UPDATE_FN) != 0
        || g_num_sent == MAX_SENT)
        return 0;
    json_error_t err;
    g_sent[g_num_sent++] = json_loadb((const char *)msg->info.net_msg.obj,
                                      msg->info.net_msg.len, 0, &err);
    return 0;
}

static void _forget_sent(void)
{
    for (size_t i = 0; i < g_num_sent; i++)
        json_decref(g_sent[i]);
    g_num_sent = 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    reputation_reset_state(1);
    reputation_set_num_updates(1);
    _forget_sent();
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    _forget_sent();
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

static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    proc->protocol.num_peers = 0;

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    return proc;
}

static void _dispatch(process_t *proc, identity_t *sender, char *function,
                      json_t *payload)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    smrt_deref(pub);
}

/* ENTRIES bilateral entries between @p a and @p b, in our own chain. */
static void _stage_chain(const identity_t *a, const identity_t *b)
{
    for (int i = 0; i < ENTRIES; i++)
    {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, a->uuid, 0.3 + 0.01 * i,
                                   b->uuid, 0.9 - 0.01 * i);
    }
}

/* Ask @p proc for its chain, as @p asker, at a page size of @p bytes; the
 * replies land in g_sent. */
static void _ask(process_t *proc, identity_t *asker, size_t bytes)
{
    reputation_set_update_page_bytes(bytes);
    json_t *len = json_integer(0);
    _dispatch(proc, asker, UPDATE_NEEDED_FN, len);
    json_decref(len);
}

/* The staged chain's pages at a 1000-byte page size, as the wire carries
 * them; the caller owns the array. */
static json_t *_pages_of_a_staged_chain(identity_t *me, identity_t *bob)
{
    _begin();
    process_t *proc = _mk_process(me);
    _stage_chain(me, bob);
    _ask(proc, bob, 1000);
    json_t *pages = json_array();
    for (size_t i = 0; i < g_num_sent; i++)
        json_array_append(pages, g_sent[i]);
    _forget_sent();
    return pages;
}

DEFINE_TEST(test_a_window_over_the_page_size_goes_in_pages)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _stage_chain(me, bob);

    _ask(proc, bob, 0);                     /* default: fits in one */
    ck_assert_int_eq((int)g_num_sent, 1);
    ck_assert(json_is_array(g_sent[0]));    /* unpaged, as before */
    json_t *whole = json_incref(g_sent[0]);
    _forget_sent();

    _ask(proc, bob, 1000);
    ck_assert(g_num_sent > 1);
    char head[TX_HASH_HEX_LEN + 1] = {0};
    reputation_get_head_hash(head);
    json_t *joined = json_array();
    for (size_t i = 0; i < g_num_sent; i++)
    {
        json_t *p = g_sent[i];
        ck_assert(json_is_object(p));
        ck_assert_int_eq((int)json_integer_value(json_object_get(p, "page")), (int)i);
        ck_assert_int_eq((int)json_integer_value(json_object_get(p, "of")),
                         (int)g_num_sent);
        ck_assert_str_eq(json_string_value(json_object_get(p, "head")), head);
        ck_assert(json_object_get(p, "group") == NULL);   /* primary chain */
        json_t *chunk = json_object_get(p, "chain");
        char *text = json_dumps(chunk, JSON_COMPACT);
        /* Within the page size, unless one entry is larger by itself. */
        ck_assert(strlen(text) <= 1000 || json_array_size(chunk) == 1);
        free(text);
        json_array_extend(joined, chunk);
    }
    /* Together, exactly the window an unpaged reply carries. */
    ck_assert(json_equal(joined, whole));
    ck_assert_int_eq((int)json_array_size(joined), ENTRIES);
    json_decref(joined);
    json_decref(whole);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pages_are_put_together_in_any_order)
{
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    json_t *pages = _pages_of_a_staged_chain(me, bob);
    size_t n = json_array_size(pages);
    ck_assert(n > 2);

    _begin();                               /* the receiver: an empty chain */
    identity_t *cal = _mk_identity("cal", "10.0.0.3");
    process_t *proc = _mk_process(cal);
    for (size_t i = n; i-- > 1;)            /* last first, the first held back */
    {
        _dispatch(proc, me, LATEST_UPDATE_FN, json_array_get(pages, i));
        ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    }
    _dispatch(proc, me, LATEST_UPDATE_FN, json_array_get(pages, 0));
    ck_assert_int_eq(reputation_get_committed_tx_count(), ENTRIES);
    json_decref(pages);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_page_of_another_head_starts_over)
{
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    json_t *pages = _pages_of_a_staged_chain(me, bob);
    size_t n = json_array_size(pages);
    ck_assert(n > 2);

    _begin();
    identity_t *cal = _mk_identity("cal", "10.0.0.3");
    process_t *proc = _mk_process(cal);
    /* Every page but the last, then the last as if from a window that moved
     * on: nothing is applied. */
    for (size_t i = 0; i + 1 < n; i++)
        _dispatch(proc, me, LATEST_UPDATE_FN, json_array_get(pages, i));
    json_t *moved = json_deep_copy(json_array_get(pages, n - 1));
    json_object_set_new(moved, "head", json_string("another head"));
    _dispatch(proc, me, LATEST_UPDATE_FN, moved);
    json_decref(moved);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    /* The pages of the new head start over, so the earlier ones count for
     * nothing: the whole window again, and only then is it applied. */
    for (size_t i = 0; i < n; i++)
    {
        ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
        _dispatch(proc, me, LATEST_UPDATE_FN, json_array_get(pages, i));
    }
    ck_assert_int_eq(reputation_get_committed_tx_count(), ENTRIES);
    json_decref(pages);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pages_from_two_senders_do_not_mix)
{
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    json_t *pages = _pages_of_a_staged_chain(me, bob);
    size_t n = json_array_size(pages);
    ck_assert(n > 1);

    _begin();
    identity_t *cal = _mk_identity("cal", "10.0.0.3");
    process_t *proc = _mk_process(cal);
    for (size_t i = 0; i < n; i++)
        _dispatch(proc, i % 2 == 0 ? me : bob, LATEST_UPDATE_FN,
                  json_array_get(pages, i));
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    json_decref(pages);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepUpdatePages,
          test_a_window_over_the_page_size_goes_in_pages,
          test_pages_are_put_together_in_any_order,
          test_a_page_of_another_head_starts_over,
          test_pages_from_two_senders_do_not_mix)
