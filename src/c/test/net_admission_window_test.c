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
/* The moment of admission into a proto-format cohort.
 *
 * The admitter counts the joiner a member, and so speaks the cohort's format to
 * it, the instant it admits it; the joiner learns that format only when its
 * group arrives a beat later. Both directions used to lose frames in that gap:
 * the joiner refused the admitter's proto frames on a JSON path, and the
 * admitter refused the joiner's JSON on a proto one. Now the joiner defers a
 * decrypted frame from a known peer it cannot place yet, and holds its own
 * point-to-point traffic to an admitter until it can say which format that
 * admitter expects. Twin of Python test_net_admission_format_window.py. */
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/net_wire_format.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/allocation.h"

#define ADMITTER "10.0.0.1"
#define JOINER   "10.0.0.2"

static int g_delivered;      /* frames routed to a sibling process */

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking; (void)msg;
    if (type == NET_MESSAGE)
        g_delivered++;
    return 0;
}

/* The fake transport: every unicast, in order, as the format it went in and
 * the verb it carried. Frames are sent unencrypted so the test can read them. */
#define MAX_SENT 8
static int t_sent;
static net_wire_format_t t_fmt[MAX_SENT];
static char t_fn[MAX_SENT][64];

static int t_send_unicast(net_transport_ctx_t *ctx, const uint8_t *wire,
                          size_t len, const char *target, int port)
{
    (void)ctx; (void)target; (void)port;
    if (t_sent < MAX_SENT) {
        net_wire_format_t fmt = (len > 0 && wire[0] == NET_WIRE_PROTO_MAGIC)
                                ? NET_WIRE_PROTO : NET_WIRE_JSON;
        net_wire_msg_t w;
        t_fmt[t_sent] = fmt;
        t_fn[t_sent][0] = '\0';
        if (net_message_from_wire_fmt(wire, len, NULL, fmt, &w) == 0) {
            snprintf(t_fn[t_sent], sizeof(t_fn[0]), "%s",
                     w.function != NULL ? w.function : "");
            net_wire_msg_free(&w);
        }
    }
    t_sent++;
    return 0;
}
static int t_send_broadcast(net_transport_ctx_t *ctx, net_channel_t ch,
                            const uint8_t *wire, size_t len, int port)
{
    (void)ctx; (void)ch; (void)wire; (void)len; (void)port;
    return 0;
}
static const net_transport_t T_TRANSPORT = {
    .name = "t_fake",
    .send_unicast = t_send_unicast,
    .send_broadcast = t_send_broadcast,
};

static identity_t *_mk(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

/* The joiner's network process: it knows the admitter as a peer, and holds a
 * group (not yet the admitter's cohort) that cannot place it. */
static process_t *_mk_proc(identity_t *admitter)
{
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    char gaddr[] = "group-addr";
    ck_assert_int_eq(group_init(NULL, gaddr, &proc->protocol.group), 0);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(admitter, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(*pub));
    smrt_deref(pub);
    proc->protocol.num_peers = 1;
    return proc;
}

/* Our group arrives: the admitter's proto cohort, both of us in it. */
static void _placed(process_t *proc, identity_t *admitter, identity_t *joiner)
{
    char a[UUID_STR_LEN + 1], b[UUID_STR_LEN + 1];
    uuid_unparse_lower(admitter->uuid, a);
    uuid_unparse_lower(joiner->uuid, b);
    ck_assert_ret_ok(group_add_address(&proc->protocol.group, a, admitter->address));
    ck_assert_ret_ok(group_add_address(&proc->protocol.group, b, joiner->address));
    proc->protocol.group.wire_format = NET_WIRE_PROTO;
}

/* A negotiation invitation from @p from to @p to, in @p fmt, sealed for @p to
 * as net_encrypt_and_send's peer branch does: nonce | identity_encrypt(wire). */
static uint8_t *_frame(identity_t *from, identity_t *to, net_wire_format_t fmt,
                       size_t *out_len)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "negotiation");
    w.function = strdup("invitation");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    w.encrypt = true;
    w.to_whom.type = RECIPIENT_PEER;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&w, from, fmt, &wire, &wire_len));
    free(w.function);
    free(w.data);

    public_identity_t *to_pub = NULL;
    ck_assert_ret_ok(identity_publish(to, &to_pub));
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    msg_str_t plain = { .msg = wire, .len = wire_len };
    size_t cipher_len = wire_len + crypto_box_MACBYTES;
    uint8_t *frame = malloc(sizeof(nonce) + cipher_len);
    ck_assert_ptr_nonnull(frame);
    memcpy(frame, nonce, sizeof(nonce));
    ck_assert_int_eq(identity_encrypt(from, &plain, to_pub, nonce,
                                      frame + sizeof(nonce)), 0);
    smrt_deref(to_pub);
    free(wire);
    *out_len = sizeof(nonce) + cipher_len;
    return frame;
}

static void _receive(net_thread_ctx_t *ctx, identity_t *from, identity_t *to,
                     net_wire_format_t fmt)
{
    size_t fl = 0;
    uint8_t *f = _frame(from, to, fmt, &fl);
    handle_inbound_peer(ctx, f, fl, from->address);
    free(f);
}

/* An admitter's access_granted, routed as it arrives: plaintext, from an
 * address the joiner cannot place yet. */
static void _admitted_from(process_t *proc, const char *addr,
                           net_route_path_t path)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = (char *)"access_granted";
    snprintf(w.from_whom.address, sizeof(w.from_whom.address), "%s", addr);
    ck_assert_int_eq(net_proc_test_route_on_path(&w, proc, NULL, path), 0);
}

static void _admitted(process_t *proc, net_route_path_t path)
{
    _admitted_from(proc, ADMITTER, path);
}

/* A group arrives that lists @p who alone: a proto cohort placing that one
 * peer and no other. */
static void _place_only(process_t *proc, identity_t *who)
{
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    ck_assert_ret_ok(group_add_address(&proc->protocol.group, u, who->address));
    proc->protocol.group.wire_format = NET_WIRE_PROTO;
}

/* One outbound message to the admitter, as the main loop dequeues it. */
static void _send(const net_outbound_t *out, identity_t *admitter,
                  const char *process, const char *function)
{
    generic_msg_t buf = {0};
    buf.type = NET_MESSAGE;
    net_msg_t *m = &buf.info.net_msg;
    snprintf(m->process, sizeof(m->process), "%s", process);
    m->function = (char *)function;
    m->obj = (uint8_t *)"{}";
    m->len = 2;
    m->encrypt = false;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(admitter, &pub));
    memcpy(&m->to_whom, pub, sizeof(*pub));
    smrt_deref(pub);
    net_send_outbound(out, &buf);
}

static net_outbound_t _outbound(process_t *proc, identity_t *me)
{
    net_outbound_t out = {
        .proc = proc, .myself = me, .transport = &T_TRANSPORT,
        .port_num = 27787, .bcast_addr = "10.0.0.255",
    };
    return out;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    g_delivered = t_sent = 0;
    net_proc_test_reset_deferred();
    net_proc_test_reset_admissions();
    net_proc_test_reset_pests();
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    net_proc_test_reset_deferred();
    net_proc_test_reset_admissions();
    messaging_set_test_hook(NULL);
}

/* ---- receiving: defer, never drop ---------------------------------------- */

DEFINE_TEST(test_a_proto_frame_from_a_known_peer_we_cannot_place_is_deferred)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    _receive(&ctx, adm, me, NET_WIRE_PROTO);
    ck_assert_int_eq(g_delivered, 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);
    /* Still unplaced: the replay pass keeps it. */
    ck_assert_int_eq((int)net_replay_placed_deferred(&ctx), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);
    _end();
}

DEFINE_TEST(test_the_deferred_frame_reads_in_the_group_format_once_placed)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    _receive(&ctx, adm, me, NET_WIRE_PROTO);
    _placed(proc, adm, me);
    ck_assert_int_eq((int)net_replay_placed_deferred(&ctx), 1);
    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 0);
    _end();
}

DEFINE_TEST(test_a_json_frame_from_a_peer_we_cannot_place_still_routes)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    _receive(&ctx, adm, me, NET_WIRE_JSON);
    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 0);
    _end();
}

DEFINE_TEST(test_a_member_in_the_wrong_format_is_still_a_drop)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    _placed(proc, adm, me);
    _receive(&ctx, adm, me, NET_WIRE_JSON);
    ck_assert_int_eq(g_delivered, 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 0);
    _end();
}

/* A deferral for the peer's KEY (an unknown sender) is not one for its group:
 * the group replay leaves it to the PEER admission that supplies the key. */
DEFINE_TEST(test_the_group_replay_leaves_unknown_sender_deferrals_alone)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    const uint8_t junk[64] = {0};
    net_proc_test_defer(junk, sizeof(junk), ADMITTER);
    _placed(proc, adm, me);
    ck_assert_int_eq((int)net_replay_placed_deferred(&ctx), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);
    _end();
}

/* ---- sending: hold until the format is known ----------------------------- */

DEFINE_TEST(test_without_an_admission_traffic_goes_out_at_once)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _send(&out, adm, "negotiation", "invitation");
    ck_assert_int_eq(t_sent, 1);
    ck_assert_int_eq(t_fmt[0], NET_WIRE_JSON);
    _end();
}

DEFINE_TEST(test_traffic_to_an_admitter_is_held_until_it_can_be_placed)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted(proc, NET_PATH_STRANGER);
    ck_assert(net_proc_test_admission_pending(ADMITTER));
    _send(&out, adm, "negotiation", "first");
    _send(&out, adm, "negotiation", "second");
    ck_assert_int_eq(t_sent, 0);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 2);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 0);
    ck_assert_int_eq(t_sent, 0);

    _placed(proc, adm, me);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 2);
    ck_assert_int_eq(t_sent, 2);
    ck_assert_str_eq(t_fn[0], "first");
    ck_assert_str_eq(t_fn[1], "second");
    ck_assert_int_eq(t_fmt[0], NET_WIRE_PROTO);
    ck_assert_int_eq(t_fmt[1], NET_WIRE_PROTO);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 0);
    ck_assert(!net_proc_test_admission_pending(ADMITTER));
    _end();
}

DEFINE_TEST(test_bootstrap_is_never_held)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted(proc, NET_PATH_STRANGER);
    _send(&out, adm, "identity", "full_history");
    ck_assert_int_eq(t_sent, 1);
    ck_assert_int_eq(t_fmt[0], NET_WIRE_JSON);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 0);
    _end();
}

DEFINE_TEST(test_a_hold_that_outlives_the_bound_goes_out_as_the_lookup_says)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted(proc, NET_PATH_STRANGER);
    _send(&out, adm, "negotiation", "invitation");
    ck_assert_int_eq(t_sent, 0);
    net_proc_test_backdate_admissions(3600);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 1);
    ck_assert_int_eq(t_sent, 1);
    ck_assert_str_eq(t_fn[0], "invitation");
    ck_assert_int_eq(t_fmt[0], NET_WIRE_JSON);
    _end();
}

DEFINE_TEST(test_an_access_granted_from_a_member_starts_no_hold)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    _placed(proc, adm, me);
    _admitted(proc, NET_PATH_STRANGER);
    ck_assert(!net_proc_test_admission_pending(ADMITTER));
    _end();
}

/* The broadcast channel is not how an admission arrives. */
DEFINE_TEST(test_an_access_granted_on_the_broadcast_path_starts_no_hold)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER);
    process_t *proc = _mk_proc(adm);
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = (char *)"access_granted";
    snprintf(w.from_whom.address, sizeof(w.from_whom.address), "%s", ADMITTER);
    (void)net_proc_test_route_on_path(&w, proc, NULL, NET_PATH_BROADCAST);
    ck_assert(!net_proc_test_admission_pending(ADMITTER));
    _end();
}

/* A DTN endpoint ID is an address whole, slashes and all: an admission by one
 * DTN peer holds traffic to that peer, never to every DTN peer. */
DEFINE_TEST(test_an_admission_by_one_dtn_peer_does_not_hold_another)
{
    _begin();
    identity_t *adm = _mk("admitter", "dtn://at-1a2b3c4d/peer");
    identity_t *other = _mk("other", "dtn://at-5e6f7a8b/peer");
    identity_t *me = _mk("joiner", "dtn://at-9c0d1e2f/peer");
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted_from(proc, adm->address, NET_PATH_STRANGER);
    ck_assert(net_proc_test_admission_pending(adm->address));
    ck_assert(!net_proc_test_admission_pending(other->address));
    ck_assert(!net_proc_test_admission_pending("dtn:"));

    _send(&out, other, "negotiation", "to_other");
    ck_assert_int_eq(t_sent, 1);
    ck_assert_str_eq(t_fn[0], "to_other");
    _send(&out, adm, "negotiation", "to_admitter");
    ck_assert_int_eq(t_sent, 1);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 1);

    /* Placing the admitter by its whole EID settles the admission. */
    _place_only(proc, adm);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 1);
    ck_assert_int_eq(t_sent, 2);
    ck_assert_str_eq(t_fn[1], "to_admitter");
    ck_assert_int_eq(t_fmt[1], NET_WIRE_PROTO);
    ck_assert(!net_proc_test_admission_pending(adm->address));
    _end();
}

/* A frame dequeued after the admission settled but before the release pass is
 * held behind the frames already waiting, never sent ahead of them. */
DEFINE_TEST(test_a_new_frame_behind_held_ones_is_held_too)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted(proc, NET_PATH_STRANGER);
    _send(&out, adm, "negotiation", "first");
    _placed(proc, adm, me);
    _send(&out, adm, "negotiation", "second");
    ck_assert_int_eq(t_sent, 0);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 2);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 2);
    ck_assert_int_eq(t_sent, 2);
    ck_assert_str_eq(t_fn[0], "first");
    ck_assert_str_eq(t_fn[1], "second");
    _end();
}

/* Two admitters, interleaved in the hold: the one that settles goes out, the
 * other keeps its frames and their order until it settles in turn. */
DEFINE_TEST(test_holds_for_two_admitters_release_independently_in_order)
{
    _begin();
    identity_t *a = _mk("a", ADMITTER), *b = _mk("b", "10.0.0.3");
    identity_t *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(a);
    net_outbound_t out = _outbound(proc, me);
    _admitted_from(proc, a->address, NET_PATH_STRANGER);
    _admitted_from(proc, b->address, NET_PATH_STRANGER);
    _send(&out, a, "negotiation", "a1");
    _send(&out, b, "negotiation", "b1");
    _send(&out, a, "negotiation", "a2");
    ck_assert_int_eq(t_sent, 0);

    _place_only(proc, b);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 1);
    ck_assert_int_eq(t_sent, 1);
    ck_assert_str_eq(t_fn[0], "b1");
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(), 2);
    ck_assert_str_eq(net_proc_test_held_for_admission_function(0), "a1");
    ck_assert_str_eq(net_proc_test_held_for_admission_function(1), "a2");

    net_proc_test_backdate_admissions(3600);
    ck_assert_int_eq((int)net_release_admission_holds(&out), 2);
    ck_assert_int_eq(t_sent, 3);
    ck_assert_str_eq(t_fn[1], "a1");
    ck_assert_str_eq(t_fn[2], "a2");
    _end();
}

/* The hold is bounded: one frame past NET_HELD_FOR_ADMISSION drops the oldest,
 * and the drop is counted. */
DEFINE_TEST(test_the_hold_is_bounded_and_drops_the_oldest)
{
    _begin();
    identity_t *adm = _mk("admitter", ADMITTER), *me = _mk("joiner", JOINER);
    process_t *proc = _mk_proc(adm);
    net_outbound_t out = _outbound(proc, me);
    _admitted(proc, NET_PATH_STRANGER);
    unsigned long overflows = net_proc_test_held_for_admission_overflows();
    for (int i = 0; i <= NET_HELD_FOR_ADMISSION; i++) {
        char fn[32];
        snprintf(fn, sizeof(fn), "frame%d", i);
        _send(&out, adm, "negotiation", fn);
    }
    ck_assert_int_eq(t_sent, 0);
    ck_assert_int_eq((int)net_proc_test_held_for_admission_count(),
                     NET_HELD_FOR_ADMISSION);
    ck_assert_uint_eq(net_proc_test_held_for_admission_overflows(), overflows + 1);
    ck_assert_str_eq(net_proc_test_held_for_admission_function(0), "frame1");
    _end();
}

RUN_TESTS(NetAdmissionWindow,
          test_a_proto_frame_from_a_known_peer_we_cannot_place_is_deferred,
          test_the_deferred_frame_reads_in_the_group_format_once_placed,
          test_a_json_frame_from_a_peer_we_cannot_place_still_routes,
          test_a_member_in_the_wrong_format_is_still_a_drop,
          test_the_group_replay_leaves_unknown_sender_deferrals_alone,
          test_without_an_admission_traffic_goes_out_at_once,
          test_traffic_to_an_admitter_is_held_until_it_can_be_placed,
          test_bootstrap_is_never_held,
          test_a_hold_that_outlives_the_bound_goes_out_as_the_lookup_says,
          test_an_access_granted_from_a_member_starts_no_hold,
          test_an_access_granted_on_the_broadcast_path_starts_no_hold,
          test_an_admission_by_one_dtn_peer_does_not_hold_another,
          test_a_new_frame_behind_held_ones_is_held_too,
          test_holds_for_two_admitters_release_independently_in_order,
          test_the_hold_is_bounded_and_drops_the_oldest)
