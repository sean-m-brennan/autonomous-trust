/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/* The rendezvous relay protocol (network/net_relay.{h,c}) over real localhost
 * sockets. The C twin of Python tests/a_unit/test_relay.py's protocol half. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_relay.h"
#include "network/net_proc_priv.h"
#include "contacts/reach.h"
#include "network/net_message.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"
#include "utilities/util.h"

static logger_t *g_log = NULL;

typedef struct {
    pthread_mutex_t lock;
    int n;
    char from[UUID_STR_LEN + 1];
    uint8_t frame[64];
    size_t len;
} inbox_t;

static void _deliver(void *arg, const char *from, const uint8_t *frame,
                     size_t len, const char *host, int port)
{
    (void)host; (void)port;
    inbox_t *in = arg;
    pthread_mutex_lock(&in->lock);
    in->n++;
    at_strlcpy(in->from, from, sizeof(in->from));
    in->len = len < sizeof(in->frame) ? len : sizeof(in->frame);
    memcpy(in->frame, frame, in->len);
    pthread_mutex_unlock(&in->lock);
}

static bool _wait_n(inbox_t *in, int n)
{
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&in->lock);
        int got = in->n;
        pthread_mutex_unlock(&in->lock);
        if (got >= n)
            return true;
        usleep(10 * 1000);
    }
    return false;
}

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static bool _registered(net_relay_server_t *srv, const identity_t *who)
{
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    for (int i = 0; i < 500; i++) {
        if (net_relay_server_has(srv, u))
            return true;
        usleep(10 * 1000);
    }
    return false;
}

DEFINE_TEST(test_endpoints_and_hints)
{
    char h[AT_RELAY_HOST_LEN];
    int p = 0;
    ck_assert_ret_ok(net_relay_parse_endpoint("relay://10.0.0.9:27790", h, sizeof(h), &p));
    ck_assert_str_eq(h, "10.0.0.9");
    ck_assert_int_eq(p, 27790);
    ck_assert_ret_ok(net_relay_parse_endpoint("relay://[2001:db8::1]:9000", h, sizeof(h), &p));
    ck_assert_str_eq(h, "2001:db8::1");
    ck_assert_ret_ok(net_relay_parse_endpoint("host.example:1/", h, sizeof(h), &p));
    ck_assert_str_eq(h, "host.example");
    ck_assert_int_eq(net_relay_parse_endpoint("relay://10.0.0.9", h, sizeof(h), &p), -1);
    ck_assert_int_eq(net_relay_parse_endpoint("relay://:27790", h, sizeof(h), &p), -1);
    ck_assert_int_eq(net_relay_parse_endpoint("10.0.0.9:99999", h, sizeof(h), &p), -1);
    char hint[96];
    ck_assert_ret_ok(net_relay_hint_for("2001:db8::1", 9000, hint, sizeof(hint)));
    ck_assert_str_eq(hint, "relay://[2001:db8::1]:9000");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_two_clients_exchange_frames_and_from_is_the_relays)
{
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    ck_assert_ptr_nonnull(srv);
    int port = net_relay_server_port(srv);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    inbox_t a_in = { .lock = PTHREAD_MUTEX_INITIALIZER };
    inbox_t b_in = { .lock = PTHREAD_MUTEX_INITIALIZER };
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice, _deliver, &a_in, g_log);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _deliver, &b_in, g_log);
    ck_assert_ret_ok(net_relay_client_connect(a));
    ck_assert_ret_ok(net_relay_client_connect(b));
    ck_assert(_registered(srv, alice) && _registered(srv, bob));

    ck_assert_ret_ok(net_relay_client_send(a, bob->uuid, (const uint8_t *)"sealed", 6));
    ck_assert(_wait_n(&b_in, 1));
    char au[UUID_STR_LEN + 1];
    uuid_unparse_lower(alice->uuid, au);
    ck_assert_str_eq(b_in.from, au);
    ck_assert_int_eq(b_in.len, 6);
    ck_assert(memcmp(b_in.frame, "sealed", 6) == 0);

    const uint8_t bin[3] = { 0x00, 0xff, 0x7f };
    ck_assert_ret_ok(net_relay_client_send(b, alice->uuid, bin, 3));
    ck_assert(_wait_n(&a_in, 1));
    ck_assert(memcmp(a_in.frame, bin, 3) == 0);

    /* An unregistered target: the relay says so. */
    identity_t *ghost = _mk("ghost");
    char gu[UUID_STR_LEN + 1];
    uuid_unparse_lower(ghost->uuid, gu);
    ck_assert_ret_ok(net_relay_client_send(a, ghost->uuid, (const uint8_t *)"x", 1));
    bool said = false;
    for (int i = 0; i < 500 && !said; i++) {
        said = net_relay_client_was_unreachable(a, gu);
        usleep(10 * 1000);
    }
    ck_assert(said);
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
}
END_TEST_DEFINITION()

static int _dial(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Register by hand as `claimed` (its uuid and pubkey), signing with `signer`. */
static char *_raw_register(int port, const identity_t *claimed,
                           const identity_t *signer)
{
    int fd = _dial(port);
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(claimed->uuid, u);
    char hello[256];
    snprintf(hello, sizeof(hello),
             "{\"op\":\"hello\",\"uuid\":\"%s\",\"pubkey\":\"%s\"}",
             u, (const char *)claimed->signature.public_hex);
    net_relay_send_json(fd, hello);
    char *ch = net_relay_recv_json(fd);
    json_error_t err;
    json_t *cj = json_loads(ch, 0, &err);
    const char *nonce = json_string_value(json_object_get(cj, "nonce"));
    char text[160];
    snprintf(text, sizeof(text), "%s|%s|%s", AT_RELAY_DOMAIN, nonce, u);
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)text, strlen(text),
                         signer->signature.private);
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
    char reg[256];
    snprintf(reg, sizeof(reg), "{\"op\":\"register\",\"sig\":\"%s\"}", sig_hex);
    net_relay_send_json(fd, reg);
    char *ans = net_relay_recv_json(fd);
    json_decref(cj);
    free(ch);
    close(fd);
    return ans;
}

DEFINE_TEST(test_registering_someone_elses_uuid_is_refused)
{
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    int port = net_relay_server_port(srv);
    identity_t *alice = _mk("alice"), *mallory = _mk("mallory");
    char *ans = _raw_register(port, alice, mallory);
    ck_assert_ptr_nonnull(ans);
    ck_assert(strstr(ans, "\"error\"") != NULL);
    char au[UUID_STR_LEN + 1];
    uuid_unparse_lower(alice->uuid, au);
    ck_assert(!net_relay_server_has(srv, au));
    free(ans);
    ans = _raw_register(port, alice, alice);
    ck_assert(ans != NULL && strstr(ans, "\"registered\"") != NULL);
    free(ans);
    net_relay_server_stop(srv);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_oversized_frame_drops_the_connection)
{
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    int fd = _dial(net_relay_server_port(srv));
    uint32_t big = htonl(AT_RELAY_MAX_FRAME + 1);
    ck_assert_int_eq(send(fd, &big, 4, 0), 4);
    char c;
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ck_assert_int_eq(recv(fd, &c, 1, 0), 0);    /* closed */
    close(fd);
    net_relay_server_stop(srv);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_reconnect_replaces_the_old_registration)
{
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    int port = net_relay_server_port(srv);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    inbox_t first = { .lock = PTHREAD_MUTEX_INITIALIZER };
    inbox_t second = { .lock = PTHREAD_MUTEX_INITIALIZER };
    net_relay_client_t *a1 = net_relay_client_new("127.0.0.1", port, alice, _deliver, &first, g_log);
    net_relay_client_t *a2 = net_relay_client_new("127.0.0.1", port, alice, _deliver, &second, g_log);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _deliver, NULL, g_log);
    ck_assert_ret_ok(net_relay_client_connect(a1));
    ck_assert_ret_ok(net_relay_client_connect(a2));
    ck_assert_ret_ok(net_relay_client_connect(b));
    usleep(200 * 1000);
    ck_assert_ret_ok(net_relay_client_send(b, alice->uuid, (const uint8_t *)"hi", 2));
    ck_assert(_wait_n(&second, 1));
    ck_assert_int_eq(first.n, 0);
    net_relay_server_stop(srv);
}
END_TEST_DEFINITION()

/* ---- the network process's side ----------------------------------------- */

static int g_routed;
static char g_routed_fn[64];

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL) {
        g_routed++;
        at_strlcpy(g_routed_fn, msg->info.net_msg.function, sizeof(g_routed_fn));
    }
    return 0;
}

DEFINE_TEST(test_a_relay_route_is_refused_from_the_wire)
{
    net_relay_reset_routes();
    identity_t *bob = _mk("bob"), *mallory = _mk("mallory");
    char bu[UUID_STR_LEN + 1];
    uuid_unparse_lower(bob->uuid, bu);
    json_t *body = json_object();
    json_object_set_new(body, "uuid", json_string(bu));
    json_object_set_new(body, "relay", json_string("127.0.0.1:1"));

    net_msg_t wire = {0};
    net_msg_pack_json(&wire, body);
    uuid_copy(wire.from_whom.uuid, mallory->uuid);     /* from a peer */
    ck_assert_int_eq(net_handle_relay_route(&wire, g_log), -1);
    ck_assert(!net_relay_has_route(bob->uuid));

    net_msg_t local = {0};
    net_msg_pack_json(&local, body);                    /* no sender: local */
    ck_assert_int_eq(net_handle_relay_route(&local, g_log), 0);
    ck_assert(net_relay_has_route(bob->uuid));
    json_decref(body);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()

/* A plaintext first-contact hello from `sender`, as the relay would carry it. */
static uint8_t *_hello_wire(const identity_t *sender, size_t *len)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)sender, &pub));
    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "identity");
    w.function = strdup("first_contact_hello");
    w.data = (uint8_t *)strdup("at+contact:x");
    w.data_len = strlen((char *)w.data);
    w.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(&w.from_whom, pub, sizeof(*pub));
    w.encrypt = false;
    uint8_t *out = NULL;
    ck_assert_ret_ok(net_message_to_wire(&w, sender, &out, len));
    free(w.function);
    free(w.data);
    smrt_deref(pub);
    return out;
}

DEFINE_TEST(test_a_relayed_frame_must_claim_the_sender_the_relay_stamped)
{
    identity_t *alice = _mk("alice"), *bob = _mk("bob"), *mallory = _mk("mallory");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    net_thread_ctx_t ctx = { .proc = proc, .logger = g_log, .myself = alice };
    size_t len = 0;
    uint8_t *frame = _hello_wire(bob, &len);
    char bu[UUID_STR_LEN + 1], mu[UUID_STR_LEN + 1];
    uuid_unparse_lower(bob->uuid, bu);
    uuid_unparse_lower(mallory->uuid, mu);

    messaging_set_test_hook(_hook);
    g_routed = 0;
    /* Stamped as Mallory, the envelope says Bob: dropped. */
    handle_inbound_relayed(&ctx, frame, len, mu);
    ck_assert_int_eq(g_routed, 0);
    /* Stamped as Bob, the envelope says Bob: delivered to identity. */
    handle_inbound_relayed(&ctx, frame, len, bu);
    ck_assert_int_eq(g_routed, 1);
    ck_assert_str_eq(g_routed_fn, "first_contact_hello");
    messaging_set_test_hook(NULL);
    free(frame);
}
END_TEST_DEFINITION()


/* ---- several relays: routes, failover, unreachable ---------------------- */

static struct {
    char dead[4][AT_RELAY_HOST_LEN];
    size_t n_dead;
    char sent_host[16][AT_RELAY_HOST_LEN];
    size_t n_sent;
} g_fake;

static int _fake_send(const char *host, int port, const uuid_t to,
                      const uint8_t *buf, size_t len)
{
    (void)port; (void)to; (void)buf; (void)len;
    for (size_t i = 0; i < g_fake.n_dead; i++)
        if (strcmp(g_fake.dead[i], host) == 0)
            return -1;
    if (g_fake.n_sent < 16)
        at_strlcpy(g_fake.sent_host[g_fake.n_sent++], host, AT_RELAY_HOST_LEN);
    return 0;
}

static void _fake_reset(void)
{
    memset(&g_fake, 0, sizeof(g_fake));
    net_relay_reset_routes();
    net_relay_set_test_sender(_fake_send);
}

static void _route(const identity_t *who, const char *const *relays, size_t n)
{
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    json_t *body = json_object();
    json_t *list = json_array();
    for (size_t i = 0; i < n; i++)
        json_array_append_new(list, json_string(relays[i]));
    json_object_set_new(body, "uuid", json_string(u));
    json_object_set_new(body, "relays", list);
    net_msg_t local = {0};
    net_msg_pack_json(&local, body);
    ck_assert_int_eq(net_handle_relay_route(&local, g_log), 0);
    json_decref(body);
}

static const char *_active(const identity_t *who)
{
    static net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert(net_relay_route_endpoints(who->uuid, eps, AT_RELAY_MAX) > 0);
    return eps[0].host;
}

DEFINE_TEST(test_own_relays_parse_a_list)
{
    net_relay_ep_t eps[AT_RELAY_MAX];
    setenv("AT_USE_RELAY", "a:1,b:2, a:1 ,nonsense,c:3,d:4,e:5", 1);
    ck_assert_uint_eq(net_relay_own_list(eps, AT_RELAY_MAX), 4);
    ck_assert_str_eq(eps[0].host, "a");
    ck_assert_str_eq(eps[1].host, "b");
    ck_assert_str_eq(eps[2].host, "c");
    ck_assert_int_eq(eps[3].port, 4);
    char host[AT_RELAY_HOST_LEN];
    int port = 0;
    ck_assert_int_eq(net_relay_own(host, sizeof(host), &port), 0);
    ck_assert_str_eq(host, "a");
    setenv("AT_USE_RELAY", "", 1);
    ck_assert_uint_eq(net_relay_own_list(eps, AT_RELAY_MAX), 0);
    unsetenv("AT_USE_RELAY");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_route_list_goes_ahead_of_the_old_one)
{
    _fake_reset();
    identity_t *p = _mk("peer");
    const char *first[] = {"10.0.0.1:1"};
    _route(p, first, 1);
    const char *more[] = {"10.0.0.9:1", "10.0.0.1:1"};
    _route(p, more, 2);
    net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert_uint_eq(net_relay_route_endpoints(p->uuid, eps, AT_RELAY_MAX), 2);
    ck_assert_str_eq(eps[0].host, "10.0.0.9");
    ck_assert_str_eq(eps[1].host, "10.0.0.1");
    net_relay_set_test_sender(NULL);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_send_fails_over_to_the_next_relay_that_is_up)
{
    _fake_reset();
    identity_t *p = _mk("peer");
    const char *relays[] = {"10.0.0.1:1", "10.0.0.2:2", "10.0.0.3:3"};
    _route(p, relays, 3);
    at_strlcpy(g_fake.dead[g_fake.n_dead++], "10.0.0.1", AT_RELAY_HOST_LEN);
    const uint8_t frame[] = "one";
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), 0);
    ck_assert_uint_eq(g_fake.n_sent, 1);
    ck_assert_str_eq(g_fake.sent_host[0], "10.0.0.2");
    ck_assert_str_eq(_active(p), "10.0.0.2");   /* the dead one went to the back */
    at_strlcpy(g_fake.dead[g_fake.n_dead++], "10.0.0.2", AT_RELAY_HOST_LEN);
    at_strlcpy(g_fake.dead[g_fake.n_dead++], "10.0.0.3", AT_RELAY_HOST_LEN);
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), -1);
    /* A peer with no route is not the relay's to send. */
    identity_t *q = _mk("direct");
    ck_assert_int_eq(net_relay_send_to_peer(q->uuid, frame, sizeof(frame)), 1);
    net_relay_set_test_sender(NULL);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unreachable_resends_through_the_next_relay)
{
    _fake_reset();
    identity_t *p = _mk("peer");
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(p->uuid, u);
    const char *relays[] = {"10.0.0.1:1", "10.0.0.2:2", "10.0.0.3:3"};
    _route(p, relays, 3);
    const uint8_t frame[] = "hello";
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), 0);
    net_relay_note_unreachable("10.0.0.1", 1, u);
    net_relay_drain_unreachable();
    ck_assert_uint_eq(g_fake.n_sent, 2);
    ck_assert_str_eq(g_fake.sent_host[1], "10.0.0.2");
    ck_assert_str_eq(_active(p), "10.0.0.2");
    /* A late refusal from the first is stale now: nothing more is sent. */
    net_relay_note_unreachable("10.0.0.1", 1, u);
    net_relay_drain_unreachable();
    ck_assert_uint_eq(g_fake.n_sent, 2);
    net_relay_set_test_sender(NULL);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unreachable_everywhere_ends_after_each_relay_once)
{
    _fake_reset();
    identity_t *p = _mk("peer");
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(p->uuid, u);
    const char *relays[] = {"10.0.0.1:1", "10.0.0.2:2"};
    _route(p, relays, 2);
    const uint8_t frame[] = "hello";
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), 0);
    const char *order[] = {"10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2"};
    for (size_t i = 0; i < 4; i++) {
        net_relay_note_unreachable(order[i], i % 2 == 0 ? 1 : 2, u);
        net_relay_drain_unreachable();
    }
    ck_assert_uint_eq(g_fake.n_sent, 2);
    ck_assert_str_eq(g_fake.sent_host[0], "10.0.0.1");
    ck_assert_str_eq(g_fake.sent_host[1], "10.0.0.2");
    net_relay_set_test_sender(NULL);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()


static void _refuse_all(const identity_t *p, const char *u)
{
    for (int i = 0; i < 2; i++) {
        net_relay_ep_t eps[AT_RELAY_MAX];
        ck_assert(net_relay_route_endpoints(p->uuid, eps, AT_RELAY_MAX) > 0);
        net_relay_note_unreachable(eps[0].host, eps[0].port, u);
        net_relay_drain_unreachable();
    }
}

DEFINE_TEST(test_a_frame_every_relay_refused_is_retried_a_few_rounds)
{
    _fake_reset();
    net_relay_set_retry_sec(0);
    identity_t *p = _mk("peer");
    char u[UUID_STR_LEN + 1];
    uuid_unparse_lower(p->uuid, u);
    const char *relays[] = {"10.0.0.1:1", "10.0.0.2:2"};
    _route(p, relays, 2);
    const uint8_t frame[] = "hello";
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), 0);
    _refuse_all(p, u);
    ck_assert_uint_eq(g_fake.n_sent, 2);
    for (int round = 0; round < 3; round++) {
        size_t before = g_fake.n_sent;
        net_relay_retry_refused();
        ck_assert_uint_eq(g_fake.n_sent, before + 1);
        _refuse_all(p, u);
    }
    /* Three rounds, then it gives up. */
    size_t before = g_fake.n_sent;
    net_relay_retry_refused();
    ck_assert_uint_eq(g_fake.n_sent, before);
    /* A newer frame cancels a pending retry. */
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, frame, sizeof(frame)), 0);
    _refuse_all(p, u);
    const uint8_t newer[] = "newer";
    ck_assert_int_eq(net_relay_send_to_peer(p->uuid, newer, sizeof(newer)), 0);
    before = g_fake.n_sent;
    net_relay_retry_refused();
    ck_assert_uint_eq(g_fake.n_sent, before);
    net_relay_set_retry_sec(5);
    net_relay_set_test_sender(NULL);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()


/* ---- reputation-gated relays: the relay proves itself, both ends gate ---- */

static net_relay_pin_t _pin_of(const identity_t *who)
{
    net_relay_pin_t pin;
    memset(&pin, 0, sizeof(pin));
    pin.set = true;
    uuid_unparse_lower(who->uuid, pin.uuid);
    ck_assert_ret_ok(net_relay_key_fingerprint((const char *)who->signature.public_hex,
                                               pin.fp, sizeof(pin.fp)));
    return pin;
}

DEFINE_TEST(test_pinned_hints_parse_and_round_trip)
{
    identity_t *carol = _mk("carol");
    net_relay_pin_t pin = _pin_of(carol), got;
    char hint[256], host[AT_RELAY_HOST_LEN];
    int port = 0;
    ck_assert_ret_ok(net_relay_hint_for_pinned("203.0.113.7", 27790, &pin, hint,
                                               sizeof(hint)));
    char want[256];
    snprintf(want, sizeof(want), "relay://%s:%s@203.0.113.7:27790", pin.uuid, pin.fp);
    ck_assert_str_eq(hint, want);
    ck_assert_ret_ok(net_relay_parse_hint(hint, host, sizeof(host), &port, &got));
    ck_assert(got.set);
    ck_assert_str_eq(got.uuid, pin.uuid);
    ck_assert_str_eq(got.fp, pin.fp);
    ck_assert_str_eq(host, "203.0.113.7");
    ck_assert_int_eq(port, 27790);
    ck_assert_ret_ok(net_relay_parse_endpoint(hint, host, sizeof(host), &port));
    ck_assert_str_eq(host, "203.0.113.7");
    ck_assert_ret_ok(net_relay_parse_hint("relay://[2001:db8::1]:5", host,
                                          sizeof(host), &port, &got));
    ck_assert(!got.set);
    /* A pin that cannot be checked is refused, never dropped. */
    char bad[256];
    snprintf(bad, sizeof(bad), "relay://%s@1.2.3.4:5", pin.uuid);
    ck_assert_int_eq(net_relay_parse_hint(bad, host, sizeof(host), &port, &got), -1);
    snprintf(bad, sizeof(bad), "relay://nope:%s@1.2.3.4:5", pin.fp);
    ck_assert_int_eq(net_relay_parse_hint(bad, host, sizeof(host), &port, &got), -1);
    snprintf(bad, sizeof(bad), "relay://%s:abc@1.2.3.4:5", pin.uuid);
    ck_assert_int_eq(net_relay_parse_hint(bad, host, sizeof(host), &port, &got), -1);
    ck_assert_uint_eq(strlen(pin.fp), AT_RELAY_FP_BYTES * 2);
    identity_free(carol);
}
END_TEST_DEFINITION()

static bool _distrust_uuid(void *arg, const char *uuid, const char *key)
{
    (void)key;
    return strcmp((const char *)arg, uuid) == 0;
}

DEFINE_TEST(test_a_relay_proves_itself_and_a_pin_is_enforced)
{
    identity_t *carol = _mk("carol"), *alice = _mk("alice"), *dave = _mk("dave");
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    ck_assert_ptr_nonnull(srv);
    int port = net_relay_server_port(srv);
    inbox_t in = { .lock = PTHREAD_MUTEX_INITIALIZER };

    /* Without an identity the relay proves nothing: fine unpinned... */
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice,
                                                 _deliver, &in, g_log);
    ck_assert_int_eq(net_relay_client_connect(a), 0);
    ck_assert(!net_relay_client_proven(a, NULL, NULL, 0));
    net_relay_client_free(a);
    /* ...refused when the link pins it. */
    net_relay_pin_t carol_pin = _pin_of(carol);
    a = net_relay_client_new("127.0.0.1", port, alice, _deliver, &in, g_log);
    net_relay_client_set_pin(a, &carol_pin);
    ck_assert_int_eq(net_relay_client_connect(a), -1);
    char why[160];
    net_relay_client_refused(a, why, sizeof(why));
    ck_assert_ptr_nonnull(strstr(why, "no proof"));
    net_relay_client_free(a);

    /* Proving as Carol: the pin holds, and the proof names her key. */
    net_relay_server_set_identity(srv, carol);
    a = net_relay_client_new("127.0.0.1", port, alice, _deliver, &in, g_log);
    net_relay_client_set_pin(a, &carol_pin);
    ck_assert_int_eq(net_relay_client_connect(a), 0);
    net_relay_pin_t proven;
    ck_assert(net_relay_client_proven(a, &proven, NULL, 0));
    ck_assert_str_eq(proven.uuid, carol_pin.uuid);
    ck_assert_str_eq(proven.fp, carol_pin.fp);
    net_relay_client_free(a);
    /* A link naming Dave refuses Carol. */
    net_relay_pin_t dave_pin = _pin_of(dave);
    a = net_relay_client_new("127.0.0.1", port, alice, _deliver, &in, g_log);
    net_relay_client_set_pin(a, &dave_pin);
    ck_assert_int_eq(net_relay_client_connect(a), -1);
    net_relay_client_refused(a, why, sizeof(why));
    ck_assert_ptr_nonnull(strstr(why, "not the relay the link names"));
    net_relay_client_free(a);
    /* A client that distrusts Carol refuses her. */
    a = net_relay_client_new("127.0.0.1", port, alice, _deliver, &in, g_log);
    net_relay_client_set_distrust(a, _distrust_uuid, carol_pin.uuid);
    ck_assert_int_eq(net_relay_client_connect(a), -1);
    net_relay_client_refused(a, why, sizeof(why));
    ck_assert_ptr_nonnull(strstr(why, "distrusted"));
    net_relay_client_free(a);
    net_relay_server_stop(srv);
    identity_free(carol);
    identity_free(alice);
    identity_free(dave);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_relay_refuses_and_evicts_a_distrusted_client)
{
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    char au[UUID_STR_LEN + 1];
    uuid_unparse_lower(alice->uuid, au);
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    int port = net_relay_server_port(srv);
    inbox_t in = { .lock = PTHREAD_MUTEX_INITIALIZER };
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _deliver,
                                                 &in, g_log);
    ck_assert_int_eq(net_relay_client_connect(b), 0);
    ck_assert(_registered(srv, bob));
    /* Bob, registered, is evicted; his client sees the drop. */
    char bu[UUID_STR_LEN + 1];
    uuid_unparse_lower(bob->uuid, bu);
    net_relay_server_evict(srv, bu);
    bool down = false;
    for (int i = 0; i < 500 && !down; i++) {
        down = !net_relay_client_connected(b);
        usleep(10 * 1000);
    }
    ck_assert(down);
    /* Alice, distrusted, cannot register at all. */
    net_relay_server_set_distrust(srv, _distrust_uuid, au);
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice, _deliver,
                                                 &in, g_log);
    ck_assert_int_eq(net_relay_client_connect(a), -1);
    ck_assert(!net_relay_server_has(srv, au));
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
    identity_free(alice);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_network_gate_matches_by_uuid_and_by_key)
{
    net_relay_reset_routes();
    process_t *proc = calloc(1, sizeof(*proc));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    identity_t *mallory = _mk("mallory"), *carol = _mk("carol");
    public_identity_t *mp = NULL, *cp = NULL;
    ck_assert_ret_ok(identity_publish(mallory, &mp));
    ck_assert_ret_ok(identity_publish(carol, &cp));
    proc->protocol.peers[0] = *mp;
    proc->protocol.peers[1] = *cp;
    proc->protocol.num_peers = 2;
    net_relay_set_test_proc(proc);
    char mu[UUID_STR_LEN + 1], cu[UUID_STR_LEN + 1];
    uuid_unparse_lower(mallory->uuid, mu);
    uuid_unparse_lower(carol->uuid, cu);
    const char *mk = (const char *)mallory->signature.public_hex;
    const char *ck = (const char *)carol->signature.public_hex;
    ck_assert(!net_relay_is_distrusted(mu, mk));           /* neutral passes */
    net_relay_note_exclusion(mu, true);
    ck_assert(net_relay_is_distrusted(mu, mk));
    ck_assert(net_relay_is_distrusted("12345678-0000-4000-8000-000000000000", mk));
    ck_assert(net_relay_is_distrusted(cu, mk));            /* impostor */
    ck_assert(!net_relay_is_distrusted(cu, ck));
    net_relay_note_exclusion(mu, false);
    ck_assert(!net_relay_is_distrusted(mu, mk));
    net_relay_set_test_proc(NULL);
    smrt_deref(mp);
    smrt_deref(cp);
    identity_free(mallory);
    identity_free(carol);
    free(proc);
    net_relay_reset_routes();
}
END_TEST_DEFINITION()


/* ---- reachability records ------------------------------------------------ */

static void _record(const identity_t *who, int64_t seq, const char *relay,
                    long expiry, at_reach_record_t *out)
{
    const char *relays[1] = { relay };
    const char *eps[1] = { "10.0.0.1" };
    ck_assert_int_eq(at_reach_create(who, seq, relays, 1, eps, 1, expiry, out),
                     AT_REACH_OK);
}

DEFINE_TEST(test_a_reach_record_verifies_and_refuses_tampering)
{
    identity_t *alice = _mk("alice");
    at_reach_record_t rec, back;
    _record(alice, 3, "relay://203.0.113.7:27790", 0, &rec);
    ck_assert_int_eq(at_reach_verify(&rec, (double)time(NULL)), AT_REACH_OK);
    json_t *wire = at_reach_to_wire(&rec);
    ck_assert_int_eq(at_reach_from_wire(wire, &back), AT_REACH_OK);
    ck_assert_int_eq(at_reach_verify(&back, (double)time(NULL)), AT_REACH_OK);
    ck_assert_int_eq(at_reach_seq(&back), 3);
    char au[UUID_STR_LEN + 1];
    uuid_unparse_lower(alice->uuid, au);
    ck_assert_str_eq(at_reach_uuid(&back), au);
    at_reach_free(&back);
    /* A body changed after signing does not verify. */
    char *body = strdup(rec.body_str);
    char *p = strstr(body, "\"seq\":3");
    ck_assert_ptr_nonnull(p);
    p[6] = '9';
    json_object_set_new(wire, "body", json_string(body));
    ck_assert_int_eq(at_reach_from_wire(wire, &back), AT_REACH_OK);
    ck_assert_int_eq(at_reach_verify(&back, (double)time(NULL)), AT_REACH_BAD_SIG);
    at_reach_free(&back);
    free(body);
    json_decref(wire);
    at_reach_free(&rec);
    /* Expired. */
    _record(alice, 4, "relay://203.0.113.7:27790", (long)time(NULL) - 1, &rec);
    ck_assert_int_eq(at_reach_verify(&rec, (double)time(NULL)), AT_REACH_EXPIRED);
    at_reach_free(&rec);
    identity_free(alice);
}
END_TEST_DEFINITION()

static struct {
    pthread_mutex_t lock;
    int n;
    bool got_null;
    int64_t seq;
} g_ans = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _on_record(void *arg, const char *rid, const json_t *wire)
{
    (void)arg; (void)rid;
    pthread_mutex_lock(&g_ans.lock);
    g_ans.n++;
    if (wire == NULL) {
        g_ans.got_null = true;
    } else {
        at_reach_record_t r;
        if (at_reach_from_wire(wire, &r) == AT_REACH_OK) {
            g_ans.seq = at_reach_seq(&r);
            at_reach_free(&r);
        }
    }
    pthread_mutex_unlock(&g_ans.lock);
}

static bool _wait_answers(int n)
{
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&g_ans.lock);
        int got = g_ans.n;
        pthread_mutex_unlock(&g_ans.lock);
        if (got >= n)
            return true;
        usleep(10 * 1000);
    }
    return false;
}

DEFINE_TEST(test_a_relay_files_only_the_holders_newer_record)
{
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, g_log);
    int port = net_relay_server_port(srv);
    inbox_t in = { .lock = PTHREAD_MUTEX_INITIALIZER };
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice,
                                                 _deliver, &in, g_log);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob,
                                                 _deliver, &in, g_log);
    net_relay_client_on_record(b, _on_record, NULL);
    ck_assert_int_eq(net_relay_client_connect(a), 0);
    ck_assert_int_eq(net_relay_client_connect(b), 0);
    memset(&g_ans.n, 0, sizeof(g_ans.n));
    g_ans.got_null = false;

    at_reach_record_t r5, r4, rb;
    _record(alice, 5, "relay://203.0.113.7:27790", 0, &r5);
    _record(alice, 4, "relay://198.51.100.1:1", 0, &r4);
    _record(bob, 9, "relay://198.51.100.9:9", 0, &rb);
    json_t *w5 = at_reach_to_wire(&r5), *w4 = at_reach_to_wire(&r4),
           *wb = at_reach_to_wire(&rb);
    ck_assert_int_eq(net_relay_client_publish(a, w5), 0);
    ck_assert_int_eq(net_relay_client_publish(a, w4), 0);   /* stale: refused */
    ck_assert_int_eq(net_relay_client_publish(a, wb), 0);   /* Bob's: refused */
    char rid[AT_RELAY_FP_BYTES * 2 + 1], bid[AT_RELAY_FP_BYTES * 2 + 1];
    ck_assert_int_eq(at_reach_record_id(&r5, rid, sizeof(rid)), 0);
    ck_assert_int_eq(at_reach_record_id(&rb, bid, sizeof(bid)), 0);
    usleep(200 * 1000);
    ck_assert_int_eq(net_relay_client_lookup(b, rid), 0);
    ck_assert(_wait_answers(1));
    ck_assert_int_eq(g_ans.seq, 5);
    /* Bob's record was never filed (Alice cannot file it), and a lookup of
     * something unknown answers null. */
    ck_assert_int_eq(net_relay_client_lookup(b, bid), 0);
    ck_assert(_wait_answers(2));
    ck_assert(g_ans.got_null);
    json_decref(w5);
    json_decref(w4);
    json_decref(wb);
    at_reach_free(&r5);
    at_reach_free(&r4);
    at_reach_free(&rb);
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
    identity_free(alice);
    identity_free(bob);
}
END_TEST_DEFINITION()

RUN_TESTS(NetRelay,
          test_endpoints_and_hints,
          test_two_clients_exchange_frames_and_from_is_the_relays,
          test_registering_someone_elses_uuid_is_refused,
          test_an_oversized_frame_drops_the_connection,
          test_a_reconnect_replaces_the_old_registration,
          test_a_relay_route_is_refused_from_the_wire,
          test_a_relayed_frame_must_claim_the_sender_the_relay_stamped,
          test_own_relays_parse_a_list,
          test_a_route_list_goes_ahead_of_the_old_one,
          test_a_send_fails_over_to_the_next_relay_that_is_up,
          test_unreachable_resends_through_the_next_relay,
          test_unreachable_everywhere_ends_after_each_relay_once,
          test_a_frame_every_relay_refused_is_retried_a_few_rounds,
          test_pinned_hints_parse_and_round_trip,
          test_a_relay_proves_itself_and_a_pin_is_enforced,
          test_a_relay_refuses_and_evicts_a_distrusted_client,
          test_the_network_gate_matches_by_uuid_and_by_key,
          test_a_reach_record_verifies_and_refuses_tampering,
          test_a_relay_files_only_the_holders_newer_record)
