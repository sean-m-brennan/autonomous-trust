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

/* Area cards (contacts/area_card) and the area hub on a relay (network/net_hub).
 * Mirrors Python tests/a_unit/test_area_hub.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "contacts/area_card.h"
#include "contacts/directory.h"
#include "identity/identity_priv.h"
#include "network/net_hub.h"
#include "network/net_relay.h"
#include "network/net_proc_priv.h"
#include "network/network.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

static double g_mono = 1000.0;
static double g_wall = 0.0;   /* > 0: the wall clock stands here */

static double _mono(void) { return g_mono; }
static double _wall(void) { return g_wall > 0.0 ? g_wall : (double)time(NULL); }

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static void _ids(const identity_t *who, char *uu, const char **key)
{
    uuid_unparse_lower(who->uuid, uu);
    *key = (const char *)who->signature.public_hex;
}

/* A wire card (new reference). */
static json_t *_card(const identity_t *who, const char *area, const char *bucket,
                     int64_t seq, long ttl)
{
    at_dir_signed_t c;
    double now = (double)time(NULL);
    ck_assert_int_eq(at_area_card_create(who, area, bucket, "", seq, (long)now + ttl, now, &c),
                     AT_DIR_OK);
    json_t *w = at_dir_to_wire(&c);
    at_dir_free(&c);
    return w;
}

static net_hub_t *_hub(int rate)
{
    const char *areas[] = {"u4pr", "gcpv"};
    net_hub_t *h = net_hub_new(areas, 2, rate);
    g_mono = 1000.0;
    g_wall = 0.0;
    net_hub_set_clocks(h, _mono, _wall);
    return h;
}

static const char *_op(const json_t *reply)
{
    return json_string_value(json_object_get(reply, "op"));
}

static const char *_reason(const json_t *reply)
{
    const char *r = json_string_value(json_object_get(reply, "reason"));
    return r != NULL ? r : "";
}

static void _publish_is(net_hub_t *h, const identity_t *as, json_t *wire, const char *op,
                        const char *reason)
{
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(as, uu, &key);
    json_t *rep = net_hub_publish(h, uu, key, wire);
    ck_assert_str_eq(_op(rep), op);
    if (reason != NULL)
        ck_assert_str_eq(_reason(rep), reason);
    json_decref(rep);
    json_decref(wire);
}

/* How many cards @p as sees in @p area. */
static size_t _seen(net_hub_t *h, const identity_t *as, const char *area)
{
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(as, uu, &key);
    json_t *rep = net_hub_lookup(h, uu, area);
    ck_assert_str_eq(_op(rep), "hub_cards");
    size_t n = json_array_size(json_object_get(rep, "cards"));
    json_decref(rep);
    return n;
}

DEFINE_TEST(test_a_card_verifies_and_a_tampered_or_bad_one_does_not)
{
    identity_t *alice = _mk("alice");
    at_dir_signed_t c;
    double now = (double)time(NULL);
    ck_assert_int_eq(at_area_card_create(alice, "U4PR", "u4pru", "Alice B.", 1, 0, now, &c),
                     AT_DIR_OK);
    ck_assert_int_eq(at_area_card_verify(&c, now), AT_DIR_OK);
    ck_assert_str_eq(at_area_card_area(&c), "u4pr");
    ck_assert_int_eq(at_area_card_verify(&c, now + AT_AREA_DEFAULT_TTL_SECONDS + 1),
                     AT_DIR_EXPIRED);
    json_t *w = at_dir_to_wire(&c);
    at_dir_free(&c);
    char *body = strdup(json_string_value(json_object_get(w, "body")));
    char *at = strstr(body, "\"u4pru\"");
    ck_assert(at != NULL);
    at[5] = 'v';
    json_object_set_new(w, "body", json_string(body));
    free(body);
    ck_assert_int_eq(at_dir_from_wire(w, &c), AT_DIR_OK);
    ck_assert_int_eq(at_area_card_verify(&c, now), AT_DIR_BAD_SIG);
    at_dir_free(&c);
    json_decref(w);
    /* Cards no hub would take are not made. */
    const char *bad[][3] = {{"u", "u4pru", ""}, {"u4pru1", "u4pru1", ""},
                            {"u4pa", "u4pau", ""}, {"u4pr", "u4ps", ""},
                            {"u4pr", "u4pruu", ""}, {"u4pr", "u4pru", "a\nb"}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ck_assert_int_eq(at_area_card_create(alice, bad[i][0], bad[i][1], bad[i][2], 1, 0, now,
                                             &c), AT_DIR_MALFORMED);
    char longname[80];
    memset(longname, 'x', 65);
    longname[65] = '\0';
    ck_assert_int_eq(at_area_card_create(alice, "u4pr", "u4pru", longname, 1, 0, now, &c),
                     AT_DIR_MALFORMED);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_listed_people_see_each_other_but_never_themselves_and_outsiders_see_none)
{
    net_hub_t *h = _hub(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob"), *eve = _mk("eve");
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    ck_assert_int_eq(_seen(h, eve, "u4pr"), 0);         /* not listed: sees an empty area */
    _publish_is(h, bob, _card(bob, "u4pr", "u4prv", 1, 3600), "hub_published", NULL);
    char uu[UUID_STR_LEN + 1], au[UUID_STR_LEN + 1];
    const char *key;
    _ids(bob, uu, &key);
    _ids(alice, au, &key);
    json_t *rep = net_hub_lookup(h, uu, "U4PR");
    ck_assert_str_eq(json_string_value(json_object_get(rep, "area")), "u4pr");
    json_t *cards = json_object_get(rep, "cards");
    ck_assert_int_eq(json_array_size(cards), 1);
    at_dir_signed_t c;
    ck_assert_int_eq(at_dir_from_wire(json_array_get(cards, 0), &c), AT_DIR_OK);
    ck_assert_str_eq(at_dir_uuid(&c), au);
    at_dir_free(&c);
    json_decref(rep);
    /* Listed in ANOTHER area of the same hub is still outside this one. */
    _publish_is(h, eve, _card(eve, "gcpv", "gcpvj", 1, 3600), "hub_published", NULL);
    ck_assert_int_eq(_seen(h, eve, "u4pr"), 0);
    identity_free(alice);
    identity_free(bob);
    identity_free(eve);
    net_hub_free(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_card_is_refused_for_the_area_the_holder_the_expiry_and_a_stale_seq)
{
    net_hub_t *h = _hub(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob"), *mallory = _mk("mallory");
    _publish_is(h, alice, _card(alice, "9q8y", "9q8yy", 1, 3600), "hub_refused", "area");
    _publish_is(h, mallory, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_refused", "not_holder");
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, AT_AREA_MAX_TTL_SECONDS + 60),
                "hub_refused", "expiry");
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, -1), "hub_refused", "expired");
    _publish_is(h, bob, _card(bob, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    json_t *two = _card(alice, "u4pr", "u4pru", 2, 3600);
    json_incref(two);
    _publish_is(h, alice, two, "hub_published", NULL);
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_refused", "stale");
    _publish_is(h, alice, two, "hub_published", NULL);  /* the same one refiles */
    _publish_is(h, alice, _card(alice, "u4pr", "u4prw", 3, 3600), "hub_published", NULL);
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 1);           /* one card per holder */
    identity_free(alice);
    identity_free(bob);
    identity_free(mallory);
    net_hub_free(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_withdraw_is_holder_only_and_an_expired_listing_neither_shows_nor_sees)
{
    net_hub_t *h = _hub(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob"), *eve = _mk("eve");
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    _publish_is(h, bob, _card(bob, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(eve, uu, &key);
    json_decref(net_hub_withdraw(h, uu, key, "u4pr"));
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 1);
    _ids(alice, uu, &key);
    json_t *rep = net_hub_withdraw(h, uu, key, "U4PR");
    ck_assert_str_eq(_op(rep), "hub_withdrawn");
    ck_assert_str_eq(json_string_value(json_object_get(rep, "area")), "u4pr");
    json_decref(rep);
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 0);
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 2, 3600), "hub_published", NULL);
    g_wall = (double)time(NULL) + 7200;
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 0);
    identity_free(alice);
    identity_free(bob);
    identity_free(eve);
    net_hub_free(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_lookups_are_rate_limited_and_an_answer_is_bounded_freshest_first)
{
    net_hub_t *h = _hub(3);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    _publish_is(h, bob, _card(bob, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    char bu[UUID_STR_LEN + 1];
    const char *key;
    _ids(bob, bu, &key);
    const char *want[] = {"hub_cards", "hub_cards", "hub_cards", "hub_limited"};
    for (int i = 0; i < 4; i++) {
        json_t *rep = net_hub_lookup(h, bu, "u4pr");
        ck_assert_str_eq(_op(rep), want[i]);
        json_decref(rep);
    }
    g_mono += 20.0;                 /* one token back at 3/min */
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 1);
    net_hub_free(h);
    identity_free(alice);

    h = _hub(100);
    _publish_is(h, bob, _card(bob, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    identity_t *people[AT_HUB_LOOKUP_MAX + 3];
    for (size_t i = 0; i < AT_HUB_LOOKUP_MAX + 3; i++) {
        people[i] = _mk("p");
        _publish_is(h, people[i], _card(people[i], "u4pr", "u4pru", 1, 600 + (long)i),
                    "hub_published", NULL);
    }
    json_t *rep = net_hub_lookup(h, bu, "u4pr");
    json_t *cards = json_object_get(rep, "cards");
    ck_assert_int_eq(json_array_size(cards), AT_HUB_LOOKUP_MAX);
    long last = 0;
    for (size_t i = 0; i < json_array_size(cards); i++) {
        at_dir_signed_t c;
        ck_assert_int_eq(at_dir_from_wire(json_array_get(cards, i), &c), AT_DIR_OK);
        ck_assert(i == 0 || at_dir_expiry(&c) <= last);
        last = at_dir_expiry(&c);
        if (i == 0) {
            char first[UUID_STR_LEN + 1];
            uuid_unparse_lower(people[AT_HUB_LOOKUP_MAX + 2]->uuid, first);
            ck_assert_str_eq(at_dir_uuid(&c), first);
        }
        at_dir_free(&c);
    }
    json_decref(rep);
    for (size_t i = 0; i < AT_HUB_LOOKUP_MAX + 3; i++)
        identity_free(people[i]);
    identity_free(bob);
    net_hub_free(h);
}
END_TEST_DEFINITION()

static char g_bad_uuid[UUID_STR_LEN + 1];
static bool _distrust(void *arg, const char *uuid, const char *key)
{
    (void)arg;
    (void)key;
    return strcmp(uuid, g_bad_uuid) == 0;
}

DEFINE_TEST(test_a_distrusted_holder_is_not_shown_and_areas_come_from_the_environment)
{
    net_hub_t *h = _hub(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    net_hub_set_distrust(h, _distrust, NULL);
    g_bad_uuid[0] = '\0';
    _publish_is(h, alice, _card(alice, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    _publish_is(h, bob, _card(bob, "u4pr", "u4pru", 1, 3600), "hub_published", NULL);
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 1);
    uuid_unparse_lower(alice->uuid, g_bad_uuid);
    ck_assert_int_eq(_seen(h, bob, "u4pr"), 0);
    identity_free(alice);
    identity_free(bob);
    net_hub_free(h);
    setenv(AT_HUB_AREAS_ENV, " U4PR, gcpv,nonsense-area,u4pr,x", 1);
    char areas[AT_HUB_MAX_AREAS][AT_AREA_MAX + 1];
    ck_assert_int_eq(net_hub_areas(areas, AT_HUB_MAX_AREAS), 2);
    ck_assert_str_eq(areas[0], "u4pr");
    ck_assert_str_eq(areas[1], "gcpv");
    unsetenv(AT_HUB_AREAS_ENV);
    setenv("AT_HUB", "yes", 1);
    ck_assert(net_hub_enabled());
    unsetenv("AT_HUB");
    ck_assert(!net_hub_enabled());
}
END_TEST_DEFINITION()

/* -- over the relay's own link --------------------------------------------- */
static struct {
    pthread_mutex_t lock;
    int n;
    json_t *last;
} g_hubs = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _on_hub(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg; (void)host; (void)port;
    pthread_mutex_lock(&g_hubs.lock);
    json_decref(g_hubs.last);
    g_hubs.last = json_deep_copy(msg);
    g_hubs.n++;
    pthread_mutex_unlock(&g_hubs.lock);
}

static bool _wait_hub(int n)
{
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&g_hubs.lock);
        bool ok = g_hubs.n >= n;
        pthread_mutex_unlock(&g_hubs.lock);
        if (ok)
            return true;
        usleep(10 * 1000);
    }
    return false;
}

static void _nodeliver(void *arg, const char *from, const uint8_t *frame, size_t len,
                       const char *host, int port)
{
    (void)arg; (void)from; (void)frame; (void)len; (void)host; (void)port;
}

DEFINE_TEST(test_the_ops_run_over_the_relay_link)
{
    const char *areas[] = {"u4pr"};
    net_hub_t *h = net_hub_new(areas, 1, 10);
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, NULL);
    ck_assert(srv != NULL);
    net_relay_server_set_hub(srv, h);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    int port = net_relay_server_port(srv);
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice, _nodeliver, NULL, NULL);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _nodeliver, NULL, NULL);
    net_relay_client_on_hub(a, _on_hub, NULL);
    net_relay_client_on_hub(b, _on_hub, NULL);
    g_hubs.n = 0;
    json_t *c = _card(alice, "u4pr", "u4pru", 1, 3600);
    ck_assert_int_eq(net_relay_client_hub_publish(a, c), 0);
    json_decref(c);
    ck_assert(_wait_hub(1));
    ck_assert_str_eq(_op(g_hubs.last), "hub_published");
    c = _card(bob, "u4pr", "u4pru", 1, 3600);
    ck_assert_int_eq(net_relay_client_hub_publish(b, c), 0);
    json_decref(c);
    ck_assert(_wait_hub(2));
    ck_assert_int_eq(net_relay_client_hub_lookup(b, "u4pr"), 0);
    ck_assert(_wait_hub(3));
    ck_assert_str_eq(_op(g_hubs.last), "hub_cards");
    ck_assert_int_eq(json_array_size(json_object_get(g_hubs.last, "cards")), 1);
    /* A plain relay (no hub) refuses. */
    net_relay_server_set_hub(srv, NULL);
    ck_assert_int_eq(net_relay_client_hub_lookup(b, "u4pr"), 0);
    ck_assert(_wait_hub(4));
    ck_assert_str_eq(_op(g_hubs.last), "hub_refused");
    ck_assert_str_eq(_reason(g_hubs.last), "not_hub");
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
    identity_free(alice);
    identity_free(bob);
    net_hub_free(h);
    json_decref(g_hubs.last);
    g_hubs.last = NULL;
}
END_TEST_DEFINITION()

/* -- the network process between identity and the hubs --------------------- */
static struct {
    int n_asks;
    char asks[16][96];              /* "host:port op arg" */
    int n_out;
    char fn[16][32];
    json_t *body[16];
} g_net;

static int _test_hub(const char *host, int port, const char *op, const char *area,
                     const json_t *card)
{
    (void)card;
    if (g_net.n_asks < 16)
        snprintf(g_net.asks[g_net.n_asks++], sizeof(g_net.asks[0]), "%s:%d %s %s",
                 host, port, op, area != NULL ? area : "-");
    return 0;
}

static int _net_hook(const char *key, const message_type_t type, generic_msg_t *msg,
                     bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL && g_net.n_out < 16) {
        at_strlcpy(g_net.fn[g_net.n_out], msg->info.net_msg.function, sizeof(g_net.fn[0]));
        json_t *b = NULL;
        (void)net_msg_unpack_json(&msg->info.net_msg, &b);
        g_net.body[g_net.n_out++] = b;
    }
    return 0;
}

static void _net_begin(void)
{
    for (int i = 0; i < g_net.n_out; i++)
        json_decref(g_net.body[i]);
    memset(&g_net, 0, sizeof(g_net));
    setenv("AT_USE_RELAY", "198.51.100.1:27790,198.51.100.2:27790", 1);
    net_relay_reset_routes();
    net_relay_set_test_hub(_test_hub);
    messaging_set_test_hook(_net_hook);
}

static void _net_end(void)
{
    messaging_set_test_hook(NULL);
    net_relay_set_test_hub(NULL);
    unsetenv("AT_USE_RELAY");
    for (int i = 0; i < g_net.n_out; i++)
        json_decref(g_net.body[i]);
    memset(&g_net, 0, sizeof(g_net));
}

static void _ipc(int (*fn)(net_msg_t *, logger_t *), const char *verb, json_t *body,
                 const identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = (char *)verb;
    if (from != NULL)
        uuid_copy(msg.info.net_msg.from_whom.uuid, from->uuid);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    (void)fn(&msg.info.net_msg, NULL);
}

static void _answer(const char *host, json_t *frame)
{
    net_relay_hub_answer(NULL, frame, host, 27790);
    json_decref(frame);
}

DEFINE_TEST(test_the_network_gathers_every_hubs_cards_and_answers_once)
{
    _net_begin();
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    _ipc(net_handle_hub_lookup, NET_FN_HUB_LOOKUP, json_pack("{s:s}", "area", "U4PR"), NULL);
    ck_assert_int_eq(g_net.n_asks, 2);
    ck_assert_str_eq(g_net.asks[0], "198.51.100.1:27790 hub_lookup u4pr");
    ck_assert_str_eq(g_net.asks[1], "198.51.100.2:27790 hub_lookup u4pr");
    json_t *wa = _card(alice, "u4pr", "u4pru", 1, 3600), *wb = _card(bob, "u4pr", "u4pru", 1, 3600);
    _answer("198.51.100.1", json_pack("{s:s, s:s, s:[O]}", "op", "hub_cards", "area", "u4pr",
                                      "cards", wa));
    net_relay_drain_hub();
    ck_assert_int_eq(g_net.n_out, 0);           /* the second has not answered */
    _answer("198.51.100.2", json_pack("{s:s, s:s, s:[O]}", "op", "hub_cards", "area", "u4pr",
                                      "cards", wb));
    net_relay_drain_hub();
    ck_assert_int_eq(g_net.n_out, 1);
    ck_assert_str_eq(g_net.fn[0], "hub_result");
    json_t *want = json_pack("{s:s, s:[{s:O, s:s}, {s:O, s:s}], s:b}", "area", "u4pr",
                             "cards", "card", wa, "relay", "198.51.100.1:27790",
                             "card", wb, "relay", "198.51.100.2:27790", "limited", 0);
    ck_assert(json_equal(g_net.body[0], want));
    json_decref(want);
    /* A relay that is no hub counts as empty; limited is passed on; our card
     * is filed at our relays, and a no-hub refusal of it is not reported. */
    _ipc(net_handle_hub_lookup, NET_FN_HUB_LOOKUP, json_pack("{s:s}", "area", "u4pr"), NULL);
    _answer("198.51.100.1", json_pack("{s:s, s:s}", "op", "hub_limited", "area", "u4pr"));
    _answer("198.51.100.2", json_pack("{s:s, s:s, s:s}", "op", "hub_refused", "area", "u4pr",
                                      "reason", "not_hub"));
    net_relay_drain_hub();
    ck_assert_int_eq(g_net.n_out, 2);
    want = json_pack("{s:s, s:[], s:b}", "area", "u4pr", "cards", "limited", 1);
    ck_assert(json_equal(g_net.body[1], want));
    json_decref(want);
    _ipc(net_handle_hub_publish, NET_FN_HUB_PUBLISH, json_pack("{s:O}", "card", wa), NULL);
    ck_assert_int_eq(g_net.n_asks, 6);
    ck_assert_str_eq(g_net.asks[5], "198.51.100.2:27790 hub_publish -");
    _answer("198.51.100.1", json_pack("{s:s, s:s, s:s}", "op", "hub_refused", "area", "u4pr",
                                      "reason", "not_hub"));
    _answer("198.51.100.2", json_pack("{s:s, s:s, s:i}", "op", "hub_published", "area", "u4pr",
                                      "seq", 1));
    net_relay_drain_hub();
    ck_assert_int_eq(g_net.n_out, 3);
    ck_assert_str_eq(g_net.fn[2], "hub_status");
    ck_assert_str_eq(json_string_value(json_object_get(g_net.body[2], "op")), "hub_published");
    /* A lookup nobody finishes answering times out with what came. */
    _ipc(net_handle_hub_lookup, NET_FN_HUB_LOOKUP, json_pack("{s:s}", "area", "u4pr"), NULL);
    _answer("198.51.100.1", json_pack("{s:s, s:s, s:[O]}", "op", "hub_cards", "area", "u4pr",
                                      "cards", wa));
    net_relay_drain_hub();
    net_relay_hub_age_lookups(NET_HUB_LOOKUP_TIMEOUT_SEC + 1);
    net_relay_drain_hub();
    ck_assert_int_eq(g_net.n_out, 4);
    ck_assert_int_eq(json_array_size(json_object_get(g_net.body[3], "cards")), 1);
    /* Refused from the wire. */
    int asks = g_net.n_asks;
    _ipc(net_handle_hub_lookup, NET_FN_HUB_LOOKUP, json_pack("{s:s}", "area", "u4pr"), alice);
    _ipc(net_handle_hub_withdraw, NET_FN_HUB_WITHDRAW, json_pack("{s:s}", "area", "u4pr"), alice);
    ck_assert_int_eq(g_net.n_asks, asks);
    json_decref(wa);
    json_decref(wb);
    identity_free(alice);
    identity_free(bob);
    _net_end();
}
END_TEST_DEFINITION()

RUN_TESTS(NetHub,
          test_a_card_verifies_and_a_tampered_or_bad_one_does_not,
          test_listed_people_see_each_other_but_never_themselves_and_outsiders_see_none,
          test_a_card_is_refused_for_the_area_the_holder_the_expiry_and_a_stale_seq,
          test_withdraw_is_holder_only_and_an_expired_listing_neither_shows_nor_sees,
          test_lookups_are_rate_limited_and_an_answer_is_bounded_freshest_first,
          test_a_distrusted_holder_is_not_shown_and_areas_come_from_the_environment,
          test_the_ops_run_over_the_relay_link,
          test_the_network_gathers_every_hubs_cards_and_answers_once)
