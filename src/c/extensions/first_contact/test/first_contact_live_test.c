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

/* First contact between two real C daemons, as their apps drive it.
 *
 * The C twin of tests/b_integration/test_first_contact_two_node.py. Two AT
 * daemons, each started by its own host process through at_app_node_start,
 * on separate loopback addresses and one shared comm port. Each host talks to
 * its daemon ONLY through the flat app ABI -- at_app_first_contact_* to ask,
 * at_app_events_poll to hear -- which is what a foreign consumer would do:
 *
 *   alice's host   invite ............................ established -> list (1)
 *   bob's host              initiate -> hello_sent -> established -> remove -> list (0)
 *
 * The parent is the out-of-band channel: it carries Alice's link to Bob's host
 * and collects each host's report. What this covers that the unit tests and
 * the corpus cannot: the app verbs crossing a real daemon's main loop to
 * identity, the hello and ack crossing real sockets, app_bound forwarding of
 * both first-contact event types, and a removal inside a running daemon.
 *
 * A config is generated per node and its address rewritten to the loopback
 * one, because generation skips loopback interfaces -- left alone, both nodes
 * would claim the same real address. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>

#include "app_events.h"
#include "app_node.h"
#include "first_contact/at_first_contact.h"
#include "config/configuration.h"
#include "config/generate.h"
#include "utilities/util.h"
#include "first_contact/contacts.h"
#include "first_contact/directory.h"
#include "first_contact/net_registry.h"
#include "rendezvous/net_relay_seeds.h"
#include "first_contact/first_contact.h"
#include "processes/plaintext_verbs.h"
#include <sodium.h>

#define STEP_TIMEOUT_S 60
/* How long one step may wait. The no-relay control shortens it: the event it
 * waits for is one that must NOT come. */
static int g_step_timeout = STEP_TIMEOUT_S;
#define ALICE_IP "127.0.0.1"
#define BOB_IP   "127.0.0.2"

/* ------------------------------------------------------------------ */
/* Config: generate, then move the node onto its loopback address      */
/* ------------------------------------------------------------------ */

/* Replace every JSON string that is `from` (or `from/<bits>`) with `to`
 * (or `to/8`), in place, recursively. */
static int _swap_address(json_t *v, const char *from, const char *to)
{
    int n = 0;
    if (json_is_object(v)) {
        const char *k;
        json_t *x;
        json_object_foreach(v, k, x) {
            const char *s = json_string_value(x);
            size_t fl = strlen(from);
            if (s != NULL && strcmp(s, from) == 0) {
                json_object_set_new(v, k, json_string(to));
                n++;
            } else if (s != NULL && strncmp(s, from, fl) == 0 && s[fl] == '/') {
                char cidr[64];
                snprintf(cidr, sizeof(cidr), "%s/8", to);
                json_object_set_new(v, k, json_string(cidr));
                n++;
            } else {
                n += _swap_address(x, from, to);
            }
        }
    } else if (json_is_array(v)) {
        for (size_t i = 0; i < json_array_size(v); i++)
            n += _swap_address(json_array_get(v, i), from, to);
    }
    return n;
}

/* The address generation chose, read back from the identity config. */
static int _generated_address(const char *cfg_dir, char *out, size_t len)
{
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/identity.cfg.json", cfg_dir);
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
        return -1;
    const char *a = json_string_value(json_object_get(root, "address"));
    int rc = -1;
    if (a != NULL && a[0] != '\0') {
        snprintf(out, len, "%s", a);
        rc = 0;
    }
    json_decref(root);
    return rc;
}

static int _move_to(const char *cfg_dir, const char *ip)
{
    char from[64];
    if (_generated_address(cfg_dir, from, sizeof(from)) != 0)
        return -1;
    DIR *d = opendir(cfg_dir);
    if (d == NULL)
        return -1;
    int swapped = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t l = strlen(e->d_name);
        if (l < 9 || strcmp(e->d_name + l - 9, ".cfg.json") != 0)
            continue;
        char path[CFG_PATH_LEN + 300];
        snprintf(path, sizeof(path), "%s/%s", cfg_dir, e->d_name);
        json_error_t err;
        json_t *root = json_load_file(path, 0, &err);
        if (root == NULL)
            continue;
        int n = _swap_address(root, from, ip);
        if (n > 0 && json_dump_file(root, path, JSON_INDENT(2)) == 0)
            swapped += n;
        json_decref(root);
    }
    closedir(d);
    return swapped > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* The host side: one app, one daemon                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    const char *ip;
    char root[512];
    char q_in[64];
    char q_out[64];
    int to_parent;          /* write end */
    int from_parent;        /* read end */
    int port;               /* this node's AT_COMM_PORT */
    const char *use_relay;  /* AT_USE_RELAY, or NULL */
    int serve_relay;        /* > 0: serve as a relay on this port, nothing else */
    bool registry;          /* the relay also serves the directory */
    bool directory;         /* alice/bob find each other by handle, not by link */
    bool no_accept;         /* directory alice never answers the request */
} host_t;

static at_app_node_t *g_node;
static at_app_events_t *g_ev;

static void _report(host_t *h, const char *fmt, ...)
{
    char line[AT_FC_BLOB_LEN + 256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n > sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\n';
    ssize_t w = write(h->to_parent, line, (size_t)n);
    (void)w;
}

/* Poll until an event of `kind` arrives (or a REFUSED, which is returned so
 * the caller can report the reason); copies it into *out. One event per poll,
 * so whatever arrived behind the match stays queued for the next wait -- a
 * list's CONTACT and CONTACTS_DONE land together, and a batch read would
 * discard the second. Other events (the peer carrier's) are skipped. */
static bool _await(int32_t kind, at_app_event_t *out)
{
    time_t deadline = time(NULL) + g_step_timeout;
    at_app_event_t one;
    while (time(NULL) < deadline) {
        if (at_app_events_poll(g_ev, &one, 1) == 1) {
            if (one.kind == kind || one.kind == AT_APP_EVENT_FC_REFUSED) {
                *out = one;
                return true;
            }
            continue;
        }
        usleep(50 * 1000);
    }
    return false;
}

/* Send until the daemon's queue is there to receive it. */
#define FC_SEND(call)                                                       \
    do {                                                                       \
        int _rc;                                                               \
        time_t _dl = time(NULL) + g_step_timeout;                              \
        while ((_rc = (call)) == AT_APP_NOT_READY && time(NULL) < _dl)         \
            usleep(100 * 1000);                                                \
        if (_rc != 0) {                                                        \
            _report(h, "FAIL send %s rc=%d", #call, _rc);                     \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define FC_EXPECT(want, ev, step)                                                 \
    do {                                                                       \
        if (!_await((want), &(ev))) {                                          \
            _report(h, "FAIL %s: no event within %ds", (step), g_step_timeout); \
            return 1;                                                          \
        }                                                                      \
        if ((ev).kind == AT_APP_EVENT_FC_REFUSED) {                            \
            _report(h, "FAIL %s: refused, reason %d", (step),                  \
                    at_first_contact_event(&(ev))->reason);                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int _alice(host_t *h)
{
    at_app_event_t ev;
    const char *hint = ALICE_IP;
    FC_SEND(at_app_first_contact_invite(g_ev, h->q_out, "for-bob", 600,
                                           &hint, 1));
    FC_EXPECT(AT_APP_EVENT_FC_INVITATION, ev, "invitation");
    _report(h, "LINK %s", at_first_contact_event(&ev)->blob);

    FC_EXPECT(AT_APP_EVENT_FC_ESTABLISHED, ev, "established");
    const at_app_first_contact_t *fc = at_first_contact_event(&ev);
    if (fc->role != AT_FC_ROLE_INVITER || strcmp(fc->ref, "for-bob") != 0) {
        _report(h, "FAIL established: role %d ref '%s'", fc->role, fc->ref);
        return 1;
    }
    _report(h, "OK established");

    FC_SEND(at_app_first_contact_list(g_ev, h->q_out, "l"));
    /* Bob, recorded from a real envelope, which carries no petname: the record
     * must still have one to show. */
    FC_EXPECT(AT_APP_EVENT_FC_CONTACT, ev, "list record");
    if (at_first_contact_contact_event(&ev)->petname[0] == '\0') {
        _report(h, "FAIL list: Bob's record has no petname");
        return 1;
    }
    FC_EXPECT(AT_APP_EVENT_FC_CONTACTS_DONE, ev, "list");
    int count = at_first_contact_contact_event(&ev)->count;
    if (count != 1) {
        _report(h, "FAIL list: %d contacts, expected 1", count);
        return 1;
    }
    _report(h, "OK list 1");
    return 0;
}

static int _bob(host_t *h)
{
    /* Alice's link, carried by the parent. */
    char line[AT_FC_BLOB_LEN + 64];
    FILE *in = fdopen(h->from_parent, "r");
    if (in == NULL || fgets(line, sizeof(line), in) == NULL) {
        _report(h, "FAIL no link from parent");
        return 1;
    }
    line[strcspn(line, "\n")] = '\0';

    at_app_event_t ev;
    FC_SEND(at_app_first_contact_initiate(g_ev, h->q_out, "add-alice", line,
                                             NULL, false, "Alice"));
    FC_EXPECT(AT_APP_EVENT_FC_HELLO_SENT, ev, "hello_sent");
    uint8_t alice[AT_APP_UUID_LEN];
    memcpy(alice, at_first_contact_event(&ev)->peer_uuid, sizeof(alice));

    FC_EXPECT(AT_APP_EVENT_FC_ESTABLISHED, ev, "established");
    const at_app_first_contact_t *fc = at_first_contact_event(&ev);
    if (fc->role != AT_FC_ROLE_INITIATOR || strcmp(fc->ref, "add-alice") != 0
        || memcmp(fc->peer_uuid, alice, sizeof(alice)) != 0) {
        _report(h, "FAIL established: role %d ref '%s'", fc->role, fc->ref);
        return 1;
    }
    _report(h, "OK established");

    FC_SEND(at_app_first_contact_remove(g_ev, h->q_out, "rm", alice));
    FC_EXPECT(AT_APP_EVENT_FC_REMOVED, ev, "removed");
    if (!at_first_contact_contact_event(&ev)->peer_dropped) {
        _report(h, "FAIL removed: the direct peer was not dropped");
        return 1;
    }
    _report(h, "OK removed");

    FC_SEND(at_app_first_contact_list(g_ev, h->q_out, "l"));
    FC_EXPECT(AT_APP_EVENT_FC_CONTACTS_DONE, ev, "list");
    int count = at_first_contact_contact_event(&ev)->count;
    if (count != 0) {
        _report(h, "FAIL list: %d contacts, expected 0", count);
        return 1;
    }
    _report(h, "OK list 0");
    return 0;
}

/* -- the directory (FIRST_CONTACT_PLAN Phase 3) ------------------------------ */
static unsigned char g_issuer_sk[crypto_sign_SECRETKEYBYTES];
static char g_issuer_hex[65];

static void _issuer(void)
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, 0x44, sizeof(seed));
    crypto_sign_seed_keypair(pk, g_issuer_sk, seed);
    sodium_bin2hex(g_issuer_hex, sizeof(g_issuer_hex), pk, sizeof(pk));
}

/* Poll for a directory event of @p kind (or DIR_REFUSED) within @p secs. */
static bool _await_kind(int32_t kind, int secs, at_app_event_t *out)
{
    time_t deadline = time(NULL) + secs;
    at_app_event_t one;
    while (time(NULL) < deadline) {
        if (at_app_events_poll(g_ev, &one, 1) == 1) {
            if (one.kind == kind || one.kind == AT_APP_EVENT_DIR_REFUSED
                || one.kind == AT_APP_EVENT_FC_REFUSED) {
                *out = one;
                return one.kind == kind;
            }
            continue;
        }
        usleep(50 * 1000);
    }
    return false;
}

static int _dir_alice(host_t *h)
{
    char key[65];
    at_dir_signed_t att;
    if (net_relay_seeds_node_key(key, sizeof(key)) != 0
        || at_dir_attest(g_issuer_sk, "alice@example.org", key, (long)time(NULL) + 3600,
                         &att) != AT_DIR_OK) {
        _report(h, "FAIL attestation");
        return 1;
    }
    json_t *w = at_dir_to_wire(&att);
    char *att_text = json_dumps(w, JSON_COMPACT);
    json_decref(w);
    at_dir_free(&att);
    at_app_event_t ev;
    /* Registration with Carol runs in the background: publish until filed. */
    time_t deadline = time(NULL) + g_step_timeout;
    bool filed = false;
    while (!filed && time(NULL) < deadline) {
        FC_SEND(at_app_directory_publish(g_ev, h->q_out, "pub", att_text, NULL));
        filed = _await_kind(AT_APP_EVENT_DIR_PUBLISHED, 5, &ev);
    }
    free(att_text);
    if (!filed) {
        _report(h, "FAIL published");
        return 1;
    }
    _report(h, "OK published");
    if (!_await_kind(AT_APP_EVENT_DIR_CONTACT_REQUEST, g_step_timeout, &ev)) {
        _report(h, "FAIL contact_request");
        return 1;
    }
    char ref[AT_FC_REF_LEN];
    snprintf(ref, sizeof(ref), "%s", at_first_contact_directory_event(&ev)->ref);
    _report(h, "OK contact_request %s", at_first_contact_directory_event(&ev)->handle);
    if (h->no_accept) {
        /* Stay up, and never answer: silence must not add anyone. */
        _report(h, "OK not answering");
        char buf[16];
        while (read(h->from_parent, buf, sizeof(buf)) > 0)
            ;
        return 0;
    }
    FC_SEND(at_app_first_contact_accept(g_ev, h->q_out, ref));
    FC_EXPECT(AT_APP_EVENT_FC_ESTABLISHED, ev, "established");
    const at_app_first_contact_t *fc = at_first_contact_event(&ev);
    if (fc->role != AT_FC_ROLE_INVITER || strcmp(fc->ref, ref) != 0) {
        _report(h, "FAIL established: role %d ref '%s'", fc->role, fc->ref);
        return 1;
    }
    _report(h, "OK established");
    FC_SEND(at_app_first_contact_list(g_ev, h->q_out, "l"));
    FC_EXPECT(AT_APP_EVENT_FC_CONTACT, ev, "list record");
    const at_app_contact_t *c = at_first_contact_contact_event(&ev);
    if (c->provenance != AT_PROV_DIRECTORY || c->verified) {
        _report(h, "FAIL list: provenance %d verified %d", c->provenance, c->verified);
        return 1;
    }
    _report(h, "OK list directory");
    return 0;
}

static int _dir_bob(host_t *h)
{
    at_app_event_t ev;
    time_t deadline = time(NULL) + g_step_timeout;
    bool found = false;
    while (!found && time(NULL) < deadline) {
        FC_SEND(at_app_directory_lookup(g_ev, h->q_out, "look", "Alice@Example.org"));
        found = _await_kind(AT_APP_EVENT_DIR_FOUND, 15, &ev);
        if (!found)
            sleep(1);
    }
    if (!found) {
        _report(h, "FAIL found");
        return 1;
    }
    _report(h, "OK found %s", at_first_contact_directory_event(&ev)->nickname);
    FC_SEND(at_app_first_contact_request(g_ev, h->q_out, "ask", "alice@example.org"));
    if (!_await_kind(AT_APP_EVENT_DIR_REQUEST_SENT, g_step_timeout, &ev)) {
        _report(h, "FAIL request_sent");
        return 1;
    }
    FC_EXPECT(AT_APP_EVENT_FC_ESTABLISHED, ev, "established");
    const at_app_first_contact_t *fc = at_first_contact_event(&ev);
    if (fc->role != AT_FC_ROLE_INITIATOR || strcmp(fc->ref, "ask") != 0) {
        _report(h, "FAIL established: role %d ref '%s'", fc->role, fc->ref);
        return 1;
    }
    _report(h, "OK established");
    FC_SEND(at_app_first_contact_list(g_ev, h->q_out, "l"));
    FC_EXPECT(AT_APP_EVENT_FC_CONTACT, ev, "list record");
    const at_app_contact_t *c = at_first_contact_contact_event(&ev);
    if (c->provenance != AT_PROV_DIRECTORY || c->verified) {
        _report(h, "FAIL list: provenance %d verified %d", c->provenance, c->verified);
        return 1;
    }
    _report(h, "OK list directory");
    return 0;
}

/* A relay-only host: run the daemon until the parent hangs up. */
static int _carol(host_t *h)
{
    _report(h, "OK up");
    char buf[16];
    while (read(h->from_parent, buf, sizeof(buf)) > 0)
        ;
    return 0;
}

static int _host_main(host_t *h, int port)
{
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%d", h->port > 0 ? h->port : port);
    setenv("AUTONOMOUS_TRUST_ROOT", h->root, 1);
    setenv("AT_FIRST_CONTACT", "1", 1);
    setenv("AT_PEER_NAME", h->name, 1);   /* the nickname a lookup reports */
    setenv("AT_COMM_PORT", port_s, 1);
    if (h->use_relay != NULL)
        setenv("AT_USE_RELAY", h->use_relay, 1);
    if (h->serve_relay > 0) {
        char rp[16];
        snprintf(rp, sizeof(rp), "%d", h->serve_relay);
        setenv("AT_RELAY", "1", 1);
        setenv("AT_RELAY_PORT", rp, 1);
        if (h->registry)
            setenv("AT_REGISTRY", "1", 1);
    }

    char cfg[CFG_PATH_LEN + 1];
    if (get_cfg_dir(cfg, sizeof(cfg)) <= 0 || makedirs(cfg, 0755) != 0
        || random_config(cfg, h->name) != 0 || _move_to(cfg, h->ip) != 0) {
        _report(h, "FAIL config generation in %s", h->root);
        return 1;
    }
    {
        /* First contact's plaintext verbs: granted, as a deployment must
         * (processes/plaintext_verbs.h). */
        char path[CFG_PATH_LEN + 64];
        snprintf(path, sizeof(path), "%s/%s", cfg, PLAINTEXT_VERBS_FILENAME);
        json_t *pv = json_pack("{s:[s,s,s,s,s]}", "verbs", ID_FC_HELLO,
                               ID_FC_HELLO_ACK, ID_FC_REQUEST, ID_FC_ACCEPT,
                               ID_FC_DEVICE_ANNOUNCE);
        int wrc = json_dump_file(pv, path, 0);
        json_decref(pv);
        if (wrc != 0) {
            _report(h, "FAIL plaintext-verbs file");
            return 1;
        }
    }
    if (h->registry) {
        char path[CFG_PATH_LEN + 64];
        snprintf(path, sizeof(path), "%s/%s", cfg, AT_REGISTRY_ISSUERS_FILE);
        json_t *iss = json_pack("{s:[s]}", "issuers", g_issuer_hex);
        int wrc = json_dump_file(iss, path, 0);
        json_decref(iss);
        if (wrc != 0) {
            _report(h, "FAIL issuers file");
            return 1;
        }
    }
    char log[600];
    snprintf(log, sizeof(log), "%s/daemon.log", h->root);
    g_node = at_app_node_start(h->name, h->q_in, h->q_out, 2, false, log);
    if (g_node == NULL) {
        _report(h, "FAIL at_app_node_start");
        return 1;
    }
    g_ev = at_app_events_open_existing();
    int rc = h->serve_relay > 0 ? _carol(h)
           : h->directory ? (strcmp(h->name, "alice") == 0 ? _dir_alice(h) : _dir_bob(h))
           : strcmp(h->name, "alice") == 0 ? _alice(h) : _bob(h);
    _report(h, "DONE %d", rc);
    at_app_events_close(g_ev);
    at_app_node_stop(g_node);
    return rc;
}

/* ------------------------------------------------------------------ */
/* The parent: the out-of-band channel, and the referee                */
/* ------------------------------------------------------------------ */

typedef struct {
    pid_t pid;
    FILE *reports;
    int to_child;
} child_t;

static child_t _spawn(host_t *h, int port)
{
    int up[2], down[2];
    child_t c = { -1, NULL, -1 };
    if (pipe(up) != 0 || pipe(down) != 0)
        return c;
    pid_t pid = fork();
    if (pid == 0) {
        close(up[0]);
        close(down[1]);
        h->to_parent = up[1];
        h->from_parent = down[0];
        _exit(_host_main(h, port));
    }
    close(up[1]);
    close(down[0]);
    c.pid = pid;
    c.reports = fdopen(up[0], "r");
    c.to_child = down[1];
    return c;
}

/* The next report line from a host, or NULL at EOF. */
static char *_next(child_t *c, char *buf, size_t len)
{
    if (fgets(buf, (int)len, c->reports) == NULL)
        return NULL;
    buf[strcspn(buf, "\n")] = '\0';
    fprintf(stderr, "  [%d] %s\n", (int)c->pid,
            strncmp(buf, "LINK ", 5) == 0 ? "LINK <at+contact:...>" : buf);
    return buf;
}

static void _expect_line(child_t *c, const char *want)
{
    char buf[AT_FC_BLOB_LEN + 64];
    char *got = _next(c, buf, sizeof(buf));
    ck_assert_ptr_nonnull(got);
    if (got != NULL)
        ck_assert_str_eq(got, want);
}

DEFINE_TEST(test_two_c_daemons_add_each_other)
{
    char base[] = "/tmp/fc_live.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 30000 + (int)(getpid() % 20000);

    host_t alice = { .name = "alice", .ip = ALICE_IP };
    host_t bob = { .name = "bob", .ip = BOB_IP };
    snprintf(alice.root, sizeof(alice.root), "%s/alice", base);
    snprintf(bob.root, sizeof(bob.root), "%s/bob", base);
    snprintf(alice.q_in, sizeof(alice.q_in), "fcl_a_in");
    snprintf(alice.q_out, sizeof(alice.q_out), "fcl_a_out");
    snprintf(bob.q_in, sizeof(bob.q_in), "fcl_b_in");
    snprintf(bob.q_out, sizeof(bob.q_out), "fcl_b_out");

    child_t a = _spawn(&alice, port);
    child_t b = _spawn(&bob, port);
    ck_assert(a.pid > 0 && b.pid > 0);

    /* Alice's link, carried to Bob's app: the out-of-band hop. */
    char buf[AT_FC_BLOB_LEN + 64];
    char *link = _next(&a, buf, sizeof(buf));
    ck_assert_ptr_nonnull(link);
    if (link != NULL && strncmp(link, "LINK ", 5) == 0) {
        char *blob = link + 5;
        ck_assert(strncmp(blob, "at+contact:", 11) == 0);
        size_t n = strlen(blob);
        blob[n] = '\n';
        ck_assert_int_eq(write(b.to_child, blob, n + 1), (ssize_t)(n + 1));
    } else {
        ck_assert(false);      /* alice failed before minting; see her line */
    }

    _expect_line(&b, "OK established");
    _expect_line(&a, "OK established");
    _expect_line(&a, "OK list 1");
    _expect_line(&a, "DONE 0");
    _expect_line(&b, "OK removed");
    _expect_line(&b, "OK list 0");
    _expect_line(&b, "DONE 0");

    int sa = 0, sb = 0;
    waitpid(a.pid, &sa, 0);
    waitpid(b.pid, &sb, 0);
    ck_assert(WIFEXITED(sa) && WEXITSTATUS(sa) == 0);
    ck_assert(WIFEXITED(sb) && WEXITSTATUS(sb) == 0);
    fprintf(stderr, "  logs under %s\n", base);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Through a rendezvous relay: no direct path at all (Phase 0 spike)   */
/* ------------------------------------------------------------------ */

/* Alice and Bob on different addresses AND different comm ports, so a hello
 * sent straight to Alice lands where nobody listens and neither discovers the
 * other -- the in-sandbox stand-in for NAT (no CAP_NET_ADMIN here;
 * tools/relay_nat/run.sh is the real-NAT check). Carol, an ordinary daemon
 * with AT_RELAY=1, is the only thing both can reach. */
static void _relay_hosts(const char *base, int port, bool alice_uses_relay,
                         host_t *alice, host_t *bob, host_t *carol, char *relay_ep,
                         size_t relay_ep_len)
{
    *alice = (host_t){ .name = "alice", .ip = ALICE_IP, .port = port };
    *bob = (host_t){ .name = "bob", .ip = BOB_IP, .port = port + 1 };
    *carol = (host_t){ .name = "carol", .ip = "127.0.0.3", .port = port + 2,
                       .serve_relay = port + 10 };
    snprintf(relay_ep, relay_ep_len, "127.0.0.3:%d", port + 10);
    if (alice_uses_relay)
        alice->use_relay = relay_ep;
    host_t *all[3] = { alice, bob, carol };
    const char *tags[3] = { "a", "b", "c" };
    for (int i = 0; i < 3; i++) {
        snprintf(all[i]->root, sizeof(all[i]->root), "%s/%s", base, all[i]->name);
        snprintf(all[i]->q_in, sizeof(all[i]->q_in), "fcr_%s_in", tags[i]);
        snprintf(all[i]->q_out, sizeof(all[i]->q_out), "fcr_%s_out", tags[i]);
    }
}

static void _carry_link(child_t *a, child_t *b)
{
    char buf[AT_FC_BLOB_LEN + 64];
    char *link = _next(a, buf, sizeof(buf));
    ck_assert(link != NULL && strncmp(link, "LINK ", 5) == 0);
    if (link == NULL || strncmp(link, "LINK ", 5) != 0)
        return;
    char *blob = link + 5;
    size_t n = strlen(blob);
    blob[n] = '\n';
    ck_assert_int_eq(write(b->to_child, blob, n + 1), (ssize_t)(n + 1));
}

static void _reap(child_t *c)
{
    int st = 0;
    close(c->to_child);
    waitpid(c->pid, &st, 0);
}

DEFINE_TEST(test_two_c_daemons_with_no_direct_path_meet_through_a_relay)
{
    char base[] = "/tmp/fc_relay.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 32000 + (int)(getpid() % 15000);
    host_t alice, bob, carol;
    char relay_ep[64];
    _relay_hosts(base, port, true, &alice, &bob, &carol, relay_ep, sizeof(relay_ep));
    g_step_timeout = STEP_TIMEOUT_S;
    /* AT_TEST_EXTERNAL_RELAY=host:port uses a relay someone else runs -- the
     * Python one, for the cross-runtime check -- instead of Carol. */
    const char *external = getenv("AT_TEST_EXTERNAL_RELAY");
    if (external != NULL && external[0] != '\0')
        alice.use_relay = external;

    child_t c = { -1, NULL, -1 };
    if (external == NULL || external[0] == '\0') {
        c = _spawn(&carol, port);
        _expect_line(&c, "OK up");
    }
    child_t a = _spawn(&alice, port);
    child_t b = _spawn(&bob, port);
    _carry_link(&a, &b);
    _expect_line(&b, "OK established");
    _expect_line(&a, "OK established");
    _expect_line(&a, "OK list 1");
    _expect_line(&a, "DONE 0");
    _expect_line(&b, "OK removed");
    _expect_line(&b, "OK list 0");
    _expect_line(&b, "DONE 0");
    _reap(&a);
    _reap(&b);
    if (c.pid < 0) {
        fprintf(stderr, "  through external relay %s; logs under %s\n",
                external, base);
        return;
    }
    _reap(&c);

    /* It went through Carol: both registered with her relay. */
    char path[600], line[512];
    int registered = 0;
    snprintf(path, sizeof(path), "%s/carol/daemon.log", base);
    FILE *f = fopen(path, "r");
    while (f != NULL && fgets(line, sizeof(line), f) != NULL)
        if (strstr(line, "Relay: ") && strstr(line, " registered"))
            registered++;
    if (f != NULL)
        fclose(f);
    ck_assert(registered >= 2);
    /* Carol proved who she is, and Alice's links pin her from then on. */
    bool pinned = false;
    snprintf(path, sizeof(path), "%s/alice/daemon.log", base);
    f = fopen(path, "r");
    while (f != NULL && fgets(line, sizeof(line), f) != NULL)
        if (strstr(line, "links now pin it") != NULL)
            pinned = true;
    if (f != NULL)
        fclose(f);
    ck_assert(pinned);
    fprintf(stderr, "  logs under %s\n", base);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_dead_first_relay_fails_over_to_the_next)
{
    /* Alice names two relays and the first is down: her link names both, in
     * order, and Bob's hello fails over to the second (Carol). */
    char base[] = "/tmp/fc_relay2.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 17000 + (int)(getpid() % 15000);
    host_t alice, bob, carol;
    char relay_ep[64], both[160];
    _relay_hosts(base, port, true, &alice, &bob, &carol, relay_ep, sizeof(relay_ep));
    snprintf(both, sizeof(both), "127.0.0.5:%d,%s", port + 11, relay_ep);
    alice.use_relay = both;
    g_step_timeout = STEP_TIMEOUT_S;

    child_t c = _spawn(&carol, port);
    _expect_line(&c, "OK up");
    child_t a = _spawn(&alice, port);
    child_t b = _spawn(&bob, port);
    _carry_link(&a, &b);
    _expect_line(&b, "OK established");
    _expect_line(&a, "OK established");
    _expect_line(&a, "OK list 1");
    _expect_line(&a, "DONE 0");
    _expect_line(&b, "OK removed");
    _expect_line(&b, "OK list 0");
    _expect_line(&b, "DONE 0");
    _reap(&a);
    _reap(&b);
    _reap(&c);

    char path[600], line[512], want[96];
    bool failed_over = false;
    snprintf(want, sizeof(want), "Relay: 127.0.0.5:%d unusable", port + 11);
    snprintf(path, sizeof(path), "%s/bob/daemon.log", base);
    FILE *f = fopen(path, "r");
    while (f != NULL && fgets(line, sizeof(line), f) != NULL)
        if (strstr(line, want) != NULL)
            failed_over = true;
    if (f != NULL)
        fclose(f);
    ck_assert(failed_over);
    fprintf(stderr, "  logs under %s\n", base);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_relay_they_never_meet)
{
    /* The control: same topology, Alice NOT behind the relay. Bob's hello goes
     * straight to Alice's address on a port nobody listens on, so nothing
     * establishes -- which is what makes the relay test's success the
     * relay's doing. */
    char base[] = "/tmp/fc_norelay.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 47500 + (int)(getpid() % 15000);
    host_t alice, bob, carol;
    char relay_ep[64];
    _relay_hosts(base, port, false, &alice, &bob, &carol, relay_ep, sizeof(relay_ep));
    g_step_timeout = 20;

    child_t a = _spawn(&alice, port);
    child_t b = _spawn(&bob, port);
    _carry_link(&a, &b);
    _expect_line(&b, "FAIL established: no event within 20s");
    _expect_line(&a, "FAIL established: no event within 20s");
    _reap(&a);
    _reap(&b);
    g_step_timeout = STEP_TIMEOUT_S;
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Find a friend by handle (FIRST_CONTACT_PLAN Phase 3)                */
/* ------------------------------------------------------------------ */

/* The C twin of tests/b_integration/test_directory_three_node.py: Carol is a
 * relay that also serves the directory, trusting one issuer; Alice and Bob
 * have no direct path and both register with her. No link ever passes between
 * the two people. */
static void _directory_hosts(const char *base, int port, host_t *alice, host_t *bob,
                             host_t *carol, char *relay_ep, size_t len)
{
    _issuer();
    _relay_hosts(base, port, true, alice, bob, carol, relay_ep, len);
    bob->use_relay = relay_ep;
    carol->registry = true;
    alice->directory = bob->directory = true;
}

DEFINE_TEST(test_two_c_daemons_find_each_other_by_handle)
{
    char base[] = "/tmp/fc_dir.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 21000 + (int)(getpid() % 9000);
    host_t alice, bob, carol;
    char relay_ep[64];
    _directory_hosts(base, port, &alice, &bob, &carol, relay_ep, sizeof(relay_ep));
    g_step_timeout = STEP_TIMEOUT_S;
    child_t c = _spawn(&carol, port);
    _expect_line(&c, "OK up");
    child_t a = _spawn(&alice, port);
    _expect_line(&a, "OK published");
    child_t b = _spawn(&bob, port);
    _expect_line(&b, "OK found alice");
    _expect_line(&a, "OK contact_request alice@example.org");
    _expect_line(&b, "OK established");
    _expect_line(&b, "OK list directory");
    _expect_line(&b, "DONE 0");
    _expect_line(&a, "OK established");
    _expect_line(&a, "OK list directory");
    _expect_line(&a, "DONE 0");
    _reap(&a);
    _reap(&b);
    _reap(&c);
    fprintf(stderr, "  logs under %s\n", base);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_directory_request_waits_for_the_app)
{
    char base[] = "/tmp/fc_dir_wait.XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(base));
    int port = 12000 + (int)(getpid() % 5000);
    host_t alice, bob, carol;
    char relay_ep[64];
    _directory_hosts(base, port, &alice, &bob, &carol, relay_ep, sizeof(relay_ep));
    alice.no_accept = true;
    g_step_timeout = STEP_TIMEOUT_S;
    child_t c = _spawn(&carol, port);
    _expect_line(&c, "OK up");
    child_t a = _spawn(&alice, port);
    _expect_line(&a, "OK published");
    g_step_timeout = 25;        /* Bob's wait for an ESTABLISHED that must not come */
    child_t b = _spawn(&bob, port);
    _expect_line(&b, "OK found alice");
    _expect_line(&a, "OK contact_request alice@example.org");
    _expect_line(&a, "OK not answering");
    _expect_line(&b, "FAIL established: no event within 25s");
    _reap(&a);
    _reap(&b);
    _reap(&c);
    g_step_timeout = STEP_TIMEOUT_S;
}
END_TEST_DEFINITION()

RUN_TESTS(FirstContactLive, test_two_c_daemons_add_each_other,
          test_two_c_daemons_find_each_other_by_handle,
          test_a_directory_request_waits_for_the_app,
          test_two_c_daemons_with_no_direct_path_meet_through_a_relay,
          test_a_dead_first_relay_fails_over_to_the_next,
          test_without_the_relay_they_never_meet)
