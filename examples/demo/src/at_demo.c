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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <sodium.h>

#include "autonomous_trust.h"
#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/fleet/update_proposal.h"
#include "autonomous_trust/fleet/fleet_proc.h"

/* ------------------------------------------------------------------ */
/* CLI helpers                                                         */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--generate-config] [--log-level LEVEL] [--test] [--inject-update]\n", prog);
    fprintf(stderr, "  --generate-config   Generate identity, network, and subsystems configs\n");
    fprintf(stderr, "  --log-level LEVEL   Set log level: debug, info, warning, error, critical\n");
    fprintf(stderr, "  --test              Run in test mode (limited iterations)\n");
    fprintf(stderr, "  --inject-update     Inject a self-referencing update proposal after peer discovery\n");
    fprintf(stderr, "  --ingest-readings PATH  Feed ISR Readings to the data-source service over an\n");
    fprintf(stderr, "                          AF_UNIX SOCK_STREAM socket at PATH (length-prefixed JSON\n");
    fprintf(stderr, "                          batches). Equivalent to setting AT_INGEST_SOCKET=PATH.\n");
}

static log_level_t parse_log_level(const char *str)
{
    if (strcasecmp(str, "debug") == 0) return DEBUG;
    if (strcasecmp(str, "info") == 0) return INFO;
    if (strcasecmp(str, "warning") == 0) return WARNING;
    if (strcasecmp(str, "error") == 0) return ERROR;
    if (strcasecmp(str, "critical") == 0) return CRITICAL;
    fprintf(stderr, "Unknown log level '%s', defaulting to INFO\n", str);
    return INFO;
}

/* ------------------------------------------------------------------ */
/* Inject-update (test-only)                                           */
/* ------------------------------------------------------------------ */

#define TEST_ITERATIONS 1600      /* ~800s at 500ms cadence */
#define INJECT_ITERATIONS 1600    /* same; inject starts after INJECT_DELAY */
#define INJECT_DELAY_ITERATIONS 60 /* ~30s delay for peer discovery */

typedef struct {
    bool inject_update;
    bool roster_requested;      /* the pull has landed; stop retrying */
    unsigned roster_attempts;
} demo_ctx_t;

/**
 * Inject a self-referencing update proposal: store our own binary as an
 * artifact and submit a signed proposal to the fleet process.
 * Exercises the full fleet-update pipeline end-to-end.
 */
static void inject_self_update(at_node_t *node)
{
    logger_t *log = at_node_logger(node);
    log_info(log, "Inject-update: starting self-referencing update proposal\n");

    if (sodium_init() < 0)
    {
        log_error(log, "Inject-update: sodium_init failed\n");
        return;
    }

    /* Resolve our own binary path */
    char self_path[256];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len <= 0)
    {
        log_error(log, "Inject-update: could not read /proc/self/exe\n");
        return;
    }
    self_path[len] = '\0';

    /* Store binary as artifact */
    uint8_t hash[UPDATE_HASH_LEN];
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    if (fleet_store_artifact(self_path, "test-1.0.0", log, hash, hash_hex) != 0)
        return;

    /* Propose update with throwaway keypair (test only) */
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    fleet_propose_update(hash, "test-1.0.0", "test", pk, sk, log);
}

/* ------------------------------------------------------------------ */
/* App-facing peer carrier                                             */
/* ------------------------------------------------------------------ */

/* Reported through the logger rather than stdout: in a container these lines
 * belong in the same stream as the admission and reputation logs they are
 * meant to be read against. The minimal integrator's reference is
 * src/c/example.c; see doc/architecture/app-peer-carrier.md. */

/* ~20s at the 500ms loop cadence. Past this the daemon is not coming up, and
 * retrying forever would only bury the reason in log noise. */
#define ROSTER_MAX_ATTEMPTS 40

/* ~30s. See the "answers NOW" note below: one startup pull is not enough. */
#define ROSTER_REFRESH_ITERATIONS 60

/**
 * Ask AT to re-emit everything it currently knows about its peers. Worth doing
 * at startup: the carrier is otherwise event-driven, so a node that admitted
 * peers before this app attached would report nothing until the next change.
 * It is also the only path on which an unrated peer can cross.
 *
 * Returns messaging_send's result: this MUST be retried rather than fired once.
 * at_node_start forks the daemon and returns without waiting for it, so on the
 * early ticks the identity and reputation processes have not necessarily bound
 * their queues, and a single-shot request is silently lost.
 *
 * AND A SUCCESSFUL SEND IS NOT ENOUGH EITHER. A pull answers "what do you know
 * NOW", so on a node that has not finished discovery the honest answer is
 * "nothing yet" — measured on a 3-node cohort (2026-07-30): the pull landed on
 * both halves at 15:45:47 reporting 0 observations and 0 reputations, and the
 * first peer was admitted at 15:46:10, twenty-three seconds later. So this is
 * also re-sent periodically. Repeats are cheap and harmless: the feed is
 * upsert-only by design, so a restated observation costs one message.
 */
static int request_peer_roster(at_node_t *node)
{
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_ROSTER_REQUEST;
    req.info.net_msg.encrypt = false;
    return messaging_send(node->config.q_out, NET_MESSAGE, &req, false);
}

static void log_peer_observed(at_node_t *node, const peer_observed_msg_t *p)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p->peer_uuid, uuid_str);

    /* The stamp is only meaningful against a clock, which is why AT does not
     * reduce it to a bool. Bound-but-unattended is a normal steady state. */
    const char *operator_state = "none";
    if (p->operator_bound)
        operator_state = p->operator_attested_at > 0.0 ? "bound" : "bound-unattended";

    log_info(at_node_logger(node),
             "peer observed: %s rank=%d key=%02x%02x..%02x operator=%s attended_at=%.0f\n",
             uuid_str, p->rank, p->signing_pubkey[0], p->signing_pubkey[1],
             p->signing_pubkey[crypto_sign_PUBLICKEYBYTES - 1],
             operator_state, p->operator_attested_at);
}

static void log_peer_reputation(at_node_t *node, const peer_reputation_msg_t *r)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(r->peer_uuid, uuid_str);

    /* "unrated" rather than a number: AT has no rating for this peer, and a
     * placeholder is indistinguishable from a score a peer can genuinely earn. */
    if (r->rated)
        log_info(at_node_logger(node), "peer reputation: %s score=%.3f\n",
                 uuid_str, r->score);
    else
        log_info(at_node_logger(node), "peer reputation: %s unrated\n", uuid_str);
}

/* ------------------------------------------------------------------ */
/* Tick callback                                                       */
/* ------------------------------------------------------------------ */

static int demo_tick(at_node_t *node, void *user_data)
{
    demo_ctx_t *ctx = (demo_ctx_t *)user_data;
    if (ctx->inject_update && at_node_iteration(node) == INJECT_DELAY_ITERATIONS)
        inject_self_update(node);

    if (!ctx->roster_requested && ctx->roster_attempts < ROSTER_MAX_ATTEMPTS)
    {
        ctx->roster_attempts++;
        if (request_peer_roster(node) == 0)
            ctx->roster_requested = true;
        else if (ctx->roster_attempts == ROSTER_MAX_ATTEMPTS)
            log_warn(at_node_logger(node),
                     "peer roster request never accepted (%u attempts); "
                     "the app will still see change-driven observations\n",
                     ctx->roster_attempts);
    }
    else if (ctx->roster_requested
             && at_node_iteration(node) % ROSTER_REFRESH_ITERATIONS == 0)
    {
        /* Refresh. A failure here needs no handling — the next one is 30s away,
         * and change-driven observations keep arriving regardless. */
        request_peer_roster(node);
    }

    generic_msg_t buf = {0};
    int err = messaging_recv(&buf);
    if (err == -1)
        log_exception(at_node_logger(node));
    if (err != 0)
        return 0;  /* no message this tick */

    switch (buf.type)
    {
    case PEER_OBSERVED:
        log_peer_observed(node, &buf.info.peer_observed);
        break;
    case PEER_REPUTATION:
        log_peer_reputation(node, &buf.info.peer_reputation);
        break;
    default:
        break;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    log_level_t log_level = INFO;
    bool gen_config = false;
    bool test_mode = false;
    bool inject_update = false;

    static struct option long_options[] = {
        {"generate-config", no_argument, NULL, 'g'},
        {"log-level", required_argument, NULL, 'l'},
        {"test", no_argument, NULL, 't'},
        {"inject-update", no_argument, NULL, 'i'},
        {"ingest-readings", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "gl:tir:h", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'g':
            gen_config = true;
            break;
        case 'l':
            log_level = parse_log_level(optarg);
            break;
        case 't':
            test_mode = true;
            break;
        case 'i':
            inject_update = true;
            test_mode = true;
            break;
        case 'r':
            /* The data-source process (forked child) reads this from the
             * environment; set it before at_node_init so the child inherits it. */
            setenv("AT_INGEST_SOCKET", optarg, 1);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Configure and run the AT node */
    size_t max_iters = 0;
    if (test_mode)
        max_iters = inject_update ? INJECT_ITERATIONS : TEST_ITERATIONS;

    /* Optional file sink: AT_LOG_FILE=/path routes the AT daemon AND every
     * subsystem child to that file (append) instead of stderr. Empty/unset
     * keeps the stderr default. The daemon's file descriptor survives each
     * subsystem's daemonize via logger_reopen (see processes.c). */
    const char *log_file = getenv("AT_LOG_FILE");
    if (log_file != NULL && log_file[0] == '\0')
        log_file = NULL;

    at_node_config_t cfg = {
        .log_level = log_level,
        .log_file = log_file,
        .generate_config = gen_config,
        .app_name = "at_demo",
        .q_out = "demo_to_at",
        .q_in = "at_to_demo",
        .max_iterations = max_iters,
    };

    at_node_t node = {0};
    if (at_node_init(&node, &cfg) != 0)
        return 1;
    if (at_node_start(&node) != 0)
        return 1;

    demo_ctx_t ctx = { .inject_update = inject_update };
    int ret = at_node_run(&node, demo_tick, &ctx);
    at_node_shutdown(&node);
    return ret;
}
