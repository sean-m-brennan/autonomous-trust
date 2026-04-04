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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <sodium.h>

#include "autonomous_trust.h"
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
/* Tick callback                                                       */
/* ------------------------------------------------------------------ */

static int demo_tick(at_node_t *node, void *user_data)
{
    demo_ctx_t *ctx = (demo_ctx_t *)user_data;
    if (ctx->inject_update && at_node_iteration(node) == INJECT_DELAY_ITERATIONS)
        inject_self_update(node);
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
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "gl:tih", long_options, NULL)) != -1)
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

    at_node_config_t cfg = {
        .log_level = log_level,
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
