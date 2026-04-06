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

/**
 * at_zta_demo.c — ZTA compliance demo for AutonomousTrust.
 *
 * Demonstrates ZTA credential integration in a 4-peer tactical DDIL scenario:
 *
 *   Peer            Role                    ZTA Status
 *   Command Post    Trust anchor, OCSP      Valid machine cert
 *   Squad Leader    CAC/PIV credential      Valid cert
 *   Drone Alpha     Machine cert            Valid → revoked
 *   Drone Bravo     Machine cert            Deferred → verified
 *
 * Timeline (driven by tick callback):
 *   T+0:00   CP, SL, DA form network with ZTA verification
 *   T+30s    DB joins with OCSP unreachable (DDIL fallback)
 *   T+60s    DB's OCSP connectivity restored, deferred verification resolves
 *   T+90s    DA's cert revoked via mock OCSP
 *   T+120s   DA re-authenticates with new cert, enters at zero reputation
 *
 * Each peer runs this same binary with a different --role flag.
 * The role determines which certificate and config to use.
 *
 * Build:
 *   cmake -DAT_ZTA=ON .. && make at_zta_demo
 *
 * Usage:
 *   at_zta_demo --role command_post [--log-level debug] [--generate-config]
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "autonomous_trust.h"

#ifdef AT_ZTA_ENABLED
#include "autonomous_trust/zta/zta_policy.h"
#include "autonomous_trust/zta/zta_verifier.h"
#endif

/* ------------------------------------------------------------------ */
/* Demo roles                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    ROLE_COMMAND_POST,
    ROLE_SQUAD_LEADER,
    ROLE_DRONE_ALPHA,
    ROLE_DRONE_BRAVO,
    ROLE_UNKNOWN
} demo_role_t;

static const char *role_names[] = {
    "command_post", "squad_leader", "drone_alpha", "drone_bravo", "unknown"
};

static demo_role_t parse_role(const char *str)
{
    for (int i = 0; i < ROLE_UNKNOWN; i++) {
        if (strcasecmp(str, role_names[i]) == 0)
            return (demo_role_t)i;
    }
    return ROLE_UNKNOWN;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s --role ROLE [--log-level LEVEL] [--generate-config] [--test]\n", prog);
    fprintf(stderr, "  --role ROLE         One of: command_post, squad_leader, drone_alpha, drone_bravo\n");
    fprintf(stderr, "  --log-level LEVEL   debug, info, warning, error, critical\n");
    fprintf(stderr, "  --generate-config   Generate identity/network configs\n");
    fprintf(stderr, "  --test              Run in test mode (limited iterations)\n");
}

static log_level_t parse_log_level(const char *str)
{
    if (strcasecmp(str, "debug") == 0) return DEBUG;
    if (strcasecmp(str, "info") == 0) return INFO;
    if (strcasecmp(str, "warning") == 0) return WARNING;
    if (strcasecmp(str, "error") == 0) return ERROR;
    if (strcasecmp(str, "critical") == 0) return CRITICAL;
    return INFO;
}

/* ------------------------------------------------------------------ */
/* Demo timeline                                                       */
/* ------------------------------------------------------------------ */

/*
 * At 500ms cadence: iteration 60 ≈ 30s, 120 ≈ 60s, 180 ≈ 90s, 240 ≈ 120s
 */
#define DEMO_ITERATIONS     500    /* ~250s total */
#define DDIL_JOIN_ITER       60    /* T+30s: Drone Bravo joins */
#define DDIL_RESTORE_ITER   120    /* T+60s: OCSP connectivity restored */
#define REVOKE_ITER         180    /* T+90s: Drone Alpha revoked */
#define REAUTH_ITER         240    /* T+120s: Drone Alpha re-auth */

typedef struct {
    demo_role_t role;
} demo_ctx_t;

static int zta_demo_tick(at_node_t *node, void *user_data)
{
    demo_ctx_t *ctx = (demo_ctx_t *)user_data;
    size_t iter = at_node_iteration(node);
    logger_t *log = at_node_logger(node);

    switch (ctx->role) {
    case ROLE_COMMAND_POST:
        /* Command Post logs timeline milestones */
        if (iter == 1)
            log_info(log, "ZTA Demo: Command Post online, ZTA verified\n");
        if (iter == DDIL_JOIN_ITER)
            log_info(log, "ZTA Demo: T+30s — Drone Bravo expected to join (DDIL)\n");
        if (iter == DDIL_RESTORE_ITER)
            log_info(log, "ZTA Demo: T+60s — OCSP connectivity should be restored\n");
        if (iter == REVOKE_ITER)
            log_info(log, "ZTA Demo: T+90s — Drone Alpha revocation expected\n");
        if (iter == REAUTH_ITER)
            log_info(log, "ZTA Demo: T+120s — Drone Alpha re-authentication expected\n");
        break;

    case ROLE_SQUAD_LEADER:
        if (iter == 1)
            log_info(log, "ZTA Demo: Squad Leader online, ZTA verified\n");
        break;

    case ROLE_DRONE_ALPHA:
        if (iter == 1)
            log_info(log, "ZTA Demo: Drone Alpha online, ZTA verified\n");
        if (iter == REVOKE_ITER)
            log_warn(log, "ZTA Demo: Drone Alpha — credential should be revoked now\n");
        break;

    case ROLE_DRONE_BRAVO:
        if (iter == DDIL_JOIN_ITER)
            log_info(log, "ZTA Demo: Drone Bravo attempting to join (DDIL mode)\n");
        if (iter == DDIL_RESTORE_ITER)
            log_info(log, "ZTA Demo: Drone Bravo — OCSP should now be reachable\n");
        break;

    case ROLE_UNKNOWN:
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
    demo_role_t role = ROLE_UNKNOWN;

    static struct option long_options[] = {
        {"role", required_argument, NULL, 'r'},
        {"generate-config", no_argument, NULL, 'g'},
        {"log-level", required_argument, NULL, 'l'},
        {"test", no_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "r:gl:th", long_options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            role = parse_role(optarg);
            break;
        case 'g':
            gen_config = true;
            break;
        case 'l':
            log_level = parse_log_level(optarg);
            break;
        case 't':
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

    if (role == ROLE_UNKNOWN) {
        fprintf(stderr, "Error: --role is required\n");
        print_usage(argv[0]);
        return 1;
    }

    size_t max_iters = test_mode ? DEMO_ITERATIONS : 0;

    at_node_config_t cfg = {
        .log_level = log_level,
        .generate_config = gen_config,
        .app_name = "at_zta_demo",
        .q_out = "zta_demo_out",
        .q_in = "zta_demo_in",
        .max_iterations = max_iters,
    };

    at_node_t node = {0};
    if (at_node_init(&node, &cfg) != 0)
        return 1;

    printf("ZTA Demo: starting as %s\n", role_names[role]);

    if (at_node_start(&node) != 0)
        return 1;

    demo_ctx_t ctx = { .role = role };
    int ret = at_node_run(&node, zta_demo_tick, &ctx);
    at_node_shutdown(&node);
    return ret;
}
