/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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
 * Minimal example of an application hosting an Autonomous Trust node.
 *
 * The tick callback receives messages from the AT daemon and can react
 * to them — replace the body with your application logic.
 *
 * It also demonstrates the app-facing peer carrier: one roster request on the
 * first tick, then PEER_OBSERVED / PEER_REPUTATION as the node's view changes.
 * See doc/architecture/app-peer-carrier.md.
 */

#include <stdio.h>
#include <string.h>

#include "autonomous_trust.h"
#include "autonomous_trust/utilities/message.h"

#define EXAMPLE_ITERATIONS 200

/* ~20s at the 500ms loop cadence. */
#define ROSTER_MAX_ATTEMPTS 40

/* Ask AT to re-emit everything it currently knows. Worth doing at startup: the
 * carrier is otherwise event-driven, so an app that attached after the node
 * admitted its peers would otherwise see nothing until the next change.
 *
 * RETRY THIS — do not fire it once. at_node_start forks the daemon and returns
 * without waiting for it, so on the early ticks AT's identity and reputation
 * processes have not necessarily bound their queues yet, and the request goes
 * nowhere. A single attempt at iteration 1 always loses the race. */
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

static void print_peer_observed(const peer_observed_msg_t *p)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p->peer_uuid, uuid_str);
    printf("  peer %s rank=%d key=%02x%02x..%02x", uuid_str, p->rank,
           p->signing_pubkey[0], p->signing_pubkey[1],
           p->signing_pubkey[crypto_sign_PUBLICKEYBYTES - 1]);
    if (!p->operator_bound)
        printf(" operator=none\n");
    else if (p->operator_attested_at > 0.0)
        /* A human is behind this node AND was verified present recently. How
         * recently is the reader's call — the stamp is only meaningful
         * against a clock, which is why AT does not reduce it to a bool. */
        printf(" operator=bound attended_at=%.0f\n", p->operator_attested_at);
    else
        /* Bound but unattended is a normal steady state, not an error. */
        printf(" operator=bound attended=no\n");
}

static void print_peer_reputation(const peer_reputation_msg_t *r)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(r->peer_uuid, uuid_str);
    /* Print "unrated" rather than a number: AT has no rating for this peer,
     * and an unrated peer's placeholder is indistinguishable from a score a
     * peer can genuinely earn. */
    if (r->rated)
        printf("  peer %s reputation=%.3f\n", uuid_str, r->score);
    else
        printf("  peer %s reputation=unrated\n", uuid_str);
}

/* Retry state for the startup roster pull. A real app would more likely keep
 * this in the struct it passes as user_data. */
typedef struct {
    bool roster_requested;
    unsigned roster_attempts;
} example_ctx_t;

static int example_tick(at_node_t *node, void *user_data)
{
    example_ctx_t *ctx = (example_ctx_t *)user_data;

    if (!ctx->roster_requested && ctx->roster_attempts < ROSTER_MAX_ATTEMPTS)
    {
        ctx->roster_attempts++;
        if (request_peer_roster(node) == 0)
            ctx->roster_requested = true;
        else if (ctx->roster_attempts == ROSTER_MAX_ATTEMPTS)
            log_warn(at_node_logger(node),
                     "roster request never accepted (%u attempts)\n",
                     ctx->roster_attempts);
    }

    /* Check for messages from AT sub-processes */
    generic_msg_t buf = {0};
    int err = messaging_recv(&buf);
    if (err == -1)
        log_exception(at_node_logger(node));
    if (err != 0)
        return 0;  /* no message this tick */

    /* React to messages here — e.g. transaction scores, task results */
    switch (buf.type)
    {
    case PEER_OBSERVED:
        print_peer_observed(&buf.info.peer_observed);
        break;
    case PEER_REPUTATION:
        print_peer_reputation(&buf.info.peer_reputation);
        break;
    default:
        break;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    at_node_config_t cfg = {
        .log_level = DEBUG,
        .app_name = "at_example",
        .q_out = "extern_to_at",
        .q_in = "at_to_extern",
        .max_iterations = EXAMPLE_ITERATIONS,
    };

    at_node_t node = {0};
    if (at_node_init(&node, &cfg) != 0)
        return 1;
    if (at_node_start(&node) != 0)
        return 1;

    example_ctx_t ctx = {0};
    int ret = at_node_run(&node, example_tick, &ctx);
    at_node_shutdown(&node);
    return ret;
}
