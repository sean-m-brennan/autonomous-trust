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

/** @file Negotiation-protocol adapter (Phase E).
 *
 *  Constructs per-participant `process_t` instances with negotiation
 *  handlers registered, installs a messaging_send test hook, and runs
 *  the universal scenario engine. Mirrors the identity adapter; the
 *  protocol-specific bits live in `_build_inbound` (one builder per
 *  function, wrapping a JSON payload the C handler can decode) and in
 *  the conformance setters from `neg_proc_priv.h` that pre-populate
 *  per-participant own-capabilities and peer-level overrides.
 *
 *  Task UUIDs are derived as UUIDv5 in namespace
 *  00000000-0000-0000-0000-000000000aaa with name "task:{slug}", which
 *  is what the Python adapter does — guarantees the same byte values
 *  cross-language so a future byte-pinned diff is meaningful.
 */

#include "negotiation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "negotiation/negotiation.h"
#include "negotiation/neg_proc_priv.h"
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

#include "../negative_runner.h"

#include "../scenario_engine.h"

/* ------------------------------------------------------------------------- */
/* Per-participant impl carries a process_t plus the identity used to        */
/* build inbound messages (from_whom / to_whom).                             */
/* ------------------------------------------------------------------------- */

typedef struct {
    identity_t *full;
    public_identity_t *pub;
    process_t *proc;
} np_impl_t;

static sce_run_ctx_t *g_active_ctx = NULL;

/* Same NS as the Python adapter (uuid5 in this NS for both participant
 * identities and task uuids), so cross-language diffs are bit-equal. */
static const uuid_t NEG_NS = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xaa
};

static void _uuid5(const char *prefix, const char *name, uuid_t out)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", prefix, name);
    uuid_generate_sha1(out, NEG_NS, buf, strlen(buf));
}

/* Resolve a generic_msg_t.to_whom uuid back to a scenario participant id. */
static const char *_resolve_to_id(const generic_msg_t *msg)
{
    if (msg->type != NET_MESSAGE) return "internal";
    if (g_active_ctx == NULL) return "unknown";
    /* Negotiation messages are always direct unicast to a peer (never
     * group broadcast), so plain uuid match suffices. */
    for (size_t i = 0; i < g_active_ctx->participant_count; i++)
    {
        np_impl_t *impl = (np_impl_t *)g_active_ctx->participants[i].impl;
        if (impl == NULL || impl->pub == NULL) continue;
        if (uuid_compare(impl->pub->uuid, msg->info.net_msg.to_whom.uuid) == 0)
            return g_active_ctx->participants[i].id;
    }
    return "unknown";
}

static int _send_hook(const char *key,
                      const message_type_t type,
                      generic_msg_t *msg,
                      bool blocking)
{
    (void)key; (void)blocking;
    if (g_active_ctx == NULL) return 0;
    const char *to_id = _resolve_to_id(msg);
    const char *function = (type == NET_MESSAGE && msg->info.net_msg.function != NULL)
        ? msg->info.net_msg.function : "__internal__";
    sce_capture(g_active_ctx, to_id, function);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Participant construction                                                   */
/* ------------------------------------------------------------------------- */

static int _make_identity(const char *id, size_t idx, identity_t **out)
{
    uuid_t uuid;
    _uuid5("neg:", id, uuid);
    char addr[ADDR_LEN + 1] = {0};
    snprintf(addr, sizeof(addr), "10.0.50.%zu", idx + 1);
    char nickname[NAME_LEN + 1] = {0};
    snprintf(nickname, sizeof(nickname), "%s.neg", id);
    return identity_create(&uuid, addr, nickname, id, out);
}

static np_impl_t *_build_participant_impl(const char *id, size_t idx)
{
    np_impl_t *impl = calloc(1, sizeof(np_impl_t));
    if (impl == NULL) return NULL;
    if (_make_identity(id, idx, &impl->full) != 0 || impl->full == NULL) goto fail;
    if (identity_publish(impl->full, &impl->pub) != 0 || impl->pub == NULL) goto fail;
    impl->proc = smrt_create(sizeof(process_t));
    if (impl->proc == NULL) goto fail;
    pthread_rwlock_init(&impl->proc->protocol.peers_rwlock, NULL);
    strncpy(impl->proc->name, "negotiation", PROC_NAME_LEN);
    if (map_create(&impl->proc->protocol.handlers) != 0) goto fail;
    impl->proc->protocol.phase = 1;  /* matches negotiation_run's initial phase */
    if (negotiation_register_handlers(impl->proc) != 0) goto fail;
    return impl;
fail:
    if (impl != NULL)
    {
        if (impl->proc != NULL)
        {
            if (impl->proc->protocol.handlers != NULL) map_free(impl->proc->protocol.handlers);
            pthread_rwlock_destroy(&impl->proc->protocol.peers_rwlock);
            smrt_deref(impl->proc);
        }
        if (impl->pub != NULL) smrt_deref(impl->pub);
        if (impl->full != NULL) identity_free(impl->full);
        free(impl);
    }
    return NULL;
}

static void _free_participant_impl(np_impl_t *impl)
{
    if (impl == NULL) return;
    if (impl->proc != NULL)
    {
        negotiation_clear_test_state(impl->proc);
        if (impl->proc->protocol.handlers != NULL) map_free(impl->proc->protocol.handlers);
        pthread_rwlock_destroy(&impl->proc->protocol.peers_rwlock);
        smrt_deref(impl->proc);
    }
    if (impl->pub != NULL) smrt_deref(impl->pub);
    if (impl->full != NULL) identity_free(impl->full);
    free(impl);
}

/* Apply scenario fixtures: capabilities map + peer_levels map. */
static void _apply_fixtures(sce_run_ctx_t *ctx)
{
    json_t *fixtures = json_object_get(ctx->case_data, "fixtures");
    if (!json_is_object(fixtures)) return;

    /* Pre-populate every participant's protocol.peers list with every
     * other participant. handle_invite and handle_haggle don't strictly
     * need this for the four Phase E scenarios, but mirroring the
     * Python adapter keeps the harnesses symmetric. */
    for (size_t i = 0; i < ctx->participant_count; i++)
    {
        np_impl_t *impl_i = (np_impl_t *)ctx->participants[i].impl;
        if (impl_i == NULL || impl_i->proc == NULL) continue;
        for (size_t j = 0; j < ctx->participant_count; j++)
        {
            if (i == j) continue;
            np_impl_t *impl_j = (np_impl_t *)ctx->participants[j].impl;
            if (impl_j == NULL || impl_j->pub == NULL) continue;
            if (impl_i->proc->protocol.num_peers >= DEFAULT_MAX_PEERS) break;
            memcpy(&impl_i->proc->protocol.peers[impl_i->proc->protocol.num_peers],
                   impl_j->pub, sizeof(public_identity_t));
            impl_i->proc->protocol.num_peers++;
        }
    }

    /* capabilities: { "<participant>": ["<cap>", ...], ... } — install
     * each participant's own-capability allowlist on their process_t.
     * Empty list (e.g. "bob: []") explicitly opts a participant out of
     * the static capability_table and forces refusal-on-not-capable. */
    json_t *caps = json_object_get(fixtures, "capabilities");
    if (json_is_object(caps))
    {
        const char *pid;
        json_t *cap_arr;
        json_object_foreach(caps, pid, cap_arr) {
            sce_participant_t *part = sce_find_participant(ctx, pid);
            if (part == NULL) continue;
            np_impl_t *impl = (np_impl_t *)part->impl;
            if (impl == NULL || impl->proc == NULL) continue;
            if (!json_is_array(cap_arr)) continue;

            size_t n = json_array_size(cap_arr);
            const char **names = (n > 0) ? calloc(n, sizeof(char *)) : NULL;
            size_t k = 0;
            for (size_t i = 0; i < n; i++)
            {
                const char *name = json_string_value(json_array_get(cap_arr, i));
                if (name) names[k++] = name;
            }
            negotiation_set_own_capabilities(impl->proc, names, k);
            free((void *)names);
        }
    }

    /* peer_tiers: { "<participant>": <int>, ... }. Sets the named
     * participant's trust tier *as seen by every other participant*.
     * Mirrors the Python adapter's `peer_tiers` handling. */
    json_t *pt = json_object_get(fixtures, "peer_tiers");
    if (json_is_object(pt))
    {
        const char *pid;
        json_t *tier_j;
        json_object_foreach(pt, pid, tier_j) {
            if (!json_is_integer(tier_j)) continue;
            int t = (int)json_integer_value(tier_j);
            sce_participant_t *target = sce_find_participant(ctx, pid);
            if (target == NULL) continue;
            np_impl_t *target_impl = (np_impl_t *)target->impl;
            if (target_impl == NULL || target_impl->pub == NULL) continue;
            for (size_t i = 0; i < ctx->participant_count; i++)
            {
                if (strcmp(ctx->participants[i].id, pid) == 0) continue;
                np_impl_t *other = (np_impl_t *)ctx->participants[i].impl;
                if (other == NULL || other->proc == NULL) continue;
                negotiation_set_peer_tier(other->proc, target_impl->pub->uuid, t);
            }
        }
    }

    /* capability_tiers: { "<cap_name>": <required_tier_int>, ... }.
     * Sets the required_tier on a named capability on every
     * participant's process. The tier-gate in handle_invite then
     * refuses invites for that capability when the sender's tier is
     * below this threshold. */
    json_t *ct = json_object_get(fixtures, "capability_tiers");
    if (json_is_object(ct))
    {
        const char *cap_name;
        json_t *tier_j;
        json_object_foreach(ct, cap_name, tier_j) {
            if (!json_is_integer(tier_j)) continue;
            int t = (int)json_integer_value(tier_j);
            for (size_t i = 0; i < ctx->participant_count; i++)
            {
                np_impl_t *impl = (np_impl_t *)ctx->participants[i].impl;
                if (impl == NULL || impl->proc == NULL) continue;
                negotiation_set_capability_required_tier(impl->proc, cap_name, t);
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Inbound construction                                                       */
/* ------------------------------------------------------------------------- */

static json_t *_build_task_json(json_t *payload, const uuid_t task_uuid,
                                const uuid_t requestor_uuid,
                                bool include_full)
{
    json_t *j = json_object();
    if (j == NULL) return NULL;

    char uuid_buf[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, uuid_buf);
    json_object_set_new(j, "task_uuid", json_string(uuid_buf));
    if (!include_full) return j;

    uuid_unparse_lower(requestor_uuid, uuid_buf);
    json_object_set_new(j, "requestor_uuid", json_string(uuid_buf));

    const char *cap_name = "noop";
    json_t *cap_j = json_object_get(payload, "capability");
    if (json_is_string(cap_j)) cap_name = json_string_value(cap_j);
    json_object_set_new(j, "capability_name", json_string(cap_name));

    bool flexible = true;
    json_t *flex_j = json_object_get(payload, "flexible");
    if (json_is_boolean(flex_j)) flexible = json_boolean_value(flex_j);
    json_object_set_new(j, "flexible", json_boolean(flexible));

    json_object_set_new(j, "timeout", json_integer(0));

    /* when_sec / duration_sec: pin a stable time so handle_invite's
     * schedule check is deterministic. when=now, duration=60s is plenty
     * to avoid spurious haggling on a fresh task_stack. */
    json_object_set_new(j, "when_sec", json_integer((json_int_t)time(NULL)));
    json_object_set_new(j, "duration_sec", json_integer(60));
    return j;
}

static int _build_inbound(sce_run_ctx_t *ctx,
                          const char *from_id,
                          const char *to_id,
                          const char *function,
                          json_t *payload,
                          generic_msg_t *out)
{
    (void)to_id;
    sce_participant_t *sender = sce_find_participant(ctx, from_id);
    sce_participant_t *recipient = sce_find_participant(ctx, to_id);
    if (sender == NULL)
    {
        snprintf(ctx->err, sizeof(ctx->err), "build_inbound: unknown from %s", from_id);
        return -1;
    }
    np_impl_t *sender_impl = (np_impl_t *)sender->impl;
    np_impl_t *recipient_impl = recipient ? (np_impl_t *)recipient->impl : NULL;

    /* Task uuid: scenarios identify tasks by `task_id` slug; uuid5 the
     * slug (Python parity). Default slug stops the engine matching
     * separate steps' tasks together. */
    const char *slug = "default-task";
    if (payload && json_is_object(payload))
    {
        json_t *tid_j = json_object_get(payload, "task_id");
        if (json_is_string(tid_j)) slug = json_string_value(tid_j);
    }
    uuid_t task_uuid;
    _uuid5("task:", slug, task_uuid);

    /* Requestor: the original inviter, which initiates 'invitation'
     * and 'status request' (alice→bob); the worker initiates the
     * replies ack/nack/haggle and the report ('report results') —
     * the requestor on those is therefore the recipient. Mirrors
     * the Python adapter's `_build_inbound` after the 2026-05-22
     * fix (see trust-tiers.md slice 5 notes). */
    bool requestor_is_sender = (strcmp(function, "invitation") == 0
                                || strcmp(function, "status request") == 0
                                || strcmp(function, "spawn task") == 0);
    const uuid_t *requestor_uuid;
    if (requestor_is_sender || recipient_impl == NULL)
        requestor_uuid = (const uuid_t *)&sender_impl->pub->uuid;
    else
        requestor_uuid = (const uuid_t *)&recipient_impl->pub->uuid;

    /* Build the JSON payload appropriate to each handler. */
    json_t *body = NULL;
    if (strcmp(function, "invitation") == 0
        || strcmp(function, "haggle") == 0
        || strcmp(function, "spawn task") == 0)
    {
        body = _build_task_json(payload, task_uuid, *requestor_uuid, true);
    }
    else if (strcmp(function, "ack") == 0
             || strcmp(function, "nack") == 0
             || strcmp(function, "status request") == 0)
    {
        body = _build_task_json(payload, task_uuid, *requestor_uuid, false);
    }
    else if (strcmp(function, "status response") == 0)
    {
        body = _build_task_json(payload, task_uuid, *requestor_uuid, false);
        if (body)
        {
            /* status enum: harness uses 'pending', 'running', etc.; the
             * C handle_stat_resp reads the integer so map common
             * strings. NEG_RUNNING == 1 in neg_status_t per neg_proc.c. */
            const char *st = "running";
            json_t *st_j = json_object_get(payload, "status");
            if (json_is_string(st_j)) st = json_string_value(st_j);
            int status_int = 0; /* unknown */
            if (strcmp(st, "running") == 0 || strcmp(st, "pending") == 0)
                status_int = 1;
            json_object_set_new(body, "status", json_integer(status_int));
        }
    }
    else if (strcmp(function, "report results") == 0)
    {
        body = _build_task_json(payload, task_uuid, *requestor_uuid, false);
    }
    else if (strcmp(function, "tier_lost") == 0)
    {
        /* Local-IPC tier_lost payload: 2-element array
         * [peer_uuid_str, new_tier_int]. Mirrors Python's
         * to_json_string((key, new_tier)) in repprocess.py and the
         * conformance adapter (`tier_lost` branch in negotiation.py).
         * Payload fields: `peer` is the slug of the affected peer
         * (resolved via sce_find_participant); `new_tier` is the
         * peer's post-demotion tier. */
        const char *peer_slug = NULL;
        int new_tier = 0;
        if (payload && json_is_object(payload))
        {
            json_t *p_j = json_object_get(payload, "peer");
            if (json_is_string(p_j)) peer_slug = json_string_value(p_j);
            json_t *t_j = json_object_get(payload, "new_tier");
            if (json_is_integer(t_j)) new_tier = (int)json_integer_value(t_j);
        }
        if (peer_slug == NULL)
        {
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: tier_lost missing peer slug");
            return -1;
        }
        sce_participant_t *affected = sce_find_participant(ctx, peer_slug);
        if (affected == NULL)
        {
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: tier_lost unknown peer %s", peer_slug);
            return -1;
        }
        np_impl_t *affected_impl = (np_impl_t *)affected->impl;
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(affected_impl->pub->uuid, uuid_str);
        body = json_array();
        if (body == NULL) return -1;
        json_array_append_new(body, json_string(uuid_str));
        json_array_append_new(body, json_integer(new_tier));
    }
    else
    {
        snprintf(ctx->err, sizeof(ctx->err),
                 "build_inbound: unsupported function %s", function);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    strncpy(out->info.net_msg.process, "negotiation", PROC_NAME_LEN);
    out->info.net_msg.function = (char *)function;
    out->info.net_msg.encrypt = false;
    memcpy(&out->info.net_msg.from_whom, sender_impl->pub, sizeof(public_identity_t));
    if (recipient_impl)
        memcpy(&out->info.net_msg.to_whom, recipient_impl->pub, sizeof(public_identity_t));

    if (body)
    {
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }
    return 0;
}

static int _dispatch(sce_run_ctx_t *ctx,
                     sce_participant_t *target,
                     generic_msg_t *inbound)
{
    (void)ctx;
    np_impl_t *impl = (np_impl_t *)target->impl;
    array_t *queues = NULL;
    array_create(&queues);
    run_message_handlers(impl->proc, queues, NET_MESSAGE, inbound);
    array_free(queues);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Adapter entry                                                              */
/* ------------------------------------------------------------------------- */

/* Validate `expected_state` against post-scenario negotiation state.
 * Mirrors the Python negotiation adapter (`harness/python/adapters/
 * negotiation.py::_check_expected_state`) — supported keys:
 *   - task_in_stack: bool   → asserts whether the shared task_stack
 *                             has any entries.
 *   - confirmed:     bool   → asserts whether neg_state.confirmed map
 *                             has any entries.
 *   - has_my_task:   slug   → asserts that neg_state.my_tasks has an
 *                             entry keyed by uuid5(NEG_NS, "task:<slug>")
 *                             (same derivation the adapter uses when
 *                             building task inbounds in _build_inbound,
 *                             so the C side compares bit-equal keys to
 *                             Python's `uuid5(_NS, f'task:{slug}')`).
 *   - flood_count:   {task:<slug>, count:<int>}
 *                           → asserts that the per-task flood counter
 *                             handle_invite maintains equals `count`.
 *                             Reads via negotiation_get_task_flood_count
 *                             (production-side accessor over the
 *                             "flood:<uuid>" key); Python reads
 *                             `proposed_tasks[uuid].count` directly.
 *
 * Per-participant `pid` is honored for the iteration form, but the C
 * neg_state is global (one negotiation instance per binary), so any
 * pid's check reads the same shared state. Single-acceptor scenarios
 * are unambiguous; multi-acceptor scenarios would need the production
 * code itself to split per-process state — out of scope here. */
static int _negotiation_check_expected_state(sce_run_ctx_t *ctx)
{
    json_t *expected = json_object_get(ctx->case_data, "expected_state");
    if (!json_is_object(expected)) return 0;

    const char *pid;
    json_t *checks;
    json_object_foreach(expected, pid, checks) {
        if (!json_is_object(checks)) continue;
        if (sce_find_participant(ctx, pid) == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "expected_state references unknown participant %s", pid);
            return -1;
        }

        const char *key;
        json_t *val;
        json_object_foreach(checks, key, val) {
            if (strcmp(key, "task_in_stack") == 0) {
                bool want = json_is_true(val);
                int sz = negotiation_get_task_stack_size();
                bool got = (sz > 0);
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: task_in_stack=%s (stack size=%d), expected %s",
                             pid, got ? "true" : "false", sz,
                             want ? "true" : "false");
                    return -1;
                }
            } else if (strcmp(key, "confirmed") == 0) {
                bool want = json_is_true(val);
                bool got = negotiation_has_confirmed_any();
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: confirmed=%s, expected %s",
                             pid, got ? "true" : "false",
                             want ? "true" : "false");
                    return -1;
                }
            } else if (strcmp(key, "has_my_task") == 0) {
                /* Accepts either a slug string (positive presence) or a
                 * dict {slug, present: bool} for either direction.
                 * Same derivation the adapter uses when building task
                 * inbounds (see `_build_inbound` / `_uuid5`): the key
                 * stored in production my_tasks is the stringified
                 * uuid5 of NEG_NS + "task:<slug>". Python's adapter
                 * derives identically with uuid5(_NS, f'task:{slug}'). */
                const char *slug = NULL;
                bool want_present = true;
                if (json_is_string(val)) {
                    slug = json_string_value(val);
                } else if (json_is_object(val)) {
                    slug = json_string_value(json_object_get(val, "slug"));
                    json_t *p_j = json_object_get(val, "present");
                    if (p_j != NULL) want_present = json_is_true(p_j);
                }
                if (slug == NULL) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_my_task expects slug-string or "
                             "{slug, present} dict", pid);
                    return -1;
                }
                uuid_t want_uuid;
                _uuid5("task:", slug, want_uuid);
                bool got = negotiation_has_my_task_uuid(want_uuid);
                if (got != want_present) {
                    char uuid_str[UUID_STRING_LEN + 1] = {0};
                    uuid_unparse_lower(want_uuid, uuid_str);
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_my_task slug=%s (uuid=%s) present=%s, expected %s",
                             pid, slug, uuid_str,
                             got ? "true" : "false",
                             want_present ? "true" : "false");
                    return -1;
                }
            } else if (strcmp(key, "flood_count") == 0) {
                /* {task: <slug>, count: <int>} — derive uuid from slug
                 * (same _uuid5 used elsewhere), read the per-task flood
                 * counter via the production-side accessor. Mirrors
                 * the Python adapter's read on
                 * `proposed_tasks[uuid].count`. */
                if (!json_is_object(val)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: flood_count expects {task:<slug>, count:<int>}", pid);
                    return -1;
                }
                const char *slug = json_string_value(
                    json_object_get(val, "task"));
                json_t *count_j = json_object_get(val, "count");
                if (slug == NULL || !json_is_integer(count_j)) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: flood_count requires task=<slug> and count=<int>", pid);
                    return -1;
                }
                int want = (int)json_integer_value(count_j);
                uuid_t want_uuid;
                _uuid5("task:", slug, want_uuid);
                int got = negotiation_get_task_flood_count(want_uuid);
                if (got != want) {
                    char uuid_str[UUID_STRING_LEN + 1] = {0};
                    uuid_unparse_lower(want_uuid, uuid_str);
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: flood_count for slug=%s (uuid=%s) = %d, expected %d",
                             pid, slug, uuid_str, got, want);
                    return -1;
                }
            } else {
                /* Unknown key: surface so a scenario can't silently
                 * skip C-side enforcement of something Python checks. */
                snprintf(ctx->err, sizeof(ctx->err),
                         "%s: unsupported expected_state key %s", pid, key);
                return -1;
            }
        }
    }
    return 0;
}

void at_negotiation_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "negative") == 0)
    {
        at_neg_run_wire(c, out);
        return;
    }
    if (strcmp(c->kind, "scenario") != 0)
    {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C negotiation adapter only handles kind:scenario|negative (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    char err[256] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    sce_run_ctx_t ctx;
    sce_init(&ctx);
    ctx.case_data = c->data;
    ctx.build_inbound = _build_inbound;
    ctx.dispatch = _dispatch;

    /* Wipe singleton neg_state so observables like task_in_stack:false /
     * has_my_task:false are not polluted by prior scenarios. */
    negotiation_reset_state();

    json_t *parts = json_object_get(c->data, "participants");
    if (!json_is_array(parts))
    {
        snprintf(err, sizeof(err), "scenario: participants array missing");
        goto fail;
    }
    size_t n = json_array_size(parts);
    if (n > SCE_MAX_PARTICIPANTS)
    {
        snprintf(err, sizeof(err), "scenario: too many participants (%zu)", n);
        goto fail;
    }
    for (size_t i = 0; i < n; i++)
    {
        json_t *p = json_array_get(parts, i);
        const char *id = json_string_value(json_object_get(p, "id"));
        const char *role = json_string_value(json_object_get(p, "role"));
        if (id == NULL || role == NULL)
        {
            snprintf(err, sizeof(err), "participants[%zu] missing id or role", i);
            goto fail;
        }
        snprintf(ctx.participants[i].id, SCE_ID_LEN, "%s", id);
        snprintf(ctx.participants[i].role, SCE_ID_LEN, "%s", role);
        ctx.participants[i].impl = _build_participant_impl(id, i);
        if (ctx.participants[i].impl == NULL)
        {
            snprintf(err, sizeof(err),
                     "participants[%zu] (%s) impl build failed", i, id);
            goto fail;
        }
        ctx.participant_count++;
    }

    _apply_fixtures(&ctx);

    g_active_ctx = &ctx;
    messaging_set_test_hook(_send_hook);

    int rc = sce_run(&ctx);
    if (rc == 0) rc = _negotiation_check_expected_state(&ctx);

    messaging_set_test_hook(NULL);
    g_active_ctx = NULL;

    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) at_case_result_set_pass(out, duration_ms);
    else         at_case_result_set_fail(out, duration_ms, "AssertionError", ctx.err);

    for (size_t i = 0; i < ctx.participant_count; i++)
        _free_participant_impl((np_impl_t *)ctx.participants[i].impl);
    return;

fail:
    g_active_ctx = NULL;
    messaging_set_test_hook(NULL);
    for (size_t i = 0; i < ctx.participant_count; i++)
        _free_participant_impl((np_impl_t *)ctx.participants[i].impl);
    at_case_result_set_fail(out, 0, "AssertionError", err);
}
