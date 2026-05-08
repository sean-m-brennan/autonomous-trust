/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

/** @file Identity-protocol adapter.
 *
 *  Builds participants, installs the messaging_send test hook, and drives
 *  the universal scenario_engine. The adapter's only protocol-specific
 *  responsibilities are participant construction (per-id `process_t`
 *  instantiation + handler registration) and inbound construction (turn a
 *  scenario step into a `generic_msg_t` the C handler can dispatch).
 *
 *  Phase C: both amnesia-readmission and new-node-admission run end-to-
 *  end. The adapter flips `identity_set_synchronous_dispatch(true)` on
 *  the file-scope id_state so welcoming_committee inline-finalizes (no
 *  inbound vote messages required) and emits propose_peer / peer_accepted
 *  as one broadcast each — mirroring Python's group-targeted sends.
 */

#include "identity.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/id_proc_priv.h"
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"

#include "../scenario_engine.h"

/* ------------------------------------------------------------------------- */
/* Per-participant impl carries a process_t plus a public_identity_t copy    */
/* for the to_whom→id resolution path.                                        */
/* ------------------------------------------------------------------------- */

typedef struct {
    identity_t *full;
    public_identity_t *pub;
    process_t *proc;
} ic_impl_t;

/* The engine ctx is global because the messaging-hook signature has no
 * void* context; one scenario runs at a time. */
static sce_run_ctx_t *g_active_ctx = NULL;

/* Scan ctx->participants for a uuid match — the messaging hook gets a
 * net_msg.to_whom (public_identity_t) and needs to map back to a
 * participant id.
 *
 * Identity protocol's `peer_accepted` and `propose_peer` are conceptually
 * group broadcasts (Python sends each as a single `to_whom=self.group`
 * Message). In synchronous_dispatch mode the C implementation now also
 * emits one broadcast per call, with a zeroed to_whom — `is_broadcast`
 * detects that. Either way we surface them as "broadcast" so cross-
 * language scenarios match. */
static bool _is_zero_uuid(const uuid_t u) {
    for (size_t i = 0; i < sizeof(uuid_t); i++)
        if (u[i] != 0) return false;
    return true;
}

static const char *_resolve_to_id(const generic_msg_t *msg) {
    if (msg->type != NET_MESSAGE) return "internal";
    const char *fn = msg->info.net_msg.function;
    if (fn != NULL
        && (strcmp(fn, "peer_accepted") == 0
            || strcmp(fn, "propose_peer") == 0)) {
        return "broadcast";
    }
    if (_is_zero_uuid(msg->info.net_msg.to_whom.uuid)) {
        return "broadcast";
    }
    if (g_active_ctx == NULL) return "unknown";
    for (size_t i = 0; i < g_active_ctx->participant_count; i++) {
        ic_impl_t *impl = (ic_impl_t *)g_active_ctx->participants[i].impl;
        if (impl == NULL || impl->pub == NULL) continue;
        if (uuid_compare(impl->pub->uuid, msg->info.net_msg.to_whom.uuid) == 0) {
            return g_active_ctx->participants[i].id;
        }
    }
    return "unknown";
}

static int _send_hook(const char *key,
                      const message_type_t type,
                      generic_msg_t *msg,
                      bool blocking) {
    (void)key; (void)blocking;
    if (g_active_ctx == NULL) return 0;
    const char *to_id = _resolve_to_id(msg);
    const char *function = (type == NET_MESSAGE && msg->info.net_msg.function != NULL)
        ? msg->info.net_msg.function : "__internal__";
    sce_capture(g_active_ctx, to_id, function);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Participant construction                                                    */
/* ------------------------------------------------------------------------- */

static int _make_identity(const char *id, size_t idx, identity_t **out) {
    uuid_t uuid;
    crypto_generichash(uuid, sizeof(uuid_t),
                       (const unsigned char *)id, strlen(id), NULL, 0);
    /* Cosmetic v4-shaped uuid: clearer in logs than raw hash bytes. */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    char addr[ADDR_LEN + 1] = {0};
    snprintf(addr, sizeof(addr), "10.0.70.%zu", idx + 1);
    char fullname[NAME_LEN + 1] = {0};
    snprintf(fullname, sizeof(fullname), "%s.scenario", id);
    return identity_create(&uuid, addr, fullname, id, "me", out);
}

static ic_impl_t *_build_participant_impl(const char *id, size_t idx) {
    ic_impl_t *impl = calloc(1, sizeof(ic_impl_t));
    if (impl == NULL) return NULL;
    if (_make_identity(id, idx, &impl->full) != 0 || impl->full == NULL) goto fail;
    if (identity_publish(impl->full, &impl->pub) != 0 || impl->pub == NULL) goto fail;
    impl->proc = smrt_create(sizeof(process_t));
    if (impl->proc == NULL) goto fail;
    pthread_rwlock_init(&impl->proc->protocol.peers_rwlock, NULL);
    strncpy(impl->proc->name, "identity", PROC_NAME_LEN);
    if (map_create(&impl->proc->protocol.handlers) != 0) goto fail;
    impl->proc->protocol.phase = 3;
    if (identity_register_handlers(impl->proc) != 0) goto fail;
    return impl;
fail:
    if (impl != NULL) {
        if (impl->proc != NULL) {
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

static void _free_participant_impl(ic_impl_t *impl) {
    if (impl == NULL) return;
    if (impl->proc != NULL) {
        if (impl->proc->protocol.handlers != NULL) map_free(impl->proc->protocol.handlers);
        pthread_rwlock_destroy(&impl->proc->protocol.peers_rwlock);
        smrt_deref(impl->proc);
    }
    if (impl->pub != NULL) smrt_deref(impl->pub);
    if (impl->full != NULL) identity_free(impl->full);
    free(impl);
}

/* Apply scenario fixtures: amnesia_known => pre-stage non-newcomer
 * participants' peer lists with the newcomer (so welcoming_committee's
 * already-known branch is reachable). */
static void _apply_fixtures(sce_run_ctx_t *ctx) {
    json_t *fixtures = json_object_get(ctx->case_data, "fixtures");
    if (!json_is_object(fixtures)) return;
    json_t *amnesia_j = json_object_get(fixtures, "amnesia_known");
    bool amnesia_known = json_is_true(amnesia_j);

    /* Find the new_node by role. */
    int newcomer_idx = -1;
    for (size_t i = 0; i < ctx->participant_count; i++) {
        if (strcmp(ctx->participants[i].role, "new_node") == 0) {
            newcomer_idx = (int)i;
            break;
        }
    }
    if (!amnesia_known || newcomer_idx < 0) return;

    /* Add the newcomer to each existing peer's peers list. */
    ic_impl_t *new_impl = (ic_impl_t *)ctx->participants[newcomer_idx].impl;
    for (size_t i = 0; i < ctx->participant_count; i++) {
        if ((int)i == newcomer_idx) continue;
        ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
        process_t *p = impl->proc;
        if (p->protocol.num_peers >= DEFAULT_MAX_PEERS) continue;
        memcpy(&p->protocol.peers[p->protocol.num_peers],
               new_impl->pub, sizeof(public_identity_t));
        p->protocol.num_peers++;
    }
}

/* ------------------------------------------------------------------------- */
/* Engine callbacks                                                           */
/* ------------------------------------------------------------------------- */

static int _build_inbound(sce_run_ctx_t *ctx,
                          const char *from_id,
                          const char *to_id,
                          const char *function,
                          json_t *payload,
                          generic_msg_t *out) {
    (void)payload; (void)to_id;
    sce_participant_t *sender = sce_find_participant(ctx, from_id);
    if (sender == NULL) {
        snprintf(ctx->err, sizeof(ctx->err), "build_inbound: unknown from %s", from_id);
        return -1;
    }
    ic_impl_t *sender_impl = (ic_impl_t *)sender->impl;

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    strncpy(out->info.net_msg.process, "identity", PROC_NAME_LEN);
    /* function string is owned by the JSON loaded by the runner; lifetime
     * spans the entire scenario, which is what the handler dispatch
     * requires (strcmp against handler keys). */
    out->info.net_msg.function = (char *)function;
    out->info.net_msg.encrypt = false;
    memcpy(&out->info.net_msg.from_whom, sender_impl->pub, sizeof(public_identity_t));
    return 0;
}

static int _dispatch(sce_run_ctx_t *ctx,
                     sce_participant_t *target,
                     generic_msg_t *inbound) {
    (void)ctx;
    ic_impl_t *impl = (ic_impl_t *)target->impl;
    /* directory_t is array_t; _remember_activity walks it without a NULL
     * guard. Pass an empty array. */
    array_t *queues = NULL;
    array_create(&queues);
    run_message_handlers(impl->proc, queues, NET_MESSAGE, inbound);
    array_free(queues);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Adapter entry                                                              */
/* ------------------------------------------------------------------------- */

void at_identity_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C identity adapter only handles kind:scenario (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    char err[256] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Inline-finalize the welcoming-committee cascade and emit propose /
     * peer_accepted as broadcasts, so a single-bg scenario sees the full
     * outbound. Mirrors Python's per-instance synchronous_dispatch=True. */
    identity_set_synchronous_dispatch(true);

    sce_run_ctx_t ctx;
    sce_init(&ctx);
    ctx.case_data = c->data;
    ctx.build_inbound = _build_inbound;
    ctx.dispatch = _dispatch;

    /* Build participants. */
    json_t *parts = json_object_get(c->data, "participants");
    if (!json_is_array(parts)) {
        snprintf(err, sizeof(err), "scenario: participants array missing");
        goto fail;
    }
    size_t n = json_array_size(parts);
    if (n > SCE_MAX_PARTICIPANTS) {
        snprintf(err, sizeof(err), "scenario: too many participants (%zu)", n);
        goto fail;
    }
    for (size_t i = 0; i < n; i++) {
        json_t *p = json_array_get(parts, i);
        const char *id = json_string_value(json_object_get(p, "id"));
        const char *role = json_string_value(json_object_get(p, "role"));
        if (id == NULL || role == NULL) {
            snprintf(err, sizeof(err), "participants[%zu] missing id or role", i);
            goto fail;
        }
        snprintf(ctx.participants[i].id, SCE_ID_LEN, "%s", id);
        snprintf(ctx.participants[i].role, SCE_ID_LEN, "%s", role);
        ctx.participants[i].impl = _build_participant_impl(id, i);
        if (ctx.participants[i].impl == NULL) {
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

    messaging_set_test_hook(NULL);
    g_active_ctx = NULL;
    identity_set_synchronous_dispatch(false);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) {
        at_case_result_set_pass(out, duration_ms);
    } else {
        at_case_result_set_fail(out, duration_ms, "AssertionError", ctx.err);
    }

    /* Cleanup. */
    for (size_t i = 0; i < ctx.participant_count; i++) {
        _free_participant_impl((ic_impl_t *)ctx.participants[i].impl);
    }
    return;

fail:
    g_active_ctx = NULL;
    messaging_set_test_hook(NULL);
    identity_set_synchronous_dispatch(false);
    for (size_t i = 0; i < ctx.participant_count; i++) {
        _free_participant_impl((ic_impl_t *)ctx.participants[i].impl);
    }
    at_case_result_set_fail(out, 0, "AssertionError", err);
}
