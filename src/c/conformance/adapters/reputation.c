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

/** @file Reputation-protocol adapter (Phase F).
 *
 *  Drives `kind: scenario` for `protocol: reputation`. Each scenario
 *  step's dispatch resets the file-scope rep_state, re-installs the
 *  TARGET participant's fixtures (history_len, last_id, my_requests,
 *  pre-granted requests), then runs the handler. This works around C's
 *  shared rep_state design: only one participant's handler runs per
 *  step, so the shared state only needs to be correct for that
 *  participant at that moment.
 *
 *  Identities + task UUIDs are derived as UUIDv5 in namespace
 *  00000000-0000-0000-0000-000000000aaa, matching the Python adapter
 *  byte-for-byte (rep:<id> for participants, tx:<slug> for tasks).
 */

#include "reputation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"     /* config_t (proc->configs["identity"]) */
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

#include "../negative_runner.h"

#include "utilities/util.h"
#include "../scenario_engine.h"

typedef struct {
    identity_t *full;
    public_identity_t *pub;
    process_t *proc;
} rp_impl_t;

/* Per-participant post-dispatch snapshot of rep_state. Each `_dispatch`
 * runs against the dispatcher's freshly-installed state, then this
 * snapshot is taken. expected_state checks read here — without
 * snapshotting, the very next dispatch's reset+install clobbers the
 * state we wanted to verify. */
/* Per-peer reputation snapshot. Holds rep_state.reputations[uuid_of(pid)]
 * for every other known participant after the dispatcher's handler ran.
 * One slot per participant; absent entries (uuid not in rep_state.reputations)
 * keep `has_value=false`. */
typedef struct {
    char id[SCE_ID_LEN];
    bool has_value;
    double value;
} rp_peer_rep_t;

typedef struct {
    char id[SCE_ID_LEN];
    bool valid;
    int chain_len;
    int committed_tx_count;
    char window_root[TX_HASH_HEX_LEN + 1];
    char checkpoint_root[TX_HASH_HEX_LEN + 1];
    int request_count;
    int64_t last_id;
    rp_peer_rep_t peer_reps[SCE_MAX_PARTICIPANTS];
    /* Verifiable warm start (doc/architecture/reputation.md). The evidence document is the one
     * artifact BOTH runtimes read, so its shape is worth pinning here; the
     * ceilings are the arithmetic that decides how much standing a restored
     * peer may hold, and a silent drift between runtimes would hand the same
     * peer different tiers on the two implementations. */
    char evidence_schema[8];
    int  evidence_chain_len;
    char evidence_checkpoint_root[TX_HASH_HEX_LEN + 1];
    rp_peer_rep_t evidence_ceilings[SCE_MAX_PARTICIPANTS];
    /* Slash proposals this participant ORIGINATED, cumulative over the whole
     * scenario (R+D.md §12.8). Unlike every other field here this is a TALLY
     * rather than a snapshot: it is incremented by _send_hook as messages go
     * out, not re-read after a dispatch, because the assertion it exists for
     * is "over the whole scenario, none" and the engine's step matching is
     * permissive about extra messages. g_snaps is zeroed per scenario, which
     * is exactly the lifetime a cumulative count wants. */
    int slashes_proposed;
    /* Peers this participant reported on the app-facing carrier
     * (doc/architecture/app-peer-carrier.md). Like slashes_proposed this is a
     * TALLY filled by _send_hook, not a snapshot: PeerReputation goes to
     * AT_MAIN_QUEUE as a PEER_REPUTATION message rather than onto the network
     * outbox, so there is nothing for the engine to capture. Recorded as
     * uuids and mapped back to participant ids at check time. */
    char app_roster[SCE_MAX_PARTICIPANTS][UUID_STRING_LEN + 1];
    int  app_roster_n;
} rp_snap_t;
static rp_snap_t g_snaps[SCE_MAX_PARTICIPANTS];

static sce_run_ctx_t *g_active_ctx = NULL;
static json_t *g_fixtures = NULL;        /* borrowed; lifetime is the scenario */

static rp_snap_t *_snap_find(const char *id)
{
    for (size_t i = 0; i < SCE_MAX_PARTICIPANTS; i++)
        if (g_snaps[i].valid && strcmp(g_snaps[i].id, id) == 0)
            return &g_snaps[i];
    return NULL;
}

static rp_snap_t *_snap_get_or_make(const char *id)
{
    rp_snap_t *s = _snap_find(id);
    if (s) return s;
    for (size_t i = 0; i < SCE_MAX_PARTICIPANTS; i++)
        if (!g_snaps[i].valid)
        {
            snprintf(g_snaps[i].id, SCE_ID_LEN, "%s", id);
            g_snaps[i].valid = true;
            return &g_snaps[i];
        }
    return NULL;
}

static const uuid_t REP_NS = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xaa
};

static void _uuid5(const char *prefix, const char *name, uuid_t out)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", prefix, name);
    uuid_generate_sha1(out, REP_NS, buf, strlen(buf));
}

/* Resolve a generic_msg_t.to_whom uuid back to a participant id, or
 * "broadcast" when zeroed (the C handler family stamps zero on
 * group-bound messages — handle_nack's retry, etc.). */
static bool _is_zero_uuid(const uuid_t u)
{
    for (size_t i = 0; i < sizeof(uuid_t); i++)
        if (u[i] != 0) return false;
    return true;
}

static const char *_resolve_to_id(const generic_msg_t *msg)
{
    if (msg->type != NET_MESSAGE) return "internal";
    if (_is_zero_uuid(msg->info.net_msg.to_whom.uuid)) return "broadcast";
    if (g_active_ctx == NULL) return "unknown";
    for (size_t i = 0; i < g_active_ctx->participant_count; i++)
    {
        rp_impl_t *impl = (rp_impl_t *)g_active_ctx->participants[i].impl;
        if (impl == NULL || impl->pub == NULL) continue;
        if (uuid_compare(impl->pub->uuid, msg->info.net_msg.to_whom.uuid) == 0)
            return g_active_ctx->participants[i].id;
    }
    return "unknown";
}

/* Whose handler is running right now. _send_hook sees the message but not the
 * emitter, and a tally has to be attributed to somebody; _dispatch is the only
 * place that knows. NULL outside a dispatch (participant construction also
 * sends), in which case there is nobody to attribute to and the tally is
 * skipped. */
static const char *g_current_emitter = NULL;

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
    if (g_current_emitter != NULL
        && strcmp(function, REP_PROTO_SLASH_PROPOSE) == 0)
    {
        rp_snap_t *es = _snap_get_or_make(g_current_emitter);
        if (es != NULL)
            es->slashes_proposed++;
    }
    if (g_current_emitter != NULL && type == PEER_REPUTATION)
    {
        rp_snap_t *es = _snap_get_or_make(g_current_emitter);
        if (es != NULL && es->app_roster_n < SCE_MAX_PARTICIPANTS)
            uuid_unparse_lower(msg->info.peer_reputation.peer_uuid,
                               es->app_roster[es->app_roster_n++]);
    }
    sce_capture(g_active_ctx, to_id, function);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Participant construction                                                   */
/* ------------------------------------------------------------------------- */

static int _make_identity(const char *id, size_t idx, identity_t **out)
{
    uuid_t uuid;
    _uuid5("rep:", id, uuid);
    char addr[ADDR_LEN + 1] = {0};
    snprintf(addr, sizeof(addr), "10.0.60.%zu", idx + 1);
    char nickname[NAME_LEN + 1] = {0};
    snprintf(nickname, sizeof(nickname), "%s.rep", id);
    return identity_create(&uuid, addr, nickname, id, out);
}

static rp_impl_t *_build_participant_impl(const char *id, size_t idx)
{
    rp_impl_t *impl = calloc(1, sizeof(rp_impl_t));
    if (impl == NULL) return NULL;
    if (_make_identity(id, idx, &impl->full) != 0 || impl->full == NULL) goto fail;
    if (identity_publish(impl->full, &impl->pub) != 0 || impl->pub == NULL) goto fail;
    impl->proc = smrt_create(sizeof(process_t));
    if (impl->proc == NULL) goto fail;
    pthread_rwlock_init(&impl->proc->protocol.peers_rwlock, NULL);
    strncpy(impl->proc->name, "reputation", PROC_NAME_LEN);
    if (map_create(&impl->proc->protocol.handlers) != 0) goto fail;
    impl->proc->protocol.phase = 1;
    if (reputation_register_handlers(impl->proc) != 0) goto fail;

    /* Wire the participant's own identity into proc->configs under the
     * "identity" key — where _resolve_self_identity looks for the private
     * signing key. Without it a participant cannot co-sign a slash or
     * checkpoint round at all (it declines, by design, rather than emitting an
     * unsigned ack). Same wiring the identity adapter already does. */
    {
        config_t *id_cfg = calloc(1, sizeof(config_t));
        if (id_cfg == NULL) goto fail;
        id_cfg->name = "identity";
        id_cfg->data_struct = impl->full;
        data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
        if (id_dat == NULL) { free(id_cfg); goto fail; }
        if (map_create(&impl->proc->configs) != 0) { free(id_cfg); goto fail; }
        if (map_set(impl->proc->configs, (map_key_t)"identity", id_dat) != 0)
            goto fail;
    }
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

static void _free_participant_impl(rp_impl_t *impl)
{
    if (impl == NULL) return;
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

/* Pre-populate every participant's protocol.peers list with every other
 * participant — handle_grant iterates protocol.peers when broadcasting
 * the resulting transaction. */
static void _link_peer_lists(sce_run_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->participant_count; i++)
    {
        rp_impl_t *impl_i = (rp_impl_t *)ctx->participants[i].impl;
        if (impl_i == NULL || impl_i->proc == NULL) continue;
        for (size_t j = 0; j < ctx->participant_count; j++)
        {
            if (i == j) continue;
            rp_impl_t *impl_j = (rp_impl_t *)ctx->participants[j].impl;
            if (impl_j == NULL || impl_j->pub == NULL) continue;
            if (impl_i->proc->protocol.num_peers >= DEFAULT_MAX_PEERS) break;
            memcpy(&impl_i->proc->protocol.peers[impl_i->proc->protocol.num_peers],
                   impl_j->pub, sizeof(public_identity_t));
            impl_i->proc->protocol.num_peers++;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Per-step state installation                                                */
/* ------------------------------------------------------------------------- */

/* Look up @p pid in participants and return its public uuid (or NULL). */
static const uuid_t *_uuid_of(sce_run_ctx_t *ctx, const char *pid)
{
    sce_participant_t *p = sce_find_participant(ctx, pid);
    if (p == NULL) return NULL;
    rp_impl_t *impl = (rp_impl_t *)p->impl;
    return (impl && impl->pub) ? (const uuid_t *)&impl->pub->uuid : NULL;
}

/* Reset rep_state and re-install the per-participant fixtures relevant
 * to the dispatcher (target). Run BEFORE every handler dispatch so each
 * step sees the right slice of state. */
static void _install_target_state(sce_run_ctx_t *ctx, const char *target_id)
{
    /* num_peers = participant_count - 1 (everyone except self) */
    int num_peers = (int)ctx->participant_count - 1;
    if (num_peers < 1) num_peers = 1;
    reputation_reset_state(num_peers);

    if (g_fixtures == NULL || target_id == NULL) return;

    /* history_len: { "<pid>": N, ... } */
    json_t *hl = json_object_get(g_fixtures, "history_len");
    if (json_is_object(hl))
    {
        json_t *n_j = json_object_get(hl, target_id);
        if (json_is_integer(n_j))
            reputation_set_chain_len((int)json_integer_value(n_j));
    }

    /* last_id: { "<pid>": N, ... } */
    json_t *li = json_object_get(g_fixtures, "last_id");
    if (json_is_object(li))
    {
        json_t *id_j = json_object_get(li, target_id);
        if (json_is_integer(id_j))
            reputation_set_last_id((int64_t)json_integer_value(id_j));
    }

    /* num_updates: { "<pid>": N } — lower the catch-up quorum so a single
     * `latest update` step fires the chain merge (Phase 1). */
    json_t *nu = json_object_get(g_fixtures, "num_updates");
    if (json_is_object(nu))
    {
        json_t *n_j = json_object_get(nu, target_id);
        if (json_is_integer(n_j))
            reputation_set_num_updates((int)json_integer_value(n_j));
    }

    /* slash_enabled: true — arm the slash protocol for this case. It is
     * opt-in in production (R+D.md §12.8): unarmed, a node originates
     * nothing, declines to co-sign a proposal, and ignores a finalized
     * slash. Set/cleared on every install rather than only when present, so
     * one armed case cannot leak into the next. Scenario-level (not
     * per-participant) because the knob is an environment variable that the
     * whole cohort in this process shares -- the Python twin reads the same
     * fixture and sets its instance attribute. */
    if (json_is_true(json_object_get(g_fixtures, "slash_enabled")))
        setenv("AT_SLASH_ENABLED", "1", 1);
    else
        unsetenv("AT_SLASH_ENABLED");

    /* requests: { "<pid>": [[id1, id2], ...] } — pre-stage granted Paxos
     * rounds (so handle_transaction's paxos_has_granted_id check passes). */
    json_t *reqs = json_object_get(g_fixtures, "requests");
    if (json_is_object(reqs))
    {
        json_t *pair_arr = json_object_get(reqs, target_id);
        if (json_is_array(pair_arr))
        {
            for (size_t i = 0; i < json_array_size(pair_arr); i++)
            {
                json_t *pair = json_array_get(pair_arr, i);
                if (!json_is_array(pair) || json_array_size(pair) < 2) continue;
                int64_t r_id1 = json_integer_value(json_array_get(pair, 0));
                int64_t r_id2 = json_integer_value(json_array_get(pair, 1));
                reputation_install_accepted(r_id1, r_id2);
            }
        }
    }

    /* my_requests: { "<pid>": [{id1, id2, task_id, score}, ...] } —
     * pre-stage outstanding paxos rounds for proposers. */
    json_t *myr = json_object_get(g_fixtures, "my_requests");
    if (json_is_object(myr))
    {
        json_t *entries = json_object_get(myr, target_id);
        if (json_is_array(entries))
        {
            const uuid_t *self_uuid = _uuid_of(ctx, target_id);
            for (size_t i = 0; i < json_array_size(entries); i++)
            {
                json_t *e = json_array_get(entries, i);
                if (!json_is_object(e)) continue;
                int64_t e_id1 = json_integer_value(json_object_get(e, "id1"));
                int64_t e_id2 = json_integer_value(json_object_get(e, "id2"));
                double  score = 1.0;
                json_t *s_j = json_object_get(e, "score");
                if (json_is_real(s_j))    score = json_real_value(s_j);
                else if (json_is_integer(s_j)) score = (double)json_integer_value(s_j);

                const char *slug = "default";
                json_t *t_j = json_object_get(e, "task_id");
                if (json_is_string(t_j)) slug = json_string_value(t_j);
                uuid_t task_uuid;
                _uuid5("tx:", slug, task_uuid);

                /* my_requests is keyed by proposer uuid in C; install
                 * with self-as-proposer so handle_grant looks us up via
                 * the grant's peer_uuid field, which we also stamp as
                 * self. */
                if (self_uuid)
                    reputation_install_my_request(e_id1, e_id2, *self_uuid,
                                                   score, task_uuid);
            }
        }
    }

    /* tx_history: { "<pid>": [{task_id, p1, p1_score, p2, p2_score}, ...] }
     * — pre-stage bilateral Transactions in rep_state.history so
     * reputation_pure / _contrite_tft can score against them. p1/p2 are
     * participant ids resolved to their UUIDv5. Mirrors Python's
     * tx_history fixture in reputation.py. */
    json_t *txh = json_object_get(g_fixtures, "tx_history");
    if (json_is_object(txh))
    {
        json_t *entries = json_object_get(txh, target_id);
        if (json_is_array(entries))
        {
            for (size_t i = 0; i < json_array_size(entries); i++)
            {
                json_t *e = json_array_get(entries, i);
                if (!json_is_object(e)) continue;

                const char *slug = json_string_value(json_object_get(e, "task_id"));
                const char *p1_id = json_string_value(json_object_get(e, "p1"));
                const char *p2_id = json_string_value(json_object_get(e, "p2"));
                if (slug == NULL || p1_id == NULL) continue;
                json_t *p1s_j = json_object_get(e, "p1_score");
                json_t *p2s_j = json_object_get(e, "p2_score");
                double p1_score = json_is_real(p1s_j) ? json_real_value(p1s_j)
                    : json_is_integer(p1s_j) ? (double)json_integer_value(p1s_j) : 0.0;
                double p2_score = json_is_real(p2s_j) ? json_real_value(p2s_j)
                    : json_is_integer(p2s_j) ? (double)json_integer_value(p2s_j) : 0.0;

                uuid_t task_uuid;
                _uuid5("tx:", slug, task_uuid);
                const uuid_t *p1_uuid = _uuid_of(ctx, p1_id);
                const uuid_t *p2_uuid = _uuid_of(ctx, p2_id);
                if (p1_uuid && p2_uuid)
                    reputation_install_tx_pair(task_uuid,
                                               *p1_uuid, p1_score,
                                               *p2_uuid, p2_score);
                else if (p1_uuid && p2_id == NULL)
                    /* One side only, counterparty slot left open: lets a
                     * single step drive the arrival that COMPLETES the entry,
                     * which is the only way to assert on the committed window
                     * in a harness that resets state between steps. */
                    reputation_install_tx_single(task_uuid, *p1_uuid, p1_score);
                /* A staged pair is untagged on both sides. A scenario that
                 * needs a channel on a committed entry drives the
                 * `tx committed` path, which carries one -- the seeding hook
                 * deliberately has no channel argument (R+D.md §12.8). */
            }
        }
    }

    /* reputations: { "<pid>": { "<other_pid>": float, ... } } — pre-stage
     * rep_state.reputations so _compute_reputation's coop-mode latch sees
     * the right `previous` value and reputation_pure's counterparty
     * lookup succeeds. */
    json_t *rps = json_object_get(g_fixtures, "reputations");
    if (json_is_object(rps))
    {
        json_t *table = json_object_get(rps, target_id);
        if (json_is_object(table))
        {
            const char *other_id;
            json_t *score_j;
            json_object_foreach(table, other_id, score_j)
            {
                double v = json_is_real(score_j) ? json_real_value(score_j)
                    : json_is_integer(score_j) ? (double)json_integer_value(score_j) : 0.0;
                const uuid_t *u = _uuid_of(ctx, other_id);
                if (u)
                    reputation_install_peer_reputation(*u, v);
            }
        }
    }

    /* task_weights: { "<pid>": { "<task_slug>": int, ... } } — pre-stage
     * rep_state.task_weights so reputation_pure weights each tx by the
     * cached transaction_weight. */
    json_t *tws = json_object_get(g_fixtures, "task_weights");
    if (json_is_object(tws))
    {
        json_t *table = json_object_get(tws, target_id);
        if (json_is_object(table))
        {
            const char *slug;
            json_t *w_j;
            json_object_foreach(table, slug, w_j)
            {
                int w = json_is_integer(w_j) ? (int)json_integer_value(w_j) : 1;
                uuid_t task_uuid;
                _uuid5("tx:", slug, task_uuid);
                reputation_install_task_weight(task_uuid, w);
            }
        }
    }

    /* coop_mode: { "<pid>": { "<other_pid>": bool, ... } } — pre-stage
     * rep_state.coop_mode (keyed by peer uuid). Mirrors Python's
     * self._coop_mode latch. Combined with `reputations[other] = X`,
     * controls whether _compute_reputation picks the pure or CTFT
     * branch via hysteresis. */
    json_t *cm = json_object_get(g_fixtures, "coop_mode");
    if (json_is_object(cm))
    {
        json_t *table = json_object_get(cm, target_id);
        if (json_is_object(table))
        {
            const char *other_id;
            json_t *flag;
            json_object_foreach(table, other_id, flag)
            {
                bool b = json_is_true(flag);
                const uuid_t *u = _uuid_of(ctx, other_id);
                if (u)
                    reputation_install_coop_mode(*u, b);
            }
        }
    }

#ifdef AT_ZTA_ENABLED
    /* zta_standing: { "<pid>": { "<other_pid>": {status, ceiling}, ... } } —
     * pre-stage what ZTA proved about a peer (doc/architecture/zta-integration.md).
     * Installed directly
     * rather than driven through an admission step: the verdict is produced by
     * the IDENTITY process and this protocol's harness stands up only the
     * reputation one, so what is pinned cross-language is what reputation DOES
     * with a standing. Mirrors the Python adapter's preset_zta_standing. */
    json_t *zs = json_object_get(g_fixtures, "zta_standing");
    if (json_is_object(zs))
    {
        json_t *table = json_object_get(zs, target_id);
        if (json_is_object(table))
        {
            const char *other_id;
            json_t *spec;
            json_object_foreach(table, other_id, spec)
            {
                const uuid_t *u = _uuid_of(ctx, other_id);
                if (u == NULL || !json_is_object(spec))
                    continue;
                const char *status = json_string_value(
                    json_object_get(spec, "status"));
                json_t *ceil_j = json_object_get(spec, "ceiling");
                zta_standing_msg_t st;
                memset(&st, 0, sizeof(st));
                memcpy(st.peer_uuid, *u, sizeof(uuid_t));
                st.standing = (int32_t)ZTA_STANDING_CAPPED;
                if (status != NULL && strcmp(status, "proved") == 0)
                    st.standing = (int32_t)ZTA_STANDING_PROVED;
                else if (status != NULL && strcmp(status, "failed") == 0)
                    st.standing = (int32_t)ZTA_STANDING_FAILED;
                st.ceiling = json_is_number(ceil_j)
                                 ? json_number_value(ceil_j)
                                 : ZTA_NO_CEILING;
                const char *reason = json_string_value(
                    json_object_get(spec, "reason"));
                at_strlcpy(st.reason, reason ? reason : "", sizeof(st.reason));
                /* The standing is applied against the TARGET's process --
                 * the node whose state this call is installing. */
                sce_participant_t *self_p = sce_find_participant(ctx, target_id);
                if (self_p != NULL && self_p->impl != NULL)
                    reputation_apply_zta_standing(
                        ((rp_impl_t *)self_p->impl)->proc, &st);
            }
        }
    }
#endif

    /* checkpoint: { "<pid>": {root: <hex>, epoch: N} } — pre-seed a finalized
     * Phase 2 checkpoint so an evidence-bearing slash can verify against it in
     * a single step (Phase 3). */
    json_t *ck = json_object_get(g_fixtures, "checkpoint");
    if (json_is_object(ck))
    {
        json_t *spec = json_object_get(ck, target_id);
        if (json_is_object(spec))
        {
            const char *root = json_string_value(json_object_get(spec, "root"));
            int64_t epoch = json_integer_value(json_object_get(spec, "epoch"));
            if (root != NULL)
                reputation_install_checkpoint(root, epoch);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Inbound construction                                                       */
/* ------------------------------------------------------------------------- */

/* --- Quorum co-signatures, signed at scenario time -----------------------
 * The slash / checkpoint finalizers carry real Ed25519 co-signatures over the
 * round's designation, and every receiver verifies them before acting. The
 * adapters therefore MINT the signatures here with each named co-signer's own
 * key rather than replaying pinned blobs, which is what holds both runtimes to
 * the same pre-image and scheme instead of to one side's recorded output (the
 * doc/architecture/zta-integration.md precedent). Designation bytes must match Python
 * SlashAttestation.designation / Checkpoint.designation exactly. */
#define RP_DESIG_MAX 512
#define RP_SIG_HEX_LEN (crypto_sign_BYTES * 2)

static size_t _rp_slash_designation(const char *slasher, const char *target,
                                    const char *reason, double floor,
                                    int64_t epoch, uint8_t *out, size_t cap)
{
    static const char tag[] = "AT-SLASH";
    size_t tag_len = sizeof(tag);   /* includes the NUL separator */
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%s|%.6f|%lld", slasher, target, reason, floor,
                     (long long)epoch);
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

static size_t _rp_checkpoint_designation(const char *proposer, const char *root,
                                         int64_t epoch, int64_t first_index,
                                         int64_t count, uint8_t *out,
                                         size_t cap)
{
    static const char tag[] = "AT-CKPT";
    size_t tag_len = sizeof(tag);
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%lld|%lld|%lld", proposer, root, (long long)epoch,
                     (long long)first_index, (long long)count);
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

/* Sign `desig` with a participant's own key; hex out. */
static int _rp_sign_hex(const rp_impl_t *impl, const uint8_t *desig,
                        size_t dlen, char *hex_out)
{
    if (impl == NULL || impl->full == NULL || dlen == 0)
        return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, desig, dlen,
                             impl->full->signature.private) != 0)
        return -1;
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex_out);
    return 0;
}

/* Build the `sigs` map a *_final step carries: {voter_uuid: sig_hex}.
 *
 * `cosigners` names the co-signers (participant ids); the default is every
 * participant except `exclude` (the slash target — a peer does not co-sign its
 * own slash), the ordinary quorum-agreed case. Negative controls override it: a
 * shorter list is sub-quorum, and `forged_by` makes ONE participant sign every
 * entry while the entries stay labelled with the others' uuids. Mirrors the
 * Python adapter's _cosignatures. */
static json_t *_rp_cosignatures(sce_run_ctx_t *ctx, json_t *payload,
                                const uint8_t *desig, size_t dlen,
                                const char *exclude)
{
    json_t *sigs = json_object();
    if (sigs == NULL || dlen == 0)
        return sigs;
    json_t *named = (payload && json_is_object(payload))
        ? json_object_get(payload, "cosigners") : NULL;
    const char *forger = NULL;
    if (payload && json_is_object(payload))
    {
        json_t *f = json_object_get(payload, "forged_by");
        if (json_is_string(f)) forger = json_string_value(f);
    }
    const rp_impl_t *signer = NULL;
    if (forger != NULL)
    {
        sce_participant_t *p = sce_find_participant(ctx, forger);
        if (p != NULL) signer = (const rp_impl_t *)p->impl;
    }
    size_t n_ids = (named && json_is_array(named)) ? json_array_size(named)
                                                   : ctx->participant_count;
    for (size_t i = 0; i < n_ids; i++)
    {
        sce_participant_t *p = NULL;
        if (named && json_is_array(named))
        {
            const char *pid = json_string_value(json_array_get(named, i));
            if (pid == NULL) continue;
            p = sce_find_participant(ctx, pid);
        }
        else
        {
            p = &ctx->participants[i];
            if (exclude != NULL && strcmp(p->id, exclude) == 0)
                continue;
        }
        if (p == NULL) continue;
        const rp_impl_t *impl = (const rp_impl_t *)p->impl;
        if (impl == NULL || impl->pub == NULL) continue;
        char voter[UUID_STRING_LEN + 1];
        uuid_unparse_lower(impl->pub->uuid, voter);
        char sig_hex[RP_SIG_HEX_LEN + 1] = {0};
        if (_rp_sign_hex(signer ? signer : impl, desig, dlen, sig_hex) != 0)
            continue;
        json_object_set_new(sigs, voter, json_string(sig_hex));
    }
    return sigs;
}

static int _build_inbound(sce_run_ctx_t *ctx,
                          const char *from_id,
                          const char *to_id,
                          const char *function,
                          json_t *payload,
                          generic_msg_t *out)
{
    sce_participant_t *sender = sce_find_participant(ctx, from_id);
    if (sender == NULL)
    {
        snprintf(ctx->err, sizeof(ctx->err), "build_inbound: unknown from %s", from_id);
        return -1;
    }
    rp_impl_t *sender_impl = (rp_impl_t *)sender->impl;
    sce_participant_t *recipient = (to_id && strcmp(to_id, "broadcast") != 0)
        ? sce_find_participant(ctx, to_id) : NULL;
    rp_impl_t *recipient_impl = recipient ? (rp_impl_t *)recipient->impl : NULL;

    /* Resolve the proposer field. Default to the sender; scenarios may
     * override via payload.proposer = "<pid>". */
    const char *proposer_id = from_id;
    if (payload && json_is_object(payload))
    {
        json_t *p_j = json_object_get(payload, "proposer");
        if (json_is_string(p_j)) proposer_id = json_string_value(p_j);
    }
    const uuid_t *proposer_uuid = _uuid_of(ctx, proposer_id);
    char proposer_str[UUID_STRING_LEN + 1] = {0};
    if (proposer_uuid) uuid_unparse_lower(*proposer_uuid, proposer_str);

    int64_t id1 = 0, id2 = 0;
    if (payload && json_is_object(payload))
    {
        json_t *j = json_object_get(payload, "id1");
        if (json_is_integer(j)) id1 = json_integer_value(j);
        j = json_object_get(payload, "id2");
        if (json_is_integer(j)) id2 = json_integer_value(j);
    }

    json_t *body = NULL;
    if (strcmp(function, REP_PROTO_REQUEST) == 0
        || strcmp(function, REP_PROTO_NACK) == 0
        || strcmp(function, REP_PROTO_BACKDATE) == 0
        || strcmp(function, REP_PROTO_ACCEPTED) == 0)
    {
        body = json_object();
        json_object_set_new(body, "id1", json_integer(id1));
        json_object_set_new(body, "id2", json_integer(id2));
        json_object_set_new(body, "peer_uuid", json_string(proposer_str));
    }
    else if (strcmp(function, REP_PROTO_GRANT) == 0)
    {
        body = json_object();
        json_object_set_new(body, "id1", json_integer(id1));
        json_object_set_new(body, "id2", json_integer(id2));
        json_object_set_new(body, "peer_uuid", json_string(proposer_str));
        json_object_set_new(body, "last_id", json_integer(0));
        json_object_set_new(body, "chain_len", json_integer(0));
    }
    else if (strcmp(function, REP_PROTO_TX) == 0)
    {
        double score = 1.0;
        const char *task_slug = NULL;
        /* Evidence channel (R+D.md §12.8), passed through VERBATIM and
         * deliberately unvalidated here: a scenario needs to be able to send a
         * bogus channel and assert that handle_transaction refuses it. The
         * adapter's job is to put on the wire exactly what the scenario said.
         * Kept at parity with the Python adapter so one scenario can drive
         * both. */
        const char *channel = NULL;
        if (payload && json_is_object(payload))
        {
            json_t *s_j = json_object_get(payload, "score");
            if (json_is_real(s_j))    score = json_real_value(s_j);
            else if (json_is_integer(s_j)) score = (double)json_integer_value(s_j);
            json_t *t_j = json_object_get(payload, "task_id");
            if (json_is_string(t_j)) task_slug = json_string_value(t_j);
            json_t *c_j = json_object_get(payload, "channel");
            if (json_is_string(c_j)) channel = json_string_value(c_j);
        }
        body = json_object();
        json_object_set_new(body, "id1", json_integer(id1));
        json_object_set_new(body, "id2", json_integer(id2));
        json_object_set_new(body, "peer_uuid", json_string(proposer_str));
        json_object_set_new(body, "score", json_real(score));
        /* Omitted when the scenario says nothing, which is how a receiver reads
         * "task outcome" -- so every pre-channel scenario keeps its meaning. */
        if (channel)
            json_object_set_new(body, "channel", json_string(channel));
        if (task_slug)
        {
            uuid_t task_uuid;
            _uuid5("tx:", task_slug, task_uuid);
            char task_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(task_uuid, task_str);
            json_object_set_new(body, "task_uuid", json_string(task_str));
        }
    }
    else if (strcmp(function, REP_PROTO_COMMITTED) == 0)
    {
        /* Phase 3 — (task_uuid, peer_uuid, score).  Mirrors the
         * commit-broadcast payload built by handle_accepted. */
        double score = 1.0;
        const char *task_slug = NULL;
        const char *channel = NULL;
        if (payload && json_is_object(payload))
        {
            json_t *s_j = json_object_get(payload, "score");
            if (json_is_real(s_j))    score = json_real_value(s_j);
            else if (json_is_integer(s_j)) score = (double)json_integer_value(s_j);
            json_t *t_j = json_object_get(payload, "task_id");
            if (json_is_string(t_j)) task_slug = json_string_value(t_j);
            json_t *c_j = json_object_get(payload, "channel");
            if (json_is_string(c_j)) channel = json_string_value(c_j);
        }
        body = json_object();
        json_object_set_new(body, "peer_uuid", json_string(proposer_str));
        json_object_set_new(body, "score", json_real(score));
        /* The evidence channel is part of the committed fact (R+D.md §12.8),
         * so a scenario can drive one; omitted when the scenario names none,
         * which keeps every pre-channel vector byte-identical. */
        if (channel != NULL)
            json_object_set_new(body, "channel", json_string(channel));
        if (task_slug)
        {
            uuid_t task_uuid;
            _uuid5("tx:", task_slug, task_uuid);
            char task_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(task_uuid, task_str);
            json_object_set_new(body, "task_uuid", json_string(task_str));
        }
    }
    else if (strcmp(function, REP_PROTO_OUTDATED) == 0)
    {
        body = json_object();  /* empty payload */
    }
    else if (strcmp(function, REP_PROTO_UPDATE) == 0)
    {
        /* Phase 1: optionally carry a real hash-linked chain so a catch-up
         * scenario exercises verify-on-replay. payload.chain is a list of
         * {task, p1, p2} committed entries; build them through a temp
         * tx_history so prev_hash links are computed by the production code,
         * then serialize via era_to_json. With tamper:true a committed score
         * is mutated AFTER linking, so the successor's recorded prev_hash no
         * longer matches and the receiver's era_from_json rejects the whole
         * segment. Mirrors the Python adapter; the task/peer UUIDs match it
         * byte-for-byte (_uuid5 == uuid5(_NS, ...)). Default (no chain) is the
         * empty-array no-crash case, matching Python's to_json_string([]). */
        json_t *spec = NULL;
        if (payload && json_is_object(payload))
            spec = json_object_get(payload, "chain");
        if (spec == NULL || !json_is_array(spec) || json_array_size(spec) == 0)
        {
            body = json_array();  /* empty chain */
        }
        else
        {
            tx_history_t tmp;
            tx_history_init(&tmp);
            size_t ci;
            json_t *ce;
            json_array_foreach(spec, ci, ce)
            {
                const char *task = json_string_value(json_object_get(ce, "task"));
                if (task == NULL)
                    continue;
                double p1s = json_number_value(json_object_get(ce, "p1"));
                double p2s = json_number_value(json_object_get(ce, "p2"));
                uuid_t tk, p1u, p2u;
                _uuid5("chain:", task, tk);
                _uuid5("chainp1:", task, p1u);
                _uuid5("chainp2:", task, p2u);
                tx_history_update(&tmp, tk, p1u, p1s, NULL);
                tx_history_update(&tmp, tk, p2u, p2s, NULL);
            }
            json_t *arr = NULL;
            tx_history_era_to_json(&tmp, 0, tx_history_len(&tmp), &arr);
            json_t *tamper = payload ? json_object_get(payload, "tamper") : NULL;
            if (arr != NULL && tamper != NULL && json_is_true(tamper)
                && json_array_size(arr) >= 2)
            {
                json_t *e1 = json_array_get(arr, 1);
                json_object_set_new(e1, "p2_score", json_real(-1.0));
            }
            body = (arr != NULL) ? arr : json_array();
            tx_history_free(&tmp);
        }
    }
    else if (strcmp(function, REP_PROTO_REP_REQ) == 0
             || strcmp(function, REP_PROTO_CONSENSUS_REP_REQ) == 0)
    {
        /* C's `handle_rep_request` expects a `{peer_uuid,
         * requesting_process}` object; Python's `handle_reputation_request`
         * expects a `(ident, req_proc)` JSON list. See BUGS.md §P9 for
         * the wire-format divergence. Each adapter builds its language's
         * native form here so both handlers exercise without crashing.
         * consensus_rep_req shares the same payload shape; the op name
         * dispatches to the consensus computation on either side. */
        const char *target_pid = from_id;
        const char *req_proc = "negotiation";
        if (payload && json_is_object(payload))
        {
            json_t *t = json_object_get(payload, "target");
            if (json_is_string(t)) target_pid = json_string_value(t);
            json_t *p = json_object_get(payload, "proc");
            if (json_is_string(p)) req_proc = json_string_value(p);
        }
        char target_uuid[UUID_STRING_LEN + 1] = {0};
        sce_participant_t *target = sce_find_participant(ctx, target_pid);
        if (target != NULL)
        {
            rp_impl_t *t_impl = (rp_impl_t *)target->impl;
            if (t_impl && t_impl->pub)
                uuid_unparse_lower(t_impl->pub->uuid, target_uuid);
        }
        body = json_object();
        json_object_set_new(body, "peer_uuid", json_string(target_uuid));
        json_object_set_new(body, "requesting_process", json_string(req_proc));
    }
    else if (strcmp(function, REP_PROTO_APP_ROSTER) == 0)
    {
        /* The app pulling the current peer view. The verb carries no payload
         * at all: it names no subject, because the answer is the whole roster
         * (doc/architecture/app-peer-carrier.md). */
        body = json_object();
    }
    else if (strcmp(function, REP_PROTO_CONSENSUS_REP_BATCH_REQ) == 0)
    {
        /* Batched consensus request: one message naming MANY subjects, answered
         * with one roster. Same fields as the single-subject form but plural
         * (`peer_uuids`); both adapters build these identical bytes, so wire
         * interop is pinned here as it is for the single form. `targets` is a
         * list of participant ids; an id that is not a participant passes
         * through verbatim so a scenario can name an unknown uuid on purpose. */
        const char *req_proc = "negotiation";
        json_t *targets = NULL;
        if (payload && json_is_object(payload))
        {
            json_t *p = json_object_get(payload, "proc");
            if (json_is_string(p)) req_proc = json_string_value(p);
            json_t *t = json_object_get(payload, "targets");
            if (json_is_array(t)) targets = t;
        }
        json_t *uuids = json_array();
        size_t n = (targets != NULL) ? json_array_size(targets) : 0;
        for (size_t i = 0; i < n; i++)
        {
            const char *target_pid = json_string_value(json_array_get(targets, i));
            if (target_pid == NULL)
                continue;
            char target_uuid[UUID_STRING_LEN + 1] = {0};
            sce_participant_t *target = sce_find_participant(ctx, target_pid);
            if (target != NULL)
            {
                rp_impl_t *t_impl = (rp_impl_t *)target->impl;
                if (t_impl && t_impl->pub)
                    uuid_unparse_lower(t_impl->pub->uuid, target_uuid);
            }
            json_array_append_new(uuids,
                                  json_string(target_uuid[0] != '\0'
                                              ? target_uuid : target_pid));
        }
        body = json_object();
        json_object_set_new(body, "peer_uuids", uuids);
        json_object_set_new(body, "requesting_process", json_string(req_proc));
    }
    else if (strcmp(function, REP_PROTO_SLASH_PROPOSE) == 0
             || strcmp(function, REP_PROTO_SLASH_SIGN) == 0
             || strcmp(function, REP_PROTO_SLASH_FINAL) == 0)
    {
        /* Slashing — plain JSON objects (per-implementation shape;
         * byte_pinning:false checks state equivalence). target resolves a
         * participant pid -> uuid; floor_score/epoch come from the step
         * payload. C's handlers read target_uuid/floor_score/epoch. */
        const char *target_pid = from_id;
        double floor = 0.0;
        int64_t epoch = 1;
        if (payload && json_is_object(payload))
        {
            json_t *t = json_object_get(payload, "target");
            if (json_is_string(t)) target_pid = json_string_value(t);
            json_t *f = json_object_get(payload, "floor_score");
            if (json_is_real(f)) floor = json_real_value(f);
            else if (json_is_integer(f)) floor = (double)json_integer_value(f);
            json_t *e = json_object_get(payload, "epoch");
            if (json_is_integer(e)) epoch = json_integer_value(e);
        }
        char target_uuid[UUID_STRING_LEN + 1] = {0};
        sce_participant_t *target = sce_find_participant(ctx, target_pid);
        if (target != NULL)
        {
            rp_impl_t *t_impl = (rp_impl_t *)target->impl;
            if (t_impl && t_impl->pub)
                uuid_unparse_lower(t_impl->pub->uuid, target_uuid);
        }
        /* The designation covers the reason as well as the floor, so every
         * step in a slash round has to name it, and both adapters have to
         * default it identically (Python's adapter uses REASON_PEER_EXCLUDE). */
        const char *reason = REP_SLASH_REASON_PEER_EXCLUDE;
        if (payload && json_is_object(payload))
        {
            json_t *r = json_object_get(payload, "reason");
            if (json_is_string(r)) reason = json_string_value(r);
        }
        uint8_t desig[RP_DESIG_MAX];
        size_t dlen = _rp_slash_designation(proposer_str, target_uuid, reason,
                                            floor, epoch, desig, sizeof(desig));
        body = json_object();
        json_object_set_new(body, "target_uuid", json_string(target_uuid));
        json_object_set_new(body, "floor_score", json_real(floor));
        json_object_set_new(body, "epoch", json_integer(epoch));
        json_object_set_new(body, "reason", json_string(reason));
        json_object_set_new(body, "slasher_uuid", json_string(proposer_str));
        if (strcmp(function, REP_PROTO_SLASH_SIGN) == 0)
        {
            /* An ack names its SENDER and carries that sender's own signature:
             * the receiver credits the authenticated sender, not the claim. */
            char signer[UUID_STRING_LEN + 1] = {0};
            if (sender_impl && sender_impl->pub)
                uuid_unparse_lower(sender_impl->pub->uuid, signer);
            char sig_hex[RP_SIG_HEX_LEN + 1] = {0};
            _rp_sign_hex(sender_impl, desig, dlen, sig_hex);
            json_object_set_new(body, "signer_uuid", json_string(signer));
            json_object_set_new(body, "signature", json_string(sig_hex));
        }
        else if (strcmp(function, REP_PROTO_SLASH_FINAL) == 0)
        {
            json_t *sigs = _rp_cosignatures(ctx, payload, desig, dlen,
                                            target_pid);
            json_object_set_new(body, "sigs", sigs);
        }
        /* Phase 3: pass through optional Merkle evidence verbatim
         * ({task_id, leaf, proof, root}); the handler verifies it against the
         * finalized checkpoint root. */
        if (payload && json_is_object(payload))
        {
            json_t *ev = json_object_get(payload, "evidence");
            if (json_is_object(ev))
                json_object_set(body, "evidence", ev);
        }
    }
    else if (strcmp(function, REP_PROTO_REP_RESOLVED) == 0)
    {
        /* Deep resolution (doc/architecture/gateway-reputation-tree.md): the answer
         * carries the holder's WHOLE quorum-signed window, so the receiver can
         * recompute the root and see both fabrication and OMISSION.
         *
         * The window is rebuilt here from the holder's `tx_history` fixture rather than
         * read out of rep_state: the engine resets rep_state per step and stages
         * fixtures for the DISPATCH TARGET, so the sender's chain does not exist while
         * we are building a message to it. Same entries, same order, same uuids as the
         * Python adapter reads from the holder's live history -- both sides therefore
         * checkpoint the same root. */
        const char *peer_pid = payload ? json_string_value(
            json_object_get(payload, "peer")) : NULL;
        const char *qid = payload ? json_string_value(
            json_object_get(payload, "query_id")) : NULL;
        if (peer_pid == NULL || qid == NULL)
        {
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: rep_resolved needs peer and query_id");
            return -1;
        }
        tx_history_t tmp;
        tx_history_init(&tmp);
        json_t *txh = json_object_get(g_fixtures, "tx_history");
        json_t *entries = json_is_object(txh)
            ? json_object_get(txh, from_id) : NULL;
        size_t ei;
        json_t *e;
        if (json_is_array(entries))
        {
            json_array_foreach(entries, ei, e)
            {
                const char *slug = json_string_value(json_object_get(e, "task_id"));
                const char *p1_id = json_string_value(json_object_get(e, "p1"));
                const char *p2_id = json_string_value(json_object_get(e, "p2"));
                if (slug == NULL || p1_id == NULL || p2_id == NULL)
                    continue;
                uuid_t task_uuid;
                _uuid5("tx:", slug, task_uuid);
                const uuid_t *p1u = _uuid_of(ctx, p1_id);
                const uuid_t *p2u = _uuid_of(ctx, p2_id);
                if (p1u == NULL || p2u == NULL)
                    continue;
                tx_history_update(&tmp, task_uuid, *p1u,
                                  json_number_value(json_object_get(e, "p1_score")),
                                  json_string_value(json_object_get(e, "p1_channel")));
                tx_history_update(&tmp, task_uuid, *p2u,
                                  json_number_value(json_object_get(e, "p2_score")),
                                  json_string_value(json_object_get(e, "p2_channel")));
            }
        }
        rep_checkpoint_t ckpt;
        rep_checkpoint_init(&ckpt);
        ckpt.present = true;
        transaction_window_root(&tmp, ckpt.root);
        snprintf(ckpt.proposer_uuid, sizeof(ckpt.proposer_uuid), "%s",
                 proposer_str);
        json_t *ep = payload ? json_object_get(payload, "epoch") : NULL;
        ckpt.epoch = json_is_integer(ep) ? json_integer_value(ep) : 1;
        ckpt.first_index = 0;
        ckpt.count = tx_history_len(&tmp);
        uint8_t desig[RP_DESIG_MAX];
        size_t dlen = _rp_checkpoint_designation(ckpt.proposer_uuid, ckpt.root,
                                                ckpt.epoch, ckpt.first_index,
                                                ckpt.count, desig,
                                                sizeof(desig));
        json_t *sigs = _rp_cosignatures(ctx, payload, desig, dlen, NULL);
        const char *voter = NULL;
        json_t *sv = NULL;
        json_object_foreach(sigs, voter, sv)
        {
            const char *sig_hex = json_string_value(sv);
            if (sig_hex != NULL)
                map_set(&ckpt.sigs, (map_key_t)voter,
                        string_data((string_t)sig_hex, strlen(sig_hex) + 1));
        }

        json_t *doc = NULL;
        if (reputation_evidence_to_json(&tmp, &ckpt, &doc) != 0 || doc == NULL)
        {
            json_decref(sigs);
            rep_checkpoint_free(&ckpt);
            tx_history_free(&tmp);
            snprintf(ctx->err, sizeof(ctx->err),
                     "build_inbound: could not build resolved evidence");
            return -1;
        }
        /* The negative control: signed over the FULL window, one entry then
         * dropped from what travels. Everything left is genuine, which is
         * exactly why an inclusion proof would not catch it. */
        json_t *omit = payload ? json_object_get(payload, "omit_last") : NULL;
        json_t *chain_arr = json_object_get(doc, "chain");
        if (omit != NULL && json_is_true(omit) && json_is_array(chain_arr)
            && json_array_size(chain_arr) > 0)
            json_array_remove(chain_arr, json_array_size(chain_arr) - 1);

        char peer_uuid_str[UUID_STRING_LEN + 1] = {0};
        const uuid_t *peer_uu = _uuid_of(ctx, peer_pid);
        if (peer_uu != NULL)
            uuid_unparse_lower(*peer_uu, peer_uuid_str);
        json_object_set_new(doc, "query_id", json_string(qid));
        json_object_set_new(doc, "peer_uuid", json_string(peer_uuid_str));
        json_t *claimed = payload ? json_object_get(payload, "score") : NULL;
        json_object_set_new(doc, "score",
                            json_is_number(claimed)
                                ? json_real(json_number_value(claimed))
                                : json_null());
        /* Signer identities in the canonical public form, so a receiver that
         * holds nobody from the answering group can still check a signature. */
        json_t *signers = json_array();
        json_object_foreach(sigs, voter, sv)
        {
            for (size_t pi = 0; pi < ctx->participant_count; pi++)
            {
                const rp_impl_t *pim = (const rp_impl_t *)ctx->participants[pi].impl;
                if (pim == NULL || pim->pub == NULL)
                    continue;
                char pu[UUID_STRING_LEN + 1];
                uuid_unparse_lower(pim->pub->uuid, pu);
                if (strcmp(pu, voter) != 0)
                    continue;
                json_t *ident = NULL;
                if (public_identity_to_json(pim->pub, &ident) == 0 && ident != NULL)
                    json_array_append_new(signers, ident);
                break;
            }
        }
        json_object_set_new(doc, "signers", signers);
        json_decref(sigs);
        rep_checkpoint_free(&ckpt);
        tx_history_free(&tmp);

        /* The receiver only accepts an answer to a query it is waiting for.
         * Registering it is harness setup standing in for the resolve this
         * scenario does not send, so the step tests VERIFICATION rather than
         * relay bookkeeping (which has its own coverage). */
        {
            sce_participant_t *rcv = sce_find_participant(ctx, to_id);
            const rp_impl_t *rim = (rcv != NULL)
                ? (const rp_impl_t *)rcv->impl : NULL;
            if (rim != NULL)
                reputation_deep_resolve(rim->proc, qid, peer_uuid_str, 4);
        }
        body = doc;
    }
    else if (strcmp(function, REP_PROTO_CHECKPOINT_PROPOSE) == 0
             || strcmp(function, REP_PROTO_CHECKPOINT_SIGN) == 0
             || strcmp(function, REP_PROTO_CHECKPOINT_FINAL) == 0)
    {
        /* Phase 2 checkpoints — plain JSON objects (byte_pinning:false). The
         * sender is the proposer; propose/final carry the agreed window
         * `root` (hex string), sign is keyed by proposer + epoch. C's
         * handlers read proposer_uuid/root/epoch. */
        const char *root = "";
        int64_t epoch = 1;
        int64_t first_index = 0;
        int64_t count_covered = 0;
        if (payload && json_is_object(payload))
        {
            json_t *r = json_object_get(payload, "root");
            if (json_is_string(r)) root = json_string_value(r);
            json_t *e = json_object_get(payload, "epoch");
            if (json_is_integer(e)) epoch = json_integer_value(e);
            json_t *fi = json_object_get(payload, "first_index");
            if (json_is_integer(fi)) first_index = json_integer_value(fi);
            json_t *c = json_object_get(payload, "count");
            if (json_is_integer(c)) count_covered = json_integer_value(c);
        }
        uint8_t desig[RP_DESIG_MAX];
        size_t dlen = _rp_checkpoint_designation(proposer_str, root, epoch,
                                                first_index, count_covered,
                                                desig, sizeof(desig));
        body = json_object();
        json_object_set_new(body, "proposer_uuid", json_string(proposer_str));
        json_object_set_new(body, "epoch", json_integer(epoch));
        /* The window bounds ride every step: the designation covers them, so a
         * sign / final step that omitted them would sign or verify different
         * bytes than the propose. */
        json_object_set_new(body, "first_index", json_integer(first_index));
        json_object_set_new(body, "count", json_integer(count_covered));
        json_object_set_new(body, "root", json_string(root));
        if (strcmp(function, REP_PROTO_CHECKPOINT_SIGN) == 0)
        {
            char signer[UUID_STRING_LEN + 1] = {0};
            if (sender_impl && sender_impl->pub)
                uuid_unparse_lower(sender_impl->pub->uuid, signer);
            char sig_hex[RP_SIG_HEX_LEN + 1] = {0};
            _rp_sign_hex(sender_impl, desig, dlen, sig_hex);
            json_object_set_new(body, "signer_uuid", json_string(signer));
            json_object_set_new(body, "signature", json_string(sig_hex));
        }
        else if (strcmp(function, REP_PROTO_CHECKPOINT_FINAL) == 0)
        {
            json_t *sigs = _rp_cosignatures(ctx, payload, desig, dlen, NULL);
            json_object_set_new(body, "sigs", sigs);
        }
    }
    else
    {
        snprintf(ctx->err, sizeof(ctx->err),
                 "build_inbound: unsupported function %s", function);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    strncpy(out->info.net_msg.process, "reputation", PROC_NAME_LEN);
    out->info.net_msg.function = (char *)function;
    out->info.net_msg.encrypt = false;
    memcpy(&out->info.net_msg.from_whom, sender_impl->pub, sizeof(public_identity_t));
    if (recipient_impl)
        memcpy(&out->info.net_msg.to_whom, recipient_impl->pub, sizeof(public_identity_t));

    /* handle_transaction / handle_accepted / the slash handlers gate on
     * verified; the harness signs locally, so set verified=true to mirror
     * the production "I just received a verified network message" state.
     * Set universally to match the Python adapter (verified=True for every
     * function). */
    out->info.net_msg.verified = true;

    if (body)
    {
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }
    return 0;
}

/* Per-dispatch state setup wraps the engine's _build_and_deliver path.
 * sce drives every dispatch through ctx->dispatch, so this is where we
 * reset+install state for the target participant before its handler
 * runs. */
static int _dispatch(sce_run_ctx_t *ctx,
                     sce_participant_t *target,
                     generic_msg_t *inbound)
{
    _install_target_state(ctx, target->id);

    rp_impl_t *impl = (rp_impl_t *)target->impl;
    array_t *queues = NULL;
    array_create(&queues);
    g_current_emitter = target->id;
    run_message_handlers(impl->proc, queues, NET_MESSAGE, inbound);
    g_current_emitter = NULL;
    array_free(queues);

    /* Snapshot the dispatcher's resulting state. Subsequent dispatches
     * reset rep_state, so we can't re-read it for expected_state checks
     * later; the snapshot is the only durable record. */
    rp_snap_t *s = _snap_get_or_make(target->id);
    if (s)
    {
        s->chain_len     = reputation_get_chain_len();
        s->committed_tx_count = reputation_get_committed_tx_count();
        reputation_get_window_root(s->window_root);
        reputation_get_checkpoint_root(s->checkpoint_root);
        s->request_count = reputation_get_request_count();
        s->last_id       = reputation_get_last_id();
        /* Record this dispatcher's view of every other participant's
         * reputation, so `expected_state[pid].reputation_of[other]`
         * can be checked after the next step resets rep_state. */
        for (size_t i = 0; i < ctx->participant_count && i < SCE_MAX_PARTICIPANTS; i++)
        {
            const char *other_id = ctx->participants[i].id;
            snprintf(s->peer_reps[i].id, SCE_ID_LEN, "%s", other_id);
            s->peer_reps[i].has_value = false;
            const uuid_t *u = _uuid_of(ctx, other_id);
            if (u == NULL) continue;
            double v = 0.0;
            if (reputation_get_peer_reputation(*u, &v) == 0)
            {
                s->peer_reps[i].has_value = true;
                s->peer_reps[i].value = v;
            }
            snprintf(s->evidence_ceilings[i].id, SCE_ID_LEN, "%s", other_id);
            s->evidence_ceilings[i].has_value = false;
            double c = 0.0;
            const uuid_t *self_u = _uuid_of(ctx, target->id);
            if (self_u != NULL
                && reputation_get_evidence_ceiling(*self_u, *u, &c) == 0)
            {
                s->evidence_ceilings[i].has_value = true;
                s->evidence_ceilings[i].value = c;
            }
        }
        /* The document this node would persist right now. */
        s->evidence_schema[0] = '\0';
        s->evidence_chain_len = 0;
        s->evidence_checkpoint_root[0] = '\0';
        json_t *doc = NULL;
        if (reputation_get_evidence_doc(&doc) == 0 && doc != NULL)
        {
            const char *schema = json_string_value(json_object_get(doc, "schema"));
            if (schema != NULL)
                snprintf(s->evidence_schema, sizeof(s->evidence_schema), "%s",
                         schema);
            s->evidence_chain_len =
                (int)json_array_size(json_object_get(doc, "chain"));
            json_t *ck = json_object_get(doc, "checkpoint");
            const char *ck_root = json_is_object(ck)
                ? json_string_value(json_object_get(ck, "root")) : NULL;
            if (ck_root != NULL)
            {
                strncpy(s->evidence_checkpoint_root, ck_root, TX_HASH_HEX_LEN);
                s->evidence_checkpoint_root[TX_HASH_HEX_LEN] = '\0';
            }
            json_decref(doc);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* expected_state                                                              */
/* ------------------------------------------------------------------------- */

/* Validate scenario-level expected_state assertions on the LAST
 * participant we dispatched to. The engine's stub _check_expected_state
 * defers to per-protocol logic; for reputation we read from rep_state
 * directly (since we reset+install per dispatch, the values reflect
 * the most recent dispatcher's state). */
static int _check_expected_state(sce_run_ctx_t *ctx)
{
    json_t *exp = json_object_get(ctx->case_data, "expected_state");
    if (!json_is_object(exp)) return 0;

    const char *pid;
    json_t *checks;
    json_object_foreach(exp, pid, checks) {
        if (!json_is_object(checks)) continue;
        rp_snap_t *snap = _snap_find(pid);
        if (snap == NULL)
        {
            /* No dispatch ever ran with this pid as target — likely a
             * scenario that asserts state on a participant who was
             * always the sender, never the receiver. Skip silently
             * since we have nothing to compare against. */
            continue;
        }

        const char *key;
        json_t *val;
        json_object_foreach(checks, key, val) {
            if (strcmp(key, "history_len") == 0)
            {
                int want = (int)json_integer_value(val);
                if (snap->chain_len != want)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: history_len=%d, expected %d",
                             pid, snap->chain_len, want);
                    return -1;
                }
            }
            else if (strcmp(key, "committed_tx_count") == 0)
            {
                int want = (int)json_integer_value(val);
                if (snap->committed_tx_count != want)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: committed_tx_count=%d, expected %d",
                             pid, snap->committed_tx_count, want);
                    return -1;
                }
            }
            else if (strcmp(key, "window_root") == 0)
            {
                const char *want = json_string_value(val);
                if (want == NULL ||
                    strncmp(snap->window_root, want, TX_HASH_HEX_LEN + 1) != 0)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: window_root=%s, expected %s",
                             pid, snap->window_root, want ? want : "(null)");
                    return -1;
                }
            }
            else if (strcmp(key, "checkpoint_root") == 0)
            {
                const char *want = json_string_value(val);
                if (want == NULL ||
                    strncmp(snap->checkpoint_root, want, TX_HASH_HEX_LEN + 1) != 0)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: checkpoint_root=%s, expected %s",
                             pid, snap->checkpoint_root, want ? want : "(null)");
                    return -1;
                }
            }
            else if (strcmp(key, "resolved_reputation") == 0)
            {
                /* The verdict on a deep-resolution answer, and the score this
                 * node computed FROM the attested window rather than the one
                 * the answer claimed. Both runtimes must reach the same
                 * verdict on the same evidence, or the same peer is trusted on
                 * one implementation and refused on the other. */
                const char *peer_pid = json_string_value(
                    json_object_get(val, "peer"));
                const uuid_t *peer_uu = (peer_pid != NULL)
                    ? _uuid_of(ctx, peer_pid) : NULL;
                if (peer_uu == NULL)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: resolved_reputation names unknown "
                             "participant %s", pid,
                             peer_pid ? peer_pid : "(none)");
                    return -1;
                }
                char peer_str[UUID_STRING_LEN + 1];
                uuid_unparse_lower(*peer_uu, peer_str);
                double score = 0.0;
                bool have_score = false, verified = false;
                char reason[192] = {0};
                if (!reputation_resolved_get(peer_str, &score, &have_score,
                                             &verified, reason, sizeof(reason)))
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: resolved_reputation[%s]: no answer recorded",
                             pid, peer_pid);
                    return -1;
                }
                json_t *want_v = json_object_get(val, "verified");
                if (want_v != NULL
                    && verified != json_is_true(want_v))
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: resolved_reputation.verified=%s, expected "
                             "%s (reason: %s)", pid, verified ? "true" : "false",
                             json_is_true(want_v) ? "true" : "false", reason);
                    return -1;
                }
                json_t *want_s = json_object_get(val, "score");
                if (want_s != NULL && json_is_null(want_s))
                {
                    if (have_score)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: resolved_reputation.score=%.6f, expected "
                                 "none", pid, score);
                        return -1;
                    }
                }
                else if (json_is_number(want_s))
                {
                    double want = json_number_value(want_s);
                    if (!have_score || fabs(score - want) > 1e-3)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: resolved_reputation.score=%.6f, expected "
                                 "%.6f", pid, have_score ? score : -1.0, want);
                        return -1;
                    }
                }
            }
            else if (strcmp(key, "evidence_doc") == 0)
            {
                /* The persisted-evidence document, pinned by the fields that
                 * carry meaning across runtimes: the schema (a mismatch is a
                 * refusal to rebuild, not a misparse), how many entries the
                 * document carries, and the root the checkpoint block commits
                 * to. Mirrors Python's `evidence_doc` assertion. */
                if (!json_is_object(val)) continue;
                json_t *w_schema = json_object_get(val, "schema");
                if (json_is_string(w_schema)
                    && strcmp(snap->evidence_schema,
                              json_string_value(w_schema)) != 0)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: evidence_doc.schema=%s, expected %s",
                             pid, snap->evidence_schema,
                             json_string_value(w_schema));
                    return -1;
                }
                json_t *w_len = json_object_get(val, "chain_len");
                if (json_is_integer(w_len)
                    && snap->evidence_chain_len != (int)json_integer_value(w_len))
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: evidence_doc.chain_len=%d, expected %d",
                             pid, snap->evidence_chain_len,
                             (int)json_integer_value(w_len));
                    return -1;
                }
                json_t *w_root = json_object_get(val, "checkpoint_root");
                if (json_is_string(w_root)
                    && strncmp(snap->evidence_checkpoint_root,
                               json_string_value(w_root),
                               TX_HASH_HEX_LEN + 1) != 0)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: evidence_doc.checkpoint_root=%s, expected %s",
                             pid, snap->evidence_checkpoint_root,
                             json_string_value(w_root));
                    return -1;
                }
            }
            else if (strcmp(key, "evidence_ceiling_of") == 0)
            {
                /* { "<other_pid>": float } — the ceiling the resident window
                 * supports for that peer, 1e-3 tolerance as reputation_of
                 * uses. This is the security parameter of warm start made
                 * observable. */
                if (!json_is_object(val)) continue;
                const char *other;
                json_t *want_j;
                json_object_foreach(val, other, want_j)
                {
                    double want = json_is_real(want_j)
                        ? json_real_value(want_j)
                        : (json_is_integer(want_j)
                           ? (double)json_integer_value(want_j) : 0.0);
                    const rp_peer_rep_t *found = NULL;
                    for (size_t i = 0; i < SCE_MAX_PARTICIPANTS; i++)
                    {
                        if (strcmp(snap->evidence_ceilings[i].id, other) == 0)
                        {
                            found = &snap->evidence_ceilings[i];
                            break;
                        }
                    }
                    if (found == NULL || !found->has_value)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s.evidence_ceiling_of[%s]: not bounded by "
                                 "the window (expected %.4f)", pid, other, want);
                        return -1;
                    }
                    if (fabs(found->value - want) > 1e-3)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s.evidence_ceiling_of[%s]=%.4f, expected "
                                 "%.4f", pid, other, found->value, want);
                        return -1;
                    }
                }
            }
            else if (strcmp(key, "requests_count") == 0)
            {
                int want = (int)json_integer_value(val);
                if (snap->request_count != want)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: requests_count=%d, expected %d",
                             pid, snap->request_count, want);
                    return -1;
                }
            }
            else if (strcmp(key, "slashes_proposed") == 0)
            {
                /* How many slash proposals this participant ORIGINATED
                 * (R+D.md §12.8). Its reason for existing is the zero case: a
                 * hard-channel refutation that arrived FROM A PEER must not
                 * let that peer accuse a third party, because the sender picks
                 * its own channel tag. Both runtimes enforce that structurally
                 * -- the accused subject is local-only and never serialized --
                 * and this key is what makes the two agree about it in the
                 * corpus rather than only in each side's unit tests. */
                int want = (int)json_integer_value(val);
                if (snap->slashes_proposed != want)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: slashes_proposed=%d, expected %d",
                             pid, snap->slashes_proposed, want);
                    return -1;
                }
            }
            else if (strcmp(key, "app_roster") == 0)
            {
                /* Which peers the app-facing roster pull reported, as
                 * participant ids. Asserted as a SET rather than a count
                 * because the content is the point: the roster is peers only
                 * and never carries the answering node itself. Python emitted
                 * a self-entry (N+1) while C emitted N until that was
                 * aligned, and a bare count would have hidden which entry
                 * differed. */
                size_t want_n = json_is_array(val) ? json_array_size(val) : 0;
                if ((size_t)snap->app_roster_n != want_n)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: app_roster has %d entries, expected %zu",
                             pid, snap->app_roster_n, want_n);
                    return -1;
                }
                for (size_t wi = 0; wi < want_n; wi++)
                {
                    const char *want_pid =
                        json_string_value(json_array_get(val, wi));
                    if (want_pid == NULL)
                        continue;
                    sce_participant_t *wp =
                        sce_find_participant(ctx, want_pid);
                    if (wp == NULL)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: app_roster names %s, not a participant",
                                 pid, want_pid);
                        return -1;
                    }
                    char wu[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(((rp_impl_t *)wp->impl)->pub->uuid, wu);
                    bool found = false;
                    for (int ri = 0; ri < snap->app_roster_n; ri++)
                        if (strcmp(snap->app_roster[ri], wu) == 0)
                        {
                            found = true;
                            break;
                        }
                    if (!found)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s: app_roster is missing %s",
                                 pid, want_pid);
                        return -1;
                    }
                }
            }
            else if (strcmp(key, "last_id_set") == 0)
            {
                /* Python's check is `self.process.last_id is not None`;
                 * the C side uses int64_t initialized to 0 and only
                 * advances on a granted ballot (paxos.c:123). > 0
                 * therefore means "set". Scenarios pin ballot ids > 0
                 * so this maps cleanly to Python's None semantics. */
                bool want = json_is_true(val);
                bool got = (snap->last_id > 0);
                if (got != want)
                {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: last_id_set=%s (value=%lld), expected %s",
                             pid, got ? "true" : "false",
                             (long long)snap->last_id,
                             want ? "true" : "false");
                    return -1;
                }
            }
            else if (strcmp(key, "reputation_of") == 0)
            {
                /* reputation_of: { "<other_pid>": float_with_tolerance }
                 * — compare snapshotted rep_state.reputations[pid_of(other)]
                 * against the expected value with a small absolute
                 * tolerance (1e-3). Catches weighted-pure / CTFT math
                 * regressions in either direction. */
                if (!json_is_object(val)) continue;
                const char *other;
                json_t *want_j;
                json_object_foreach(val, other, want_j)
                {
                    double want = json_is_real(want_j) ? json_real_value(want_j)
                        : json_is_integer(want_j) ? (double)json_integer_value(want_j) : 0.0;
                    rp_peer_rep_t *pr = NULL;
                    for (size_t i = 0; i < SCE_MAX_PARTICIPANTS; i++)
                        if (snap->peer_reps[i].id[0] != '\0' &&
                            strcmp(snap->peer_reps[i].id, other) == 0)
                        {
                            pr = &snap->peer_reps[i];
                            break;
                        }
                    if (pr == NULL || !pr->has_value)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s.reputation_of[%s]: not present (expected %.4f)",
                                 pid, other, want);
                        return -1;
                    }
                    double diff = pr->value - want;
                    if (diff < 0) diff = -diff;
                    if (diff > 1e-3)
                    {
                        snprintf(ctx->err, sizeof(ctx->err),
                                 "%s.reputation_of[%s]=%.4f, expected %.4f",
                                 pid, other, pr->value, want);
                        return -1;
                    }
                }
            }
            else
            {
                /* Unknown key: error rather than silently skip. The
                 * Python adapter does the same (`raise
                 * AssertionError(f'{self.id}: unsupported expected_state
                 * key {key!r}')`); without this, a scenario could pin
                 * a key that Python enforces but C ignores, hiding a
                 * real asymmetry behind a green C result. */
                snprintf(ctx->err, sizeof(ctx->err),
                         "%s: unsupported expected_state key %s", pid, key);
                return -1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Adapter entry                                                              */
/* ------------------------------------------------------------------------- */

void at_reputation_run(const at_case_t *c, at_case_result_t *out)
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
                 "C reputation adapter only handles kind:scenario|negative (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    /* Scenarios that pre-stage a ZTA standing (fixtures.zta_standing) need the
     * ceiling machinery, which is compiled in only under AT_ZTA — and AT_ZTA is
     * OFF by default. Skip rather than run: without the gate the fixture is
     * silently ignored, the scenario scores as though nothing were capped, and
     * the miss surfaces as a plain value mismatch that reads exactly like a
     * cross-language divergence. A skip on one side is not asymmetric
     * (diff_results), and the Python adapter still pins the case. Mirrors the
     * identity adapter's fixtures.zta_policy skip. */
#ifndef AT_ZTA_ENABLED
    {
        json_t *fx = json_object_get(c->data, "fixtures");
        if (json_is_object(fx) && json_object_get(fx, "zta_standing") != NULL)
        {
            at_case_result_set_skip(
                out, "ZTA scenario skipped: C built without AT_ZTA "
                     "(build -DAT_ZTA=ON to run it symmetrically)");
            return;
        }
    }
#endif

    char err[256] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    sce_run_ctx_t ctx;
    sce_init(&ctx);
    ctx.case_data = c->data;
    ctx.build_inbound = _build_inbound;
    ctx.dispatch = _dispatch;

    g_fixtures = json_object_get(c->data, "fixtures");
    memset(g_snaps, 0, sizeof(g_snaps));

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
    _link_peer_lists(&ctx);

    g_active_ctx = &ctx;
    messaging_set_test_hook(_send_hook);
    reputation_set_synchronous_dispatch(true);

    int rc = sce_run(&ctx);

    /* expected_state is run after the engine's normal finalize; the
     * engine's _check_expected_state stub doesn't know our protocol,
     * so we re-validate here. */
    if (rc == 0) rc = _check_expected_state(&ctx);

    messaging_set_test_hook(NULL);
    g_active_ctx = NULL;
    g_fixtures = NULL;
    reputation_set_synchronous_dispatch(false);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) at_case_result_set_pass(out, duration_ms);
    else         at_case_result_set_fail(out, duration_ms, "AssertionError", ctx.err);

    for (size_t i = 0; i < ctx.participant_count; i++)
        _free_participant_impl((rp_impl_t *)ctx.participants[i].impl);
    return;

fail:
    g_active_ctx = NULL;
    g_fixtures = NULL;
    messaging_set_test_hook(NULL);
    reputation_set_synchronous_dispatch(false);
    for (size_t i = 0; i < ctx.participant_count; i++)
        _free_participant_impl((rp_impl_t *)ctx.participants[i].impl);
    at_case_result_set_fail(out, 0, "AssertionError", err);
}
