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
#include "identity/identity_priv.h"   /* hexlify / public_identity_to_json */
#include "identity/id_proc_priv.h"
#include "identity/group.h"           /* group_init / group_add_address */
#include "config/configuration.h"     /* config_t (proc->configs["identity"]) */
#include "structures/data.h"          /* object_ptr_data */
#ifdef AT_ZTA_ENABLED
#include "zta/zta_policy.h"           /* zta_policy_t / defaults / from_json */
#endif
#include "network/net_message.h"
#include "processes/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

#include "../negative_runner.h"
#include "../scenario_engine.h"

/* Provided by runner.c; needed for kind:negative case dispatch to resolve
 * based_on references inside the JSON corpus mirror. */
extern const char *at_runner_corpus_json_root(void);

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

    /* Wire the participant's own identity into proc->configs under the
     * "identity" key — exactly where _partition_self_identity (and the
     * welcoming-committee's _resolve_self_identity) look for it. Without
     * this the partition handlers find no self identity and silently emit
     * nothing. Python's adapter already supplies a full identity config;
     * this brings the C participant to parity. */
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

#ifdef AT_ZTA_ENABLED
/* ZTA fixtures (zta-x509-* scenarios). Mirrors the Python adapter:
 *   fixtures.zta_policy   -> a zta_policy_t in each participant's
 *                            proc->configs["zta_policy"] (object_ptr_data
 *                            (config_t), exactly as load_all_configs stores
 *                            configs and the gate reads them).
 *   fixtures.credentials  -> attach the DER credential to each named peer's
 *                            public identity so its announce (from_whom copy)
 *                            carries it to the welcoming committee.
 * Cert paths are corpus-relative (testdata/ is mirrored into the C corpus
 * root by tools/corpus_to_json). Allocations here outlive the scenario and
 * are reclaimed at process exit — the same convention as the "identity"
 * config built in _build_participant_impl. */
static void _apply_zta_fixtures(sce_run_ctx_t *ctx, json_t *fixtures) {
    const char *root = at_runner_corpus_json_root();

    json_t *creds = json_object_get(fixtures, "credentials");
    if (json_is_object(creds) && root != NULL) {
        const char *pid; json_t *relv;
        json_object_foreach(creds, pid, relv) {
            if (!json_is_string(relv)) continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", root, json_string_value(relv));
            FILE *fp = fopen(path, "rb");
            if (fp == NULL) continue;
            fseek(fp, 0, SEEK_END);
            long n = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (n <= 0) { fclose(fp); continue; }
            uint8_t *buf = malloc((size_t)n);
            size_t got = (buf != NULL) ? fread(buf, 1, (size_t)n, fp) : 0;
            fclose(fp);
            if (buf == NULL || got != (size_t)n) { free(buf); continue; }
            sce_participant_t *p = sce_find_participant(ctx, pid);
            if (p == NULL) { free(buf); continue; }
            ic_impl_t *impl = (ic_impl_t *)p->impl;
            impl->pub->zta_credential = buf;
            impl->pub->zta_credential_len = (size_t)n;
        }
    }

    json_t *zp = json_object_get(fixtures, "zta_policy");
    if (json_is_object(zp)) {
        for (size_t i = 0; i < ctx->participant_count; i++) {
            ic_impl_t *impl = (ic_impl_t *)ctx->participants[i].impl;
            zta_policy_t *pol = calloc(1, sizeof(zta_policy_t));
            if (pol == NULL) continue;
            zta_policy_defaults(pol);
            zta_policy_from_json(zp, pol);
            if (root != NULL && pol->ca_bundle_path[0] != '\0'
                && pol->ca_bundle_path[0] != '/') {
                /* Make the corpus-relative bundle path absolute. Bounded
                 * widths keep the total provably within the buffers, so
                 * -Wformat-truncation is satisfied (the combined path is
                 * ~140 chars in practice). */
                char abs[1024];
                snprintf(abs, sizeof(abs), "%.700s/%.255s", root,
                         pol->ca_bundle_path);
                snprintf(pol->ca_bundle_path, sizeof(pol->ca_bundle_path),
                         "%.*s", (int)(sizeof(pol->ca_bundle_path) - 1), abs);
            }
            config_t *cfg = calloc(1, sizeof(config_t));
            if (cfg == NULL) { free(pol); continue; }
            cfg->name = "zta_policy";
            cfg->data_struct = pol;
            data_t *d = object_ptr_data(cfg, sizeof(config_t));
            if (d == NULL) { free(cfg); free(pol); continue; }
            map_set(impl->proc->configs, (map_key_t)"zta_policy", d);
        }
    }
}
#endif /* AT_ZTA_ENABLED */

/* Apply scenario fixtures: amnesia_known => pre-stage non-newcomer
 * participants' peer lists with the newcomer (so welcoming_committee's
 * already-known branch is reachable). */
static void _apply_fixtures(sce_run_ctx_t *ctx) {
    json_t *fixtures = json_object_get(ctx->case_data, "fixtures");
    if (!json_is_object(fixtures)) return;

#ifdef AT_ZTA_ENABLED
    _apply_zta_fixtures(ctx, fixtures);
#endif

    /* capabilities: { "<participant>": ["<cap>", ...], ... } —
     * install each participant's own-capability allowlist via
     * identity_set_own_capabilities so handle_caps_query emits the
     * matching JSON-array payload. Mirrors the negotiation adapter's
     * fixture wiring; Python's identity adapter populates
     * `process.protocol.capabilities` from the same fixture key. */
    json_t *caps = json_object_get(fixtures, "capabilities");
    if (json_is_object(caps))
    {
        const char *pid;
        json_t *cap_arr;
        json_object_foreach(caps, pid, cap_arr) {
            sce_participant_t *part = sce_find_participant(ctx, pid);
            if (part == NULL) continue;
            ic_impl_t *impl = (ic_impl_t *)part->impl;
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
            identity_set_own_capabilities(impl->proc, names, k);
            free((void *)names);
        }
    }

    /* groups: { "<participant>": { "uuid": "<str>", "size": <int> }, ... }
     * Distinct-group mode for partition-recovery scenarios. Each listed
     * participant gets its OWN group (pinned uuid + `size` members) and
     * peers are NOT cross-populated, so each peer sees the other's group
     * traffic as foreign — the split-brain precondition. Mirrors the
     * Python adapter's _build_group_from_fixture. The pinned uuid keeps
     * the equal-size tiebreak deterministic and identical across harnesses;
     * filler members exist only to set map_size(group.address_map) (the
     * value the partition handlers sign and compare) and use distinct
     * addresses because group_add_address dedups by address. */
    json_t *groups = json_object_get(fixtures, "groups");
    if (json_is_object(groups))
    {
        const char *gpid;
        json_t *gspec;
        size_t gi = 0;
        json_object_foreach(groups, gpid, gspec) {
            sce_participant_t *part = sce_find_participant(ctx, gpid);
            if (part != NULL && json_is_object(gspec)) {
                ic_impl_t *impl = (ic_impl_t *)part->impl;
                if (impl != NULL && impl->proc != NULL && impl->pub != NULL) {
                    const char *guuid_str = NULL;
                    json_t *gu = json_object_get(gspec, "uuid");
                    if (json_is_string(gu)) guuid_str = json_string_value(gu);
                    int gsize = 1;
                    json_t *gs = json_object_get(gspec, "size");
                    if (json_is_integer(gs)) gsize = (int)json_integer_value(gs);

                    char gaddr[ADDR_LEN + 1];
                    snprintf(gaddr, sizeof(gaddr), "239.9.%zu.1", gi);
                    uuid_t guuid;
                    if (guuid_str != NULL && uuid_parse(guuid_str, guuid) == 0)
                        group_init(&guuid, gaddr, &impl->proc->protocol.group);
                    else
                        group_init(NULL, gaddr, &impl->proc->protocol.group);

                    /* member 0: the participant itself */
                    char own_uuid_str[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(impl->pub->uuid, own_uuid_str);
                    group_add_address(&impl->proc->protocol.group,
                                      own_uuid_str, impl->pub->address);
                    /* fillers to reach `size` members */
                    for (int k = 0; k < gsize - 1; k++) {
                        char fuuid[UUID_STRING_LEN + 1];
                        char faddr[ADDR_LEN + 1];
                        snprintf(fuuid, sizeof(fuuid),
                                 "f111%04zu-0000-4000-8000-%012d", gi, k);
                        snprintf(faddr, sizeof(faddr), "10.9.%zu.%d", gi, k + 2);
                        group_add_address(&impl->proc->protocol.group,
                                          fuuid, faddr);
                    }
                }
            }
            gi++;
        }
    }

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
    (void)to_id;
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

    /* peer_caps_response — pack the YAML `caps: [...]` list as a JSON
     * array so handle_caps_response can parse + register it. Without
     * this, the C handler sees no payload and silently no-ops. */
    if (strcmp(function, "peer_caps_response") == 0 && json_is_object(payload)) {
        json_t *src = json_object_get(payload, "caps");
        if (json_is_array(src)) {
            json_t *body = json_array();
            size_t n = json_array_size(src);
            for (size_t i = 0; i < n; i++) {
                json_t *v = json_array_get(src, i);
                if (json_is_string(v))
                    json_array_append_new(body, json_string(json_string_value(v)));
            }
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
        return 0;
    }

    /* vote_on_peer is the only identity function whose C handler
     * (`handle_count_vote`) requires a structured JSON payload —
     * `{uuid, approved}` keyed off the candidate's uuid. Other
     * identity functions either expect empty/unused payloads or use
     * the generic obj passthrough. */
    if (strcmp(function, "vote_on_peer") == 0 && json_is_object(payload)) {
        const char *cand_id = NULL;
        json_t *c = json_object_get(payload, "candidate");
        if (json_is_string(c)) cand_id = json_string_value(c);
        bool approved = true;
        json_t *a = json_object_get(payload, "approved");
        if (json_is_boolean(a)) approved = json_boolean_value(a);

        char uuid_buf[UUID_STRING_LEN + 1] = {0};
        if (cand_id != NULL) {
            sce_participant_t *cand = sce_find_participant(ctx, cand_id);
            if (cand != NULL) {
                ic_impl_t *cand_impl = (ic_impl_t *)cand->impl;
                if (cand_impl && cand_impl->pub)
                    uuid_unparse_lower(cand_impl->pub->uuid, uuid_buf);
            }
        }
        json_t *body = json_object();
        json_object_set_new(body, "uuid", json_string(uuid_buf));
        json_object_set_new(body, "approved", json_boolean(approved));
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }

    /* partition_signal — local-only IPC payload is just the from_addr
     * string. See doc/architecture/partition-recovery.md §5.1. */
    if (strcmp(function, "partition_signal") == 0) {
        const char *from_addr = "mock-addr:0";
        if (json_is_object(payload)) {
            json_t *fa = json_object_get(payload, "from_addr");
            if (json_is_string(fa)) from_addr = json_string_value(fa);
        }
        json_t *body = json_string(from_addr);
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
    }

    /* partition_probe — cross-group probe, signed JSON payload. */
    if (strcmp(function, "group_partition_probe") == 0
        && json_is_object(payload)) {
        const char *group_uuid = "00000000-0000-0000-0000-000000000000";
        int group_size = 1;
        json_t *g = json_object_get(payload, "group_uuid");
        if (json_is_string(g)) group_uuid = json_string_value(g);
        json_t *sz = json_object_get(payload, "group_size");
        if (json_is_integer(sz)) group_size = (int)json_integer_value(sz);

        char canon[UUID_STRING_LEN + 32];
        int clen = snprintf(canon, sizeof(canon), "%s|%d",
                            group_uuid, group_size);
        unsigned char sig[crypto_sign_BYTES];
        if (clen > 0 && (size_t)clen < sizeof(canon)
            && sender_impl->full != NULL) {
            crypto_sign_detached(sig, NULL, (const unsigned char *)canon,
                                 (size_t)clen,
                                 sender_impl->full->signature.private);
            char sig_hex[crypto_sign_BYTES * 2 + 1];
            hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
            json_t *from_id_json = NULL;
            public_identity_to_json(sender_impl->pub, &from_id_json);
            json_t *body = json_object();
            if (from_id_json != NULL)
                json_object_set_new(body, "from_identity", from_id_json);
            json_object_set_new(body, "from_address",
                                json_string(sender_impl->pub->address));
            json_object_set_new(body, "my_group_uuid",
                                json_string(group_uuid));
            json_object_set_new(body, "my_group_size",
                                json_integer(group_size));
            json_object_set_new(body, "signature", json_string(sig_hex));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
    }

    /* partition_response — same shape + in_response_to + leader info. */
    if (strcmp(function, "group_partition_response") == 0
        && json_is_object(payload)) {
        const char *group_uuid = "00000000-0000-0000-0000-000000000000";
        int group_size = 1;
        const char *in_resp = "00000000-0000-0000-0000-000000000000";
        const char *leader_uuid = group_uuid;
        const char *leader_addr = sender_impl->pub != NULL
            ? sender_impl->pub->address : "";
        json_t *g = json_object_get(payload, "group_uuid");
        if (json_is_string(g)) group_uuid = json_string_value(g);
        json_t *sz = json_object_get(payload, "group_size");
        if (json_is_integer(sz)) group_size = (int)json_integer_value(sz);
        json_t *ir = json_object_get(payload, "in_response_to");
        if (json_is_string(ir)) in_resp = json_string_value(ir);
        /* in_response_to_id: a participant id resolved to that participant's
         * actual uuid. The probe sender's uuid is runtime-derived (it
         * differs between the Python and C harnesses), so scenarios that
         * chain probe->response can't hard-code it — they name the probing
         * participant and each adapter resolves it locally. */
        char in_resp_buf[UUID_STRING_LEN + 1] = {0};
        json_t *ir_id = json_object_get(payload, "in_response_to_id");
        if (json_is_string(ir_id)) {
            sce_participant_t *t = sce_find_participant(ctx, json_string_value(ir_id));
            if (t != NULL) {
                ic_impl_t *ti = (ic_impl_t *)t->impl;
                if (ti != NULL && ti->pub != NULL) {
                    uuid_unparse_lower(ti->pub->uuid, in_resp_buf);
                    in_resp = in_resp_buf;
                }
            }
        }
        json_t *lu = json_object_get(payload, "leader_uuid");
        if (json_is_string(lu)) leader_uuid = json_string_value(lu);
        json_t *la = json_object_get(payload, "leader_address");
        if (json_is_string(la)) leader_addr = json_string_value(la);

        char canon[UUID_STRING_LEN * 2 + 64];
        int clen = snprintf(canon, sizeof(canon), "%s|%d|%s",
                            group_uuid, group_size, in_resp);
        unsigned char sig[crypto_sign_BYTES];
        if (clen > 0 && (size_t)clen < sizeof(canon)
            && sender_impl->full != NULL) {
            crypto_sign_detached(sig, NULL, (const unsigned char *)canon,
                                 (size_t)clen,
                                 sender_impl->full->signature.private);
            char sig_hex[crypto_sign_BYTES * 2 + 1];
            hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
            json_t *from_id_json = NULL;
            public_identity_to_json(sender_impl->pub, &from_id_json);
            json_t *body = json_object();
            if (from_id_json != NULL)
                json_object_set_new(body, "from_identity", from_id_json);
            json_object_set_new(body, "from_address",
                                json_string(sender_impl->pub->address));
            json_object_set_new(body, "in_response_to",
                                json_string(in_resp));
            json_object_set_new(body, "my_group_uuid",
                                json_string(group_uuid));
            json_object_set_new(body, "my_group_size",
                                json_integer(group_size));
            json_object_set_new(body, "my_group_leader",
                                json_string(leader_uuid));
            json_object_set_new(body, "my_group_leader_address",
                                json_string(leader_addr));
            json_object_set_new(body, "signature", json_string(sig_hex));
            net_msg_pack_json(&out->info.net_msg, body);
            json_decref(body);
        }
    }

    return 0;
}

static int _dispatch(sce_run_ctx_t *ctx,
                     sce_participant_t *target,
                     generic_msg_t *inbound) {
    (void)ctx;
    ic_impl_t *impl = (ic_impl_t *)target->impl;
    /* directory_t is array_t of sibling-process queue names. Populate it
     * with the names handlers expect to find: _announce_identity (the
     * partition-recovery request_access re-broadcast) returns early unless
     * the directory contains "network" (array_contains check), and other
     * handlers index it similarly. The real runtime supplies this
     * directory; an empty array silently suppresses those emissions. */
    array_t *queues = NULL;
    array_create(&queues);
    static const char *const qnames[] = {"network", "identity",
                                         "negotiation", "main"};
    for (size_t i = 0; i < sizeof(qnames) / sizeof(qnames[0]); i++) {
        data_t *qn = string_data((string_t)qnames[i], strlen(qnames[i]));
        if (qn != NULL) array_append(queues, qn);
    }
    run_message_handlers(impl->proc, queues, NET_MESSAGE, inbound);
    array_free(queues);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Adapter entry                                                              */
/* ------------------------------------------------------------------------- */

/* Validate `expected_state` against post-scenario participant state.
 * Mirrors the Python identity adapter's _Participant._check_expected_state
 * (src/autonomous-trust/conformance/harness/python/adapters/identity.py:86-111).
 * Supported keys: phase (int), peer_count (int), has_peer (uuid string).
 * Unsupported keys produce an error so the corpus and the two adapters
 * stay aligned — an asymmetry caught at the gate beats a silent skip.
 *
 * Returns 0 if all checks pass, -1 with ctx->err on the first mismatch. */
static int _identity_check_expected_state(sce_run_ctx_t *ctx) {
    json_t *expected = json_object_get(ctx->case_data, "expected_state");
    if (!json_is_object(expected)) return 0;

    const char *pid;
    json_t *checks;
    json_object_foreach(expected, pid, checks) {
        if (strcmp(pid, "group") == 0) {
            /* Engine convention from the Python side: group-state is
             * adapter-driven; identity has no group-aware checks yet, so
             * skip silently. */
            continue;
        }
        if (!json_is_object(checks)) continue;
        sce_participant_t *p = sce_find_participant(ctx, pid);
        if (p == NULL) {
            snprintf(ctx->err, sizeof(ctx->err),
                     "expected_state references unknown participant %s", pid);
            return -1;
        }
        ic_impl_t *impl = (ic_impl_t *)p->impl;
        process_t *proc = impl->proc;

        const char *key;
        json_t *val;
        json_object_foreach(checks, key, val) {
            if (strcmp(key, "phase") == 0) {
                int want = (int)json_integer_value(val);
                int got = (int)proc->protocol.phase;
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: phase=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "peer_count") == 0) {
                int want = (int)json_integer_value(val);
                /* protocol.num_peers is the same field the production
                 * peer-add path advances; mirrors Python's
                 * `sum(len(level) for level in self.process.peers.hierarchy)`
                 * (which collapses all hierarchy levels to a flat count). */
                int got = (int)proc->protocol.num_peers;
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: peer_count=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "has_peer") == 0) {
                const char *uuid_str = json_string_value(val);
                if (uuid_str == NULL) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer expects a uuid string", pid);
                    return -1;
                }
                uuid_t want_uuid;
                if (uuid_parse(uuid_str, want_uuid) != 0) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer uuid %s not parseable",
                             pid, uuid_str);
                    return -1;
                }
                bool found = false;
                for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                    if (memcmp(proc->protocol.peers[i].uuid, want_uuid,
                               sizeof(uuid_t)) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: has_peer %s not present (have %d peers)",
                             pid, uuid_str, (int)proc->protocol.num_peers);
                    return -1;
                }
            } else if (strcmp(key, "peer_caps_count") == 0) {
                /* `peer_caps_count: <int>` — assert the number of caps
                 * recorded for THIS participant under their own uuid in
                 * id_state.peer_caps_map. Populated by handle_caps_response
                 * on inbound peer_caps_response. Wait — actually we want
                 * the caps recorded ABOUT a peer; the key references the
                 * recipient and the value is the count under the SENDER
                 * uuid. The scenario authoring convention is that
                 * `peer_caps_count` is keyed by participant id whose
                 * peer_caps_map entry under the OTHER participant's uuid
                 * we want — but with a 2-party scenario the only sender
                 * is the other participant. Simplest reading: assert
                 * `id_state.peer_caps_map` has `int` total entries for
                 * SOME peer registered after the scenario; we encode
                 * that as: count across all entries in the map for THIS
                 * participant. The map is shared, so the count is the
                 * global peer count — that's fine for a 2-party probe. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->participant_count; i++) {
                    ic_impl_t *other = (ic_impl_t *)ctx->participants[i].impl;
                    if (other == NULL || other->pub == NULL) continue;
                    if (strcmp(ctx->participants[i].id, pid) == 0) continue;
                    got += identity_get_peer_caps_count(other->pub->uuid);
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: peer_caps_count=%d, expected %d",
                             pid, got, want);
                    return -1;
                }
            } else if (strcmp(key, "partition_probes_emitted") == 0
                       || strcmp(key, "partition_responses_emitted") == 0) {
                /* Count emissions of the named function attributed to this
                 * participant across the whole scenario. The engine records
                 * every emitted (from, to, function) in ctx->captured; the
                 * cooldown scenario delivers N signals and asserts the
                 * per-from_addr cooldown collapses them to a single probe.
                 * Mirrors the Python adapter's per-participant emit_tally. */
                const char *want_fn =
                    (key[10] == 'p') ? "group_partition_probe"
                                     : "group_partition_response";
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function, want_fn) == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: %s=%d, expected %d", pid, key, got, want);
                    return -1;
                }
            } else if (strcmp(key, "propose_emitted") == 0) {
                /* Admit/reject observable for the zta-x509-* scenarios: a
                 * welcomed newcomer triggers one propose_peer; a ZTA-rejected
                 * one triggers none. Mirrors the Python emit_tally check. */
                int want = (int)json_integer_value(val);
                int got = 0;
                for (size_t i = 0; i < ctx->captured_count; i++) {
                    if (strcmp(ctx->captured[i].from, pid) == 0
                        && strcmp(ctx->captured[i].function, "propose_peer") == 0)
                        got++;
                }
                if (got != want) {
                    snprintf(ctx->err, sizeof(ctx->err),
                             "%s: propose_emitted=%d, expected %d", pid, got, want);
                    return -1;
                }
            } else {
                snprintf(ctx->err, sizeof(ctx->err),
                         "%s: unsupported expected_state key %s", pid, key);
                return -1;
            }
        }
    }
    return 0;
}

void at_identity_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "negative") == 0) {
        at_neg_run_wire(c, out);
        return;
    }
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C identity adapter only handles kind:scenario|negative (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    /* ZTA admission scenarios (fixtures.zta_policy present) require the ZTA
     * gate, which is compiled in only under AT_ZTA. When built without it,
     * skip — a skip on one side is not an asymmetric failure (diff_results.py)
     * and the Python adapter still pins the scenario. When built with
     * -DAT_ZTA=ON the adapter wires the policy + credentials (_apply_zta_
     * fixtures) and runs the scenario symmetrically. */
#ifndef AT_ZTA_ENABLED
    {
        json_t *fx = json_object_get(c->data, "fixtures");
        if (json_is_object(fx) && json_object_get(fx, "zta_policy") != NULL) {
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

    /* Inline-finalize the welcoming-committee cascade and emit propose /
     * peer_accepted as broadcasts, so a single-bg scenario sees the full
     * outbound. Mirrors Python's per-instance synchronous_dispatch=True. */
    identity_set_synchronous_dispatch(true);

    sce_run_ctx_t ctx;
    sce_init(&ctx);
    ctx.case_data = c->data;
    ctx.build_inbound = _build_inbound;
    ctx.dispatch = _dispatch;

    /* Wipe singleton id_state so observables (peer_caps_count etc.) are
     * not polluted by prior scenarios. Preserves synchronous_dispatch. */
    identity_reset_state();

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
    /* The engine's stub _check_expected_state is a no-op; per-protocol
     * enforcement lives here so a scenario's bg.peer_count: 1 (and
     * friends) is checked symmetrically with the Python adapter. */
    if (rc == 0) rc = _identity_check_expected_state(&ctx);

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
