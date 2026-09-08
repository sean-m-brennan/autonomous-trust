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

#include <math.h>      /* NAN, for an unparseable probe answer */
#include <string.h>
#include <pthread.h>
#include <unistd.h>   /* close, for the custom run loop */

#include "processes/processes.h"
#include "negotiation/negotiation.h"
#include "structures/map.h"
#include "structures/data.h"
#include "structures/array.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"
#include "negotiation/neg_proc_priv.h"
#include "identity/id_proc_priv.h"  /* identity_get_peer_tier */
#include "identity/identity_priv.h"  /* public_identity_to_json */
#include "utilities/freshness.h"
#include "utilities/util.h"       /* at_strlcpy */
#include "bootstrap/bootstrap_capabilities.h"  /* known-answer probe verifiers */
#include "bootstrap/bootstrap_worker.h"        /* probe allocation + window */
#include "physics/physics.h"                   /* §12.2 falsification layer */
#include "calibration/calibration.h"           /* §12.4 coverage audit */
#include "prequential/prequential.h"         /* §12.5 competence weight */
#include "certificates/certificates.h"         /* §12.3 witness checking */
#include "config/configuration.h"             /* config_t, for our own identity */
#include "reputation/tx_channel.h"             /* evidence channels */

DEFINE_ERROR(ENEG_NOPEERS, "No capable peers available");

/* Protocol-string definitions (declared `extern char[]` in
 * negotiation.h). Writable arrays for direct assignment to `char *`. */
char NEG_PROTO_START[]    = "spawn task";
char NEG_PROTO_ANNOUNCE[] = "invitation";
char NEG_PROTO_RESPONSE[] = "haggle";
char NEG_PROTO_ACCEPT[]   = "ack";
char NEG_PROTO_REFUSE[]   = "nack";
char NEG_PROTO_STAT_REQ[] = "status request";
char NEG_PROTO_STAT_RSP[] = "status response";
char NEG_PROTO_RESULT[]   = "report results";
char NEG_PROTO_CANCEL[]   = "cancel";
/* Local-IPC function name for the tier_lost message. Mirrors Python
 * IdentityProtocol.tier_lost verbatim; reputation publishes this
 * onto the negotiation queue when a peer's tier drops, and
 * handle_tier_lost cancels in-flight tasks the peer can no longer
 * authorize. See doc/architecture/trust-tiers.md §7.2. */
static char ID_TIER_LOST[] = "tier_lost";

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

/* TaskParameters constants — mirrors Python TaskParameters class-level
 * defaults (negotiation.py:61-62). Kept as #defines because protobuf
 * task_t has no per-instance field for either, and changing the proto
 * would be a wire-format break. Override per-task by extending
 * TaskParameters in a subclass on the Python side, which has no C
 * analog today. */
#define NEG_TIMEOUT_EXTENSION_SEC 120L
#define NEG_DURATION_FRACTION_PCT 10L

static struct {
    job_queue_t task_stack;
    map_t proposed_tasks;  /* uuid_str -> task_t* */
    map_t my_tasks;        /* uuid_str -> task_tracker_t* */
    map_t confirmed;       /* uuid_str -> int (acceptance count, used by
                            * negotiation_has_confirmed_any) */
    /* Per-(task, peer) acceptance membership, keyed
     * "task_uuid_str:peer_uuid_str_lower" → presence marker (int 1).
     * Required for the confirmation-prereq guard in handle_stat_resp's
     * timeout-extension path (mirrors Python's `message.from_whom in
     * self.confirmed[task.uuid]` test in negprocess.py:271). The
     * existing `confirmed` count map keeps its semantics for the
     * negotiation_has_confirmed_any export. */
    map_t confirmed_pairs;
    array_t status_pending;
    int max_concurrency;
    pthread_mutex_t lock;
    bool initialized;
    /* Per-process conformance-only overrides. Key form is the process_t*
     * pointer cast to a string (printed as "%p") so it doesn't collide
     * with the uuid-string keys used elsewhere in this state struct.
     *
     * own_caps_by_proc:    process_t* (as %p)        -> array_t* of dup'd cap-name strings
     * peer_tiers:          "{proc}|{peer_uuid_str}"  -> int* (trust tier)
     * cap_required_tiers:  "{proc}|{cap_name}"       -> int* (required_tier)
     *
     * Populated by negotiation_set_own_capabilities,
     * negotiation_set_peer_tier, and
     * negotiation_set_capability_required_tier; cleared via
     * negotiation_clear_test_state. Production code MUST NOT touch
     * these and they are silently ignored when handle_invite finds no
     * entry, so the static capability_table + identity_get_peer_tier
     * fallback drives non-test paths. */
    map_t own_caps_by_proc;
    map_t peer_tiers;
    map_t cap_required_tiers;
    /* Per-verb replay state: our own monotonic send counter and the
     * per-(sender, verb) high-water marks, both persisted. Used by
     * NEG_PROTO_ANNOUNCE only -- the invitation was the one negotiation verb
     * whose payload carried no freshness token of its own, and it is the verb
     * that asks a peer to RUN something. The others are bounded by state that
     * already exists: an ack is deduped per participant, a status response
     * spends an outstanding request. C twin of Python
     * NegotiationProcess.freshness; see utilities/freshness.h. */
    freshness_t freshness;
    /* The bootstrap corpus's prober state: window bookkeeping, per-peer and
     * per-capability probe counts, and the continuous-probe rate limit. Python
     * keeps this in a BootstrapWorker process of its own; here it rides this
     * process, which is the one that owns the announce path the worker needs.
     * See _bootstrap_tick. */
    bootstrap_worker_t bootstrap;
    /* The physical-consistency checker and its observation window (R+D.md
     * §12.2). It lives here for the same reason the prober does: this is the
     * process that retained what the requestor ASKED for, so it is the only
     * one that can say which quantity a returned result is a claim about. The
     * window is what the multi-peer intersection and the parity residuals are
     * computed over -- a checker rebuilt per result would see no history and
     * could only ever perform the single-claim checks.
     *
     * `physics_loaded` is separate from "the model is empty": an unconfigured
     * $AT_PHYSICS is a legitimate empty model, and re-reading the file on
     * every result to rediscover that would be a syscall per task. */
    at_physics_checker_t physics;
    bool physics_loaded;
    /* §12.4 coverage audit. Held here for the same reason the physics checker
     * is, only more so: the verdict IS the accumulated record of resolved
     * predictions, so an auditor built per result would have nothing to audit
     * and would be permanently silent. */
    at_calibration_auditor_t calibration;
    bool calibration_loaded;
    /* §12.5 prequential competence. Held here for the same reason the auditor
     * above it is, and rather more so: the competence multiplier IS the
     * accumulated record of resolved forecasts, so an estimator built per
     * result would weight every peer at exactly 1.0 forever -- which is
     * indistinguishable from the layer being switched off. */
    at_prequential_estimator_t prequential;
    bool prequential_loaded;
    /* The certificate declaration (R+D.md §12.3). Stateless apart from the
     * model -- a witness is self-contained by construction, so unlike the
     * physics checker there is no observation window to carry -- but held here
     * so the file is read and the inventory reported ONCE rather than per
     * task result. */
    at_cert_model_t certificates;
    bool certificates_loaded;
} neg_state;

static void _ensure_init(void)
{
    if (!neg_state.initialized)
    {
        job_queue_init(&neg_state.task_stack);
        map_init(&neg_state.proposed_tasks);
        map_init(&neg_state.my_tasks);
        map_init(&neg_state.confirmed);
        map_init(&neg_state.confirmed_pairs);
        array_init(&neg_state.status_pending);
        neg_state.max_concurrency = 4;
        pthread_mutex_init(&neg_state.lock, NULL);
        map_init(&neg_state.own_caps_by_proc);
        map_init(&neg_state.peer_tiers);
        map_init(&neg_state.cap_required_tiers);
        /* Reads AT_BOOTSTRAP_{DURATION_SEC,PAIRS,SEED,DISABLED}; marks all
         * three capabilities registered, which matches the static capability
         * table this runtime advertises them from. */
        bootstrap_worker_init(&neg_state.bootstrap);
        freshness_init(&neg_state.freshness, "negotiation", NULL);
        neg_state.initialized = true;
    }
}

/* ---- Conformance test hooks (see neg_proc_priv.h doc) ---------------------- */

static void _proc_key(const process_t *proc, char *out, size_t n)
{
    snprintf(out, n, "%p", (const void *)proc);
}

/* Look up a process's test-installed own-capability allowlist.
 * Returns the array_t* (whose elements are char* cap-name strings) or
 * NULL if no override is installed. Caller holds neg_state.lock. */
static array_t *_own_caps_for(const process_t *proc)
{
    if (proc == NULL) return NULL;
    char key[32]; _proc_key(proc, key, sizeof(key));
    data_t *dat = NULL;
    if (map_get(&neg_state.own_caps_by_proc, key, &dat) != 0 || dat == NULL)
        return NULL;
    array_t *arr = NULL;
    if (data_object_ptr(dat, (ptr_t *)&arr) != 0) return NULL;
    return arr;
}

/* Caller must hold neg_state.lock — these helpers are called from
 * inside handle_invite's already-locked section, so re-locking would
 * deadlock the non-recursive mutex. */
static bool _has_own_cap_override_locked(const process_t *proc, const char *name,
                                         bool *out_set)
{
    array_t *arr = _own_caps_for(proc);
    bool found = false;
    bool set = (arr != NULL);
    if (arr != NULL && name != NULL)
    {
        for (size_t i = 0; i < array_size(arr); i++)
        {
            data_t *cap_dat = NULL;
            if (array_get(arr, i, &cap_dat) != 0) continue;
            char *cap_name = NULL;
            if (data_string_ptr(cap_dat, &cap_name) != 0) continue;
            if (cap_name && strcmp(cap_name, name) == 0) { found = true; break; }
        }
    }
    if (out_set) *out_set = set;
    return found;
}

static int _peer_tier_override_locked(const process_t *proc, const uuid_t peer_uuid)
{
    if (proc == NULL) return -1;
    char proc_key[32]; _proc_key(proc, proc_key, sizeof(proc_key));
    char uuid_str[UUID_STRING_LEN + 1]; uuid_unparse_lower(peer_uuid, uuid_str);
    char key[96]; snprintf(key, sizeof(key), "%s|%s", proc_key, uuid_str);

    data_t *dat = NULL;
    int tier = -1;
    if (map_get(&neg_state.peer_tiers, key, &dat) == 0 && dat != NULL)
        data_integer(dat, &tier);
    return tier;
}

/* Per-process capability required_tier override (test fixture). Returns
 * -1 if no override is installed; callers fall back to
 * find_capability(name)->required_tier or 0. Caller holds neg_state.lock. */
static int _cap_required_tier_override_locked(const process_t *proc, const char *cap_name)
{
    if (proc == NULL || cap_name == NULL) return -1;
    char proc_key[32]; _proc_key(proc, proc_key, sizeof(proc_key));
    char key[32 + 1 + CAP_NAMELEN + 1];
    snprintf(key, sizeof(key), "%s|%s", proc_key, cap_name);
    data_t *dat = NULL;
    int rt = -1;
    if (map_get(&neg_state.cap_required_tiers, key, &dat) == 0 && dat != NULL)
        data_integer(dat, &rt);
    return rt;
}

void negotiation_set_own_capabilities(const process_t *proc,
                                      const char *const *cap_names,
                                      size_t n_caps)
{
    _ensure_init();
    char key[32]; _proc_key(proc, key, sizeof(key));
    pthread_mutex_lock(&neg_state.lock);
    if (cap_names == NULL || n_caps == 0)
    {
        map_remove(&neg_state.own_caps_by_proc, key);
        pthread_mutex_unlock(&neg_state.lock);
        return;
    }
    array_t *arr = NULL;
    if (array_create(&arr) != 0 || arr == NULL)
    {
        pthread_mutex_unlock(&neg_state.lock);
        return;
    }
    for (size_t i = 0; i < n_caps; i++)
    {
        if (cap_names[i] == NULL) continue;
        size_t len = strlen(cap_names[i]);
        char *dup = smrt_create(len + 1);
        if (dup == NULL) continue;
        memcpy(dup, cap_names[i], len + 1);
        data_t *str_dat = string_data(dup, len + 1);
        if (str_dat == NULL) { smrt_deref(dup); continue; }
        array_append(arr, str_dat);
    }
    data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
    map_set(&neg_state.own_caps_by_proc, key, arr_dat);
    pthread_mutex_unlock(&neg_state.lock);
}

void negotiation_set_peer_tier(const process_t *proc,
                               const uuid_t peer_uuid,
                               int tier)
{
    _ensure_init();
    char proc_key[32]; _proc_key(proc, proc_key, sizeof(proc_key));
    char uuid_str[UUID_STRING_LEN + 1]; uuid_unparse_lower(peer_uuid, uuid_str);
    char key[96]; snprintf(key, sizeof(key), "%s|%s", proc_key, uuid_str);
    pthread_mutex_lock(&neg_state.lock);
    map_set(&neg_state.peer_tiers, key, integer_data(tier));
    pthread_mutex_unlock(&neg_state.lock);
}

void negotiation_set_capability_required_tier(const process_t *proc,
                                              const char *cap_name,
                                              int required_tier)
{
    _ensure_init();
    if (cap_name == NULL) return;
    char proc_key[32]; _proc_key(proc, proc_key, sizeof(proc_key));
    char key[32 + 1 + CAP_NAMELEN + 1];
    snprintf(key, sizeof(key), "%s|%s", proc_key, cap_name);
    pthread_mutex_lock(&neg_state.lock);
    map_set(&neg_state.cap_required_tiers, key, integer_data(required_tier));
    pthread_mutex_unlock(&neg_state.lock);
}

void negotiation_clear_test_state(const process_t *proc)
{
    if (!neg_state.initialized) return;
    char proc_key[32]; _proc_key(proc, proc_key, sizeof(proc_key));
    pthread_mutex_lock(&neg_state.lock);
    map_remove(&neg_state.own_caps_by_proc, proc_key);
    /* Sweep peer_tiers + cap_required_tiers for any keys with our proc
     * prefix. map_t doesn't expose a prefix-delete; iterate, collect
     * matching keys, then remove. Test-only, so linear sweeps are fine. */
    char prefix[40]; snprintf(prefix, sizeof(prefix), "%s|", proc_key);
    size_t plen = strlen(prefix);
    char *iter_key; data_t *iter_val;
    char *to_remove[32] = {0}; size_t n_remove = 0;
    map_entries_for_each(&neg_state.peer_tiers, iter_key, iter_val)
        if (n_remove < 32 && strncmp(iter_key, prefix, plen) == 0)
            to_remove[n_remove++] = iter_key;
    map_end_for_each
    for (size_t i = 0; i < n_remove; i++)
        map_remove(&neg_state.peer_tiers, to_remove[i]);
    n_remove = 0;
    map_entries_for_each(&neg_state.cap_required_tiers, iter_key, iter_val)
        if (n_remove < 32 && strncmp(iter_key, prefix, plen) == 0)
            to_remove[n_remove++] = iter_key;
    map_end_for_each
    for (size_t i = 0; i < n_remove; i++)
        map_remove(&neg_state.cap_required_tiers, to_remove[i]);
    pthread_mutex_unlock(&neg_state.lock);
}

void negotiation_reset_state(void)
{
    _ensure_init();
    pthread_mutex_lock(&neg_state.lock);
    job_queue_clear(&neg_state.task_stack);
    map_free(&neg_state.proposed_tasks);
    map_init(&neg_state.proposed_tasks);
    map_free(&neg_state.my_tasks);
    map_init(&neg_state.my_tasks);
    map_free(&neg_state.confirmed);
    map_init(&neg_state.confirmed);
    map_free(&neg_state.confirmed_pairs);
    map_init(&neg_state.confirmed_pairs);
    array_free(&neg_state.status_pending);
    array_init(&neg_state.status_pending);
    map_free(&neg_state.own_caps_by_proc);
    map_init(&neg_state.own_caps_by_proc);
    map_free(&neg_state.peer_tiers);
    map_init(&neg_state.peer_tiers);
    map_free(&neg_state.cap_required_tiers);
    map_init(&neg_state.cap_required_tiers);
    /* Replay marks too. The harness derives participant uuids
     * deterministically from their slugs, so "alice" is the same sender in
     * every scenario; a mark left behind by one would refuse the next
     * scenario's first invitation as a replay. */
    freshness_reset(&neg_state.freshness);
    pthread_mutex_unlock(&neg_state.lock);
}

/****************************
 * Helper: build a reply net_msg_t directed back to sender
 ****************************/

/* Frama-C: skipped — [solver-timeout] JSON + logging preconditions */
static void _build_reply(const net_msg_t *nmsg, const char *func, generic_msg_t *reply)
{
    memset(reply, 0, sizeof(*reply));
    reply->type = NET_MESSAGE;
    strncpy(reply->info.net_msg.process, "negotiation", PROC_NAME_LEN);
    reply->info.net_msg.function = (char *)func;
    reply->info.net_msg.encrypt = true;
    memcpy(&reply->info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(reply->info.net_msg.return_to, "negotiation", PROC_NAME_LEN);
}

/****************************
 * Python-tagged negotiation payloads (doc/architecture/negotiation.md)
 *
 * Every negotiation verb's payload is Python's `__type__`-tagged
 * Configuration dump -- what `config_json_decoder` reconstructs a
 * Task / TaskStatus / TaskResult from. C used to hand-build a flat object
 * (`task_uuid`, `capability_name`, `when_sec`, ...) mirroring
 * negotiation/task.proto, a schema Python does not use; the two shapes shared
 * no key but `seq`, so a C worker could not read a Python requestor's
 * invitation and a Python requestor could not read a C worker's result.
 * Negotiation between the runtimes did not work at all. It looked healthy
 * only because a Python invitation arrived at C with every key missing,
 * leaving `seq` at 0, and an unstamped invitation is refused by the freshness
 * gate rather than misexecuted.
 *
 * The type tags are shared constants, not language artifacts -- the same
 * argument that keeps the wire protocol strings byte-identical to Python's
 * enum values, and that already has C writing Python's `__type__` on the
 * reputation snapshot (rep_proc.c).
 *
 * ONE field is not Python's tagged form: `requestor` carries the flat DRY
 * canonical PUBLIC identity (@ref public_identity_to_json here,
 * `public_identity_to_canonical` in Python). Python's tagged Identity dump
 * serializes `Signature.to_dict()`, which hands back the PRIVATE signing seed
 * whenever the object is not public-only -- and the requestor is the node's
 * own private identity -- plus the local-only `petname`. Mirroring it here
 * would have built that leak into C as well. The canonical form is also what
 * the two runtimes already exchange for `peer_accepted` and `full_history`,
 * for exactly the reason that applies here (see its docstring in identity.py).
 ****************************/

/* Python `Status` member NAMES indexed by ::neg_status_t, which is 1-based and
 * declared in negotiation.h in Python's member order. An `Enumcfg:` value is
 * `obj.name`, not the enum's value. Python's tenth member, `cancelled`, has no
 * C counterpart on purpose: it never crosses the wire (handle_tier_lost puts it
 * on the LOCAL main queue), so an unrecognised name reads as `unknown` rather
 * than inventing a status this runtime cannot act on. */
static const char *const _py_status_names[] = {
    NULL, "running", "sleeping", "zombie", "stopped", "dead",
    "pending", "unknown", "no_peers", "rejected",
};

static const char *_py_status_name(neg_status_t s)
{
    size_t i = (size_t)s;
    if (i == 0 || i >= sizeof(_py_status_names) / sizeof(_py_status_names[0]))
        return "unknown";
    return _py_status_names[i];
}

static neg_status_t _py_status_value(const char *name)
{
    if (name == NULL)
        return NEG_UNKNOWN;
    for (size_t i = 1; i < sizeof(_py_status_names) / sizeof(_py_status_names[0]); i++)
        if (strcmp(name, _py_status_names[i]) == 0)
            return (neg_status_t)i;
    return NEG_UNKNOWN;
}

/* Forward declarations: both live further down with the peer/identity
 * helpers, and the serializers below need them to fill `requestor`. */
static const identity_t *_self_identity(const process_t *proc);
static bool _peer_by_uuid(const process_t *proc, const uuid_t peer_uuid,
                          public_identity_t *out);

/* The `__value__` of a Python-tagged scalar, or the bare string when a payload
 * carries one unwrapped (hand-written conformance steps do). */
static const char *_py_tagged_str(const json_t *j)
{
    if (j == NULL)
        return NULL;
    if (json_is_string(j))
        return json_string_value(j);
    if (json_is_object(j))
    {
        json_t *v = json_object_get(j, "__value__");
        if (json_is_string(v))
            return json_string_value(v);
    }
    return NULL;
}

static json_t *_py_uuid_json(const uuid_t u)
{
    char s[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(u, s);
    return json_pack("{s:s, s:s}", "__type__", "UUID", "__value__", s);
}

static int _py_uuid_read(const json_t *j, uuid_t out)
{
    const char *s = _py_tagged_str(j);
    if (s == NULL)
        return -1;
    return uuid_parse(s, out) == 0 ? 0 : -1;
}

/* Seconds since the epoch for a datetime_t, honouring its recorded offset.
 * timegm rather than mktime: the struct is UTC unless it says otherwise, and
 * mktime would apply the HOST's zone to it. */
static time_t _dt_epoch(const datetime_t *dt)
{
    struct tm tm_copy;
    memcpy(&tm_copy, dt, sizeof(struct tm));
    tm_copy.tm_isdst = 0;
    time_t t = timegm(&tm_copy);
    if (t == (time_t)-1)
        return 0;
    if (!dt->tm_utc)
        t -= (time_t)(dt->tm_tz_offset * 3600.0f);
    return t;
}

/* Re-express a datetime in UTC. Everything this file puts on the wire goes
 * through here, so the offset is always the same one. */
static void _dt_to_utc(const datetime_t *in, datetime_t *out)
{
    if (datetime_from_time(_dt_epoch(in), (long)in->tm_nsec, false, out) != 0)
        memcpy(out, in, sizeof(datetime_t));
}

/* Formatted to match Python's `datetime.isoformat('T')` on a UTC-aware
 * datetime EXACTLY -- `+00:00` rather than `Z`, and the fractional part
 * omitted when it is zero -- rather than going through datetime_to_isoformat.
 * Two reasons: that helper's `%z` writes `Z` for a UTC datetime and an
 * unpadded `+H:M` for a zoned one (dividing by a zero minute-count at offset
 * 0), and the corpus pins this payload by round-tripping ONE fixture through
 * both runtimes, so a spelling difference is a failure even though dateutil
 * would parse either. Microseconds, like Python: a sub-microsecond remainder
 * is dropped. */
static json_t *_py_datetime_json(const datetime_t *dt)
{
    datetime_t utc;
    memset(&utc, 0, sizeof(utc));
    _dt_to_utc(dt, &utc);
    const struct tm *tm = (const struct tm *)&utc;
    long usec = (long)(utc.tm_nsec / 1000);
    char buf[64] = {0};
    int n;
    if (usec != 0)
        n = snprintf(buf, sizeof(buf),
                     "%04d-%02d-%02dT%02d:%02d:%02d.%06ld+00:00",
                     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                     tm->tm_hour, tm->tm_min, tm->tm_sec, usec);
    else
        n = snprintf(buf, sizeof(buf),
                     "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
                     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                     tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return json_null();
    return json_pack("{s:s, s:s}", "__type__", "datetime", "__value__", buf);
}

static int _py_datetime_read(const json_t *j, datetime_t *out)
{
    const char *s = _py_tagged_str(j);
    if (s == NULL || out == NULL)
        return -1;
    datetime_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    if (datetime_from_isostring(s, &parsed) != 0)
        return -1;
    _dt_to_utc(&parsed, out);
    return 0;
}

/* Python serializes a timedelta as its total_seconds() float. */
static json_t *_py_timedelta_json(double seconds)
{
    return json_pack("{s:s, s:f}", "__type__", "timedelta",
                     "__value__", seconds);
}

static double _py_timedelta_read(const json_t *j, double dflt)
{
    const json_t *v = j;
    if (json_is_object(j))
        v = json_object_get(j, "__value__");
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return dflt;
}

/* The `requestor` field, resolved from the uuid the task carries: ourselves
 * when we are the requestor, otherwise the peer table.
 *
 * NULL (and so an omitted key) when the identity is not known to us. Python's
 * `public_identity_from_canonical` returns None for a dict without keys
 * anyway, and an absent key says "unknown" where a half-filled one would say
 * "this peer, with no keys". */
/* Conformance-only: the identity a re-emitted `requestor` field is filled
 * from when there is no process to resolve it against. Set only by
 * @ref negotiation_payload_roundtrip, which the corpus's byte-pinned payload
 * vectors call; NULL on every production path, and the corpus is
 * single-threaded, so this never races the real serializers. */
static const public_identity_t *_requestor_override = NULL;

static json_t *_requestor_json(const process_t *proc, const uuid_t requestor_uuid)
{
    json_t *obj = NULL;
    if (_requestor_override != NULL)
    {
        if (public_identity_to_json(_requestor_override, &obj) == 0)
            return obj;
        return NULL;
    }
    if (proc == NULL)
        return NULL;
    const identity_t *self = _self_identity(proc);
    /* identity_t embeds public_identity_t at offset 0 (anonymous member). */
    if (self != NULL && uuid_compare(self->uuid, requestor_uuid) == 0)
    {
        if (public_identity_to_json((const public_identity_t *)self, &obj) == 0)
            return obj;
        return NULL;
    }
    public_identity_t peer;
    memset(&peer, 0, sizeof(peer));
    if (_peer_by_uuid(proc, requestor_uuid, &peer)
        && public_identity_to_json(&peer, &obj) == 0)
        return obj;
    return NULL;
}

/* The fields TaskInfo carries, shared by Task, TaskStatus and TaskResult.
 * Takes ownership of nothing; fills @p j in place. */
static void _task_info_into_json(const process_t *proc, const task_t *task,
                                 json_t *j)
{
    json_object_set_new(j, "uuid", _py_uuid_json(task->uuid));
    json_t *req = _requestor_json(proc, task->requestor_uuid);
    if (req != NULL)
        json_object_set_new(j, "requestor", req);
    /* How many participants the requestor expects. Carried through rather
     * than assumed to be 1: a Python requestor's `handle_results` forwards
     * only once `len(results) >= task.size`, and it reads that off the reply
     * we send back. A task that arrived without one counts as single-
     * participant, which is what every C-originated task is. */
    json_object_set_new(j, "size", json_integer(task->size > 0 ? task->size : 1));
    /* Freshness sequence. Emitted unconditionally, including as 0, so that an
     * unstamped invitation is visibly unstamped on the wire rather than
     * indistinguishable from a field the serializer forgot. Only the invite
     * senders set it (handle_start_task, handle_haggle's re-announce); the
     * other verbs carry whatever the task already held and nothing reads it
     * there. */
    json_object_set_new(j, "seq", json_integer((json_int_t)task->seq));
}

/****************************
 * Helper: serialize task_t as Python's tagged Task
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
static json_t *_task_to_json(const process_t *proc, const task_t *task)
{
    json_t *params = json_object();
    if (params == NULL)
        return NULL;
    json_object_set_new(params, "__type__", json_string(PY_TYPE_TASK_PARAMS));
    json_object_set_new(params, "_capability",
                        json_pack("{s:s, s:s, s:i, s:i}",
                                  "__type__", PY_TYPE_CAPABILITY,
                                  "name", task->capability.name,
                                  "required_tier", task->capability.required_tier,
                                  "transaction_weight", task->capability.transaction_weight));
    json_object_set_new(params, "_flexible", json_boolean(task->flexible));
    json_object_set_new(params, "when", _py_datetime_json(&task->when));
    json_object_set_new(params, "duration",
                        _py_timedelta_json(task->duration.days * 86400.0
                                           + task->duration.seconds
                                           + task->duration.nsecs / 1000000000.0));
    json_object_set_new(params, "timeout", _py_timedelta_json((double)task->timeout));
    /* Positional arguments. Always empty: a C task carries only `kwargs_json`
     * (task.h), and negotiation/task.proto has an `argc` with no argv to fill
     * it from. Emitted rather than omitted because TaskParameters defaults it
     * to a tuple and a reader should not have to tell "none" from "absent". */
    json_object_set_new(params, "args", json_array());
    /* Keyword arguments as a real JSON object, which is what Python's
     * TaskParameters.kwargs serializes to. A blob that does not parse as an
     * object becomes an empty one rather than a quoted string: a responder
     * reading `kwargs` would find a string where it expected an object and
     * silently see no arguments, which for a probe means computing the wrong
     * answer and being scored for it. */
    json_t *kw = NULL;
    if (task->kwargs_json[0] != '\0')
    {
        json_error_t jerr;
        kw = json_loads(task->kwargs_json, 0, &jerr);
        if (kw != NULL && !json_is_object(kw))
        {
            json_decref(kw);
            kw = NULL;
        }
    }
    json_object_set_new(params, "kwargs", kw != NULL ? kw : json_object());

    json_t *j = json_object();
    if (j == NULL)
    {
        json_decref(params);
        return NULL;
    }
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK));
    _task_info_into_json(proc, task, j);
    json_object_set_new(j, "parameters", params);
    return j;
}

/****************************
 * Helper: serialize a task + status as Python's tagged TaskStatus
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
static json_t *_task_status_to_json(const process_t *proc, const task_t *task,
                                    neg_status_t status)
{
    json_t *j = _task_to_json(proc, task);
    if (j == NULL)
        return NULL;
    /* TaskStatus subclasses Task, so it carries the task fields verbatim and
     * differs only by the tag and this one key. */
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK_STATUS));
    json_object_set_new(j, "status",
                        json_pack("{s:s, s:s}",
                                  "__type__", PY_ENUM_STATUS,
                                  "__value__", _py_status_name(status)));
    return j;
}

/****************************
 * Helper: serialize an answer as Python's tagged TaskResult
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
static json_t *_task_result_to_json(const process_t *proc, const task_t *task,
                                    const char *answer, json_t *certificate,
                                    json_t *prediction)
{
    json_t *j = json_object();
    if (j == NULL)
    {
        if (certificate != NULL)
            json_decref(certificate);
        if (prediction != NULL)
            json_decref(prediction);
        return NULL;
    }
    /* TaskResult extends TaskInfo, NOT Task: it carries no `parameters`. The
     * requestor supplies what it asked for from its own record
     * (attach_requested_parameters / task_tracker_set_request), which is the
     * whole point -- reading the challenge back off the reply would verify
     * nothing. `proof` and the `requested_*` fields are likewise the
     * requestor's to fill and are omitted here; Python defaults them. */
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK_RESULT));
    _task_info_into_json(proc, task, j);
    /* `null` rather than absent when the capability produced nothing -- which
     * is also what Python emits, and the reason to match it is that the corpus
     * round-trips ONE pinned fixture through both runtimes (see
     * negotiation_payload_roundtrip). Either way the requestor's scorer reads
     * it as an empty return, which is what a failed execution deserves. */
    if (answer != NULL && answer[0] != '\0')
        json_object_set_new(j, "result", json_string(answer));
    else
        json_object_set_new(j, "result", json_null());
    json_object_set_new(j, "certificate",
                        certificate != NULL ? certificate : json_null());
    /* The prediction set (R+D.md §12.4). Always emitted, and `null` when none
     * was attached -- which is what this runtime's own executors produce,
     * since no C capability yet emits prediction sets. Present regardless
     * because Python always serializes the field and the corpus round-trips
     * ONE pinned fixture through both runtimes: a key absent on one side is a
     * diverged shape. Carried through rather than dropped when it IS present,
     * so a Python peer's set survives a C hop intact. */
    json_object_set_new(j, "prediction",
                        prediction != NULL ? prediction : json_null());
    /* Fields Python's TaskResult always serializes and that this runtime never
     * fills: `proof` is the ZK-STARK attesting the bytes were not altered
     * (Python's `generate_proof`, which C has no counterpart for), and the
     * `requested_*` trio is the REQUESTOR's record of what it asked --
     * stamped on arrival from the tracker, never read off the reply, because
     * reading the challenge off the answer would verify nothing. Emitted at
     * their defaults so both runtimes' TaskResult has one key set. */
    json_object_set_new(j, "proof", json_null());
    json_object_set_new(j, "requested_capability_name", json_null());
    json_object_set_new(j, "requested_args", json_array());
    json_object_set_new(j, "requested_kwargs", json_object());
    return j;
}

/* A TaskResult's `result` rendered as the text this runtime scores against.
 * Python's capabilities return whatever they return -- an int from `pow`, a
 * string from `echo` -- so a C requestor has to flatten a JSON scalar rather
 * than insist on a string. Returns false when there is no result at all. */
static bool _py_result_text(const json_t *j_result, char *out, size_t cap)
{
    if (j_result == NULL || json_is_null(j_result) || out == NULL || cap == 0)
        return false;
    if (json_is_string(j_result))
        return at_strlcpy(out, json_string_value(j_result), cap) < cap;
    if (json_is_integer(j_result))
        return (size_t)snprintf(out, cap, "%lld",
                                (long long)json_integer_value(j_result)) < cap;
    if (json_is_real(j_result))
        return (size_t)snprintf(out, cap, "%.17g", json_real_value(j_result)) < cap;
    if (json_is_true(j_result) || json_is_false(j_result))
        return at_strlcpy(out, json_is_true(j_result) ? "True" : "False", cap) < cap;
    /* An object or array: hand it over as compact JSON rather than dropping
     * it, so a capability that answers with a structure is at least legible
     * to whatever verifier knows its shape. */
    char *dumped = json_dumps(j_result, JSON_COMPACT | JSON_SORT_KEYS);
    if (dumped == NULL)
        return false;
    bool ok = at_strlcpy(out, dumped, cap) < cap;
    free(dumped);
    return ok;
}

/****************************
 * Helper: populate a task_t from Python's tagged Task
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
static int _task_from_json(const json_t *j, task_t *task)
{
    if (!j || !task)
        return -1;

    if (_py_uuid_read(json_object_get(j, "uuid"), task->uuid) != 0)
        return -1;

    /* The requestor rides as the flat canonical PUBLIC identity; only its uuid
     * is kept, because the peer table already holds (and has admitted) the
     * identity itself. A peer we do not know is one we cannot reply to
     * regardless of what its invitation asserted about itself. */
    json_t *j_req = json_object_get(j, "requestor");
    if (json_is_object(j_req))
    {
        const char *req_uuid = json_string_value(json_object_get(j_req, "uuid"));
        if (req_uuid != NULL)
            uuid_parse(req_uuid, task->requestor_uuid);
    }
    else if (json_is_string(j_req))
    {
        uuid_parse(json_string_value(j_req), task->requestor_uuid);
    }

    json_t *j_size = json_object_get(j, "size");
    task->size = json_is_integer(j_size) ? (int)json_integer_value(j_size) : 1;
    if (task->size <= 0)
        task->size = 1;

    /* Absent or non-integer leaves seq at the caller's memset 0 -- unstamped,
     * which handle_invite refuses. */
    json_t *j_seq = json_object_get(j, "seq");
    if (json_is_integer(j_seq))
        task->seq = (int64_t)json_integer_value(j_seq);

    /* A TaskResult carries no `parameters` (it extends TaskInfo), so their
     * absence is normal for that verb and leaves the caller's memset zeros. */
    json_t *params = json_object_get(j, "parameters");
    if (!json_is_object(params))
        return 0;

    json_t *j_cap = json_object_get(params, "_capability");
    const char *cap_name = NULL;
    if (json_is_object(j_cap))
    {
        cap_name = json_string_value(json_object_get(j_cap, "name"));
        json_t *j_tier = json_object_get(j_cap, "required_tier");
        if (json_is_integer(j_tier))
            task->capability.required_tier = (int)json_integer_value(j_tier);
        json_t *j_weight = json_object_get(j_cap, "transaction_weight");
        if (json_is_integer(j_weight))
            task->capability.transaction_weight = (int)json_integer_value(j_weight);
    }
    else if (json_is_string(j_cap))
    {
        cap_name = json_string_value(j_cap);
    }
    if (cap_name != NULL)
        at_strlcpy(task->capability.name, cap_name, sizeof(task->capability.name));

    json_t *j_flex = json_object_get(params, "_flexible");
    if (json_is_boolean(j_flex))
        task->flexible = json_boolean_value(j_flex);

    _py_datetime_read(json_object_get(params, "when"), &task->when);

    double dur = _py_timedelta_read(json_object_get(params, "duration"), 0.0);
    timedelta_normalize_long(0, (long)dur,
                             (long)((dur - (double)(long)dur) * 1000000000.0),
                             &task->duration);
    task->timeout = (long)_py_timedelta_read(json_object_get(params, "timeout"), 0.0);

    /* Keyword arguments back into their compact-JSON carrier. Absent leaves
     * the caller's memset "" -- no arguments. A blob that does not fit is
     * dropped whole, not truncated: half a JSON object parses as nothing and
     * would be a worse lie than an honest absence (the executor then produces
     * no result and the requestor scores an empty return, rather than the
     * executor answering a corrupted challenge). */
    task->kwargs_json[0] = '\0';
    json_t *j_kwargs = json_object_get(params, "kwargs");
    if (json_is_object(j_kwargs) && json_object_size(j_kwargs) > 0)
    {
        char *dumped = json_dumps(j_kwargs, JSON_COMPACT | JSON_SORT_KEYS);
        if (dumped != NULL)
        {
            if (strlen(dumped) < sizeof(task->kwargs_json))
                at_strlcpy(task->kwargs_json, dumped,
                           sizeof(task->kwargs_json));
            free(dumped);
        }
    }

    return 0;
}

/****************************
 * Conformance: byte-pin a negotiation payload's SHAPE (doc/architecture/negotiation.md)
 ****************************/

/* Parse a negotiation payload and re-emit it. Exported so the corpus can pin
 * the payload shape itself, which is the gap that let C and Python diverge
 * unnoticed: only the message ENVELOPE was byte-pinned, and each adapter built
 * its own runtime's payload from the scenario step, so every case passed with
 * the two shapes mutually unreadable.
 *
 * A round-trip against ONE shared fixture is what makes that impossible: both
 * runtimes parse the same pinned bytes and must re-emit the same pinned bytes,
 * so neither can drift without failing. Deliberately not routed through a
 * handler -- an invitation leaving `_announce_task_locked` carries a fresh
 * freshness stamp, and a shape vector has no business depending on that.
 *
 * @p verb picks the form: NEG_PROTO_RESULT a TaskResult, NEG_PROTO_STAT_RSP a
 * TaskStatus, anything else a Task. @p requestor fills the re-emitted
 * `requestor` field, which production reads out of the peer table. Caller
 * frees @p *out_json. */
/* Frama-C: skipped — [serialization] jansson JSON round-trip */
int negotiation_payload_roundtrip(const char *verb, const char *in_json,
                                  const public_identity_t *requestor,
                                  char **out_json)
{
    if (verb == NULL || in_json == NULL || out_json == NULL)
        return EINVAL;
    *out_json = NULL;

    json_error_t jerr;
    json_t *in = json_loads(in_json, 0, &jerr);
    if (in == NULL)
        return EINVAL;

    task_t task;
    memset(&task, 0, sizeof(task));
    int err = _task_from_json(in, &task);

    /* An answer and its witness live on the TaskResult, not in task_t, so they
     * are lifted out here rather than by the task parser. */
    char result_text[CAP_RESULT_LEN * 4 + 1] = {0};
    bool have_result = _py_result_text(json_object_get(in, "result"),
                                       result_text, sizeof(result_text));
    json_t *j_cert = json_object_get(in, "certificate");
    json_t *cert_copy = json_is_object(j_cert) ? json_deep_copy(j_cert) : NULL;
    json_t *j_pred = json_object_get(in, "prediction");
    json_t *pred_copy = json_is_object(j_pred) ? json_deep_copy(j_pred) : NULL;
    neg_status_t status = _py_status_value(_py_tagged_str(json_object_get(in, "status")));
    json_decref(in);

    if (err != 0)
    {
        if (cert_copy != NULL)
            json_decref(cert_copy);
        if (pred_copy != NULL)
            json_decref(pred_copy);
        return EINVAL;
    }

    _requestor_override = requestor;
    json_t *out = NULL;
    if (strcmp(verb, NEG_PROTO_RESULT) == 0)
    {
        /* Takes ownership of both copies, including on its own failure. */
        out = _task_result_to_json(NULL, &task,
                                   have_result ? result_text : NULL, cert_copy,
                                   pred_copy);
    }
    else
    {
        if (cert_copy != NULL)
            json_decref(cert_copy);
        if (pred_copy != NULL)
            json_decref(pred_copy);
        if (strcmp(verb, NEG_PROTO_STAT_RSP) == 0)
            out = _task_status_to_json(NULL, &task, status);
        else
            out = _task_to_json(NULL, &task);
    }
    _requestor_override = NULL;

    if (out == NULL)
        return ENOMEM;
    *out_json = json_dumps(out, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(out);
    return (*out_json != NULL) ? 0 : ENOMEM;
}

/****************************
 * Helper: check if a peer (by UUID string) has a given capability
 *         by looking it up in proc->protocol.peer_capabilities.
 * Returns true if peer_capabilities is NULL (fallback: assume capable).
 ****************************/

/* Frama-C: skipped — [solver-timeout] capability iteration preconditions */
static bool _peer_has_capability(const process_t *proc, const char *peer_uuid_str,
                                  const char *cap_name)
{
    if (!proc->protocol.peer_capabilities)
        return true;  /* no capability info — broadcast to all */

    data_t *cap_arr_dat = NULL;
    if (map_get(proc->protocol.peer_capabilities, (map_key_t)peer_uuid_str, &cap_arr_dat) != 0)
        return false;  /* peer not known */

    /* peer_capabilities_matrix_t maps uuid_str -> array_t of capability_t* */
    array_t *caps = NULL;
    if (data_object_ptr(cap_arr_dat, (ptr_t *)&caps) != 0 || !caps)
        return false;

    for (size_t k = 0; k < array_size(caps); k++)
    {
        data_t *cap_dat = NULL;
        if (array_get(caps, k, &cap_dat) != 0)
            continue;
        capability_t *cap = NULL;
        if (data_object_ptr(cap_dat, (ptr_t *)&cap) != 0 || !cap)
            continue;
        if (strncmp(cap->name, cap_name, CAP_NAMELEN) == 0)
            return true;
    }
    return false;
}

/****************************
 * Handler: handle_start_task (spawn task) — NEG_PROTO_START
 * Deserialize task JSON, create tracker, filter peers by capability, send invitations.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
/* TODO (divergence.md C14 follow-up): Python negprocess.py emits
 * `proc.negotiation/{iter_drained, ...}` counters and per-handler
 * `_probes.counter('proc.negotiation', 'unhandled', message.function)`
 * tags at the dispatch sites in this file. Mirror those here so
 * negotiation-side instrumentation parity completes. The framework is
 * wired (probes.h is included via processes.c) — just add focused
 * `probes_counter` calls inside each handler when interesting branches
 * fire (haggle-vs-accept, refuse-with-reason, etc.). */
/* Announce @p task to the peers that can run it, retaining a tracker for the
 * results. Split out of handle_start_task so the probe dispatcher can start a
 * task directly rather than posting a message to this very process and waiting
 * a cadence for it to come back around. Caller holds neg_state.lock.
 *
 * @p target_uuid, when non-zero, narrows the fan-out to one peer. */
static void _announce_task_locked(const process_t *proc, task_t *task,
                                  const uuid_t target_uuid)
{
    /* Store task in proposed_tasks keyed by task UUID string */
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(task->uuid, task_uuid_str);

    task_t *task_copy = (task_t *)malloc(sizeof(task_t));
    if (task_copy)
    {
        memcpy(task_copy, task, sizeof(task_t));
        data_t *task_dat = object_ptr_data(task_copy, sizeof(task_t));
        map_set(&neg_state.proposed_tasks, task_uuid_str, task_dat);
    }

    /* Create a task tracker for result collection. `expected` is corrected to
     * the number actually invited once the fan-out below has filtered by
     * capability (and by an addressed target); seeding it from num_peers and
     * leaving it there means a task whose capability only some peers hold
     * never reaches its expected count, so handle_results never forwards and
     * my_tasks grows forever. */
    task_tracker_t *tracker = NULL;
    peers_read_lock(proc);
    int expected = (int)proc->protocol.num_peers;
    peers_read_unlock(proc);
    if (task_tracker_create(&tracker, task->uuid, expected) == 0 && tracker)
    {
        /* Retain what we asked for, before the announcement goes out. This is
         * the requestor's own record and the only thing the scorer in
         * handle_results will trust -- see task_tracker_t and R+D.md §12.7. */
        task_tracker_set_request(tracker, task->capability.name,
                                 task->kwargs_json);
        data_t *trk_dat = object_ptr_data(tracker, sizeof(task_tracker_t));
        map_set(&neg_state.my_tasks, task_uuid_str, trk_dat);
    }

    /* One stamp for the whole announcement, not one per peer. The invitation
     * is a single act fanned out to every capable peer, and each receiver
     * keeps its OWN high-water mark -- so it is per-receiver monotonicity that
     * does the work, and numbering the copies separately would only make one
     * act look like N. A later re-announce (handle_haggle) draws a new, higher
     * number, which is what distinguishes it from a replay of this one.
     * Mirrors Python NegotiationProcess.start_task. */
    task->seq = freshness_stamp(&neg_state.freshness, proc->logger);
    if (task->seq <= 0)
    {
        log_warn(proc->logger,
                 "Negotiation: no freshness sequence; not announcing task %s\n",
                 task_uuid_str);
        return;
    }

    /* Build JSON payload for invitation */
    json_t *invite_json = _task_to_json(proc, task);

    /* An addressed start narrows the fan-out to one peer. A probe has to be
     * able to say "this peer": fanned out, an invitation is answered by
     * whichever peer replies first, so a broadcast cannot express a directed
     * challenge and a slow peer is never probed at all. Mirrors Python
     * start_task's `to_whom` handling; a zero target means the ordinary
     * announce-to-all. A named peer that turns out not to hold the capability
     * is invited to nothing -- deliberately not widened back to everyone,
     * which would score the wrong peer. */
    uuid_t zero_uuid;
    uuid_clear(zero_uuid);
    bool addressed = (target_uuid != NULL
                      && uuid_compare(target_uuid, zero_uuid) != 0);

    /* Send invitation to capable peers */
    int invited = 0;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char peer_uuid_str[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(proc->protocol.peers[i].uuid, peer_uuid_str);

        if (addressed && uuid_compare(proc->protocol.peers[i].uuid, target_uuid) != 0)
            continue;

        /* Filter by capability if peer_capabilities map is available */
        if (!_peer_has_capability(proc, peer_uuid_str, task->capability.name))
            continue;

        generic_msg_t invite = {0};
        invite.type = NET_MESSAGE;
        strncpy(invite.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        invite.info.net_msg.function = NEG_PROTO_ANNOUNCE;
        invite.info.net_msg.encrypt = true;
        memcpy(&invite.info.net_msg.to_whom, &proc->protocol.peers[i],
               sizeof(public_identity_t));
        strncpy(invite.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);

        if (invite_json)
            net_msg_pack_json(&invite.info.net_msg, invite_json);

        messaging_send("network", NET_MESSAGE, &invite, false);
        invited++;
    }
    peers_read_unlock(proc);

    if (invite_json)
        json_decref(invite_json);

    /* Correct the tracker to what was actually invited, so completion is
     * reachable. Seeded from num_peers and left there, a task whose capability
     * only some peers hold never reaches its expected count: handle_results
     * never forwards, never scores, and my_tasks grows forever.
     *
     * The tracker is kept even when nothing was invited, which is what Python
     * does (start_task registers it before the participant check and leaves it
     * on the no-peers path). It is also why a stray `report results` for a
     * task nobody was invited to still scores -- true of both runtimes, and
     * recorded in ISSUES.md rather than changed here, since it is a question
     * about who may answer an invitation and not about this scoring path. */
    if (tracker != NULL)
        tracker->expected = invited;

    if (invited == 0)
        log_warn(proc->logger, "Negotiation: no capable peers found for task %s\n",
                 task_uuid_str);
}

/****************************
 * Handler: handle_start_task (spawn task) — NEG_PROTO_START
 * Deserialize task JSON, then announce it (see _announce_task_locked).
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of
 * public_identity_t + JSON serialization + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_start_task(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: start task from %s\n",
             nmsg->from_whom.nickname);

    /* Deserialize task from JSON payload */
    json_t *j = NULL;
    task_t task;
    memset(&task, 0, sizeof(task));

    bool have_task = false;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        if (_task_from_json(j, &task) == 0)
            have_task = true;
        json_decref(j);
    }

    if (!have_task)
    {
        /* Fallback: generate a new UUID for this task */
        uuid_generate(task.uuid);
        uuid_copy(task.requestor_uuid, nmsg->from_whom.uuid);
    }

    /* `to_whom` on a start message is the peer the requestor wants, not a
     * destination for this message -- it is already local. Mirrors Python
     * start_task reading `message.to_whom`. */
    pthread_mutex_lock(&neg_state.lock);
    _announce_task_locked(proc, &task, nmsg->to_whom.uuid);
    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_invite (invitation) — NEG_PROTO_ANNOUNCE
 * Check capability, flood counter, accept/refuse/haggle.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_invite(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: invitation from %s\n", nmsg->from_whom.nickname);

    /* Deserialize task from payload */
    json_t *j = NULL;
    task_t task;
    memset(&task, 0, sizeof(task));

    bool have_task = false;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        if (_task_from_json(j, &task) == 0)
            have_task = true;
        json_decref(j);
    }

    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    if (have_task)
        uuid_unparse_lower(task.uuid, task_uuid_str);

    pthread_mutex_lock(&neg_state.lock);

    /* Freshness FIRST, ahead of the flood counter, and silently.
     *
     * Ahead, because the counter is the thing a replay would otherwise drive:
     * six copies of one captured invitation would push the "flood:<uuid>"
     * count past the threshold and make us refuse -- and a refusal is what the
     * requestor reads as "this worker is out" (handle_refuse drops the
     * participant). That turns a replay into a way of evicting a worker from a
     * task it had already accepted. Past this gate the counter counts what it
     * was built to count: distinct, freshly stamped invitations for one task.
     *
     * Silently, because a replay deserves no reply -- answering would spend a
     * message on a sender we cannot vouch for and tell an attacker where our
     * mark sits.
     *
     * Unstamped (seq 0: an omitted proto field 12, a missing JSON "seq", or a
     * payload we could not parse at all) is refused rather than admitted as
     * legacy. A receiver that accepts unstamped invitations is one an attacker
     * selects by not stamping. Mirrors Python handle_invite. */
    char inviter_uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(nmsg->from_whom.uuid, inviter_uuid_str);
    if (!freshness_accept(&neg_state.freshness, inviter_uuid_str,
                          NEG_PROTO_ANNOUNCE, have_task ? task.seq : 0,
                          proc->logger))
    {
        log_debug(proc->logger,
                  "Negotiation: invitation for %s from %s refused: seq %lld "
                  "not above mark %lld (replay or unstamped)\n",
                  task_uuid_str, inviter_uuid_str,
                  (long long)(have_task ? task.seq : 0),
                  (long long)freshness_mark(&neg_state.freshness,
                                            inviter_uuid_str,
                                            NEG_PROTO_ANNOUNCE));
        pthread_mutex_unlock(&neg_state.lock);
        return true;
    }

    /* Flood detection: count how many times we have seen this task */
    if (have_task)
    {
        data_t *cnt_dat = NULL;
        int flood_count = 0;
        if (map_get(&neg_state.proposed_tasks, task_uuid_str, &cnt_dat) == 0 && cnt_dat)
        {
            /* proposed_tasks stores task_t* for originator; reuse confirmed for flood */
            data_integer(cnt_dat, &flood_count);
        }
        /* We track flood counts separately using a local counter stored as integer */
        /* Use a dedicated prefix key to avoid collision with task objects */
        char flood_key[UUID_STRING_LEN + 8];
        snprintf(flood_key, sizeof(flood_key), "flood:%s", task_uuid_str);

        data_t *flood_dat = NULL;
        flood_count = 0;
        if (map_get(&neg_state.proposed_tasks, flood_key, &flood_dat) == 0 && flood_dat)
            data_integer(flood_dat, &flood_count);

        flood_count++;
        data_t *new_flood = integer_data(flood_count);
        map_set(&neg_state.proposed_tasks, flood_key, new_flood);

        if (flood_count > 5)
        {
            log_warn(proc->logger,
                     "Negotiation: flood detected for task %s (count=%d), refusing\n",
                     task_uuid_str, flood_count);

            generic_msg_t refuse = {0};
            _build_reply(nmsg, NEG_PROTO_REFUSE, &refuse);
            json_t *rj = _task_to_json(proc, &task);
            if (rj)
            {
                net_msg_pack_json(&refuse.info.net_msg, rj);
                json_decref(rj);
            }
            messaging_send("network", NET_MESSAGE, &refuse, false);
            pthread_mutex_unlock(&neg_state.lock);
            return true;
        }
    }

    /* Check own capabilities. If a conformance harness has installed a
     * per-process allowlist via negotiation_set_own_capabilities, that
     * wins over the static capability_table; otherwise fall back to
     * find_capability(). */
    bool have_own_override = false;
    bool capable = false;
    if (have_task && task.capability.name[0] != '\0')
    {
        capable = _has_own_cap_override_locked(proc, task.capability.name,
                                               &have_own_override);
        if (!have_own_override)
            capable = (find_capability(task.capability.name) != NULL);
    }

    /* Trust-tier gate (Python parity, doc/architecture/trust-tiers.md §7.1):
     * refuse if the inviter's reputation-derived trust tier is below the
     * capability's required_tier. Both are read from test overrides if
     * installed, else from production paths (identity_get_peer_tier /
     * find_capability + the capability_t fields added in Slice 1). */
    int sender_tier = _peer_tier_override_locked(proc, nmsg->from_whom.uuid);
    if (sender_tier < 0)
        sender_tier = identity_get_peer_tier(nmsg->from_whom.uuid);
    int required_tier = -1;
    if (have_task && task.capability.name[0] != '\0')
    {
        required_tier = _cap_required_tier_override_locked(proc, task.capability.name);
        if (required_tier < 0) {
            capability_t *own_cap = find_capability(task.capability.name);
            required_tier = (own_cap != NULL) ? own_cap->required_tier : 0;
        }
    }
    bool tier_refuse = (have_task && capable && required_tier > 0
                        && sender_tier < required_tier);

    if (tier_refuse)
    {
        log_info(proc->logger,
                 "Negotiation: refusing %s — sender tier %d < required %d\n",
                 task_uuid_str, sender_tier, required_tier);
        generic_msg_t refuse = {0};
        _build_reply(nmsg, NEG_PROTO_REFUSE, &refuse);
        json_t *rj = _task_to_json(proc, &task);
        if (rj) { net_msg_pack_json(&refuse.info.net_msg, rj); json_decref(rj); }
        messaging_send("network", NET_MESSAGE, &refuse, false);
        pthread_mutex_unlock(&neg_state.lock);
        return true;
    }

    if (!have_task || capable)
    {
        /* We are capable — check for schedule conflicts */
        time_t duration_secs = (time_t)(task.duration.days * 86400L
                                        + task.duration.seconds);
        time_t slot_time = 0;
        int slot_err = job_queue_find_nearest_slot(&neg_state.task_stack,
                                                   duration_secs,
                                                   neg_state.max_concurrency,
                                                   &slot_time);

        if (slot_err == 0 && slot_time > 0 && have_task && !task.flexible)
        {
            /* Schedule conflict and task is inflexible — haggle with suggested time */
            log_info(proc->logger,
                     "Negotiation: schedule conflict for task %s, hagggling\n",
                     task_uuid_str);

            task.when.tm_sec  = 0;
            task.when.tm_min  = 0;
            task.when.tm_hour = 0;
            struct tm *slot_tm = gmtime(&slot_time);
            if (slot_tm)
                memcpy(&task.when, slot_tm, sizeof(struct tm));

            generic_msg_t haggle = {0};
            _build_reply(nmsg, NEG_PROTO_RESPONSE, &haggle);
            json_t *hj = _task_to_json(proc, &task);
            if (hj)
            {
                net_msg_pack_json(&haggle.info.net_msg, hj);
                json_decref(hj);
            }
            messaging_send("network", NET_MESSAGE, &haggle, false);
        }
        else
        {
            /* Accept: push to task_stack, send ACK */
            job_t job;
            memset(&job, 0, sizeof(job));
            memcpy(&job.task, &task, sizeof(task_t));

            struct tm tm_copy;
            memcpy(&tm_copy, &task.when, sizeof(struct tm));
            job.start_time = mktime(&tm_copy);
            job.end_time   = job.start_time + duration_secs;

            job_queue_push(&neg_state.task_stack, &job);

            generic_msg_t accept = {0};
            _build_reply(nmsg, NEG_PROTO_ACCEPT, &accept);
            json_t *aj = _task_to_json(proc, &task);
            if (aj)
            {
                net_msg_pack_json(&accept.info.net_msg, aj);
                json_decref(aj);
            }
            messaging_send("network", NET_MESSAGE, &accept, false);
        }
    }
    else
    {
        /* Not capable — refuse */
        log_info(proc->logger,
                 "Negotiation: capability '%s' not available, refusing task %s\n",
                 task.capability.name, task_uuid_str);

        generic_msg_t refuse = {0};
        _build_reply(nmsg, NEG_PROTO_REFUSE, &refuse);
        json_t *rj = _task_to_json(proc, &task);
        if (rj)
        {
            net_msg_pack_json(&refuse.info.net_msg, rj);
            json_decref(rj);
        }
        messaging_send("network", NET_MESSAGE, &refuse, false);
    }

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_haggle (haggle) — NEG_PROTO_RESPONSE
 * If task is flexible, re-announce with adjusted params; otherwise refuse.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_haggle(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: haggle response from %s\n", nmsg->from_whom.nickname);

    /* Deserialize counter-offer task from payload */
    json_t *j = NULL;
    task_t task;
    memset(&task, 0, sizeof(task));

    bool have_task = false;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        if (_task_from_json(j, &task) == 0)
            have_task = true;
        json_decref(j);
    }

    if (have_task && task.flexible)
    {
        /* Re-announce with the adjusted schedule proposed by the peer */
        log_info(proc->logger,
                 "Negotiation: re-announcing flexible task with adjusted params\n");

        /* A fresh stamp: this is a NEW invitation, carrying the schedule we
         * just conceded, and the peer's mark has already consumed the
         * sequence of the first one. Reusing it would have the peer refuse
         * the resolution as a replay -- correctly, since it cannot tell the
         * two apart otherwise. Mirrors Python handle_haggle. */
        pthread_mutex_lock(&neg_state.lock);
        task.seq = freshness_stamp(&neg_state.freshness, proc->logger);
        pthread_mutex_unlock(&neg_state.lock);
        if (task.seq <= 0)
        {
            log_warn(proc->logger,
                     "Negotiation: no freshness sequence; not re-announcing\n");
            return true;
        }

        json_t *rj = _task_to_json(proc, &task);
        generic_msg_t announce = {0};
        _build_reply(nmsg, NEG_PROTO_ANNOUNCE, &announce);
        if (rj)
        {
            net_msg_pack_json(&announce.info.net_msg, rj);
            json_decref(rj);
        }
        messaging_send("network", NET_MESSAGE, &announce, false);
    }
    else
    {
        /* Not flexible (or no payload) — refuse the counter-offer */
        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        if (have_task)
            uuid_unparse_lower(task.uuid, task_uuid_str);

        log_info(proc->logger,
                 "Negotiation: task not flexible, refusing counter-offer for %s\n",
                 task_uuid_str);

        generic_msg_t refuse = {0};
        _build_reply(nmsg, NEG_PROTO_REFUSE, &refuse);
        json_t *rj = _task_to_json(proc, &task);
        if (rj)
        {
            net_msg_pack_json(&refuse.info.net_msg, rj);
            json_decref(rj);
        }
        messaging_send("network", NET_MESSAGE, &refuse, false);
    }

    return true;
}

/****************************
 * Helper: _cancel_participant
 *
 * Mirrors Python's _cancel_participant (negprocess.py:182-188). Drops
 * the peer's pending slot from the tracker's results map and decrements
 * the expected-participant count. If the remaining count falls below
 * what we need to satisfy the task, surfaces the cancellation through
 * the same log path handle_refuse uses.
 *
 * TODO (divergence.md M5 follow-up): Python additionally posts a
 * partial-result dict to `queues[CfgIds.main]` so the main process can
 * react to a sub-quorum cancellation in real time. The C build does
 * not yet route partial results back to main as a typed IPC message —
 * it requires a new `generic_msg_t` variant (e.g.
 * `negotiation_partial_result_t`) plus a NEG_PARTIAL_RESULT message
 * type and a sender hook here. Out of scope until a main-side consumer
 * needs the signal.
 *
 * Caller MUST hold neg_state.lock.
 ****************************/
static void _cancel_participant(const process_t *proc,
                                task_tracker_t *tracker,
                                const char *task_uuid_str,
                                const uuid_t peer_uuid)
{
    if (tracker == NULL)
        return;

    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, peer_str);

    /* Python only deletes the slot if it's still pending (None). The C
     * tracker->results map stores result bytes; an absent or NULL entry
     * is the equivalent of "still pending". Always remove the entry —
     * if the peer already submitted a result, dropping it would be
     * wrong, but in that case the result_data is non-NULL and we leave
     * it. Mirror Python's `if result[uuid] is None: del result[uuid]`. */
    data_t *cur = NULL;
    if (map_get(&tracker->results, peer_str, &cur) == 0 && cur != NULL) {
        ptr_t ptr = NULL;
        data_object_ptr(cur, &ptr);
        if (ptr == NULL)  /* pending — drop it */
            map_remove(&tracker->results, peer_str);
    } else {
        /* Entry was never created (e.g. participant never accepted).
         * No-op — keeps the helper safe to call from both refuse and
         * dead/zombie status paths. */
    }

    /* Drop the per-(task, peer) confirmation marker so a subsequent
     * stat_resp from this peer won't be mistaken for confirmed and
     * extend a timeout we've already cancelled them out of. */
    char pair_key[UUID_STRING_LEN * 2 + 4];
    snprintf(pair_key, sizeof(pair_key), "%s:%s",
             task_uuid_str ? task_uuid_str : "", peer_str);
    map_remove(&neg_state.confirmed_pairs, pair_key);

    /* Quorum-check parity with handle_refuse's existing log lines. */
    tracker->expected--;
    int collected = task_tracker_result_count(tracker);
    if (tracker->expected <= 0 && collected == 0)
        log_error(proc->logger,
                  "Negotiation: all peers refused/cancelled task %s — "
                  "no participants\n",
                  task_uuid_str ? task_uuid_str : "?");
    else if (tracker->expected < 1)
        log_warn(proc->logger,
                 "Negotiation: insufficient participants remaining for "
                 "task %s (cancelled %s)\n",
                 task_uuid_str ? task_uuid_str : "?", peer_str);
}

/****************************
 * Handler: handle_refuse (nack) — NEG_PROTO_REFUSE
 * Extract task UUID, decrement expected count in tracker; log failure if insufficient.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_refuse(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: refused by %s\n", nmsg->from_whom.nickname);

    pthread_mutex_lock(&neg_state.lock);

    /* Extract task_uuid from payload */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        uuid_t parsed_uuid;
        if (_py_uuid_read(json_object_get(j, "uuid"), parsed_uuid) == 0)
        {
            uuid_unparse_lower(parsed_uuid, task_uuid_str);
            have_task_uuid = true;
        }
        json_decref(j);
    }

    if (have_task_uuid)
    {
        /* Look up tracker in my_tasks; drop the refusing peer and run
         * the quorum-impact log via _cancel_participant. Mirrors
         * Python's handle_refuse → _cancel_participant chain
         * (negprocess.py:225-233). */
        data_t *trk_dat = NULL;
        if (map_get(&neg_state.my_tasks, task_uuid_str, &trk_dat) == 0 && trk_dat)
        {
            task_tracker_t *tracker = NULL;
            if (data_object_ptr(trk_dat, (ptr_t *)&tracker) == 0 && tracker)
                _cancel_participant(proc, tracker, task_uuid_str,
                                    nmsg->from_whom.uuid);
        }
    }

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_accept (ack) — NEG_PROTO_ACCEPT
 * Extract task_uuid from payload; track count of confirmed peers per task.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: accepted by %s\n", nmsg->from_whom.nickname);

    pthread_mutex_lock(&neg_state.lock);

    /* Extract task_uuid from payload */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        uuid_t parsed_uuid;
        if (_py_uuid_read(json_object_get(j, "uuid"), parsed_uuid) == 0)
        {
            uuid_unparse_lower(parsed_uuid, task_uuid_str);
            have_task_uuid = true;
        }
        json_decref(j);
    }

    /* Keyed by task UUID, count confirmed peer acceptances */
    char key[UUID_STRING_LEN + 1];
    if (have_task_uuid)
        strncpy(key, task_uuid_str, UUID_STRING_LEN);
    else
        strncpy(key, "unknown", UUID_STRING_LEN);
    key[UUID_STRING_LEN] = '\0';

    /* Per-peer membership entry. Composite key "<task>:<peer>" so
     * handle_stat_resp can answer the Python check
     * `message.from_whom in self.confirmed[task.uuid]`
     * (negprocess.py:271) without restructuring the count map below.
     *
     * Established BEFORE the count, because it is what makes the count
     * dedup: one participant, one promise. An `ack` carries nothing that
     * separates a second delivery from a second promise, so a replayed one
     * used to increment the tally again and inflate the number of peers
     * believed to have committed to the task. The pair map was already
     * set-like (map_set on the same key is idempotent), so it is the
     * natural place to ask "have we counted this peer yet". Mirrors
     * Python NegotiationProcess.handle_accept's dedup on self.confirmed. */
    bool already_confirmed = false;
    if (have_task_uuid)
    {
        char peer_lower[UUID_STRING_LEN + 1];
        uuid_unparse_lower(nmsg->from_whom.uuid, peer_lower);
        char pair_key[UUID_STRING_LEN * 2 + 4];
        snprintf(pair_key, sizeof(pair_key), "%s:%s", task_uuid_str, peer_lower);
        data_t *existing_pair = NULL;
        if (map_get(&neg_state.confirmed_pairs, pair_key, &existing_pair) == 0
            && existing_pair != NULL)
            already_confirmed = true;
        else
        {
            data_t *marker = integer_data(1);
            if (marker != NULL)
                map_set(&neg_state.confirmed_pairs, pair_key, marker);
        }
    }

    data_t *count_dat = NULL;
    int count = 0;
    if (map_get(&neg_state.confirmed, key, &count_dat) == 0 && count_dat)
        data_integer(count_dat, &count);

    /* No task uuid means no pair key and so no dedup is possible; that
     * degenerate path keeps its previous behaviour rather than silently
     * dropping the acceptance. */
    if (!already_confirmed)
    {
        count++;
        data_t *new_count = integer_data(count);
        map_set(&neg_state.confirmed, key, new_count);
    }

    log_debug(proc->logger,
              "Negotiation: task %s now has %d confirmed peer(s)\n",
              key, count);

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_stat_req (status request) — NEG_PROTO_STAT_REQ
 * Look up task in task_stack, reply with current status.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_stat_req(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status request from %s\n", nmsg->from_whom.nickname);

    /* The request payload is a whole serialized Task, not a bare uuid -- the
     * response is a TaskStatus, which subclasses Task and so has to carry the
     * task's own fields back. Python's handle_stat_req builds it the same way
     * (`TaskStatus(message.obj, ...)`, from the task it was sent). */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    task_t task;
    memset(&task, 0, sizeof(task));
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        if (_task_from_json(j, &task) == 0)
        {
            uuid_unparse_lower(task.uuid, task_uuid_str);
            have_task_uuid = true;
        }
        json_decref(j);
    }

    /* Determine status. A task sitting on the task_stack has been queued
     * but has not yet been picked up by an executor, so the correct status
     * is `pending`, not `running`. Returning RUNNING here causes the
     * requestor's clock-sync detector (handle_stat_resp:269 on the Python
     * side) to miss the discrepancy. Mirrors negprocess.py:238-239. */
    neg_status_t status = NEG_UNKNOWN;
    if (have_task_uuid)
    {
        pthread_mutex_lock(&neg_state.lock);
        if (job_queue_contains(&neg_state.task_stack, task.uuid))
            status = NEG_PENDING;
        pthread_mutex_unlock(&neg_state.lock);
    }

    /* Build response JSON: Python's tagged TaskStatus (doc/architecture/negotiation.md). The
     * status rides as the `Enumcfg:` member NAME, which is what
     * config_json_decoder reconstructs the enum from -- an integer would
     * deserialize as a plain int and `handle_stat_resp`'s
     * `isinstance(task, TaskStatus)` would never see a status it understands. */
    json_t *resp_json = _task_status_to_json(proc, &task, status);

    generic_msg_t resp = {0};
    _build_reply(nmsg, NEG_PROTO_STAT_RSP, &resp);
    if (resp_json)
    {
        net_msg_pack_json(&resp.info.net_msg, resp_json);
        json_decref(resp_json);
    }

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Handler: handle_stat_resp (status response) — NEG_PROTO_STAT_RSP
 * Update tracking: extend timeout if active; log cancellation if dead.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_stat_resp(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status response from %s\n", nmsg->from_whom.nickname);

    pthread_mutex_lock(&neg_state.lock);

    json_t *j = NULL;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        neg_status_t status = NEG_UNKNOWN;

        uuid_t parsed_uuid;
        if (_py_uuid_read(json_object_get(j, "uuid"), parsed_uuid) == 0)
            uuid_unparse_lower(parsed_uuid, task_uuid_str);

        /* The `Enumcfg:` member NAME, which is how Python serializes an enum.
         * An integer is still accepted so a hand-written conformance step can
         * pin a status without spelling out the tag. */
        json_t *j_status = json_object_get(j, "status");
        if (json_is_integer(j_status))
            status = (neg_status_t)json_integer_value(j_status);
        else
            status = _py_status_value(_py_tagged_str(j_status));

        json_decref(j);

        /* Look up the task tracker */
        data_t *trk_dat = NULL;
        task_tracker_t *tracker = NULL;
        if (map_get(&neg_state.my_tasks, task_uuid_str, &trk_dat) == 0 && trk_dat)
            data_object_ptr(trk_dat, (ptr_t *)&tracker);

        switch (status)
        {
            case NEG_RUNNING:
            case NEG_SLEEPING:
            case NEG_PENDING:
            {
                /* Clock-sync error log on PENDING — mirrors Python's
                 * `if task.status == Status.pending: logger.error(...)`
                 * at negprocess.py:269-270. The remote claims the task
                 * is still queued; if we asked for status we expected
                 * it to be at least running, so our clocks differ. */
                if (status == NEG_PENDING)
                    log_error(proc->logger,
                              "Negotiation: clock synchronization error "
                              "with %s (task %s still pending)\n",
                              nmsg->from_whom.nickname, task_uuid_str);

                /* Confirmation-prereq guard (C11) — only extend timeout
                 * for peers that have ack'd this task. Mirrors Python's
                 * `if task.uuid in self.confirmed and message.from_whom
                 *    in self.confirmed[task.uuid]` test in
                 * negprocess.py:271. */
                bool peer_confirmed = false;
                {
                    char peer_lower[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(nmsg->from_whom.uuid, peer_lower);
                    char pair_key[UUID_STRING_LEN * 2 + 4];
                    snprintf(pair_key, sizeof(pair_key), "%s:%s",
                             task_uuid_str, peer_lower);
                    data_t *m = NULL;
                    if (map_get(&neg_state.confirmed_pairs, pair_key, &m) == 0
                        && m != NULL)
                        peer_confirmed = true;
                }

                /* Locate the live task in neg_state.proposed_tasks —
                 * tracker_t doesn't carry the task body in C (the
                 * proto'd task lives there instead). */
                task_t *live_task = NULL;
                {
                    data_t *t_dat = NULL;
                    if (map_get(&neg_state.proposed_tasks, task_uuid_str,
                                &t_dat) == 0 && t_dat != NULL)
                        data_object_ptr(t_dat, (ptr_t *)&live_task);
                }

                /* An extension is authorised by an OUTSTANDING status
                 * request, and the pending entry IS that authorisation:
                 * draining it here is what stops a replayed (or entirely
                 * unsolicited) status response from extending the deadline
                 * again. Mirrors Python's handle_stat_resp. EVERY matching
                 * slot is drained rather than the first — two slots for one
                 * task would be two extension tokens. An already-drained
                 * slot holds "" and cannot match a real uuid, so this is
                 * naturally idempotent.
                 *
                 * NOTE: this runtime has no status-request SENDER yet
                 * (NEG_PROTO_STAT_REQ is handled, never emitted), so nothing
                 * appends to status_pending and the gate below is currently
                 * always the refusal path. That is the correct behaviour
                 * meanwhile: with no request outstanding there is no
                 * extension to authorise. When a requester side lands it
                 * must append the task uuid at its send site, the way
                 * Python's process() loop does. */
                bool had_pending = false;
                for (size_t i = 0; i < array_size(&neg_state.status_pending); i++)
                {
                    data_t *item = NULL;
                    if (array_get(&neg_state.status_pending, i, &item) != 0)
                        continue;
                    char *stored = NULL;
                    if (data_string_ptr(item, &stored) == 0 && stored
                        && strncmp(stored, task_uuid_str, UUID_STRING_LEN) == 0)
                    {
                        stored[0] = '\0';
                        had_pending = true;
                    }
                }

                if (tracker && peer_confirmed && live_task && had_pending) {
                    /* Compute the extension. Mirrors Python's
                     * three-way choice at negprocess.py:273-277.
                     * Order matters: explicit timeout wins over
                     * duration-derived; both fall back to the class
                     * default. */
                    long extend = NEG_TIMEOUT_EXTENSION_SEC;
                    if (live_task->timeout > 0) {
                        extend = live_task->timeout;
                    } else {
                        long dur_secs = live_task->duration.seconds
                                      + (long)live_task->duration.days * 86400L;
                        if (dur_secs > 0)
                            extend = (dur_secs * NEG_DURATION_FRACTION_PCT) / 100L + 1L;
                    }
                    live_task->timeout += extend;
                    log_debug(proc->logger,
                              "Negotiation: task %s active (status=%d), "
                              "extending timeout by %lds (peer %s)\n",
                              task_uuid_str, (int)status, extend,
                              nmsg->from_whom.nickname);
                } else if (tracker && peer_confirmed && live_task) {
                    log_debug(proc->logger,
                              "Negotiation: stat_resp for task %s with no "
                              "outstanding status request — not extending "
                              "timeout\n",
                              task_uuid_str);
                } else if (tracker && !peer_confirmed) {
                    log_debug(proc->logger,
                              "Negotiation: stat_resp from unconfirmed peer "
                              "%s for task %s — not extending timeout\n",
                              nmsg->from_whom.nickname, task_uuid_str);
                }
                break;
            }

            case NEG_DEAD:
            case NEG_ZOMBIE:
            case NEG_STOPPED:
            case NEG_NO_PEERS:
            case NEG_REJECTED:
                log_warn(proc->logger,
                         "Negotiation: task %s cancelled/dead/rejected (status=%d)\n",
                         task_uuid_str, (int)status);
                /* Cancel-participant parity with Python's
                 * `handle_stat_resp` dead/zombie/stopped branch
                 * (negprocess.py:280-284). */
                if (tracker)
                    _cancel_participant(proc, tracker, task_uuid_str,
                                        nmsg->from_whom.uuid);
                break;

            case NEG_UNKNOWN:
            default:
                log_debug(proc->logger,
                          "Negotiation: task %s unknown status %d\n",
                          task_uuid_str, (int)status);
                break;
        }

        /* Remove task_uuid from status_pending list */
        for (size_t i = 0; i < array_size(&neg_state.status_pending); i++)
        {
            data_t *item = NULL;
            if (array_get(&neg_state.status_pending, i, &item) != 0)
                continue;
            char *stored = NULL;
            if (data_string_ptr(item, &stored) == 0 && stored
                && strncmp(stored, task_uuid_str, UUID_STRING_LEN) == 0)
            {
                /* Found; mark by zeroing the string so it is effectively removed */
                stored[0] = '\0';
                break;
            }
        }
    }

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Requestor-side scoring of a returned task result (R+D.md §12.7 / §12.8)
 ****************************/

/* Pull the probe challenge out of the requestor's OWN retained kwargs. Never
 * from the responder's reply: see task_tracker_t. @p payload_buf backs the
 * echo token, because probe_challenge_t holds a non-owning pointer. */
static void _challenge_from_kwargs(const char *kwargs_json,
                                   char *payload_buf, size_t payload_len,
                                   probe_challenge_t *out)
{
    out->nonce = 0;
    out->payload = NULL;
    payload_buf[0] = '\0';
    if (kwargs_json == NULL || kwargs_json[0] == '\0')
        return;
    json_error_t jerr;
    json_t *kw = json_loads(kwargs_json, 0, &jerr);
    if (kw == NULL)
        return;
    if (json_is_object(kw))
    {
        json_t *j_nonce = json_object_get(kw, "nonce");
        if (j_nonce && json_is_integer(j_nonce))
            out->nonce = (long)json_integer_value(j_nonce);
        json_t *j_payload = json_object_get(kw, "payload");
        if (j_payload && json_is_string(j_payload))
        {
            at_strlcpy(payload_buf, json_string_value(j_payload), payload_len);
            out->payload = payload_buf;
        }
    }
    json_decref(kw);
}

/* Monotonic seconds, the clock both the prober's window and the physics
 * layer's observation window are measured on. CLOCK_MONOTONIC rather than the
 * wall clock because both are measuring elapsed intervals, and a step
 * adjustment mid-window would otherwise invent a rate violation out of an NTP
 * correction. Falls back to time(2) only where the monotonic clock is
 * unavailable. Mirrors Python's time.monotonic(). */
static double _now_sec(void)
{
    struct timespec ts;
    return (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        ? (double)ts.tv_sec + (double)ts.tv_nsec / 1e9
        : (double)time(NULL);
}

/* The process-wide physical-consistency checker (R+D.md §12.2), built from
 * $AT_PHYSICS on first call and empty when that is unset. File-static: the
 * only caller is the scorer below, and the conformance adapter deliberately
 * builds its OWN checker so each scenario starts with an empty observation
 * window rather than inheriting the previous one's. */
static at_physics_checker_t *_physics_checker(void)
{
    _ensure_init();
    if (!neg_state.physics_loaded)
    {
        /* Built once, from $AT_PHYSICS. A malformed declaration is fatal at
         * load (physics.c says why) but must not take down the scoring path on
         * every subsequent result: the failure is recorded once and the layer
         * stays OFF, which is the same end state as never having configured
         * it. Mirrors Python automate.physics_checker(). */
        at_physics_model_t model;
        char err[AT_PHYS_ERR_LEN] = {0};
        if (!at_physics_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "physics: declaration rejected, layer stays OFF: %s\n",
                      err);
            at_physics_model_parse(NULL, &model, NULL, 0);
        }
        at_physics_checker_init(&neg_state.physics, &model);
        neg_state.physics_loaded = true;
    }
    return &neg_state.physics;
}

/* The process-wide coverage auditor (R+D.md §12.4). Mirrors Python
 * automate.calibration_auditor(): a malformed declaration is fatal at load but
 * must not take down the scoring path on every subsequent result, so the
 * failure is logged once and the layer stays off. */
static at_calibration_auditor_t *_calibration_auditor(void)
{
    if (!neg_state.calibration_loaded)
    {
        at_calibration_model_t model;
        char err[AT_CAL_ERR_LEN] = {0};
        if (!at_calibration_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "calibration: declaration rejected, layer stays "
                            "OFF: %s\n", err);
            at_calibration_model_parse(NULL, &model, NULL, 0);
        }
        at_calibration_auditor_init(&neg_state.calibration, &model);
        neg_state.calibration_loaded = true;
    }
    return &neg_state.calibration;
}

/* The §12.5 estimator, built on first use. Same load policy as the two layers
 * above (mirrors Python automate.prequential_estimator): a rejected
 * declaration is logged and the layer stays OFF rather than taking the scoring
 * path down with it, because a node that cannot learn a weighting must still
 * be able to score a task. */
static at_prequential_estimator_t *_prequential_estimator(void)
{
    if (!neg_state.prequential_loaded)
    {
        at_prequential_model_t model;
        char err[AT_PREQ_ERR_LEN] = {0};
        if (!at_prequential_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "prequential: declaration rejected, layer stays "
                            "OFF: %s\n", err);
            at_prequential_model_parse(NULL, &model, NULL, 0);
        }
        at_prequential_estimator_init(&neg_state.prequential, &model);
        neg_state.prequential_loaded = true;
    }
    return &neg_state.prequential;
}

/* The declared quantity a capability REPORTS, or NULL. Walks the physics model
 * rather than asking the calibration one: the link lives in physics.json (each
 * quantity names its reporting capability), and keeping the lookup here is what
 * lets the calibration module stay independent of the physics one -- a node can
 * run the audit with no physics declaration at all and resolve predictions
 * through at_calibration_settle instead. */
static const char *_reported_quantity(const char *capability)
{
    if (capability == NULL || capability[0] == '\0')
        return NULL;
    const at_physics_checker_t *physics = _physics_checker();
    for (int i = 0; i < physics->model.n_quantities; i++)
        if (strcmp(physics->model.quantities[i].capability, capability) == 0)
            return physics->model.quantities[i].name;
    return NULL;
}

/* Score one returned result and name the evidence channel it came from.
 * Exported (declared in negotiation.h) so tests and the conformance adapter
 * pin the same function production uses, rather than a copy of its rules.
 *
 * Mirrors the requestor-side branch of Python automate.py's TaskResult
 * handling, minus the ZKP arm: this runtime attaches no proofs, so it is
 * always Python's "ZKP unavailable" case -- score on the fact the task came
 * back with something, and say `task_outcome` so that an absent proof
 * infrastructure does not read as a failed one.
 *
 * A known-answer probe is checked FIRST and subsumes the completion score: for
 * a capability whose right answer we already hold, "it came back" is not the
 * question. A tampered or fabricated answer lands on 0.1 here rather than the
 * 0.3 a dud task gets, and carries the `probe` channel so "failed a challenge
 * whose answer we knew" stays distinguishable downstream from "scored badly on
 * a task" when both are the same number.
 *
 * Physical consistency (R+D.md §12.2) sits between the two: a claim that is
 * impossible, or that no consistent story leaves honest, reports `physical`
 * (0.1); a peer implicated by a conflict that does not name it uniquely
 * reports `swarm_disagreement` (0.3). That layer only ever refutes -- passing
 * it earns nothing -- so a claim it has nothing to say about falls through to
 * the completion arm below, unchanged. */
/* The process-wide certificate declaration, built from $AT_CERTIFICATES on
 * first call and empty when that is unset. A malformed declaration is fatal at
 * load (certificates.c says why) but must not take down the scoring path on
 * every subsequent result: the failure is recorded once and the layer stays
 * OFF, which is the same end state as never having configured it.
 *
 * Emits the inventory once, here. That report is the other half of what
 * R+D.md §12.3 asks for: a node that silently falls through to completion
 * scoring for everything it cannot check looks, from outside, exactly like a
 * node checking everything, and the expensive case is only "recognized" if
 * somebody can see it. Mirrors Python automate.certificate_verifier(). */
static const at_cert_model_t *_certificate_model(void)
{
    _ensure_init();
    if (!neg_state.certificates_loaded)
    {
        char err[AT_CERT_ERR_LEN] = {0};
        if (!at_cert_model_load(NULL, &neg_state.certificates, err, sizeof(err)))
        {
            log_error(NULL,
                      "certificates: declaration rejected, layer stays OFF: %s\n",
                      err);
            at_cert_model_parse(NULL, &neg_state.certificates, NULL, 0);
        }
        neg_state.certificates_loaded = true;
        if (at_cert_model_enabled(&neg_state.certificates))
        {
            at_cert_inv_row_t rows[AT_CERT_MAX_CAPABILITIES];
            int n = at_cert_inventory(&neg_state.certificates, NULL, 0,
                                      rows, AT_CERT_MAX_CAPABILITIES);
            if (n > 0)
            {
                char report[4096];
                at_cert_inventory_format(rows, n, report, sizeof(report));
                log_info(NULL, "%s\n", report);
            }
        }
    }
    return &neg_state.certificates;
}

double negotiation_score_task_result(const char *cap_name,
                                    const char *kwargs_json,
                                    const char *result_str, size_t result_len,
                                    const char *certificate_json,
                                    const char *prediction_json,
                                    const char *subject, double now,
                                    uint64_t seed,
                                    const char **channel_out)
{
    const char *channel_sink = NULL;
    if (channel_out == NULL)
        channel_out = &channel_sink;
    if (cap_name != NULL && cap_name[0] != '\0' && is_probe_capability(cap_name))
    {
        char payload_buf[TASK_KWARGS_LEN + 1];
        probe_challenge_t challenge;
        _challenge_from_kwargs(kwargs_json, payload_buf,
                               sizeof(payload_buf), &challenge);
        /* A numeric answer arrives as its decimal text (at.handshake,
         * at.time-attest). A reply that is not a number at all becomes NaN,
         * not 0: the verifiers treat non-finite as "unparseable" and score it
         * 0.1, where 0.0 would be a finite wrong answer -- and for
         * at.time-attest a finite 0 is "forgivable drift" (0.5), so parsing
         * prose as zero would grade a nonsense reply more kindly than a late
         * clock. Python's verifiers reach 0.1 through float() raising on the
         * same input; this is that behaviour in C. */
        double result_num = NAN;
        if (result_str != NULL && result_str[0] != '\0')
        {
            char *parse_end = NULL;
            double parsed = strtod(result_str, &parse_end);
            /* Whole-string parse only: "42abc" is not 42. */
            if (parse_end != NULL && *parse_end == '\0')
                result_num = parsed;
        }
        double score = 0.0;
        if (verify_bootstrap_result(cap_name, result_num, result_str,
                                    &challenge, 0.0, &score))
        {
            *channel_out = TX_CHANNEL_PROBE;
            return score;
        }
    }

    /* Physical consistency (R+D.md §12.2), after the known-answer probe and
     * before every other arm. A probe holds the exact right answer, which
     * strictly subsumes asking whether the answer is possible; everything
     * BELOW this point is a judgment about completion, which is what
     * doc/verification_oracle.md means by running the claim against physics
     * first. It speaks only to refute -- a claim that merely survives the
     * check earns nothing here -- so a NONE verdict falls through to the
     * completion arm unchanged. */
    {
        at_physics_checker_t *physics = _physics_checker();
        if (at_physics_checker_enabled(physics))
        {
            double phys_score = 0.0;
            char reason[AT_PHYS_ERR_LEN] = {0};
            at_physics_verdict_t verdict = at_physics_check(
                physics, cap_name, result_str, subject, now, &phys_score,
                reason, sizeof(reason));
            if (verdict == AT_PHYSICS_REFUTED)
            {
                log_warn(NULL, "physics: REFUTED (%s)\n", reason);
                *channel_out = TX_CHANNEL_PHYSICAL;
                return phys_score;
            }
            if (verdict == AT_PHYSICS_IMPLICATED)
            {
                log_info(NULL, "physics: %s\n", reason);
                *channel_out = TX_CHANNEL_SWARM_DISAGREEMENT;
                return phys_score;
            }
        }
    }

    /* Coverage audit, half one (R+D.md §12.4): let this result RESOLVE
     * predictions other peers made about the quantity it reports.
     *
     * Here, and not with the verdict arm below, because the two halves answer
     * different questions. This one asks "is this result evidence about the
     * world", and the answer stops being yes the moment physics refutes it --
     * settling an honest forecaster's prediction against a refuted observation
     * would let a lying reporter convict it. Everything past the physics arm
     * is un-refuted and usable, including a result whose own certificate arm
     * is about to score it: a wrong answer to THIS task is still a
     * measurement. Mirrors Python automate.score_task_result. */
    {
        at_calibration_auditor_t *auditor = _calibration_auditor();
        if (at_calibration_enabled(auditor))
        {
            const char *quantity = _reported_quantity(cap_name);
            if (quantity != NULL)
            {
                int settled = at_calibration_settle_result(
                    auditor, quantity, result_str, subject, now);
                if (settled > 0)
                    log_debug(NULL, "calibration: resolved %d outstanding "
                                    "prediction(s) about %s\n",
                              settled, quantity);
            }
        }
    }

    /* Prequential competence (R+D.md §12.5), both halves, here and not lower
     * down. This layer renders NO verdict -- it produces the weight
     * multiplier `negotiation_competence_weight` reads when the score is
     * submitted -- so it has no place in the arm ORDER below, and putting it
     * there would make the record depend on which other layer happened to
     * speak first: a forecast attached to a reply whose certificate arm is
     * about to score it still has to be recorded.
     *
     * After physics for the same reason the coverage audit's settle is: a
     * refuted observation must not resolve an honest forecaster's forecast,
     * and a refuted result records no forecast of its own either, since a
     * claim physics has refuted is not evidence in either direction.
     *
     * Settle before observe, so a peer forecasting the same quantity it just
     * reported is weighted against a record including everything this result
     * settled. Mirrors Python automate.score_task_result. */
    {
        at_prequential_estimator_t *est = _prequential_estimator();
        if (at_prequential_enabled(est))
        {
            const char *quantity = _reported_quantity(cap_name);
            if (quantity != NULL)
            {
                int resolved = at_prequential_settle_result(
                    est, quantity, result_str, subject, now);
                if (resolved > 0)
                    log_debug(NULL, "prequential: resolved %d outstanding "
                                    "forecast(s) about %s\n",
                              resolved, quantity);
            }
            json_t *pred = NULL;
            if (prediction_json != NULL && prediction_json[0] != '\0')
            {
                json_error_t perr;
                pred = json_loads(prediction_json, 0, &perr);
            }
            at_prequential_observe(est, cap_name, pred, subject, now);
            if (pred != NULL)
                json_decref(pred);
        }
    }

    /* Certificate-carrying interfaces (R+D.md §12.3), after physics and before
     * the completion arm. After physics because a witness proves the answer
     * satisfies the problem AS STATED, which says nothing about whether the
     * statement was physically coherent.
     *
     * This is the one layer that can return a GOOD score, and that is not an
     * inconsistency with the physics layer above it. Surviving a feasibility
     * test means "not refuted"; a witness that checks out means "proved
     * right", and declining to say so would discard the strongest positive
     * evidence this node can obtain. */
    {
        const at_cert_model_t *certs = _certificate_model();
        if (at_cert_model_enabled(certs))
        {
            char why[AT_CERT_ERR_LEN] = {0};
            at_cert_verdict_t verdict = at_cert_evaluate(
                certs, cap_name, result_str, certificate_json, kwargs_json,
                seed, why, sizeof(why));
            if (verdict == AT_CERT_VALID || verdict == AT_CERT_INVALID ||
                verdict == AT_CERT_ABSENT)
            {
                if (verdict == AT_CERT_VALID)
                    log_info(NULL, "certificates: %s verified (%s)\n",
                             cap_name ? cap_name : "-",
                             at_cert_verdict_name(verdict));
                else
                    log_warn(NULL, "certificates: %s %s: %s\n",
                             cap_name ? cap_name : "-",
                             at_cert_verdict_name(verdict), why);
                *channel_out = TX_CHANNEL_CERTIFICATE;
                return at_cert_score(verdict);
            }
            /* INDETERMINATE is OUR record failing, never the peer's fault, so
             * it falls through unscored. */
        }
    }

    /* Coverage audit, half two (R+D.md §12.4): judge the peer's CLAIM about
     * how often answers of this kind land inside the set it quotes.
     *
     * After the certificate arm because an exact check of THIS answer outranks
     * a statistical claim about a hundred of them: where a capability is both
     * certified and predictive, the witness settles what happened here, and
     * `calibration` carries the baseline weight against `certificate`'s 3.
     * Before the completion arm for the same reason physics is -- "it came
     * back" says nothing about whether the peer's account of its own
     * reliability is true.
     *
     * Falsification only: a peer that has not been caught over-claiming earns
     * nothing here, so a NONE verdict falls through to the completion arm. */
    {
        at_calibration_auditor_t *auditor = _calibration_auditor();
        if (at_calibration_enabled(auditor))
        {
            json_t *pred = NULL;
            if (prediction_json != NULL && prediction_json[0] != '\0')
            {
                json_error_t perr;
                pred = json_loads(prediction_json, 0, &perr);
            }
            double cal_score = 0.0;
            char why[AT_CAL_ERR_LEN] = {0};
            at_cal_verdict_t verdict = at_calibration_assess(
                auditor, cap_name, pred, subject, now, &cal_score,
                why, sizeof(why));
            if (pred != NULL)
                json_decref(pred);
            if (verdict != AT_CAL_NONE)
            {
                log_warn(NULL, "calibration: %s\n", why);
                *channel_out = TX_CHANNEL_CALIBRATION;
                return cal_score;
            }
        }
    }

    *channel_out = TX_CHANNEL_TASK_OUTCOME;
    return (result_str != NULL && result_len > 0) ? 0.8 : 0.3;
}

double negotiation_competence_weight(const char *cap_name, const char *subject)
{
    at_prequential_estimator_t *est = _prequential_estimator();
    if (!at_prequential_enabled(est))
        return AT_PREQ_NEUTRAL_COMPETENCE;
    return at_prequential_competence(est, subject, cap_name);
}

/* Submit a requestor-side score to the reputation process, which resolves our
 * own identity as the proposer and starts a Paxos round (rep_proc.c
 * _handle_local_tx_score). Mirrors automate.py putting a TransactionScore on
 * the reputation queue. The capability name rides along so the reputation
 * process can apply the capability's configured transaction_weight instead of
 * the weight-1 default. */
static void _submit_tx_score(const process_t *proc, const uuid_t task_uuid,
                             double score, const char *capability_name,
                             const char *channel, const uuid_t subject_uuid,
                             double competence)
{
    generic_msg_t msg = {0};
    msg.type = TRANSACTION_SCORE;
    msg.size = sizeof(tx_score_msg_t);
    uuid_copy(msg.info.tx_score.task_uuid, task_uuid);
    /* peer_uuid is the SUBJECT -- the peer this score is ABOUT, not the
     * proposer (the reputation process fills our own identity in for that,
     * since it owns our half of the bilateral transaction). It is what lets a
     * hard-channel refutation name the peer it accuses (R+D.md §12.8), and it
     * is IPC-only, so a score that arrives from the wire can never carry one.
     * Zero when the result is not attributable to a single peer. */
    if (subject_uuid != NULL)
        uuid_copy(msg.info.tx_score.peer_uuid, subject_uuid);
    msg.info.tx_score.score = score;
    /* The learned EMA weight multiplier (R+D.md §12.5), measured HERE -- this
     * is the process holding the record of resolved forecasts -- and applied
     * in the reputation process, which owns the weighted EMA. Local-only on
     * the same terms as peer_uuid above: the struct never crosses the wire, so
     * no peer can stamp a multiplier on a score about itself. */
    msg.info.tx_score.competence = competence;
    if (capability_name != NULL)
        at_strlcpy(msg.info.tx_score.capability_name, capability_name,
                   sizeof(msg.info.tx_score.capability_name));
    if (channel != NULL)
        at_strlcpy(msg.info.tx_score.channel, channel,
                   sizeof(msg.info.tx_score.channel));
    if (messaging_send("reputation", TRANSACTION_SCORE, &msg, false) != 0)
        log_warn(proc->logger,
                 "Negotiation: could not submit score %.2f (via %s)\n",
                 score, (channel != NULL) ? channel : "-");
}

/****************************
 * Handler: handle_results (report results) — NEG_PROTO_RESULT
 * Collect result, forward to main process when all results arrive.
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_results(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: results from %s\n", nmsg->from_whom.nickname);

    pthread_mutex_lock(&neg_state.lock);

    json_t *j = NULL;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        uuid_t task_uuid;
        bool have_task_uuid = false;

        if (_py_uuid_read(json_object_get(j, "uuid"), task_uuid) == 0)
        {
            uuid_unparse_lower(task_uuid, task_uuid_str);
            have_task_uuid = true;
        }

        /* Extract raw result bytes (base64-encoded string or omitted) */
        const uint8_t *result_data = NULL;
        size_t result_len = 0;
        /* The witness that makes the answer checkable (R+D.md §12.3), in its
         * OWN payload key: a reader that does not know the checker still reads
         * the answer, and nobody has to sniff bytes to tell a witness from a
         * result. Absent for every capability that does not certify, which is
         * most of them. */
        const char *certificate_json = NULL;
        json_t *j_cert = json_object_get(j, "certificate");
        if (json_is_object(j_cert))
        {
            static _Thread_local char cert_buf[AT_CERT_ERR_LEN * 16];
            char *dumped = json_dumps(j_cert, JSON_COMPACT);
            if (dumped != NULL)
            {
                if (strlen(dumped) < sizeof(cert_buf))
                {
                    at_strlcpy(cert_buf, dumped, sizeof(cert_buf));
                    certificate_json = cert_buf;
                }
                free(dumped);
            }
        }
        /* `result` is Python's TaskResult field, and it holds whatever the
         * capability returned -- an int from `pow`, a string from `echo` --
         * so it is flattened to the text this runtime scores against rather
         * than required to be a string. */
        static _Thread_local char result_buf[CAP_RESULT_LEN * 4 + 1];
        /* The peer's prediction set and claimed coverage (R+D.md §12.4), in
         * its OWN payload key for the same reason `certificate` is: `result`
         * is the answer, the witness makes the answer checkable, and this is
         * the peer's statement about how often answers of this kind land
         * inside the set it quotes. Only the last is a claim about the PEER
         * rather than about this answer. */
        const char *prediction_json = NULL;
        json_t *j_pred = json_object_get(j, "prediction");
        if (json_is_object(j_pred))
        {
            static _Thread_local char pred_buf[AT_CAL_ERR_LEN * 8];
            char *dumped = json_dumps(j_pred, JSON_COMPACT);
            if (dumped != NULL)
            {
                if (strlen(dumped) < sizeof(pred_buf))
                {
                    at_strlcpy(pred_buf, dumped, sizeof(pred_buf));
                    prediction_json = pred_buf;
                }
                free(dumped);
            }
        }
        json_t *j_result = json_object_get(j, "result");
        if (_py_result_text(j_result, result_buf, sizeof(result_buf)))
        {
            result_data = (const uint8_t *)result_buf;
            result_len  = strlen(result_buf);
        }

        if (have_task_uuid)
        {
            /* Look up tracker */
            data_t *trk_dat = NULL;
            task_tracker_t *tracker = NULL;
            if (map_get(&neg_state.my_tasks, task_uuid_str, &trk_dat) == 0 && trk_dat)
                data_object_ptr(trk_dat, (ptr_t *)&tracker);

            if (tracker)
            {
                /* Record the result from this peer */
                task_tracker_set_result(tracker, nmsg->from_whom.uuid,
                                        result_data, result_len);

                int collected = task_tracker_result_count(tracker);
                log_debug(proc->logger,
                          "Negotiation: task %s collected %d/%d results\n",
                          task_uuid_str, collected, tracker->expected);

                /* If all expected results have arrived, score and forward.
                 *
                 * Scored here rather than in the main process, where Python
                 * scores it: the judgment needs what the requestor asked for,
                 * and this is the process that retained it. Carrying the
                 * capability name and the challenge onward through
                 * task_result_msg_t would have meant widening an IPC struct
                 * that the CFFI mirror also declares, to move a fact that is
                 * already in hand here. One score per completed task, from
                 * the last result to arrive, which is what Python's
                 * handle_results forwards. */
                if (collected >= tracker->expected)
                {
                    log_info(proc->logger,
                             "Negotiation: task %s complete — forwarding results\n",
                             task_uuid_str);

                    const char *channel = TX_CHANNEL_TASK_OUTCOME;
                    /* The subject is the peer the physics layer files this
                     * observation under, and it must be the SAME peer the
                     * score is submitted against just below -- a fan-out is
                     * unattributable, so both pass NULL and the layer runs
                     * only the checks that need no identity. Filing several
                     * peers' claims under one key would manufacture conflicts
                     * between a peer and itself. */
                    char subject_buf[UUID_STRING_LEN + 1] = {0};
                    const char *subject = NULL;
                    if (tracker->expected == 1)
                    {
                        uuid_unparse_lower(nmsg->from_whom.uuid, subject_buf);
                        subject = subject_buf;
                    }
                    double score = negotiation_score_task_result(
                        tracker->capability_name, tracker->kwargs_json,
                        (const char *)result_data, result_len,
                        certificate_json, prediction_json, subject,
                        _now_sec(), at_cert_verifier_seed(), &channel);
                    log_info(proc->logger,
                             "Negotiation: task %s scored %.2f (cap %s, via %s)\n",
                             task_uuid_str, score,
                             tracker->capability_name[0] != '\0'
                                 ? tracker->capability_name : "-",
                             channel);
                    /* The executor, from the AUTHENTICATED sender of the
                     * reply -- and only for a single-participant task: the
                     * results of a fan-out arrive from several peers and only
                     * the last to answer carries the object that gets scored,
                     * so naming it would attribute the whole task's outcome to
                     * whoever happened to reply last. Mirrors Python
                     * TaskResult.attach_executor. */
                    /* The competence multiplier for the SAME peer the
                     * score is filed against: a fan-out has no subject, so it
                     * carries no learned weight either -- there is no single
                     * peer whose record it would be. */
                    _submit_tx_score(proc, task_uuid, score,
                                     tracker->capability_name, channel,
                                     (tracker->expected == 1)
                                         ? nmsg->from_whom.uuid : NULL,
                                     negotiation_competence_weight(
                                         tracker->capability_name, subject));

                    /* Build TASK_RESULT message to the main (requestor) process */
                    generic_msg_t result_msg;
                    memset(&result_msg, 0, sizeof(result_msg));
                    result_msg.type = TASK_RESULT;
                    uuid_copy(result_msg.info.task_result.task_uuid, task_uuid);
                    uuid_copy(result_msg.info.task_result.requestor_uuid,
                              nmsg->from_whom.uuid);
                    result_msg.info.task_result.result_data = (uint8_t *)result_data;
                    result_msg.info.task_result.result_len  = result_len;

                    messaging_send(AT_MAIN_QUEUE, TASK_RESULT, &result_msg, false);

                    /* Clean up tracker entry */
                    map_remove(&neg_state.my_tasks, task_uuid_str);
                    task_tracker_free(tracker);
                }
            }
            else
            {
                log_warn(proc->logger,
                         "Negotiation: received results for unknown task %s\n",
                         task_uuid_str);
            }
        }

        json_decref(j);
    }

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Worker side: run accepted jobs and report their results
 *
 * Until this existed, `job_queue_pop` had no caller in the whole tree: an
 * accepted invitation was pushed onto the task stack and sat there. No C node
 * ever executed a task, so none ever reported a result, and the requestor-side
 * scoring above had nothing to score. That is what "no C node scores a probe
 * end to end" meant (R+D.md §12.7).
 ****************************/

/* This node's own identity, from the process's config map. Same shape as the
 * reputation process's _resolve_self_uuid. */
static const identity_t *_self_identity(const process_t *proc)
{
    if (proc == NULL || proc->configs == NULL)
        return NULL;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) != 0 || id_dat == NULL)
        return NULL;
    config_t *id_cfg = NULL;
    if (data_object_ptr(id_dat, (void **)&id_cfg) != 0 || id_cfg == NULL
        || id_cfg->data_struct == NULL)
        return NULL;
    return (const identity_t *)id_cfg->data_struct;
}

/* Copy the peer record for @p peer_uuid into @p out. Takes the peers read
 * lock itself, so callers must not already hold it. */
static bool _peer_by_uuid(const process_t *proc, const uuid_t peer_uuid,
                          public_identity_t *out)
{
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, peer_uuid) == 0)
        {
            memcpy(out, &proc->protocol.peers[i], sizeof(public_identity_t));
            found = true;
            break;
        }
    }
    peers_read_unlock(proc);
    return found;
}

/* Report a finished job's answer to the peer that asked for it, as Python's
 * tagged TaskResult -- the one form both runtimes read (doc/architecture/negotiation.md). */
static void _report_result(const process_t *proc, const task_t *task,
                           const char *result)
{
    public_identity_t requestor;
    memset(&requestor, 0, sizeof(requestor));
    if (!_peer_by_uuid(proc, task->requestor_uuid, &requestor))
    {
        char req_str[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(task->requestor_uuid, req_str);
        log_warn(proc->logger,
                 "Negotiation: cannot report results, requestor %s unknown\n",
                 req_str);
        return;
    }

    /* A certifying capability wraps its answer with the witness (R+D.md
     * §12.3); split them here so the reply carries the two in SEPARATE keys,
     * exactly as Python's executor unwraps `Certified`. An ordinary capability
     * is unwrapped and this is a no-op. */
    char value_buf[CAP_RESULT_LEN + 1] = {0};
    char cert_buf[CAP_RESULT_LEN + 1] = {0};
    const char *answer = result;
    json_t *j_cert = NULL;
    if (at_cert_split_result(result, value_buf, sizeof(value_buf),
                             cert_buf, sizeof(cert_buf)))
    {
        answer = value_buf;
        if (cert_buf[0] != '\0')
        {
            json_error_t cert_err;
            j_cert = json_loads(cert_buf, 0, &cert_err);
        }
    }
    /* No prediction: no C capability emits one yet (see the serializer). */
    json_t *j = _task_result_to_json(proc, task, answer, j_cert, NULL);
    if (j == NULL)
    {
        log_error(proc->logger, "Negotiation: json_object OOM (report)\n");
        return;
    }

    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    out.info.net_msg.function = NEG_PROTO_RESULT;
    out.info.net_msg.encrypt = true;
    memcpy(&out.info.net_msg.to_whom, &requestor, sizeof(public_identity_t));
    strncpy(out.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);
    net_msg_pack_json(&out.info.net_msg, j);
    json_decref(j);

    messaging_send("network", NET_MESSAGE, &out, false);
}

/* Execute every job whose start time has arrived, report each answer, and
 * submit our own (executor) half of the bilateral transaction.
 *
 * Executed inline on the process loop rather than on a thread: these
 * capabilities are pure functions of their arguments, and a thread per job
 * would need a completion channel back to this loop for no gain. A capability
 * that blocks belongs behind `task_run`'s detached-thread path, which stays as
 * it was for the fire-and-forget shape.
 *
 * The 0.9 executor score mirrors automate.py's `_handle_results`: it is our
 * claim to have done the work, and it is the requestor's own score for the
 * same task that decides what the work was worth. */
static void _drain_task_stack(const process_t *proc)
{
    time_t now_sec = time(NULL);
    for (;;)
    {
        job_t job;
        memset(&job, 0, sizeof(job));
        bool have_job = false;

        pthread_mutex_lock(&neg_state.lock);
        job_t peek;
        memset(&peek, 0, sizeof(peek));
        /* Peek before popping: a job scheduled for later must stay queued,
         * and the queue is start-time ordered, so the earliest not being due
         * means none is. */
        if (job_queue_min(&neg_state.task_stack, &peek) == 0
            && peek.start_time <= now_sec
            && job_queue_pop(&neg_state.task_stack, &job) == 0)
            have_job = true;
        pthread_mutex_unlock(&neg_state.lock);

        if (!have_job)
            break;

        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(job.task.uuid, task_uuid_str);

        /* A node with AT_BOOTSTRAP_DISABLED advertises no probe capability, so
         * it should not answer one either -- an invitation that arrived before
         * the peer's capability view caught up is dropped rather than
         * answered. */
        if (is_probe_capability(job.task.capability.name)
            && !bootstrap_capabilities_enabled())
        {
            log_debug(proc->logger,
                      "Negotiation: bootstrap disabled; dropping job %s (%s)\n",
                      task_uuid_str, job.task.capability.name);
            continue;
        }

        capability_t *cap = find_capability(job.task.capability.name);
        if (cap == NULL)
        {
            log_warn(proc->logger,
                     "Negotiation: accepted job %s names unknown capability "
                     "'%s'; reporting no result\n",
                     task_uuid_str, job.task.capability.name);
            _report_result(proc, &job.task, NULL);
            continue;
        }

        char result[CAP_RESULT_LEN + 1] = {0};
        int rc = capability_execute_result(cap, job.task.kwargs_json,
                                          result, sizeof(result));
        if (rc != 0)
        {
            /* No result-producing entry point (the fire-and-forget shape) or
             * the capability failed. Run the void form if there is one, so a
             * legacy capability still does its work, and report nothing.
             *
             * The requestor then scores that as an empty return (0.3), which
             * is worth being explicit about because it is a judgment and not
             * an accident: a capability that cannot answer leaves the
             * requestor with nothing, and the alternative -- staying silent --
             * leaves it waiting on a tracker that never completes. Reporting
             * an empty result is the honest half of a bad trade. No capability
             * in the tree is in this shape today (`data` declares neither
             * entry point and does its real work as a subscription, not a
             * task), so this is the path for a future one. */
            if (cap->function != NULL)
                task_run(&job.task);
            log_debug(proc->logger,
                      "Negotiation: job %s (%s) produced no result (rc=%d)\n",
                      task_uuid_str, job.task.capability.name, rc);
            _report_result(proc, &job.task, NULL);
            continue;
        }

        log_info(proc->logger, "Negotiation: job %s (%s) done\n",
                 task_uuid_str, job.task.capability.name);
        _report_result(proc, &job.task, result);
        /* Executor side, scoring our own completion: no subject, and none
         * needed -- task_outcome is not slash-eligible. */
        /* No subject, so no learned weight: competence is a fact about a
         * peer's forecasting record, and this score is about our own
         * completion. Neutral == the authored transaction_weight verbatim. */
        _submit_tx_score(proc, job.task.uuid, 0.9, job.task.capability.name,
                         TX_CHANNEL_TASK_OUTCOME, NULL,
                         AT_PREQ_NEUTRAL_COMPETENCE);
    }
}

/****************************
 * Prober side: the bootstrap corpus, during the window and after it
 *
 * Python runs this as its own BootstrapWorker process, which posts a `start`
 * message onto the negotiation queue. Here it rides the negotiation loop
 * directly: the sink it needs is the announce path, and this is the process
 * that owns it. Same probes, same allocation rules, one less process.
 ****************************/

/* Context for the two emit sinks below. */
typedef struct {
    const process_t *proc;
    size_t peer_count;
} probe_ctx_t;

/* Build and announce one bootstrap task. @p target_index, when >= 0, addresses
 * a single peer (a probe); < 0 fans out to every capable peer (a window pair).
 * Takes neg_state.lock, so the caller must not hold it. */
static bool _emit_bootstrap_task(const probe_ctx_t *ctx, const char *cap_name,
                                 long nonce, const char *echo_payload,
                                 int target_index)
{
    const process_t *proc = ctx->proc;
    const identity_t *self = _self_identity(proc);

    task_t task;
    memset(&task, 0, sizeof(task));
    uuid_generate(task.uuid);
    if (self != NULL)
        uuid_copy(task.requestor_uuid, self->uuid);
    at_strlcpy(task.capability.name, cap_name, sizeof(task.capability.name));
    task.flexible = true;
    /* Now, and briefly: a probe that a peer schedules for later is a probe
     * whose answer arrives after the question stopped being interesting. */
    time_t now_sec = time(NULL);
    struct tm *tm_ptr = gmtime(&now_sec);
    if (tm_ptr != NULL)
        memcpy(&task.when, tm_ptr, sizeof(struct tm));
    task.duration.days = 0;
    task.duration.seconds = 1;
    task.timeout = 30;

    /* The challenge. This is the requestor's copy and the only one that will
     * be trusted when the answer comes back; _announce_task_locked hands it to
     * the tracker. Keys match Python BootstrapWorker._build_task_args, because
     * the responder reads them by name.
     *
     * Built through jansson rather than printf'd: the payload is a generated
     * token today, but hand-interpolating a string into JSON is the shape that
     * breaks the moment one contains a quote or a backslash, and a malformed
     * challenge is a probe that scores an honest peer 0.1. */
    json_t *kw = json_object();
    if (kw != NULL)
    {
        if (strcmp(cap_name, "at.handshake") == 0)
            json_object_set_new(kw, "nonce", json_integer((json_int_t)nonce));
        else if (echo_payload != NULL && echo_payload[0] != '\0')
            json_object_set_new(kw, "payload", json_string(echo_payload));
        if (json_object_size(kw) > 0)
        {
            char *dumped = json_dumps(kw, JSON_COMPACT | JSON_SORT_KEYS);
            if (dumped != NULL)
            {
                if (strlen(dumped) < sizeof(task.kwargs_json))
                    at_strlcpy(task.kwargs_json, dumped,
                               sizeof(task.kwargs_json));
                free(dumped);
            }
        }
        json_decref(kw);
    }
    /* A challenge that did not fit (or could not be built) would be sent as no
     * challenge at all, and the responder would answer the default one and be
     * scored wrong for it. Refuse to issue the probe instead. */
    if (strcmp(cap_name, "at.time-attest") != 0 && task.kwargs_json[0] == '\0')
    {
        log_warn(proc->logger,
                 "Negotiation: no challenge built for %s; probe not issued\n",
                 cap_name);
        return false;
    }

    uuid_t target;
    uuid_clear(target);
    if (target_index >= 0)
    {
        if ((size_t)target_index >= ctx->peer_count)
            return false;
        peers_read_lock(proc);
        if ((size_t)target_index < proc->protocol.num_peers)
            uuid_copy(target, proc->protocol.peers[target_index].uuid);
        peers_read_unlock(proc);
        /* The peer set can shrink between the worker's choice and this read;
         * a probe with no addressee is not issued rather than fanned out. */
        if (uuid_is_null(target))
            return false;
    }

    pthread_mutex_lock(&neg_state.lock);
    _announce_task_locked(proc, &task, target);
    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

static bool _pair_emit(void *vctx, const char *cap_name, long nonce,
                       const char *echo_payload)
{
    return _emit_bootstrap_task((const probe_ctx_t *)vctx, cap_name, nonce,
                                echo_payload, -1);
}

static bool _probe_emit(void *vctx, const char *cap_name, size_t peer_index,
                        long nonce, const char *echo_payload)
{
    return _emit_bootstrap_task((const probe_ctx_t *)vctx, cap_name, nonce,
                                echo_payload, (int)peer_index);
}

/* One pass of the bootstrap worker: open the window when peers first appear,
 * emit pairs while it is open, and issue rate-limited directed probes
 * thereafter (bootstrap_worker_tick_all). */
static void _bootstrap_tick(const process_t *proc)
{
    if (neg_state.bootstrap.disabled)
        return;
    peers_read_lock(proc);
    size_t peer_count = proc->protocol.num_peers;
    peers_read_unlock(proc);
    if (peer_count == 0)
        return;

    probe_ctx_t ctx = { .proc = proc, .peer_count = peer_count };
    double now_sec = _now_sec();
    bootstrap_worker_tick_all(&neg_state.bootstrap, peer_count, now_sec,
                              _pair_emit, _probe_emit, &ctx);
}

/****************************
 * Handler: handle_tier_lost (tier_lost) — local IPC from reputation
 *
 * Cancel in-flight tasks the affected peer is no longer authorized
 * to participate in. Mirrors Python's
 * NegotiationProcess.handle_tier_lost (negprocess.py); see
 * doc/architecture/trust-tiers.md §7.2.
 *
 * Walks two surfaces:
 * - task_stack (worker side): jobs scheduled to execute on the
 *   demoted peer's behalf. Cancelled in place if
 *   capability.required_tier > new_tier.
 * - my_tasks   (requestor side): trackers for tasks I've requested
 *   from peers. The C task_tracker_t does not carry the source
 *   capability, so we look the task back up via proposed_tasks (keyed
 *   by uuid_str). For locally-spawned tasks the lookup succeeds; for
 *   foreign tasks (impossible in current C flows, but the python side
 *   handles it via the tracker's own .capability) we skip — better
 *   to keep the tracker than over-aggressively drop a participant
 *   based on guessed metadata.
 ****************************/

/* Frama-C: skipped —
 * handle_tier_lost: JSON unpack + map iteration + compaction;
 * exceeds solver budget like other handlers in this file.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_tier_lost(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    /* Payload is a 2-element JSON array [uuid_str, new_tier] —
     * matches _publish_tier_change's tier_lost emission and Python
     * repprocess.py's to_json_string((key, new_tier)). */
    json_t *payload = NULL;
    if (nmsg->obj == NULL || nmsg->len == 0 ||
        net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Negotiation: handle_tier_lost: no payload\n");
        return true;
    }
    if (!json_is_array(payload) || json_array_size(payload) < 2)
    {
        log_warn(proc->logger, "Negotiation: handle_tier_lost: bad payload shape\n");
        json_decref(payload);
        return true;
    }
    json_t *j_uuid = json_array_get(payload, 0);
    json_t *j_tier = json_array_get(payload, 1);
    if (!json_is_string(j_uuid) || !json_is_integer(j_tier))
    {
        log_warn(proc->logger, "Negotiation: handle_tier_lost: bad field types\n");
        json_decref(payload);
        return true;
    }
    const char *peer_uuid_in = json_string_value(j_uuid);
    int new_tier = (int)json_integer_value(j_tier);

    char peer_uuid_str[UUID_STRING_LEN + 1] = {0};
    strncpy(peer_uuid_str, peer_uuid_in, UUID_STRING_LEN);
    uuid_t target_uuid;
    if (uuid_parse(peer_uuid_str, target_uuid) != 0)
    {
        log_warn(proc->logger,
                 "Negotiation: handle_tier_lost: bad uuid %s\n", peer_uuid_str);
        json_decref(payload);
        return true;
    }

    int cancelled = 0;
    pthread_mutex_lock(&neg_state.lock);

    /* Worker side: compact task_stack in place, dropping jobs whose
     * requestor matches the demoted peer AND whose capability's
     * required_tier no longer fits. required_tier is read from the
     * conformance per-process override (if installed) or
     * find_capability() — same source as handle_invite's gate. */
    job_queue_t *q = &neg_state.task_stack;
    int write_idx = 0;
    for (int read_idx = 0; read_idx < q->count; read_idx++)
    {
        job_t *job = &q->jobs[read_idx];
        int required_tier = _cap_required_tier_override_locked(
            proc, job->task.capability.name);
        if (required_tier < 0)
        {
            capability_t *own = find_capability(job->task.capability.name);
            required_tier = (own != NULL)
                ? own->required_tier
                : job->task.capability.required_tier;
        }
        bool peer_match = (uuid_compare(job->task.requestor_uuid, target_uuid) == 0);
        if (peer_match && required_tier > new_tier)
        {
            char tuuid[UUID_STRING_LEN + 1];
            uuid_unparse_lower(job->task.uuid, tuuid);
            log_info(proc->logger,
                     "Negotiation: cancelling task %s — requestor %s tier %d < required %d\n",
                     tuuid, peer_uuid_str, new_tier, required_tier);
            cancelled++;
            continue;  /* skip writing this job */
        }
        if (write_idx != read_idx)
            memmove(&q->jobs[write_idx], &q->jobs[read_idx], sizeof(job_t));
        write_idx++;
    }
    q->count = write_idx;

    /* Requestor side: walk my_tasks, drop the demoted peer from any
     * tracker whose source task has required_tier > new_tier. Use
     * proposed_tasks (keyed by task_uuid_str) to fetch the original
     * task_t for the capability lookup — task_tracker_t doesn't
     * carry the capability directly. */
    map_t *mt = &neg_state.my_tasks;
    array_t *keys = map_keys(mt);
    if (keys != NULL)
    {
        size_t nkeys = array_size(keys);
        for (size_t i = 0; i < nkeys; i++)
        {
            data_t *k_dat = NULL;
            if (array_get(keys, i, &k_dat) != 0 || k_dat == NULL) continue;
            char *task_uuid_str = NULL;
            if (data_string_ptr(k_dat, &task_uuid_str) != 0 || task_uuid_str == NULL)
                continue;

            data_t *trk_dat = NULL;
            task_tracker_t *tracker = NULL;
            if (map_get(mt, task_uuid_str, &trk_dat) != 0 || trk_dat == NULL)
                continue;
            if (data_object_ptr(trk_dat, (ptr_t *)&tracker) != 0 || tracker == NULL)
                continue;

            /* Fetch the original task to get its capability. If the
             * task is foreign (not in our proposed_tasks), we don't
             * know the required_tier locally — skip rather than
             * guess. Mirrors the conservative branch in
             * negprocess.py:handle_tier_lost.my_tasks. */
            data_t *task_dat = NULL;
            task_t *orig_task = NULL;
            if (map_get(&neg_state.proposed_tasks, task_uuid_str, &task_dat) != 0
                || task_dat == NULL)
                continue;
            if (data_object_ptr(task_dat, (ptr_t *)&orig_task) != 0 || orig_task == NULL)
                continue;

            int required_tier = _cap_required_tier_override_locked(
                proc, orig_task->capability.name);
            if (required_tier < 0)
            {
                capability_t *own = find_capability(orig_task->capability.name);
                required_tier = (own != NULL)
                    ? own->required_tier
                    : orig_task->capability.required_tier;
            }
            if (required_tier <= new_tier)
                continue;  /* still authorised */

            /* Drop the demoted peer if present. tracker->results keys
             * are uuid-strings (uuid_unparse_lower form). */
            if (map_get(&tracker->results, peer_uuid_str, &k_dat) == 0)
            {
                map_remove(&tracker->results, peer_uuid_str);
                cancelled++;
                log_info(proc->logger,
                         "Negotiation: dropped %s from task %s — tier %d < required %d\n",
                         peer_uuid_str, task_uuid_str, new_tier, required_tier);
            }
            /* If the tracker is now empty, treat the task as fully
             * cancelled: forward a TASK_RESULT with empty payload
             * (the requestor's main process disambiguates by uuid)
             * and remove the tracker. */
            if (tracker->expected > 0
                && map_size(&tracker->results) == 0)
            {
                generic_msg_t cancel_msg;
                memset(&cancel_msg, 0, sizeof(cancel_msg));
                cancel_msg.type = TASK_RESULT;
                uuid_copy(cancel_msg.info.task_result.task_uuid, orig_task->uuid);
                uuid_copy(cancel_msg.info.task_result.requestor_uuid,
                          orig_task->requestor_uuid);
                cancel_msg.info.task_result.result_data = NULL;
                cancel_msg.info.task_result.result_len  = 0;
                messaging_send(AT_MAIN_QUEUE, TASK_RESULT, &cancel_msg, false);

                map_remove(mt, task_uuid_str);
                task_tracker_free(tracker);
            }
        }
    }

    pthread_mutex_unlock(&neg_state.lock);

    if (cancelled > 0)
        log_info(proc->logger,
                 "Negotiation: tier_lost on %s -> %d: %d task(s)/peer(s) cancelled\n",
                 peer_uuid_str, new_tier, cancelled);

    json_decref(payload);
    return true;
}

/****************************
 * Negotiation process main entry
 ****************************/

/* Frama-C: skipped —
 * negotiation_run + handlers + helpers: [solver-timeout] memcpy of public_identity_t (9
 * sites) + JSON serialization + capability iteration + complex peer-loop msg-build
 * cascades.
 */
int negotiation_get_task_stack_size(void)
{
    if (!neg_state.initialized) return -1;
    pthread_mutex_lock(&neg_state.lock);
    int n = job_queue_count(&neg_state.task_stack);
    pthread_mutex_unlock(&neg_state.lock);
    return n;
}

bool negotiation_has_confirmed_any(void)
{
    if (!neg_state.initialized) return false;
    pthread_mutex_lock(&neg_state.lock);
    bool any = map_size(&neg_state.confirmed) > 0;
    pthread_mutex_unlock(&neg_state.lock);
    return any;
}

bool negotiation_has_my_task_uuid(const uuid_t uuid)
{
    if (!neg_state.initialized) return false;
    char key[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(uuid, key);
    pthread_mutex_lock(&neg_state.lock);
    data_t *dat = NULL;
    bool found = (map_get(&neg_state.my_tasks, key, &dat) == 0 && dat != NULL);
    pthread_mutex_unlock(&neg_state.lock);
    return found;
}

int negotiation_get_task_flood_count(const uuid_t uuid)
{
    if (!neg_state.initialized) return 0;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(uuid, task_uuid_str);
    /* Mirror the key construction in handle_invite (neg_proc.c:529-530):
     * "flood:<task-uuid>" stored on proposed_tasks. */
    char flood_key[UUID_STRING_LEN + 8];
    snprintf(flood_key, sizeof(flood_key), "flood:%s", task_uuid_str);
    pthread_mutex_lock(&neg_state.lock);
    data_t *flood_dat = NULL;
    int count = 0;
    if (map_get(&neg_state.proposed_tasks, flood_key, &flood_dat) == 0 && flood_dat)
        data_integer(flood_dat, &count);
    pthread_mutex_unlock(&neg_state.lock);
    return count;
}

int negotiation_register_handlers(process_t *proc)
{
    if (proc == NULL) return -1;
    process_register_handler(proc, NEG_PROTO_START,    (handler_ptr_t)handle_start_task);
    process_register_handler(proc, NEG_PROTO_ANNOUNCE, (handler_ptr_t)handle_invite);
    process_register_handler(proc, NEG_PROTO_RESPONSE, (handler_ptr_t)handle_haggle);
    process_register_handler(proc, NEG_PROTO_ACCEPT,   (handler_ptr_t)handle_accept);
    process_register_handler(proc, NEG_PROTO_REFUSE,   (handler_ptr_t)handle_refuse);
    process_register_handler(proc, NEG_PROTO_STAT_REQ, (handler_ptr_t)handle_stat_req);
    process_register_handler(proc, NEG_PROTO_STAT_RSP, (handler_ptr_t)handle_stat_resp);
    process_register_handler(proc, NEG_PROTO_RESULT,   (handler_ptr_t)handle_results);
    /* Tier-down task cancellation (trust-tiers.md §7.2). Local IPC
     * from ReputationProcess on demotion; not a wire-facing
     * protocol message but registered the same way so the protocol
     * dispatch table routes it. */
    process_register_handler(proc, ID_TIER_LOST,      (handler_ptr_t)handle_tier_lost);
    return 0;
}

int negotiation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();
    negotiation_register_handlers(proc);
    proc->protocol.phase = 1;

    /* Custom loop = process_loop plus the two periodic duties this process
     * gained: running the jobs it accepted, and issuing the bootstrap
     * corpus's challenges. Both sit at the documented "sub-process specific
     * post-message activity" hook point, and both run on every pass rather
     * than only when a message arrived -- process_loop `continue`s past that
     * hook on an empty queue, which is exactly when a queued job is waiting.
     * Same shape as data_source_run. */
    process_ctx_t ctx = {0};
    int err = process_setup(proc, signal, logger, &ctx);
    if (err != 0)
        return err;

    while (keep_running(proc, &ctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        int rerr = messaging_recv(&buf);
        if (rerr != -1 && rerr != ENOMSG)
            run_message_handlers(proc, queues, buf.type, &buf);

        _drain_task_stack(proc);
        _bootstrap_tick(proc);
    }

    if (ctx.fd1 > 0)
        close(ctx.fd1);
    if (ctx.fd2 > 0)
        close(ctx.fd2);
    return 0;
}
DECLARE_PROCESS(negotiation, neg_proc, negotiation_run);
