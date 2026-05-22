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

#include <string.h>
#include <pthread.h>

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
 * Helper: build a JSON payload containing just task_uuid
 ****************************/

static json_t *_task_uuid_json(const char *task_uuid_str)
{
    json_t *j = json_object();
    if (j)
        json_object_set_new(j, "task_uuid", json_string(task_uuid_str));
    return j;
}

/****************************
 * Helper: serialize task_t fields into a JSON object
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
static json_t *_task_to_json(const task_t *task)
{
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    char req_uuid_str[UUID_STRING_LEN + 1] = {0};

    uuid_unparse_lower(task->uuid, task_uuid_str);
    uuid_unparse_lower(task->requestor_uuid, req_uuid_str);

    /* duration in total seconds (days*86400 + seconds) */
    long duration_sec = task->duration.days * 86400L + (long)task->duration.seconds;

    /* when as epoch seconds (mktime on embedded tm) */
    struct tm tm_copy;
    memcpy(&tm_copy, &task->when, sizeof(struct tm));
    time_t when_sec = mktime(&tm_copy);

    json_t *j = json_object();
    if (!j)
        return NULL;

    json_object_set_new(j, "task_uuid",       json_string(task_uuid_str));
    json_object_set_new(j, "requestor_uuid",  json_string(req_uuid_str));
    json_object_set_new(j, "capability_name", json_string(task->capability.name));
    json_object_set_new(j, "flexible",        json_boolean(task->flexible));
    json_object_set_new(j, "timeout",         json_integer(task->timeout));
    json_object_set_new(j, "when_sec",        json_integer((json_int_t)when_sec));
    json_object_set_new(j, "duration_sec",    json_integer((json_int_t)duration_sec));

    return j;
}

/****************************
 * Helper: populate a task_t from a JSON object (partial – fills uuid, cap name, flexible, timeout)
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
static int _task_from_json(const json_t *j, task_t *task)
{
    if (!j || !task)
        return -1;

    const char *task_uuid_str = NULL;
    json_t *j_uuid = json_object_get(j, "task_uuid");
    if (j_uuid && json_is_string(j_uuid))
    {
        task_uuid_str = json_string_value(j_uuid);
        if (uuid_parse(task_uuid_str, task->uuid) != 0)
            return -1;
    }

    json_t *j_req = json_object_get(j, "requestor_uuid");
    if (j_req && json_is_string(j_req))
        uuid_parse(json_string_value(j_req), task->requestor_uuid);

    json_t *j_cap = json_object_get(j, "capability_name");
    if (j_cap && json_is_string(j_cap))
        strncpy(task->capability.name, json_string_value(j_cap), CAP_NAMELEN);

    json_t *j_flex = json_object_get(j, "flexible");
    if (j_flex && json_is_boolean(j_flex))
        task->flexible = json_boolean_value(j_flex);

    json_t *j_timeout = json_object_get(j, "timeout");
    if (j_timeout && json_is_integer(j_timeout))
        task->timeout = (long)json_integer_value(j_timeout);

    json_t *j_when = json_object_get(j, "when_sec");
    if (j_when && json_is_integer(j_when))
    {
        time_t when_sec = (time_t)json_integer_value(j_when);
        struct tm *tm_ptr = gmtime(&when_sec);
        if (tm_ptr)
            memcpy(&task->when, tm_ptr, sizeof(struct tm));
    }

    json_t *j_dur = json_object_get(j, "duration_sec");
    if (j_dur && json_is_integer(j_dur))
    {
        long dur = (long)json_integer_value(j_dur);
        task->duration.days    = dur / 86400L;
        task->duration.seconds = (unsigned int)(dur % 86400L);
        task->duration.nsecs   = 0;
    }

    return 0;
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
static bool handle_start_task(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: start task from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

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

    /* Store task in proposed_tasks keyed by task UUID string */
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(task.uuid, task_uuid_str);

    task_t *task_copy = (task_t *)malloc(sizeof(task_t));
    if (task_copy)
    {
        memcpy(task_copy, &task, sizeof(task_t));
        data_t *task_dat = object_ptr_data(task_copy, sizeof(task_t));
        map_set(&neg_state.proposed_tasks, task_uuid_str, task_dat);
    }

    /* Create a task tracker for result collection (expect num_peers responses) */
    task_tracker_t *tracker = NULL;
    peers_read_lock(proc);
    int expected = (int)proc->protocol.num_peers;
    peers_read_unlock(proc);
    if (task_tracker_create(&tracker, task.uuid, expected) == 0 && tracker)
    {
        data_t *trk_dat = object_ptr_data(tracker, sizeof(task_tracker_t));
        map_set(&neg_state.my_tasks, task_uuid_str, trk_dat);
    }

    /* Build JSON payload for invitation */
    json_t *invite_json = _task_to_json(&task);

    /* Send invitation to capable peers */
    int invited = 0;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char peer_uuid_str[UUID_STRING_LEN + 1] = {0};
        uuid_unparse_lower(proc->protocol.peers[i].uuid, peer_uuid_str);

        /* Filter by capability if peer_capabilities map is available */
        if (!_peer_has_capability(proc, peer_uuid_str, task.capability.name))
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

    if (invited == 0)
        log_warn(proc->logger, "Negotiation: no capable peers found for task %s\n",
                 task_uuid_str);

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
    log_info(proc->logger, "Negotiation: invitation from %s\n", nmsg->from_whom.fullname);

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
            json_t *rj = _task_uuid_json(task_uuid_str);
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
        json_t *rj = _task_uuid_json(task_uuid_str);
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
            json_t *hj = _task_to_json(&task);
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
            json_t *aj = _task_uuid_json(task_uuid_str);
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
        json_t *rj = _task_uuid_json(task_uuid_str);
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
    log_debug(proc->logger, "Negotiation: haggle response from %s\n", nmsg->from_whom.fullname);

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

        json_t *rj = _task_to_json(&task);
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
        json_t *rj = _task_uuid_json(task_uuid_str);
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
    log_info(proc->logger, "Negotiation: refused by %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* Extract task_uuid from payload */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        json_t *j_uuid = json_object_get(j, "task_uuid");
        if (j_uuid && json_is_string(j_uuid))
        {
            strncpy(task_uuid_str, json_string_value(j_uuid), UUID_STRING_LEN);
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
    log_info(proc->logger, "Negotiation: accepted by %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* Extract task_uuid from payload */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        json_t *j_uuid = json_object_get(j, "task_uuid");
        if (j_uuid && json_is_string(j_uuid))
        {
            strncpy(task_uuid_str, json_string_value(j_uuid), UUID_STRING_LEN);
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

    data_t *count_dat = NULL;
    int count = 0;
    if (map_get(&neg_state.confirmed, key, &count_dat) == 0 && count_dat)
        data_integer(count_dat, &count);

    count++;
    data_t *new_count = integer_data(count);
    map_set(&neg_state.confirmed, key, new_count);

    /* Per-peer membership entry. Composite key "<task>:<peer>" so
     * handle_stat_resp can answer the Python check
     * `message.from_whom in self.confirmed[task.uuid]`
     * (negprocess.py:271) without restructuring the count map above. */
    if (have_task_uuid)
    {
        char peer_lower[UUID_STRING_LEN + 1];
        uuid_unparse_lower(nmsg->from_whom.uuid, peer_lower);
        char pair_key[UUID_STRING_LEN * 2 + 4];
        snprintf(pair_key, sizeof(pair_key), "%s:%s", task_uuid_str, peer_lower);
        data_t *marker = integer_data(1);
        if (marker != NULL)
            map_set(&neg_state.confirmed_pairs, pair_key, marker);
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
    log_debug(proc->logger, "Negotiation: status request from %s\n", nmsg->from_whom.fullname);

    /* Extract task UUID from payload */
    json_t *j = NULL;
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_t task_uuid;
    bool have_task_uuid = false;

    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        json_t *j_uuid = json_object_get(j, "task_uuid");
        if (j_uuid && json_is_string(j_uuid))
        {
            strncpy(task_uuid_str, json_string_value(j_uuid), UUID_STRING_LEN);
            if (uuid_parse(task_uuid_str, task_uuid) == 0)
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
        if (job_queue_contains(&neg_state.task_stack, task_uuid))
            status = NEG_PENDING;
        pthread_mutex_unlock(&neg_state.lock);
    }

    /* Build response JSON */
    json_t *resp_json = json_object();
    if (resp_json)
    {
        json_object_set_new(resp_json, "task_uuid", json_string(task_uuid_str));
        json_object_set_new(resp_json, "status",    json_integer((json_int_t)status));
    }

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
    log_debug(proc->logger, "Negotiation: status response from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    json_t *j = NULL;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        neg_status_t status = NEG_UNKNOWN;

        json_t *j_uuid = json_object_get(j, "task_uuid");
        if (j_uuid && json_is_string(j_uuid))
            strncpy(task_uuid_str, json_string_value(j_uuid), UUID_STRING_LEN);

        json_t *j_status = json_object_get(j, "status");
        if (j_status && json_is_integer(j_status))
            status = (neg_status_t)json_integer_value(j_status);

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
                              nmsg->from_whom.fullname, task_uuid_str);

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

                if (tracker && peer_confirmed && live_task) {
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
                              nmsg->from_whom.fullname);

                    /* Drop the matching task uuid from status_pending —
                     * Python does `self.status_pending.remove(task)` so
                     * the periodic poller stops nagging until the next
                     * cycle. The C status_pending array holds uuid
                     * strings; zero out the slot like the cleanup loop
                     * already does below for the response itself. */
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
                            break;
                        }
                    }
                } else if (tracker && !peer_confirmed) {
                    log_debug(proc->logger,
                              "Negotiation: stat_resp from unconfirmed peer "
                              "%s for task %s — not extending timeout\n",
                              nmsg->from_whom.fullname, task_uuid_str);
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
    log_info(proc->logger, "Negotiation: results from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    json_t *j = NULL;
    if (nmsg->obj && nmsg->len > 0 && net_msg_unpack_json(nmsg, &j) == 0 && j)
    {
        char task_uuid_str[UUID_STRING_LEN + 1] = {0};
        uuid_t task_uuid;
        bool have_task_uuid = false;

        json_t *j_uuid = json_object_get(j, "task_uuid");
        if (j_uuid && json_is_string(j_uuid))
        {
            strncpy(task_uuid_str, json_string_value(j_uuid), UUID_STRING_LEN);
            if (uuid_parse(task_uuid_str, task_uuid) == 0)
                have_task_uuid = true;
        }

        /* Extract raw result bytes (base64-encoded string or omitted) */
        const uint8_t *result_data = NULL;
        size_t result_len = 0;
        json_t *j_result = json_object_get(j, "result_data");
        if (j_result && json_is_string(j_result))
        {
            result_data = (const uint8_t *)json_string_value(j_result);
            result_len  = strlen((const char *)result_data);
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

                /* If all expected results have arrived, forward to main process */
                if (collected >= tracker->expected)
                {
                    log_info(proc->logger,
                             "Negotiation: task %s complete — forwarding results\n",
                             task_uuid_str);

                    /* Build TASK_RESULT message to the main (requestor) process */
                    generic_msg_t result_msg;
                    memset(&result_msg, 0, sizeof(result_msg));
                    result_msg.type = TASK_RESULT;
                    uuid_copy(result_msg.info.task_result.task_uuid, task_uuid);
                    uuid_copy(result_msg.info.task_result.requestor_uuid,
                              nmsg->from_whom.uuid);
                    result_msg.info.task_result.result_data = (uint8_t *)result_data;
                    result_msg.info.task_result.result_len  = result_len;

                    messaging_send("main", TASK_RESULT, &result_msg, false);

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
                messaging_send("main", TASK_RESULT, &cancel_msg, false);

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
    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(negotiation, neg_proc, negotiation_run);
