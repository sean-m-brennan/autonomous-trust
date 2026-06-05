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

/* C counterpart of the Python DataProcess/DataProtocol
 * (src/autonomous-trust-services/.../services/data/server.py). Advertises the
 * `data` capability and, when a remote DataRcvr subscribes via a `request`
 * message, streams `data` messages — each a JSON array of Reading dicts — back
 * to that subscriber, per-peer encrypted (the same crypto_box path identity
 * messages use; no group key required). This is what makes a C at_demo node
 * appear as a live ISR source in the Python coordinator's dashboards.
 *
 * Readings come from data_source_set_readings() (the --ingest-readings feeder,
 * Phase 2). Until a batch has been ingested, the process emits a small
 * synthetic reading so the C->coordinator subscribe+stream path is testable on
 * its own. */

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <jansson.h>

#include "processes/processes.h"
#include "processes/capabilities.h"
#include "data_source/data_source_proc.h"
#include "structures/map.h"
#include "structures/array.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "network/net_message.h"

/* Protocol selectors (declared extern in the header) — writable arrays so they
 * can be assigned to net_msg_t.function (char *). Values match Python
 * DataProtocol.request / DataProtocol.data. */
char DATA_PROTO_REQUEST[] = "request";
char DATA_PROTO_DATA[]    = "data";

#define DS_MAX_SUBS 16

typedef struct {
    char proc_name[PROC_NAME_LEN + 1];  /* subscriber's process name (data-sink) */
    public_identity_t ident;            /* subscriber identity (encrypt target) */
    bool used;
} ds_sub_t;

static struct {
    ds_sub_t subs[DS_MAX_SUBS];
    size_t num_subs;
    struct timeval t0;        /* process start — synthetic reading clock */
    unsigned long tick;       /* emit counter (drives synthetic oscillation) */
    char *ingest_json;        /* latest ingested batch (JSON array string), or NULL */
    size_t ingest_len;
    pthread_mutex_t lock;
    bool initialized;
} ds_state;

static void _ensure_init(void)
{
    if (!ds_state.initialized) {
        memset(ds_state.subs, 0, sizeof(ds_state.subs));
        ds_state.num_subs = 0;
        gettimeofday(&ds_state.t0, NULL);
        ds_state.tick = 0;
        ds_state.ingest_json = NULL;
        ds_state.ingest_len = 0;
        pthread_mutex_init(&ds_state.lock, NULL);
        ds_state.initialized = true;
    }
}

/****************************
 * Handler: handle_request
 * A remote DataRcvr subscribes. message.obj is the subscriber's process name
 * (Python sends self.name, e.g. "data-sink"); from_whom is its identity. Store
 * it so the emit loop streams `data` messages addressed to that process name
 * and encrypted to that identity. Idempotent per subscriber UUID.
 ****************************/
static bool handle_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    /* Subscriber process name = the request payload bytes (a bare string). */
    char sub_proc[PROC_NAME_LEN + 1] = {0};
    size_t copy = nmsg->len < PROC_NAME_LEN ? nmsg->len : PROC_NAME_LEN;
    if (nmsg->obj != NULL && copy > 0)
        memcpy(sub_proc, nmsg->obj, copy);
    if (sub_proc[0] == '\0')  /* fall back to return_to if the payload was empty */
        snprintf(sub_proc, sizeof(sub_proc), "%s", nmsg->return_to);
    if (sub_proc[0] == '\0') {
        log_warn(proc->logger, "data-source: subscribe request with no subscriber name; ignoring\n");
        return true;
    }

    pthread_mutex_lock(&ds_state.lock);
    /* Dedup by subscriber UUID. */
    for (size_t i = 0; i < DS_MAX_SUBS; i++) {
        if (ds_state.subs[i].used &&
            memcmp(ds_state.subs[i].ident.uuid, nmsg->from_whom.uuid, sizeof(uuid_t)) == 0) {
            pthread_mutex_unlock(&ds_state.lock);
            log_debug(proc->logger, "data-source: %s already subscribed\n", sub_proc);
            return true;
        }
    }
    /* Insert into first free slot. */
    for (size_t i = 0; i < DS_MAX_SUBS; i++) {
        if (!ds_state.subs[i].used) {
            ds_state.subs[i].used = true;
            snprintf(ds_state.subs[i].proc_name, sizeof(ds_state.subs[i].proc_name),
                     "%s", sub_proc);
            memcpy(&ds_state.subs[i].ident, &nmsg->from_whom, sizeof(public_identity_t));
            ds_state.num_subs++;
            pthread_mutex_unlock(&ds_state.lock);
            log_info(proc->logger,
                     "data-source: subscriber '%s' (%s) registered (%zu total)\n",
                     sub_proc, nmsg->from_whom.fullname, ds_state.num_subs);
            return true;
        }
    }
    pthread_mutex_unlock(&ds_state.lock);
    log_warn(proc->logger, "data-source: subscriber table full; dropping %s\n", sub_proc);
    return true;
}

/****************************
 * Reading payload construction
 ****************************/

/* Build a synthetic single-reading JSON array, shape == Reading.to_dict():
 * {t, peer, type, value, unit, quality, metadata}. Used only until the ingest
 * feeder supplies real readings. Caller owns the returned json_t. */
static json_t *build_synthetic_readings(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    double t = (double)(now.tv_sec - ds_state.t0.tv_sec)
             + (double)(now.tv_usec - ds_state.t0.tv_usec) / 1e6;

    /* Counter-driven oscillation in [0.1, 0.9] — no libm dependency. */
    double v = 0.1 + 0.8 * ((double)(ds_state.tick % 20) / 20.0);

    const char *peer = getenv("AT_PEER_NAME");
    if (peer == NULL || peer[0] == '\0')
        peer = "c-node";

    json_t *r = json_object();
    json_object_set_new(r, "t", json_real(t));
    json_object_set_new(r, "peer", json_string(peer));
    json_object_set_new(r, "type", json_string("motion_intensity"));
    json_object_set_new(r, "value", json_real(v));
    json_object_set_new(r, "unit", json_string(""));
    json_object_set_new(r, "quality", json_real(1.0));
    json_object_set_new(r, "metadata", json_object());

    json_t *arr = json_array();
    json_array_append_new(arr, r);
    return arr;
}

/* Return the JSON array string to emit this tick: the latest ingested batch if
 * present, else a freshly-built synthetic batch. Caller frees with free(). */
static char *current_readings_json(void)
{
    pthread_mutex_lock(&ds_state.lock);
    if (ds_state.ingest_json != NULL && ds_state.ingest_len > 0) {
        char *copy = malloc(ds_state.ingest_len + 1);
        if (copy != NULL) {
            memcpy(copy, ds_state.ingest_json, ds_state.ingest_len);
            copy[ds_state.ingest_len] = '\0';
        }
        pthread_mutex_unlock(&ds_state.lock);
        return copy;
    }
    pthread_mutex_unlock(&ds_state.lock);

    json_t *arr = build_synthetic_readings();
    char *s = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    return s;
}

void data_source_set_readings(const char *readings_json, size_t len)
{
    if (readings_json == NULL)
        return;
    _ensure_init();
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return;
    memcpy(copy, readings_json, len);
    copy[len] = '\0';
    pthread_mutex_lock(&ds_state.lock);
    free(ds_state.ingest_json);
    ds_state.ingest_json = copy;
    ds_state.ingest_len = len;
    pthread_mutex_unlock(&ds_state.lock);
}

/****************************
 * Emit loop
 ****************************/

/* Stream the current reading batch to every subscriber as a per-peer-encrypted
 * `data` message. The data message's `process` field is the subscriber's own
 * process name so the coordinator's DataRcvr (that name) receives it; `function`
 * is "data"; the payload is the JSON array of Reading dicts. */
static void emit_readings(const process_t *proc)
{
    /* Snapshot subscribers under lock, then send without holding it. */
    ds_sub_t snapshot[DS_MAX_SUBS];
    size_t n = 0;
    pthread_mutex_lock(&ds_state.lock);
    for (size_t i = 0; i < DS_MAX_SUBS; i++) {
        if (ds_state.subs[i].used)
            memcpy(&snapshot[n++], &ds_state.subs[i], sizeof(ds_sub_t));
    }
    ds_state.tick++;
    pthread_mutex_unlock(&ds_state.lock);

    if (n == 0)
        return;

    char *payload = current_readings_json();
    if (payload == NULL)
        return;

    /* net_msg_pack_json wants a json_t; wrap the string back into a parsed
     * array so the wire payload is canonical JSON the Python side parses via
     * from_yaml_string (YAML superset of JSON). */
    json_error_t jerr;
    json_t *arr = json_loads(payload, 0, &jerr);
    free(payload);
    if (arr == NULL) {
        log_error(proc->logger, "data-source: bad readings JSON: %s\n", jerr.text);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        generic_msg_t out = {0};
        out.type = NET_MESSAGE;
        net_msg_t *o = &out.info.net_msg;
        /* Same-size NUL-terminated buffers (PROC_NAME_LEN+1); fixed-size copy
         * sidesteps -Wformat-truncation on the inlined %s. */
        memcpy(o->process, snapshot[i].proc_name, sizeof(o->process));
        o->function = DATA_PROTO_DATA;
        o->encrypt = true;
        memcpy(&o->to_whom, &snapshot[i].ident, sizeof(public_identity_t));
        snprintf(o->return_to, sizeof(o->return_to), "%s", DATA_SOURCE_PROC_NAME);
        net_msg_pack_json(o, arr);
        messaging_send("network", NET_MESSAGE, &out, false);
    }
    json_decref(arr);
}

/****************************
 * Ingest feeder (--ingest-readings / AT_INGEST_SOCKET)
 *
 * AF_UNIX SOCK_STREAM *server*: a sidecar (the Python flight stub) connects and
 * streams length-prefixed JSON reading batches — [uint32 big-endian len][len
 * bytes JSON array]. Each batch becomes the latest readings the emit loop ships
 * to subscribers. SOCK_STREAM (not DGRAM) so large/variable detection batches
 * never silently truncate.
 ****************************/

/* Sized to AF_UNIX sun_path (108) so the copy into sockaddr_un can't truncate. */
static char g_ingest_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
static volatile bool g_feeder_running = false;

static ssize_t read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) return 0;                       /* peer closed */
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static void *ingest_feeder(void *arg)
{
    logger_t *logger = (logger_t *)arg;

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        log_error(logger, "data-source: ingest socket() failed: %s\n", strerror(errno));
        return NULL;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_ingest_path);
    unlink(g_ingest_path);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_error(logger, "data-source: ingest bind(%s) failed: %s\n",
                  g_ingest_path, strerror(errno));
        close(srv);
        return NULL;
    }
    if (listen(srv, 1) != 0) {
        log_error(logger, "data-source: ingest listen failed: %s\n", strerror(errno));
        close(srv);
        unlink(g_ingest_path);
        return NULL;
    }
    log_info(logger, "data-source: ingest socket listening at %s\n", g_ingest_path);

    while (g_feeder_running) {
        int cli = accept(srv, NULL, NULL);   /* cancellation point on shutdown */
        if (cli < 0) {
            if (errno == EINTR) continue;
            break;
        }
        log_info(logger, "data-source: ingest feeder connected\n");
        while (g_feeder_running) {
            uint32_t nlen = 0;
            if (read_full(cli, &nlen, sizeof(nlen)) <= 0)
                break;                          /* disconnect / error */
            uint32_t len = ntohl(nlen);
            if (len == 0 || len > NET_MSG_MAX_DATA) {
                log_warn(logger, "data-source: ingest frame length %u out of range; "
                         "dropping connection\n", len);
                break;
            }
            char *buf = malloc((size_t)len + 1);
            if (buf == NULL)
                break;
            if (read_full(cli, buf, len) != (ssize_t)len) {
                free(buf);
                break;
            }
            buf[len] = '\0';
            data_source_set_readings(buf, len);
            free(buf);
        }
        close(cli);
        log_info(logger, "data-source: ingest feeder disconnected\n");
    }
    close(srv);
    unlink(g_ingest_path);
    return NULL;
}

/****************************
 * data-source process main entry
 ****************************/
int data_source_run(process_t *proc, directory_t *queues, queue_id_t signal,
                    logger_t *logger)
{
    _ensure_init();
    process_register_handler(proc, DATA_PROTO_REQUEST, (handler_ptr_t)handle_request);
    proc->protocol.phase = 1;

    /* Custom loop = process_loop + a periodic emit at the documented
     * "sub-process specific post-message activity" hook point. */
    process_ctx_t ctx;
    int err = process_setup(proc, signal, logger, &ctx);
    if (err != 0)
        return err;

    /* Start the ingest feeder if a socket path was provided; otherwise emit
     * synthetic readings (Phase-1 self-test path). */
    const char *ingest = getenv("AT_INGEST_SOCKET");
    pthread_t feeder;
    bool have_feeder = false;
    if (ingest != NULL && ingest[0] != '\0') {
        snprintf(g_ingest_path, sizeof(g_ingest_path), "%s", ingest);
        g_feeder_running = true;
        if (pthread_create(&feeder, NULL, ingest_feeder, logger) == 0)
            have_feeder = true;
        else
            log_error(logger, "data-source: failed to start ingest feeder thread\n");
    } else {
        log_info(logger, "data-source: no AT_INGEST_SOCKET set; emitting synthetic readings\n");
    }

    log_info(logger, "data-source: ready (cadence %ld us)\n", cadence);

    while (keep_running(proc, &ctx.sig_q, logger)) {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        int rerr = messaging_recv(&buf);
        if (rerr != -1 && rerr != ENOMSG)
            run_message_handlers(proc, queues, buf.type, &buf);

        emit_readings(proc);
    }

    /* Stop the feeder: accept()/read() are cancellation points, so cancel
     * unblocks it; join so the socket is closed/unlinked before we return. */
    if (have_feeder) {
        g_feeder_running = false;
        pthread_cancel(feeder);
        pthread_join(feeder, NULL);
    }

    if (ctx.fd1 > 0)
        close(ctx.fd1);
    if (ctx.fd2 > 0)
        close(ctx.fd2);
    return 0;
}

/* Advertise the `data` capability (preprocess.py emits the capability_table
 * row; build_local_capabilities includes it in the announce so the
 * coordinator's DataRcvr subscribes). Name must equal Python
 * DataProcess.capability_name == "data". */
DECLARE_CAPABILITY(data, NULL);

DECLARE_PROCESS(data_source, data_source_proc, data_source_run);
