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

/**
 * @file probes.c
 * @brief C port of `_probes/` from `core/_python/`.
 *
 * Design notes:
 *   - All public entry points short-circuit when `AT_PROBES` is unset.
 *     The branch is the only cost paid by production code in that case.
 *   - One background writer thread per process, started lazily on the
 *     first probe call. The thread drains a bounded ring buffer to a
 *     per-process JSONL file every `AT_PROBES_FLUSH_SEC` seconds.
 *   - Counters are aggregated in a `(layer, event, reason)`-keyed bag.
 *     The bag is snapshotted on a `AT_PROBES_COUNTER_SEC` schedule and
 *     emitted as a single 'counters'/'snapshot' event so output volume
 *     scales with event activity, not wall time.
 *   - Drops on overflow are silent — probes never break the run they
 *     are observing.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>

#include "probes.h"

/* ---------- env-var-driven configuration ---------- */

#define DEFAULT_PROBES_DIR       "/var/at-probes"
#define DEFAULT_FLUSH_SEC        2.0
#define DEFAULT_COUNTER_SEC      5.0
#define EVENT_QUEUE_MAX          10000

static bool   g_enabled        = false;
static bool   g_init_done      = false;
static char   g_dir[256]       = DEFAULT_PROBES_DIR;
static double g_flush_sec      = DEFAULT_FLUSH_SEC;
static double g_counter_sec    = DEFAULT_COUNTER_SEC;
static char   g_host[256]      = "unknown";

/* Truthy-env check matches Python's set of accepted values. */
static bool _truthy(const char *v)
{
    if (v == NULL || v[0] == '\0') return false;
    /* Case-insensitive compare against the small set. */
    char buf[8] = {0};
    size_t i;
    for (i = 0; v[i] != '\0' && i < sizeof(buf) - 1; i++) {
        char c = v[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        buf[i] = c;
    }
    return (strcmp(buf, "1")    == 0 ||
            strcmp(buf, "true") == 0 ||
            strcmp(buf, "yes")  == 0 ||
            strcmp(buf, "on")   == 0);
}

/* ---------- writer-thread state ---------- */

typedef struct event_node_s {
    char *line;                 /* JSON text + trailing '\n', heap-owned. */
    struct event_node_s *next;
} event_node_t;

static pthread_mutex_t  g_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_queue_cv   = PTHREAD_COND_INITIALIZER;
static event_node_t    *g_queue_head = NULL;
static event_node_t    *g_queue_tail = NULL;
static int              g_queue_len  = 0;
static long             g_drop_count = 0;
static pid_t            g_writer_pid = 0;
static pthread_t        g_writer;
static FILE            *g_fh         = NULL;
static volatile bool    g_writer_stop = false;
static bool             g_writer_failed = false;

/* ---------- counter bag ---------- */

typedef struct counter_entry_s {
    char *layer;
    char *event;
    char *reason;
    long  count;
    struct counter_entry_s *next;
} counter_entry_t;

static pthread_mutex_t   g_counter_lock = PTHREAD_MUTEX_INITIALIZER;
static counter_entry_t  *g_counter_head = NULL;
static struct timespec   g_last_snapshot = {0, 0};

/* Forward declarations. */
static void  _ensure_init(void);
static bool  _ensure_writer(void);
static void  _enqueue_line(char *line);
static void *_writer_main(void *arg);
static void  _flush_counter_bag_locked(void);
static double _now_sec(void);

/* ---------- public API ---------- */

bool probes_enabled(void)
{
    _ensure_init();
    return g_enabled;
}

void probes_emit(const char *layer, const char *event, json_t *fields)
{
    _ensure_init();
    if (!g_enabled || layer == NULL || event == NULL) return;
    if (!_ensure_writer()) return;

    json_t *rec = json_object();
    if (rec == NULL) return;

    /* Standard envelope: timestamp + pid + host + layer + event. */
    json_object_set_new(rec, "t",     json_real(_now_sec()));
    json_object_set_new(rec, "pid",   json_integer((json_int_t)getpid()));
    json_object_set_new(rec, "host",  json_string(g_host));
    json_object_set_new(rec, "layer", json_string(layer));
    json_object_set_new(rec, "event", json_string(event));

    /* Merge caller fields if any. We do not mutate the caller's object. */
    if (fields != NULL && json_is_object(fields)) {
        const char *k;
        json_t *v;
        json_object_foreach(fields, k, v) {
            json_object_set(rec, k, v);  /* shared reference; safe */
        }
    }

    char *line = json_dumps(rec, JSON_COMPACT);
    json_decref(rec);
    if (line == NULL) return;

    /* Append newline by reallocating. The writer thread expects the
     * trailing '\n' already in the line so its fwrite is a single
     * call per record. */
    size_t len = strlen(line);
    char *nl = (char *)realloc(line, len + 2);
    if (nl == NULL) { free(line); return; }
    nl[len] = '\n';
    nl[len + 1] = '\0';

    _enqueue_line(nl);
}

void probes_emit_kv(const char *layer, const char *event, ...)
{
    _ensure_init();
    if (!g_enabled || layer == NULL || event == NULL) return;

    /* Collect kv pairs into a temporary jansson object. */
    json_t *fields = json_object();
    if (fields == NULL) return;

    va_list ap;
    va_start(ap, event);
    for (;;) {
        const char *k = va_arg(ap, const char *);
        if (k == NULL) break;
        const char *v = va_arg(ap, const char *);
        if (v == NULL) v = "";
        json_object_set_new(fields, k, json_string(v));
    }
    va_end(ap);

    probes_emit(layer, event, fields);
    json_decref(fields);
}

void probes_trace_msg(const char *trace_id, const char *process,
                      const char *function, const char *hook, ...)
{
    _ensure_init();
    if (!g_enabled || hook == NULL) return;
    /* Mirror Python: no trace_id → no correlation key → drop the event
     * rather than emit an orphan trace. */
    if (trace_id == NULL || trace_id[0] == '\0') return;

    json_t *fields = json_object();
    if (fields == NULL) return;
    json_object_set_new(fields, "trace_id", json_string(trace_id));
    json_object_set_new(fields, "process",
                        process != NULL ? json_string(process) : json_null());
    json_object_set_new(fields, "function",
                        function != NULL ? json_string(function) : json_null());

    va_list ap;
    va_start(ap, hook);
    for (;;) {
        const char *k = va_arg(ap, const char *);
        if (k == NULL) break;
        const char *v = va_arg(ap, const char *);
        if (v == NULL) v = "";
        json_object_set_new(fields, k, json_string(v));
    }
    va_end(ap);

    probes_emit("msg", hook, fields);
    json_decref(fields);
}

void probes_counter(const char *layer, const char *event, const char *reason)
{
    probes_counter_n(layer, event, reason, 1);
}

void probes_counter_n(const char *layer, const char *event,
                      const char *reason, long n)
{
    _ensure_init();
    if (!g_enabled || layer == NULL || event == NULL || n == 0) return;
    if (reason == NULL) reason = "";

    bool need_snapshot = false;
    pthread_mutex_lock(&g_counter_lock);

    /* Find-or-create. The bag is small (handful of distinct keys per
     * subsystem); linear scan is fine. */
    counter_entry_t *e;
    for (e = g_counter_head; e != NULL; e = e->next) {
        if (strcmp(e->layer, layer) == 0 &&
            strcmp(e->event, event) == 0 &&
            strcmp(e->reason, reason) == 0) {
            e->count += n;
            break;
        }
    }
    if (e == NULL) {
        e = (counter_entry_t *)calloc(1, sizeof(*e));
        if (e != NULL) {
            e->layer  = strdup(layer);
            e->event  = strdup(event);
            e->reason = strdup(reason);
            e->count  = n;
            if (e->layer == NULL || e->event == NULL || e->reason == NULL) {
                free(e->layer); free(e->event); free(e->reason); free(e);
            } else {
                e->next = g_counter_head;
                g_counter_head = e;
            }
        }
    }

    /* Interval check: emit a snapshot if enough time has elapsed AND
     * the bag is non-empty. */
    double elapsed = _now_sec() -
                     ((double)g_last_snapshot.tv_sec +
                      (double)g_last_snapshot.tv_nsec / 1e9);
    if (elapsed >= g_counter_sec && g_counter_head != NULL)
        need_snapshot = true;

    if (need_snapshot)
        _flush_counter_bag_locked();
    pthread_mutex_unlock(&g_counter_lock);
}

void probes_flush(void)
{
    _ensure_init();
    if (!g_enabled) return;

    pthread_mutex_lock(&g_counter_lock);
    _flush_counter_bag_locked();
    pthread_mutex_unlock(&g_counter_lock);

    /* Force-drain the writer queue by signalling the cv and waiting a
     * brief moment. The writer drains everything available each wakeup. */
    pthread_mutex_lock(&g_queue_lock);
    pthread_cond_signal(&g_queue_cv);
    pthread_mutex_unlock(&g_queue_lock);
}

/* ---------- internals ---------- */

static void _ensure_init(void)
{
    if (g_init_done) return;

    const char *enabled = getenv("AT_PROBES");
    g_enabled = _truthy(enabled);

    const char *dir = getenv("AT_PROBES_DIR");
    if (dir != NULL && dir[0] != '\0') {
        strncpy(g_dir, dir, sizeof(g_dir) - 1);
        g_dir[sizeof(g_dir) - 1] = '\0';
    }
    const char *flush_s = getenv("AT_PROBES_FLUSH_SEC");
    if (flush_s != NULL && flush_s[0] != '\0') {
        double v = strtod(flush_s, NULL);
        if (v > 0) g_flush_sec = v;
    }
    const char *counter_s = getenv("AT_PROBES_COUNTER_SEC");
    if (counter_s != NULL && counter_s[0] != '\0') {
        double v = strtod(counter_s, NULL);
        if (v > 0) g_counter_sec = v;
    }

    /* Hostname for the envelope. AT_PEER_NAME wins if set so disaster-
     * response compose runs label events by container role. */
    const char *peer = getenv("AT_PEER_NAME");
    if (peer != NULL && peer[0] != '\0') {
        strncpy(g_host, peer, sizeof(g_host) - 1);
        g_host[sizeof(g_host) - 1] = '\0';
    } else {
        if (gethostname(g_host, sizeof(g_host) - 1) != 0)
            strncpy(g_host, "unknown", sizeof(g_host) - 1);
        g_host[sizeof(g_host) - 1] = '\0';
    }

    clock_gettime(CLOCK_MONOTONIC, &g_last_snapshot);

    g_init_done = true;
}

/* mkdir -p — best-effort. Returns 0 on success or if it already exists. */
static int _mkdir_p(const char *path)
{
    char tmp[256];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                *p = '/'; return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static bool _ensure_writer(void)
{
    pid_t cur = getpid();
    if (g_writer_failed && g_writer_pid == cur) return false;
    if (g_writer_pid == cur && g_fh != NULL) return true;

    pthread_mutex_lock(&g_queue_lock);
    if (g_writer_pid == cur && g_fh != NULL) {
        pthread_mutex_unlock(&g_queue_lock);
        return true;
    }
    if (g_writer_failed && g_writer_pid == cur) {
        pthread_mutex_unlock(&g_queue_lock);
        return false;
    }
    /* mkdir -p the output dir. */
    if (_mkdir_p(g_dir) != 0) {
        g_writer_failed = true;
        g_writer_pid    = cur;
        pthread_mutex_unlock(&g_queue_lock);
        return false;
    }

    /* probes_<host>_pid<pid>_<stamp>.jsonl */
    char stamp[32];
    time_t now_t = time(NULL);
    struct tm tm;
    gmtime_r(&now_t, &tm);
    strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%S", &tm);

    /* sizeof(g_dir)+sizeof(g_host) ≈ 512; the format adds ~30 chars
     * (literal + pid + stamp). Sized generously so the FORTIFY check
     * sees no overflow path. */
    char path[sizeof(g_dir) + sizeof(g_host) + 64];
    snprintf(path, sizeof(path), "%s/probes_%s_pid%ld_%s.jsonl",
             g_dir, g_host, (long)cur, stamp);

    FILE *fh = fopen(path, "a");
    if (fh == NULL) {
        g_writer_failed = true;
        g_writer_pid    = cur;
        pthread_mutex_unlock(&g_queue_lock);
        return false;
    }
    setvbuf(fh, NULL, _IOLBF, 0);

    g_fh         = fh;
    g_writer_pid = cur;
    g_writer_stop = false;
    pthread_mutex_unlock(&g_queue_lock);

    if (pthread_create(&g_writer, NULL, _writer_main, NULL) != 0) {
        /* Thread didn't start — keep the fh, accept that emits will
         * pile up in the queue with no drain. Mark as failed to avoid
         * burning CPU on repeated emit attempts. */
        pthread_mutex_lock(&g_queue_lock);
        g_writer_failed = true;
        pthread_mutex_unlock(&g_queue_lock);
        return false;
    }
    return true;
}

static void _enqueue_line(char *line)
{
    if (line == NULL) return;
    pthread_mutex_lock(&g_queue_lock);
    if (g_queue_len >= EVENT_QUEUE_MAX) {
        /* Drop on overflow. */
        g_drop_count++;
        pthread_mutex_unlock(&g_queue_lock);
        free(line);
        return;
    }
    event_node_t *n = (event_node_t *)calloc(1, sizeof(*n));
    if (n == NULL) {
        pthread_mutex_unlock(&g_queue_lock);
        free(line);
        return;
    }
    n->line = line;
    n->next = NULL;
    if (g_queue_tail == NULL)
        g_queue_head = n;
    else
        g_queue_tail->next = n;
    g_queue_tail = n;
    g_queue_len++;
    pthread_cond_signal(&g_queue_cv);
    pthread_mutex_unlock(&g_queue_lock);
}

static void *_writer_main(void *arg)
{
    (void)arg;
    while (!g_writer_stop) {
        struct timespec wake;
        clock_gettime(CLOCK_REALTIME, &wake);
        long whole = (long)g_flush_sec;
        long frac_ns = (long)((g_flush_sec - (double)whole) * 1e9);
        wake.tv_sec += whole;
        wake.tv_nsec += frac_ns;
        if (wake.tv_nsec >= 1000000000L) {
            wake.tv_sec  += 1;
            wake.tv_nsec -= 1000000000L;
        }

        pthread_mutex_lock(&g_queue_lock);
        if (g_queue_head == NULL && !g_writer_stop)
            pthread_cond_timedwait(&g_queue_cv, &g_queue_lock, &wake);

        event_node_t *batch = g_queue_head;
        g_queue_head = NULL;
        g_queue_tail = NULL;
        g_queue_len  = 0;
        pthread_mutex_unlock(&g_queue_lock);

        if (batch == NULL) continue;

        /* Write outside the queue lock so emit() never blocks on
         * filesystem I/O. */
        while (batch != NULL) {
            event_node_t *n = batch;
            batch = batch->next;
            if (g_fh != NULL && n->line != NULL)
                fputs(n->line, g_fh);
            free(n->line);
            free(n);
        }
        if (g_fh != NULL) fflush(g_fh);
    }
    return NULL;
}

/* Caller must hold g_counter_lock. */
static void _flush_counter_bag_locked(void)
{
    if (g_counter_head == NULL) return;

    /* Build a JSON array of {layer, event, reason, count} entries. */
    json_t *items = json_array();
    if (items != NULL) {
        for (counter_entry_t *e = g_counter_head; e != NULL; e = e->next) {
            json_t *o = json_object();
            if (o == NULL) continue;
            json_object_set_new(o, "layer",  json_string(e->layer));
            json_object_set_new(o, "event",  json_string(e->event));
            json_object_set_new(o, "reason", json_string(e->reason));
            json_object_set_new(o, "count",  json_integer((json_int_t)e->count));
            json_array_append_new(items, o);
        }
    }

    /* Drain the bag now that we have a snapshot. */
    counter_entry_t *e = g_counter_head;
    g_counter_head = NULL;
    while (e != NULL) {
        counter_entry_t *next = e->next;
        free(e->layer); free(e->event); free(e->reason); free(e);
        e = next;
    }
    clock_gettime(CLOCK_MONOTONIC, &g_last_snapshot);

    if (items != NULL) {
        json_t *fields = json_object();
        if (fields != NULL) {
            json_object_set_new(fields, "items", items);
            probes_emit("counters", "snapshot", fields);
            json_decref(fields);
        } else {
            json_decref(items);
        }
    }
}

static double _now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
