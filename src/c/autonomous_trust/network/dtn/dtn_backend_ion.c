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
 * @file dtn_backend_ion.c
 * @brief NASA ION (Interplanetary Overlay Network) Bundle Protocol backend.
 *
 * Links against libbp + libici from nasa-jpl/ION-DTN.  See README sections
 * on installing ION and provisioning endpoints via `bpadmin` — this file
 * assumes the local EID passed to init() has already been declared in the
 * node's .bprc (via `a endpoint <eid> x`).
 *
 * Thread model:
 *   - Main thread calls dtn_backend.init() which runs bp_attach() + bp_open(),
 *     then spawns a reader thread.
 *   - Reader thread loops on bp_receive(sap, &dlv, BP_BLOCKING). Inbound
 *     bundles are enqueued for dtn_backend.recv() to pop under timed-wait.
 *   - Sends are serialized under send_lock — per ION docs a single SAP is
 *     not safe for concurrent bp_send calls.
 *
 * Shutdown interrupts the reader via bp_interrupt(), then bp_close() to
 * release the SAP, then bp_detach() to unmap the SDR.
 *
 * Payload handling: ION uses ZCO (Zero Copy Object) trees rooted in the
 * SDR arena. bp_send needs a source ZCO; bp_receive hands us a delivery
 * ZCO we must read out and then release. Both flows run inside SDR
 * transactions so the SDR manages memory safety.
 *
 * NOTE: ION's API evolves between releases (BPv6 vs BPv7, SDR type-name
 * changes). The call sites below target the BPv7 `current` branch in
 * github.com/nasa-jpl/ION-DTN as of 2026. Minor type or macro names may
 * require adjustment when linked against older ION releases; the logic
 * is the same.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bp.h>
#include <ion.h>
#include <platform.h>
#include <zco.h>

/* ION's platform.h defines ERROR as (-1), which collides with AT's
 * logger.h enum value `ERROR`. Drop ION's macro before pulling in any
 * AT header; we reference its value explicitly as -1 at the one site
 * below that needs it (zco_create failure sentinel). */
#undef ERROR

#include "network/dtn/dtn_backend.h"
#include "network/dtn/dtn_eid.h"

#define ION_MAX_PAYLOAD   (16u * 1024u * 1024u)
#define INBOUND_QUEUE_CAP 64
#define MAX_ENDPOINTS     4  /* peer/bcast/group + slack */

typedef struct ion_bundle_s {
    uint8_t *payload;
    size_t   len;
    char     src_eid[DTN_EID_MAX + 1];
    char     service[DTN_EID_MAX + 1];
    struct ion_bundle_s *next;
} ion_bundle_t;

/* Per-endpoint state: one SAP + one reader thread. */
typedef struct ion_endpoint_s {
    BpSAP sap;
    char eid[DTN_EID_MAX + 1];
    char service[DTN_EID_MAX + 1];
    pthread_t reader;
    bool reader_running;
} ion_endpoint_t;

static struct {
    ion_endpoint_t eps[MAX_ENDPOINTS];
    size_t n_eps;
    bool  attached;
    logger_t *logger;

    pthread_mutex_t q_lock;
    pthread_cond_t  q_cond;
    ion_bundle_t   *q_head;
    ion_bundle_t   *q_tail;
    size_t q_len;

    pthread_mutex_t send_lock;
    bool stop;
} g = {
    .q_lock = PTHREAD_MUTEX_INITIALIZER,
    .q_cond = PTHREAD_COND_INITIALIZER,
    .send_lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ---------- Queue management ---------- */

typedef struct {
    size_t ep_idx;
} reader_arg_t;

static void enqueue_bundle(ion_bundle_t *b)
{
    pthread_mutex_lock(&g.q_lock);
    if (g.q_len >= INBOUND_QUEUE_CAP) {
        ion_bundle_t *oldest = g.q_head;
        if (oldest != NULL) {
            g.q_head = oldest->next;
            if (g.q_head == NULL) g.q_tail = NULL;
            g.q_len--;
            free(oldest->payload);
            free(oldest);
        }
    }
    b->next = NULL;
    if (g.q_tail == NULL) g.q_head = b;
    else                  g.q_tail->next = b;
    g.q_tail = b;
    g.q_len++;
    pthread_cond_signal(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
}

/* ---------- ZCO read helper (for inbound deliveries) ---------- */

/* Copy the full payload out of an incoming delivery ZCO into a fresh heap
 * buffer. Runs inside its own SDR read-only transaction. On success *out is
 * newly-malloc'd (caller frees) and *out_len is set. Returns 0 on success,
 * -1 on SDR failure or oversize payload.
 *
 * A read-only SDR transaction is closed with sdr_exit_xn() (no commit
 * needed); sdr_end_xn() is only for transactions that mutated the SDR. */
static int zco_to_buffer(Object adu, uint8_t **out, size_t *out_len)
{
    Sdr sdr = bp_get_sdr();
    ZcoReader reader;
    uint8_t *buf = NULL;

    if (sdr_begin_xn(sdr) < 0)
        return -1;

    vast content_len = zco_source_data_length(sdr, adu);
    if (content_len < 0 || (uvast)content_len > ION_MAX_PAYLOAD) {
        sdr_exit_xn(sdr);
        return -1;
    }

    zco_start_receiving(adu, &reader);
    buf = malloc((size_t)content_len);
    if (buf == NULL) {
        sdr_exit_xn(sdr);
        return -1;
    }
    vast got = zco_receive_source(sdr, &reader, content_len, (char *)buf);
    sdr_exit_xn(sdr);
    if (got < content_len) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (size_t)content_len;
    return 0;
}

/* ---------- Reader thread ---------- */

/* Frama-C: skipped — reader_thread: logging/snprintf/memset precondition chains in loop body. */
static void *reader_thread(void *arg)
{
    reader_arg_t *a = (reader_arg_t *)arg;
    size_t idx = a->ep_idx;
    ion_endpoint_t *ep = &g.eps[idx];
    free(a);

    while (true) {
        pthread_mutex_lock(&g.q_lock);
        bool stop = g.stop;
        pthread_mutex_unlock(&g.q_lock);
        if (stop) break;

        BpDelivery dlv;
        memset(&dlv, 0, sizeof(dlv));
        int rc = bp_receive(ep->sap, &dlv, BP_BLOCKING);
        if (rc < 0) {
            log_error(g.logger, "DTN[ion]: bp_receive failed on %s\n", ep->eid);
            break;
        }
        switch (dlv.result) {
        case BpPayloadPresent: {
            uint8_t *payload = NULL;
            size_t plen = 0;
            if (zco_to_buffer(dlv.adu, &payload, &plen) == 0) {
                ion_bundle_t *b = calloc(1, sizeof(*b));
                if (b != NULL) {
                    b->payload = payload;
                    b->len = plen;
                    if (dlv.bundleSourceEid != NULL)
                        snprintf(b->src_eid, sizeof(b->src_eid), "%s",
                                 dlv.bundleSourceEid);
                    snprintf(b->service, sizeof(b->service), "%s", ep->service);
                    enqueue_bundle(b);
                } else {
                    free(payload);
                }
            } else {
                log_error(g.logger, "DTN[ion]: ZCO read-out failed on %s\n", ep->eid);
            }
            break;
        }
        case BpReceptionTimedOut:
            break;
        case BpReceptionInterrupted:
        case BpEndpointStopped:
            bp_release_delivery(&dlv, 1);
            goto exit_loop;
        default:
            break;
        }
        bp_release_delivery(&dlv, 1);
    }
exit_loop:
    pthread_mutex_lock(&g.q_lock);
    ep->reader_running = false;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
    return NULL;
}

/* ---------- Backend vtable ---------- */

/* Frama-C: skipped — ion_teardown: terminates_part cascade through SDR cleanup sequence. */
static void ion_teardown(void)
{
    pthread_mutex_lock(&g.q_lock);
    g.stop = true;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);

    /* Interrupt each SAP's blocking bp_receive. */
    for (size_t i = 0; i < g.n_eps; i++) {
        if (g.eps[i].sap != NULL) {
            bp_interrupt(g.eps[i].sap);
        }
    }
    for (size_t i = 0; i < g.n_eps; i++) {
        if (g.eps[i].reader_running) {
            pthread_join(g.eps[i].reader, NULL);
        }
        if (g.eps[i].sap != NULL) {
            bp_close(g.eps[i].sap);
            g.eps[i].sap = NULL;
        }
    }
    if (g.attached) {
        bp_detach();
        g.attached = false;
    }

    pthread_mutex_lock(&g.q_lock);
    ion_bundle_t *b = g.q_head;
    while (b != NULL) {
        ion_bundle_t *next = b->next;
        free(b->payload);
        free(b);
        b = next;
    }
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    pthread_mutex_unlock(&g.q_lock);

    g.n_eps = 0;
}

/* Frama-C: skipped —
 * [solver-timeout] ion_init: 8x at_logging + 3x pthread_create state-cascade (same
 * pattern as reputation_run's 11x process_register_handler).
 */
static int ion_init(const dtn_endpoint_t *endpoints, size_t n_endpoints,
                    logger_t *logger)
{
    if (n_endpoints == 0 || n_endpoints > MAX_ENDPOINTS) {
        log_error(logger, "DTN[ion]: invalid endpoint count %zu (max %d)\n",
                  n_endpoints, MAX_ENDPOINTS);
        return -1;
    }
    if (g.attached) {
        log_warn(logger, "DTN[ion]: already initialized\n");
        return -1;
    }
    g.logger = logger;
    g.stop = false;
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    for (size_t i = 0; i < MAX_ENDPOINTS; i++) {
        g.eps[i].sap = NULL;
        g.eps[i].reader_running = false;
    }

    if (bp_attach() < 0) {
        log_error(logger, "DTN[ion]: bp_attach failed — is ionstart running?\n");
        writeErrmsgMemos();
        return -1;
    }
    g.attached = true;

    for (size_t i = 0; i < n_endpoints; i++) {
        if (endpoints[i].eid == NULL || endpoints[i].service == NULL) {
            log_error(logger, "DTN[ion]: endpoint[%zu] has NULL eid or service\n", i);
            ion_teardown();
            return -1;
        }
        snprintf(g.eps[i].eid,     sizeof(g.eps[i].eid),     "%s", endpoints[i].eid);
        snprintf(g.eps[i].service, sizeof(g.eps[i].service), "%s", endpoints[i].service);

        /* bp_open takes non-const char*; ION predates const-correctness. */
        char eid_buf[DTN_EID_MAX + 1];
        snprintf(eid_buf, sizeof(eid_buf), "%s", g.eps[i].eid);
        if (bp_open(eid_buf, &g.eps[i].sap) < 0) {
            log_error(logger, "DTN[ion]: bp_open(%s) failed — endpoint not provisioned?\n",
                      g.eps[i].eid);
            writeErrmsgMemos();
            ion_teardown();
            return -1;
        }
        g.n_eps = i + 1;  /* track progress so teardown cleans what we opened */
    }

    for (size_t i = 0; i < n_endpoints; i++) {
        reader_arg_t *a = calloc(1, sizeof(*a));
        if (a == NULL) { ion_teardown(); return -1; }
        a->ep_idx = i;
        if (pthread_create(&g.eps[i].reader, NULL, reader_thread, a) != 0) {
            free(a);
            log_error(logger, "DTN[ion]: reader thread spawn failed for %s: %s\n",
                      g.eps[i].eid, strerror(errno));
            ion_teardown();
            return -1;
        }
        g.eps[i].reader_running = true;
    }

    log_info(logger, "DTN[ion]: attached; %zu SAP(s) open\n", n_endpoints);
    for (size_t i = 0; i < n_endpoints; i++) {
        log_info(logger, "DTN[ion]:   [%zu] %s -> %s\n",
                 i, g.eps[i].eid, g.eps[i].service);
    }
    return 0;
}

static void ion_shutdown(void)
{
    ion_teardown();
}

/* Frama-C: skipped — ion_send/ion_recv: at_logging + at_snprintf cascades through ION SDR calls. */
static int ion_send(const char *dest_eid,
                    const uint8_t *payload, size_t payload_len,
                    uint32_t lifetime_sec)
{
    if (g.n_eps == 0 || g.eps[0].sap == NULL || payload_len > ION_MAX_PAYLOAD) {
        errno = EINVAL;
        return -1;
    }

    /* Build a source ZCO under an SDR transaction, then hand it to bp_send. */
    Sdr sdr = bp_get_sdr();
    Object extent = 0;
    Object adu = 0;

    pthread_mutex_lock(&g.send_lock);

    if (sdr_begin_xn(sdr) < 0) {
        pthread_mutex_unlock(&g.send_lock);
        return -1;
    }
    extent = sdr_malloc(sdr, payload_len);
    if (extent == 0) {
        sdr_cancel_xn(sdr);
        pthread_mutex_unlock(&g.send_lock);
        log_error(g.logger, "DTN[ion]: sdr_malloc(%zu) failed\n", payload_len);
        writeErrmsgMemos();
        return -1;
    }
    sdr_write(sdr, extent, (char *)payload, payload_len);
    adu = zco_create(sdr, ZcoSdrSource, extent, 0, (vast)payload_len, ZcoOutbound);
    if (adu == 0 || adu == (Object)-1) {  /* ION's ERROR macro; #undef'd above */
        sdr_cancel_xn(sdr);
        pthread_mutex_unlock(&g.send_lock);
        log_error(g.logger, "DTN[ion]: zco_create failed\n");
        writeErrmsgMemos();
        return -1;
    }
    if (sdr_end_xn(sdr) < 0) {
        pthread_mutex_unlock(&g.send_lock);
        log_error(g.logger, "DTN[ion]: sdr_end_xn failed\n");
        writeErrmsgMemos();
        return -1;
    }

    /* bp_send signature (BPv7): sap, destEid, reportToEid, lifespan, class-of-service,
     * custodySwitch, srrFlags, ackRequested, ancillary, adu, newBundle */
    char dst_buf[DTN_EID_MAX + 1];
    snprintf(dst_buf, sizeof(dst_buf), "%s", dest_eid);
    Object newBundle = 0;
    int rc = bp_send(g.eps[0].sap, dst_buf, NULL,
                     (int)lifetime_sec,
                     BP_STD_PRIORITY,
                     NoCustodyRequested,
                     0, 0, NULL,
                     adu, &newBundle);
    pthread_mutex_unlock(&g.send_lock);

    if (rc <= 0) {
        log_error(g.logger, "DTN[ion]: bp_send to %s failed\n", dest_eid);
        writeErrmsgMemos();
        return -1;
    }
    return 0;
}

/* Frama-C: skipped — ion_send/ion_recv: at_logging + at_snprintf cascades through ION SDR calls. */
static int ion_recv(uint8_t **out_payload, size_t *out_len,
                    char *src_eid, size_t src_eid_len,
                    char *dest_service, size_t dest_service_len,
                    int timeout_ms)
{
    struct timespec deadline = {0};
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g.q_lock);
    while (g.q_head == NULL && !g.stop) {
        bool any_reader_alive = false;
        for (size_t i = 0; i < g.n_eps; i++) {
            if (g.eps[i].reader_running) { any_reader_alive = true; break; }
        }
        if (!any_reader_alive) break;

        int rc = pthread_cond_timedwait(&g.q_cond, &g.q_lock, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g.q_lock);
            return ENOMSG;
        }
    }
    if (g.q_head == NULL) {
        pthread_mutex_unlock(&g.q_lock);
        return g.stop ? -1 : ENOMSG;
    }
    ion_bundle_t *b = g.q_head;
    g.q_head = b->next;
    if (g.q_head == NULL) g.q_tail = NULL;
    g.q_len--;
    pthread_mutex_unlock(&g.q_lock);

    *out_payload = b->payload;
    *out_len     = b->len;
    snprintf(src_eid,      src_eid_len,      "%s", b->src_eid);
    snprintf(dest_service, dest_service_len, "%s", b->service);
    free(b);
    return 0;
}

const dtn_backend_t dtn_backend = {
    .name     = "ion",
    .init     = ion_init,
    .shutdown = ion_shutdown,
    .send     = ion_send,
    .recv     = ion_recv,
};
