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

/* Implementation note (divergence.md L3):
 *
 * Python carries two ping paths: the synchronous one and an async wrapper
 * (`_do_ping_async` in netprocess.py) that runs the sync call in a worker.
 * The async wrapper itself is deprecated as a separate API surface —
 * callers reach it indirectly by sending a `function=ping` Message to
 * the network process. C keeps only the synchronous `ping()` here; the
 * async-from-caller pattern lives one layer up in net_proc's
 * `dispatch_ping_async`, which spawns a detached worker that runs the
 * sync function. That mirrors Python's effective surface area without
 * duplicating the deprecated standalone async entry point. */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network/ping.h"
#include "utilities/exception.h"
#include "utilities/socket_helpers.h"

DEFINE_ERROR(EPING_TIMEOUT, "Ping timed out");

/****************************
 * Timespec helpers
 ****************************/

static double timespec_diff_ms(struct timespec start, struct timespec end)
{
    double diff = (double)(end.tv_sec - start.tv_sec) * 1000.0;
    diff += (double)(end.tv_nsec - start.tv_nsec) / 1.0e6;
    return diff;
}

/****************************
 * Ping client
 ****************************/

/* Frama-C: skipped — [syscall] raw socket send/recv */
int ping(const char *host, int count, ping_stats_t *stats)
{
    memset(stats, 0, sizeof(ping_stats_t));
    strncpy(stats->host, host, IPV4_ADDR_LEN);
    if (count <= 0)
        count = PING_COUNT;
    if (count > MAX_PING_COUNT)
        count = MAX_PING_COUNT;
    stats->count = count;

    /* Sender socket: sends to PING_SND_PORT on the target host */
    int snd_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (snd_sock < 0)
        return SYS_EXCEPTION();

    /* Receiver socket: listens on PING_RCV_PORT */
    int rcv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rcv_sock < 0)
    {
        close(snd_sock);
        return SYS_EXCEPTION();
    }

    (void)at_set_rcvtimeo(rcv_sock, PING_TIMEOUT_MS, NULL);

    /* Bind receiver to PING_RCV_PORT */
    struct sockaddr_in rcv_addr;
    memset(&rcv_addr, 0, sizeof(rcv_addr));
    rcv_addr.sin_family      = AF_INET;
    rcv_addr.sin_addr.s_addr = INADDR_ANY;
    rcv_addr.sin_port        = htons(PING_RCV_PORT);
    if (bind(rcv_sock, (struct sockaddr *)&rcv_addr, sizeof(rcv_addr)) < 0)
    {
        close(snd_sock);
        close(rcv_sock);
        return SYS_EXCEPTION();
    }

    /* Destination: PING_SND_PORT on host */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(PING_SND_PORT);
    if (inet_pton(AF_INET, host, &dst.sin_addr) <= 0)
    {
        close(snd_sock);
        close(rcv_sock);
        return SYS_EXCEPTION();
    }

    stats->min_rtt = 1.0e9;
    stats->max_rtt = 0.0;

    int timed_out = 0;

    for (int i = 0; i < count; i++)
    {
        uint32_t seq     = (uint32_t)(i + 1);
        uint32_t net_seq = htonl(seq);

        struct timespec t_send, t_recv;
        clock_gettime(CLOCK_MONOTONIC, &t_send);

        ssize_t sent = at_sendto_eintr(snd_sock, &net_seq, sizeof(net_seq), 0,
                                       (struct sockaddr *)&dst, sizeof(dst));
        if (sent < 0)
        {
            timed_out++;
            continue;
        }
        stats->sent++;

        /* Wait for echo response (seq + 1) */
        uint32_t resp = 0;
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t rcvd = at_recvfrom_eintr(rcv_sock, &resp, sizeof(resp), 0,
                                         (struct sockaddr *)&from, &from_len);

        clock_gettime(CLOCK_MONOTONIC, &t_recv);

        if (rcvd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                timed_out++;
            continue;
        }

        uint32_t resp_host = ntohl(resp);
        if (resp_host != seq + 1)
            continue;  /* Bad response */

        double rtt = timespec_diff_ms(t_send, t_recv);
        stats->rtt_ms[stats->received] = rtt;
        stats->received++;

        if (rtt < stats->min_rtt) stats->min_rtt = rtt;
        if (rtt > stats->max_rtt) stats->max_rtt = rtt;
    }

    close(snd_sock);
    close(rcv_sock);

    if (stats->received == 0)
    {
        stats->min_rtt = 0.0;
        if (timed_out > 0)
            return EXCEPTION(EPING_TIMEOUT);
        return -1;
    }

    /* Compute average */
    double sum = 0.0;
    for (int i = 0; i < stats->received; i++)
        sum += stats->rtt_ms[i];
    stats->avg_rtt = sum / (double)stats->received;

    /* Packet loss fraction */
    stats->loss = (double)(stats->sent - stats->received) / (double)stats->sent;

    return 0;
}

/****************************
 * Ping server (echo daemon)
 ****************************/

static pthread_t    ping_server_thread;
static volatile int ping_server_running = 0;

/* Frama-C: skipped — [syscall] socket/select loop */
static void *ping_server_loop(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return NULL;

    /* Set receive timeout so we can check ping_server_running */
    (void)at_set_rcvtimeo(sock, 1000, NULL);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PING_SND_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return NULL;
    }

    while (ping_server_running)
    {
        uint32_t pkt = 0;
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = at_recvfrom_eintr(sock, &pkt, sizeof(pkt), 0,
                                      (struct sockaddr *)&from, &from_len);
        if (n < 0)
        {
            /* Timeout or error — check running flag and loop */
            continue;
        }

        /* Echo back seq + 1 */
        uint32_t reply = htonl(ntohl(pkt) + 1);
        (void)at_sendto_eintr(sock, &reply, sizeof(reply), 0,
                              (struct sockaddr *)&from, from_len);
    }

    close(sock);
    return NULL;
}

/* Frama-C: skipped — [syscall] pthread_create */
int ping_server_start(void)
{
    if (ping_server_running)
        return 0;
    ping_server_running = 1;
    int err = pthread_create(&ping_server_thread, NULL, ping_server_loop, NULL);
    if (err != 0)
    {
        ping_server_running = 0;
        errno = err;
        return SYS_EXCEPTION();
    }
    return 0;
}

/* Frama-C: skipped — [syscall] pthread_join */
int ping_server_stop(void)
{
    if (!ping_server_running)
        return 0;
    ping_server_running = 0;
    pthread_join(ping_server_thread, NULL);
    return 0;
}
