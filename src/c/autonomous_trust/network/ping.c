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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>

#include "network/ping.h"

DEFINE_ERROR(EPING_TIMEOUT, "Ping timeout");

static double _timespec_diff_ms(struct timespec *start, struct timespec *end)
{
    double sec = (double)(end->tv_sec - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return sec * 1000.0 + nsec / 1000000.0;
}

int ping(const char *host, ping_stats_t *stats)
{
    memset(stats, 0, sizeof(ping_stats_t));
    strncpy(stats->host, host, IPV4_ADDR_LEN);
    stats->min_rtt = 1e9;
    stats->max_rtt = 0.0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return SYS_EXCEPTION();

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PING_RCV_PORT);
    inet_pton(AF_INET, host, &dest.sin_addr);

    for (int i = 0; i < PING_COUNT; i++)
    {
        /* Send 4-byte big-endian sequence */
        uint32_t seq = htonl((uint32_t)i);
        struct timespec t_send;
        clock_gettime(CLOCK_MONOTONIC, &t_send);

        ssize_t sent = sendto(sock, &seq, sizeof(seq), 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0)
        {
            stats->sent++;
            continue;
        }
        stats->sent++;

        /* Wait for reply with timeout */
        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ready = poll(&pfd, 1, PING_TIMEOUT_MS);
        if (ready <= 0)
            continue;  /* Timeout or error */

        uint32_t reply;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t rcvd = recvfrom(sock, &reply, sizeof(reply), 0,
                                (struct sockaddr *)&from, &fromlen);
        if (rcvd < (ssize_t)sizeof(reply))
            continue;

        struct timespec t_recv;
        clock_gettime(CLOCK_MONOTONIC, &t_recv);

        /* Verify reply is seq+1 */
        uint32_t expected = htonl((uint32_t)i + 1);
        if (reply != expected)
            continue;

        double rtt = _timespec_diff_ms(&t_send, &t_recv);
        stats->rtt_ms[i] = rtt;
        stats->received++;

        if (rtt < stats->min_rtt) stats->min_rtt = rtt;
        if (rtt > stats->max_rtt) stats->max_rtt = rtt;
    }

    close(sock);

    if (stats->received > 0)
        stats->avg_rtt = (stats->min_rtt + stats->max_rtt) / 2.0;
    else
        stats->min_rtt = 0.0;

    stats->loss_pct = (stats->sent > 0)
        ? 100.0 * (1.0 - (double)stats->received / (double)stats->sent)
        : 100.0;

    return 0;
}

/****************************
 * Ping echo server (background thread)
 ****************************/

typedef struct {
    volatile bool *stop;
} ping_server_args_t;

static void *_ping_server_thread(void *arg)
{
    ping_server_args_t *args = (ping_server_args_t *)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        goto done;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PING_RCV_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        goto done;
    }

    while (!*(args->stop))
    {
        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ready = poll(&pfd, 1, 500);  /* 500ms poll timeout */
        if (ready <= 0)
            continue;

        uint32_t seq;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t rcvd = recvfrom(sock, &seq, sizeof(seq), 0,
                                (struct sockaddr *)&from, &fromlen);
        if (rcvd < (ssize_t)sizeof(seq))
            continue;

        /* Echo back seq+1 */
        uint32_t reply = htonl(ntohl(seq) + 1);
        sendto(sock, &reply, sizeof(reply), 0,
               (struct sockaddr *)&from, fromlen);
    }

    close(sock);

done:
    free(arg);
    return NULL;
}

int ping_server_start(volatile bool *stop)
{
    ping_server_args_t *args = malloc(sizeof(ping_server_args_t));
    if (args == NULL)
        return EXCEPTION(ENOMEM);
    args->stop = stop;

    pthread_t thread;
    int err = pthread_create(&thread, NULL, _ping_server_thread, args);
    if (err != 0)
    {
        free(args);
        return EXCEPTION(err);
    }
    pthread_detach(thread);
    return 0;
}
