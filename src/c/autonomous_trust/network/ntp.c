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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>

#include "network/ntp.h"

DEFINE_ERROR(ENTP_TIMEOUT, "NTP request timeout");
DEFINE_ERROR(ENTP_STRATUM, "NTP invalid stratum");

/****************************
 * Byte order conversion
 ****************************/

void ntp_packet_pack(ntp_packet_t *pkt)
{
    pkt->root_delay = htonl(pkt->root_delay);
    pkt->root_dispersion = htonl(pkt->root_dispersion);
    pkt->reference_id = htonl(pkt->reference_id);
    pkt->ref_timestamp_sec = htonl(pkt->ref_timestamp_sec);
    pkt->ref_timestamp_frac = htonl(pkt->ref_timestamp_frac);
    pkt->orig_timestamp_sec = htonl(pkt->orig_timestamp_sec);
    pkt->orig_timestamp_frac = htonl(pkt->orig_timestamp_frac);
    pkt->recv_timestamp_sec = htonl(pkt->recv_timestamp_sec);
    pkt->recv_timestamp_frac = htonl(pkt->recv_timestamp_frac);
    pkt->tx_timestamp_sec = htonl(pkt->tx_timestamp_sec);
    pkt->tx_timestamp_frac = htonl(pkt->tx_timestamp_frac);
}

void ntp_packet_unpack(ntp_packet_t *pkt)
{
    pkt->root_delay = ntohl(pkt->root_delay);
    pkt->root_dispersion = ntohl(pkt->root_dispersion);
    pkt->reference_id = ntohl(pkt->reference_id);
    pkt->ref_timestamp_sec = ntohl(pkt->ref_timestamp_sec);
    pkt->ref_timestamp_frac = ntohl(pkt->ref_timestamp_frac);
    pkt->orig_timestamp_sec = ntohl(pkt->orig_timestamp_sec);
    pkt->orig_timestamp_frac = ntohl(pkt->orig_timestamp_frac);
    pkt->recv_timestamp_sec = ntohl(pkt->recv_timestamp_sec);
    pkt->recv_timestamp_frac = ntohl(pkt->recv_timestamp_frac);
    pkt->tx_timestamp_sec = ntohl(pkt->tx_timestamp_sec);
    pkt->tx_timestamp_frac = ntohl(pkt->tx_timestamp_frac);
}

/****************************
 * Helpers
 ****************************/

static double _ntp_ts_to_double(uint32_t sec, uint32_t frac)
{
    return (double)(sec - NTP_EPOCH_DELTA) + (double)frac / (double)0x100000000ULL;
}

static void _unix_to_ntp_ts(struct timespec *ts, uint32_t *sec, uint32_t *frac)
{
    *sec = (uint32_t)(ts->tv_sec + NTP_EPOCH_DELTA);
    *frac = (uint32_t)((double)ts->tv_nsec / 1e9 * (double)0x100000000ULL);
}

double ntp_compute_offset(double t1, double t2, double t3, double t4)
{
    return ((t2 - t1) + (t3 - t4)) / 2.0;
}

/****************************
 * NTP client
 ****************************/

int ntp_client_request(const char *host, ntp_result_t *result)
{
    memset(result, 0, sizeof(ntp_result_t));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return SYS_EXCEPTION();

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(NTP_PORT);
    inet_pton(AF_INET, host, &dest.sin_addr);

    /* Build client request: version 3, mode 3 (client) */
    ntp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.li_vn_mode = (0 << 6) | (3 << 3) | 3;  /* LI=0, VN=3, Mode=3 */

    /* Record T1 */
    struct timespec t1_ts;
    clock_gettime(CLOCK_REALTIME, &t1_ts);
    {
        uint32_t sec, frac;
        _unix_to_ntp_ts(&t1_ts, &sec, &frac);
        pkt.tx_timestamp_sec = sec;
        pkt.tx_timestamp_frac = frac;
    }

    ntp_packet_pack(&pkt);

    ssize_t sent = sendto(sock, &pkt, sizeof(pkt), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0)
    {
        close(sock);
        return SYS_EXCEPTION();
    }

    /* Wait for response */
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int ready = poll(&pfd, 1, 5000);  /* 5 second timeout */
    if (ready <= 0)
    {
        close(sock);
        return EXCEPTION(ENTP_TIMEOUT);
    }

    ntp_packet_t resp;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t rcvd = recvfrom(sock, &resp, sizeof(resp), 0,
                            (struct sockaddr *)&from, &fromlen);

    /* Record T4 */
    struct timespec t4_ts;
    clock_gettime(CLOCK_REALTIME, &t4_ts);

    close(sock);

    if (rcvd < (ssize_t)sizeof(resp))
        return -1;

    ntp_packet_unpack(&resp);

    /* Extract timestamps */
    double t1 = (double)t1_ts.tv_sec + (double)t1_ts.tv_nsec / 1e9;
    double t2 = _ntp_ts_to_double(resp.recv_timestamp_sec, resp.recv_timestamp_frac);
    double t3 = _ntp_ts_to_double(resp.tx_timestamp_sec, resp.tx_timestamp_frac);
    double t4 = (double)t4_ts.tv_sec + (double)t4_ts.tv_nsec / 1e9;

    result->offset_sec = ntp_compute_offset(t1, t2, t3, t4);
    result->roundtrip_sec = (t4 - t1) - (t3 - t2);
    result->stratum = resp.stratum;

    return 0;
}

/****************************
 * NTP server (background thread)
 ****************************/

typedef struct {
    volatile bool *stop;
} ntp_server_args_t;

static void *_ntp_server_thread(void *arg)
{
    ntp_server_args_t *args = (ntp_server_args_t *)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        goto done;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(NTP_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        goto done;
    }

    while (!*(args->stop))
    {
        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ready = poll(&pfd, 1, 500);
        if (ready <= 0)
            continue;

        ntp_packet_t req;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t rcvd = recvfrom(sock, &req, sizeof(req), 0,
                                (struct sockaddr *)&from, &fromlen);
        if (rcvd < (ssize_t)sizeof(req))
            continue;

        /* Record receive time */
        struct timespec recv_ts;
        clock_gettime(CLOCK_REALTIME, &recv_ts);

        ntp_packet_unpack(&req);

        /* Build response: mode 4 (server), stratum 2 */
        ntp_packet_t resp;
        memset(&resp, 0, sizeof(resp));
        resp.li_vn_mode = (0 << 6) | (3 << 3) | 4;  /* LI=0, VN=3, Mode=4 */
        resp.stratum = 2;
        resp.poll_interval = req.poll_interval;
        resp.precision = -20;  /* ~1 microsecond */

        /* Copy client's transmit timestamp to origin */
        resp.orig_timestamp_sec = req.tx_timestamp_sec;
        resp.orig_timestamp_frac = req.tx_timestamp_frac;

        /* Set receive timestamp */
        {
            uint32_t sec, frac;
            _unix_to_ntp_ts(&recv_ts, &sec, &frac);
            resp.recv_timestamp_sec = sec;
            resp.recv_timestamp_frac = frac;
        }

        /* Set transmit timestamp */
        struct timespec tx_ts;
        clock_gettime(CLOCK_REALTIME, &tx_ts);
        {
            uint32_t sec, frac;
            _unix_to_ntp_ts(&tx_ts, &sec, &frac);
            resp.tx_timestamp_sec = sec;
            resp.tx_timestamp_frac = frac;
        }

        ntp_packet_pack(&resp);

        sendto(sock, &resp, sizeof(resp), 0,
               (struct sockaddr *)&from, fromlen);
    }

    close(sock);

done:
    free(arg);
    return NULL;
}

int ntp_server_start(volatile bool *stop)
{
    ntp_server_args_t *args = malloc(sizeof(ntp_server_args_t));
    if (args == NULL)
        return EXCEPTION(ENOMEM);
    args->stop = stop;

    pthread_t thread;
    int err = pthread_create(&thread, NULL, _ntp_server_thread, args);
    if (err != 0)
    {
        free(args);
        return EXCEPTION(err);
    }
    pthread_detach(thread);
    return 0;
}

void ntp_server_stop(void)
{
    /* Caller manages the stop flag */
}
