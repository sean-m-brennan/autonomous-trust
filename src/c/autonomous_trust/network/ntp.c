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
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network/ntp.h"
#include "utilities/exception.h"

DEFINE_ERROR(ENTP_TIMEOUT, "NTP request timed out");
DEFINE_ERROR(ENTP_STRATUM, "NTP stratum too high");

/****************************
 * Byte-order conversion helpers
 * NTP packets must be in network byte order.
 * We avoid taking addresses of packed struct members (UB) by using
 * local variables for intermediate values.
 ****************************/

void ntp_packet_pack(ntp_packet_t *pkt)
{
    uint32_t v;

    v = ntohl(pkt->root_delay);      pkt->root_delay      = htonl(v); /* already in host, convert */
    /* Actually pack: host -> network */
    v = pkt->root_delay;             pkt->root_delay      = htonl(v);
    v = pkt->root_dispersion;        pkt->root_dispersion = htonl(v);
    v = pkt->ref_id;                 pkt->ref_id          = htonl(v);
    v = pkt->ref_ts_sec;             pkt->ref_ts_sec      = htonl(v);
    v = pkt->ref_ts_frac;            pkt->ref_ts_frac     = htonl(v);
    v = pkt->orig_ts_sec;            pkt->orig_ts_sec     = htonl(v);
    v = pkt->orig_ts_frac;           pkt->orig_ts_frac    = htonl(v);
    v = pkt->rx_ts_sec;              pkt->rx_ts_sec       = htonl(v);
    v = pkt->rx_ts_frac;             pkt->rx_ts_frac      = htonl(v);
    v = pkt->tx_ts_sec;              pkt->tx_ts_sec       = htonl(v);
    v = pkt->tx_ts_frac;             pkt->tx_ts_frac      = htonl(v);
}

void ntp_packet_unpack(ntp_packet_t *pkt)
{
    uint32_t sec, frac;

    sec = pkt->root_delay;      pkt->root_delay      = ntohl(sec);
    sec = pkt->root_dispersion; pkt->root_dispersion = ntohl(sec);
    sec = pkt->ref_id;          pkt->ref_id          = ntohl(sec);

    sec = pkt->ref_ts_sec;      frac = pkt->ref_ts_frac;
    pkt->ref_ts_sec  = ntohl(sec);
    pkt->ref_ts_frac = ntohl(frac);

    sec = pkt->orig_ts_sec;     frac = pkt->orig_ts_frac;
    pkt->orig_ts_sec  = ntohl(sec);
    pkt->orig_ts_frac = ntohl(frac);

    sec = pkt->rx_ts_sec;       frac = pkt->rx_ts_frac;
    pkt->rx_ts_sec  = ntohl(sec);
    pkt->rx_ts_frac = ntohl(frac);

    sec = pkt->tx_ts_sec;       frac = pkt->tx_ts_frac;
    pkt->tx_ts_sec  = ntohl(sec);
    pkt->tx_ts_frac = ntohl(frac);
}

/****************************
 * Compute NTP clock offset and round-trip delay.
 *
 * NTP defines (all timestamps in NTP epoch):
 *   t1 = client send time  (orig_ts)
 *   t2 = server receive time (rx_ts)
 *   t3 = server transmit time (tx_ts)
 *   t4 = client receive time  (local clock at receive)
 *
 *   roundtrip = (t4 - t1) - (t3 - t2)
 *   offset    = ((t2 - t1) + (t3 - t4)) / 2
 ****************************/

int ntp_compute_offset(const ntp_packet_t *pkt, struct timespec t1, struct timespec t4,
                       ntp_result_t *result)
{
    /* Read packed fields into local variables to avoid UB on packed members */
    uint32_t rx_sec  = pkt->rx_ts_sec;
    uint32_t rx_frac = pkt->rx_ts_frac;
    uint32_t tx_sec  = pkt->tx_ts_sec;
    uint32_t tx_frac = pkt->tx_ts_frac;

    /* Convert NTP timestamps to seconds since Unix epoch */
    double d_t1 = (double)t1.tv_sec + (double)t1.tv_nsec / 1.0e9;
    double d_t4 = (double)t4.tv_sec + (double)t4.tv_nsec / 1.0e9;

    double d_t2 = (double)(rx_sec - (uint32_t)NTP_EPOCH_DELTA)
                + (double)rx_frac / 4294967296.0;
    double d_t3 = (double)(tx_sec - (uint32_t)NTP_EPOCH_DELTA)
                + (double)tx_frac / 4294967296.0;

    result->roundtrip_sec = (d_t4 - d_t1) - (d_t3 - d_t2);
    result->offset_sec    = ((d_t2 - d_t1) + (d_t3 - d_t4)) / 2.0;
    result->stratum       = pkt->stratum;

    return 0;
}

/****************************
 * NTP client
 ****************************/

int ntp_client_request(const char *server_addr, ntp_result_t *result)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return SYS_EXCEPTION();

    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec  = NTP_TIMEOUT_MS / 1000;
    tv.tv_usec = (NTP_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(NTP_PORT);
    if (inet_pton(AF_INET, server_addr, &srv.sin_addr) <= 0)
    {
        close(sock);
        return SYS_EXCEPTION();
    }

    /* Build NTP client request packet (mode 3 = client, version 4) */
    ntp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.li_vn_mode = (0 << 6) | (4 << 3) | 3;  /* LI=0, VN=4, Mode=3 */

    /* Record transmit timestamp (t1) */
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);

    uint32_t sec  = (uint32_t)(t1.tv_sec + NTP_EPOCH_DELTA);
    uint32_t frac = (uint32_t)((double)t1.tv_nsec * 4294967296.0 / 1.0e9);
    pkt.tx_ts_sec  = htonl(sec);
    pkt.tx_ts_frac = htonl(frac);

    if (sendto(sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&srv, sizeof(srv)) < 0)
    {
        close(sock);
        return SYS_EXCEPTION();
    }

    /* Receive response */
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(sock, &pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&from, &from_len);
    close(sock);

    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return EXCEPTION(ENTP_TIMEOUT);
        return SYS_EXCEPTION();
    }

    if (n < (ssize_t)sizeof(ntp_packet_t))
        return -1;

    /* Record receive time (t4) */
    struct timespec t4;
    clock_gettime(CLOCK_REALTIME, &t4);

    /* Unpack network byte order */
    ntp_packet_unpack(&pkt);

    /* Sanity check stratum */
    if (pkt.stratum == 0 || pkt.stratum > 15)
        return EXCEPTION(ENTP_STRATUM);

    return ntp_compute_offset(&pkt, t1, t4, result);
}

/****************************
 * NTP server (simple stratum-1 echo server)
 ****************************/

static pthread_t    ntp_server_thread;
static volatile int ntp_server_running = 0;

static void *ntp_server_loop(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return NULL;

    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(NTP_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return NULL;
    }

    while (ntp_server_running)
    {
        ntp_packet_t req;
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(sock, &req, sizeof(req), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0)
            continue;

        if (n < (ssize_t)sizeof(ntp_packet_t))
            continue;

        /* Copy client transmit time -> originate timestamp */
        ntp_packet_t resp;
        memset(&resp, 0, sizeof(resp));

        /* LI=0, VN=4, Mode=4 (server) */
        resp.li_vn_mode = (0 << 6) | (4 << 3) | 4;
        resp.stratum    = 1;
        resp.poll       = req.poll;
        resp.precision  = (uint8_t)(-20);  /* ~1 microsecond */

        /* Copy originate ts from request's tx_ts */
        resp.orig_ts_sec  = req.tx_ts_sec;
        resp.orig_ts_frac = req.tx_ts_frac;

        /* Receive timestamp */
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        uint32_t rx_sec  = (uint32_t)(now.tv_sec + NTP_EPOCH_DELTA);
        uint32_t rx_frac = (uint32_t)((double)now.tv_nsec * 4294967296.0 / 1.0e9);
        resp.rx_ts_sec  = htonl(rx_sec);
        resp.rx_ts_frac = htonl(rx_frac);

        /* Transmit timestamp (same as receive for simplicity) */
        clock_gettime(CLOCK_REALTIME, &now);
        uint32_t tx_sec  = (uint32_t)(now.tv_sec + NTP_EPOCH_DELTA);
        uint32_t tx_frac = (uint32_t)((double)now.tv_nsec * 4294967296.0 / 1.0e9);
        resp.tx_ts_sec  = htonl(tx_sec);
        resp.tx_ts_frac = htonl(tx_frac);

        sendto(sock, &resp, sizeof(resp), 0,
               (struct sockaddr *)&from, from_len);
    }

    close(sock);
    return NULL;
}

int ntp_server_start(void)
{
    if (ntp_server_running)
        return 0;
    ntp_server_running = 1;
    int err = pthread_create(&ntp_server_thread, NULL, ntp_server_loop, NULL);
    if (err != 0)
    {
        ntp_server_running = 0;
        errno = err;
        return SYS_EXCEPTION();
    }
    return 0;
}

int ntp_server_stop(void)
{
    if (!ntp_server_running)
        return 0;
    ntp_server_running = 0;
    pthread_join(ntp_server_thread, NULL);
    return 0;
}
