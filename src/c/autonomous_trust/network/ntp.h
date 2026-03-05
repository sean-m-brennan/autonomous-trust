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

#ifndef NTP_H
#define NTP_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "network/network.h"
#include "utilities/exception.h"

/**
 * NTP epoch delta: seconds between 1900-01-01 and 1970-01-01
 */
#define NTP_EPOCH_DELTA 2208988800UL

/**
 * RFC-1305 NTP packet (48 bytes)
 */
typedef struct __attribute__((packed)) {
    uint8_t  li_vn_mode;     /* Leap indicator(2), version(3), mode(3) */
    uint8_t  stratum;
    uint8_t  poll_interval;
    int8_t   precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;
    uint32_t ref_timestamp_sec;
    uint32_t ref_timestamp_frac;
    uint32_t orig_timestamp_sec;
    uint32_t orig_timestamp_frac;
    uint32_t recv_timestamp_sec;
    uint32_t recv_timestamp_frac;
    uint32_t tx_timestamp_sec;
    uint32_t tx_timestamp_frac;
} ntp_packet_t;

/**
 * NTP client result
 */
typedef struct {
    double offset_sec;      /* Clock offset in seconds */
    double roundtrip_sec;   /* Round-trip delay in seconds */
    uint8_t stratum;
} ntp_result_t;

/**
 * Pack NTP packet fields to network byte order.
 */
void ntp_packet_pack(ntp_packet_t *pkt);

/**
 * Unpack NTP packet fields from network byte order.
 */
void ntp_packet_unpack(ntp_packet_t *pkt);

/**
 * Send NTP client request and compute offset.
 * offset = ((T2-T1) + (T3-T4)) / 2
 */
int ntp_client_request(const char *host, ntp_result_t *result);

/**
 * Compute clock offset from four timestamps.
 */
double ntp_compute_offset(double t1, double t2, double t3, double t4);

/**
 * Start NTP server in background thread (mode 4, stratum 2).
 */
int ntp_server_start(volatile bool *stop);

/**
 * Stop NTP server.
 */
void ntp_server_stop(void);

#define ENTP_TIMEOUT 280
DECLARE_ERROR(ENTP_TIMEOUT, "NTP request timeout");

#define ENTP_STRATUM 281
DECLARE_ERROR(ENTP_STRATUM, "NTP invalid stratum");

#endif  /* NTP_H */
