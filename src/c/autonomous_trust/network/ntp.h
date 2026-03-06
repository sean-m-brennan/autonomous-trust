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

#include <stdint.h>
#include <time.h>

#include "network/network.h"
#include "utilities/exception.h"

/****************************
 * Constants
 ****************************/

#define NTP_EPOCH_DELTA  2208988800UL
#define NTP_TIMEOUT_MS   5000

/****************************
 * Error codes
 ****************************/

#define ENTP_TIMEOUT 280
DECLARE_ERROR(ENTP_TIMEOUT, "NTP request timed out");

#define ENTP_STRATUM 281
DECLARE_ERROR(ENTP_STRATUM, "NTP stratum too high");

/****************************
 * NTP packet (48 bytes, network byte order)
 ****************************/

typedef struct __attribute__((packed)) {
    uint8_t  li_vn_mode;
    uint8_t  stratum;
    uint8_t  poll;
    uint8_t  precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t orig_ts_sec;
    uint32_t orig_ts_frac;
    uint32_t rx_ts_sec;
    uint32_t rx_ts_frac;
    uint32_t tx_ts_sec;
    uint32_t tx_ts_frac;
} ntp_packet_t;

/****************************
 * NTP result
 ****************************/

typedef struct {
    double  offset_sec;
    double  roundtrip_sec;
    uint8_t stratum;
} ntp_result_t;

/****************************
 * API
 ****************************/

void ntp_packet_pack(ntp_packet_t *pkt);
void ntp_packet_unpack(ntp_packet_t *pkt);
int  ntp_compute_offset(const ntp_packet_t *pkt, struct timespec t1, struct timespec t4,
                        ntp_result_t *result);
int  ntp_client_request(const char *server_addr, ntp_result_t *result);
int  ntp_server_start(void);
int  ntp_server_stop(void);

#endif  /* NTP_H */
