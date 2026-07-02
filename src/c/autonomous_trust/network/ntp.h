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

#ifndef NTP_H
#define NTP_H

/** @addtogroup internal_network
 *  @{
 */

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

#define ENTP_SHORT   282
DECLARE_ERROR(ENTP_SHORT, "NTP response truncated");

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

/*@
  requires \valid(pkt);
  assigns pkt->root_delay, pkt->root_dispersion, pkt->ref_id,
          pkt->ref_ts_sec, pkt->ref_ts_frac,
          pkt->orig_ts_sec, pkt->orig_ts_frac,
          pkt->rx_ts_sec, pkt->rx_ts_frac,
          pkt->tx_ts_sec, pkt->tx_ts_frac;
*/
void ntp_packet_pack(ntp_packet_t *pkt);

/*@
  requires \valid(pkt);
  assigns pkt->root_delay, pkt->root_dispersion, pkt->ref_id,
          pkt->ref_ts_sec, pkt->ref_ts_frac,
          pkt->orig_ts_sec, pkt->orig_ts_frac,
          pkt->rx_ts_sec, pkt->rx_ts_frac,
          pkt->tx_ts_sec, pkt->tx_ts_frac;
*/
void ntp_packet_unpack(ntp_packet_t *pkt);

/*@
  requires \valid(pkt);
  requires \valid(result);
  assigns result->offset_sec, result->roundtrip_sec, result->stratum;
  ensures \result == 0;
  ensures result->stratum == pkt->stratum;
*/
int  ntp_compute_offset(const ntp_packet_t *pkt, struct timespec t1, struct timespec t4,
                        ntp_result_t *result);

/*@
  requires server_addr != \null && \valid_read(server_addr);
  requires \valid(result);
  assigns result->offset_sec, result->roundtrip_sec, result->stratum;
  behavior success:
    ensures \result == 0;
    ensures result->stratum >= 1 && result->stratum <= 15;
  behavior timeout:
    ensures \result == -1;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors success, timeout;
*/
int  ntp_client_request(const char *server_addr, ntp_result_t *result);

/*@
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int  ntp_server_start(void);

/*@
  assigns \nothing;
  ensures \result == 0;
*/
int  ntp_server_stop(void);

/****************************
 * Background sync (mirrors Python start_sync)
 ****************************/

#define NTP_DEFAULT_SYNC_INTERVAL 300  /* seconds */

/*@
  requires server_addr == \null || \valid_read(server_addr);
  behavior null_addr:
    assumes server_addr == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes server_addr != \null;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int    ntp_start_sync(const char *server_addr, int interval_sec);

/*@
  assigns \nothing;
  ensures \result == 0;
*/
int    ntp_stop_sync(void);

/*@
  assigns \nothing;
*/
double ntp_get_offset(void);


/** @} */ /* end of internal_network */

#endif  /* NTP_H */
