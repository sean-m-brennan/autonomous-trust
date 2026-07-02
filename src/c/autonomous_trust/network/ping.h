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

#ifndef PING_H
#define PING_H

/** @addtogroup internal_network
 *  @{
 */

#include <stdint.h>
#include <stdbool.h>

#include "network/network.h"
#include "utilities/exception.h"

/****************************
 * Constants
 ****************************/

#define PING_COUNT       4      /* default count */
#define MAX_PING_COUNT   64     /* maximum allowed count */
#define PING_TIMEOUT_MS  2000

/****************************
 * Error codes
 ****************************/

#define EPING_TIMEOUT 270
DECLARE_ERROR(EPING_TIMEOUT, "Ping timed out");

/****************************
 * Data structures
 ****************************/

typedef struct {
    char host[IPV4_ADDR_LEN + 1];
    double rtt_ms[MAX_PING_COUNT];
    double min_rtt;
    double max_rtt;
    double avg_rtt;
    double loss;
    int sent;
    int received;
    int count;   /* actual count used */
} ping_stats_t;

/****************************
 * API
 ****************************/

/*@
  requires host != \null && \valid_read(host);
  requires \valid(stats);
  assigns *stats;
  behavior success:
    ensures \result == 0;
    ensures stats->sent > 0;
    ensures stats->received >= 0 && stats->received <= stats->sent;
    ensures stats->loss >= 0.0 && stats->loss <= 1.0;
  behavior timeout:
    ensures \result == -1;
  disjoint behaviors;
*/
int ping(const char *host, int count, ping_stats_t *stats);

/*@
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int ping_server_start(void);

/*@
  assigns \nothing;
  ensures \result == 0;
*/
int ping_server_stop(void);


/** @} */ /* end of internal_network */

#endif  /* PING_H */
