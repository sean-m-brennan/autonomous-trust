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

#ifndef PING_H
#define PING_H

#include <stdint.h>
#include <stdbool.h>

#include "network/network.h"
#include "utilities/exception.h"

/****************************
 * Constants
 ****************************/

#define PING_COUNT       4
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
    double rtt_ms[PING_COUNT];
    double min_rtt;
    double max_rtt;
    double avg_rtt;
    double loss;
    int sent;
    int received;
} ping_stats_t;

/****************************
 * API
 ****************************/

int ping(const char *host, ping_stats_t *stats);
int ping_server_start(void);
int ping_server_stop(void);

#endif  /* PING_H */
