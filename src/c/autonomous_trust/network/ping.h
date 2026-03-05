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

#include <stdbool.h>
#include <stdint.h>

#include "network/network.h"
#include "utilities/exception.h"

#define PING_COUNT 4
#define PING_TIMEOUT_MS 2000

typedef struct {
    char host[IPV4_ADDR_LEN + 1];
    double rtt_ms[PING_COUNT];
    double min_rtt;
    double max_rtt;
    double avg_rtt;
    double loss_pct;
    int sent;
    int received;
} ping_stats_t;

/**
 * UDP ping client: sends 4-byte big-endian sequence numbers,
 * expects seq+1 echo. Measures RTT via clock_gettime.
 */
int ping(const char *host, ping_stats_t *stats);

/**
 * Start UDP ping echo server in a background pthread.
 * Echoes received seq+1 back to sender.
 * Set *stop to true to terminate.
 */
int ping_server_start(volatile bool *stop);

#define EPING_TIMEOUT 270
DECLARE_ERROR(EPING_TIMEOUT, "Ping timeout");

#endif  /* PING_H */
