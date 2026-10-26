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
#ifndef AT_NET_LIVENESS_H
#define AT_NET_LIVENESS_H

/**
 * @file net_liveness.h
 * @brief When each peer was last heard through this node's own transport.
 *
 * Presence (net_presence.h) counts every frame from a peer, however it
 * arrived. This tracker counts only frames the core transport delivered, so
 * an extension that carries traffic some other way (a relay, a radio) can ask
 * whether the transport path to a peer is working. Frames an extension injects
 * never stamp it.
 */

#include <stdbool.h>
#include <uuid/uuid.h>

/** Peers tracked at once; past this the one heard longest ago is forgotten. */
#define NET_LIVENESS_MAX 512

/** CLOCK_MONOTONIC, in seconds. */
double net_liveness_now(void);

/** Forget every peer; @p start is when the network process started. */
void net_liveness_reset(double start);

/** A frame from @p peer arrived through the transport at @p now. An older
 *  time than the one held is ignored. */
void net_liveness_heard(const uuid_t peer, double now);

/** Seconds since @p peer was last heard through the transport, or since
 *  start for a peer never heard. Never negative. */
double net_liveness_quiet_for(const uuid_t peer, double now);

#endif /* AT_NET_LIVENESS_H */
