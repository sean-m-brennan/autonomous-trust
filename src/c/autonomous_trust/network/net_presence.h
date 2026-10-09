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

/**
 * net_presence.h — local soft-absence (doc/architecture/peer-presence.md).
 *
 * The network process stamps every frame it routes from a known peer and every
 * frame it sends, and from those two clocks decides, per peer, whether the peer
 * has gone quiet. Nothing here touches the roster, the group key or any quorum:
 * an absent peer is still a member. What changes is that the node stops asking
 * it to do work (task invitations and probes), and the app is told.
 *
 * Two thresholds, both wall-clock seconds:
 *  - AT_PRESENCE_HEARTBEAT_SEC (default 30): a node that has sent nothing to
 *    some peer for this long sends one group presence frame, so an idle
 *    cohort still hears from everyone. A busy node never sends one.
 *  - AT_PRESENCE_ABSENT_SEC (default 90): a peer heard from nothing for this
 *    long is absent. A peer is never absent before it has been on the roster
 *    this long.
 *
 * Mirrors Python autonomous_trust.core.network.presence.PresenceTracker.
 */

#ifndef AT_NET_PRESENCE_H
#define AT_NET_PRESENCE_H

#include <stdbool.h>
#include <stddef.h>
#include <uuid/uuid.h>

/** The envelope a presence frame travels under. Labelled for the identity
 *  process, not the network one, so a node built before presence existed
 *  drops it as an unknown identity verb rather than routing it back into its
 *  own outbound loop. A node that knows the verb consumes it in the network
 *  process and never routes it. */
#define NET_PRESENCE_PROCESS  "identity"
#define NET_PRESENCE_FUNCTION "presence"

#define NET_PRESENCE_HEARTBEAT_DEFAULT_SEC 30.0
#define NET_PRESENCE_ABSENT_DEFAULT_SEC    90.0

/** One peer whose presence changed on a tick, or one row of a snapshot. */
typedef struct {
    uuid_t peer_uuid;
    bool   present;
    /** Epoch seconds of the last frame routed from this peer; 0 if none yet
     *  (a peer on the roster we have not heard from, inside its grace). */
    double last_heard;
} net_presence_change_t;

/** Read AT_PRESENCE_HEARTBEAT_SEC / AT_PRESENCE_ABSENT_SEC and clear all
 *  state. A non-positive or unparsable value keeps the default, and the
 *  absent threshold is held above the heartbeat (a peer cannot be absent
 *  before it was due to speak). */
void net_presence_init(void);

/** Test seam: set the thresholds directly and clear all state. */
void net_presence_configure(double heartbeat_sec, double absent_sec);

double net_presence_heartbeat_sec(void);
double net_presence_absent_sec(void);

/** A frame from @p peer was routed. Called on receiver threads. A uuid not on
 *  the roster at the next tick is forgotten there. */
void net_presence_heard(const uuid_t peer, double now);

/** A frame went out to @p peer, or to every peer when @p peer is NULL (a group
 *  multicast or a broadcast). */
void net_presence_sent(const uuid_t peer, double now);

/** Reconcile with the roster and evaluate it at @p now.
 *
 *  Peers new to the roster start present, with their grace and heartbeat
 *  clocks at @p now; peers gone from it are forgotten. Every peer whose
 *  present/absent state flipped is written to @p out (up to @p out_max) and
 *  counted in @p *n_out.
 *
 *  @return true iff a heartbeat is due: some roster peer has had nothing from
 *          us for the heartbeat interval. The caller sends one presence frame
 *          to the group and reports it with net_presence_sent(NULL, now). */
bool net_presence_tick(const uuid_t *roster, size_t n, double now,
                       net_presence_change_t *out, size_t out_max,
                       size_t *n_out);

/** The current state of each @p roster peer, in roster order, for the app's
 *  roster pull. A peer the tracker has not seen yet reads present with
 *  last_heard 0. Returns the number written (min of @p n and @p out_max). */
size_t net_presence_snapshot(const uuid_t *roster, size_t n,
                             net_presence_change_t *out, size_t out_max);

#endif /* AT_NET_PRESENCE_H */
