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

/** @file The area hub: an opt-in role on a relay (`AT_HUB=1`), serving the
 *  areas in `AT_HUB_AREAS`. C twin of Python network/hub.py: same ops, same
 *  replies, same reasons, same order of cards.
 *      client -> hub  {"op":"hub_publish","card":{body,sig}}
 *      hub -> client  {"op":"hub_published","area":A,"seq":N}
 *                   | {"op":"hub_refused","area":A,"reason":R}
 *      client -> hub  {"op":"hub_withdraw","area":A}
 *      hub -> client  {"op":"hub_withdrawn","area":A}
 *      client -> hub  {"op":"hub_lookup","area":A}
 *      hub -> client  {"op":"hub_cards","area":A,"cards":[{body,sig},...]}
 *                   | {"op":"hub_limited","area":A}
 *  A card is filed only from the registered holder of its key, only for an
 *  area this hub serves, only over a lower seq, never for longer than a day,
 *  one per holder per area. A lookup is reciprocal: only a client with a live
 *  card in that area sees the area's cards, and anyone else the empty list a
 *  quiet area gets. At most AT_HUB_LOOKUP_MAX cards, freshest first (uuid
 *  breaks a tie), never the asker's own, never a distrusted holder's; one
 *  token per lookup (`AT_HUB_RATE` a minute, default 6).
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_HUB_H
#define AUTONOMOUS_TRUST_NETWORK_NET_HUB_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "contacts/area_card.h"
#include "network/net_relay.h"

#define AT_HUB_AREAS_ENV "AT_HUB_AREAS"
#define AT_HUB_RATE_ENV "AT_HUB_RATE"
/** Lookups a client may make per minute, by default. Same as Python's. */
#define AT_HUB_DEFAULT_RATE 6
/** Most cards one hub holds, and one area. Same as Python's. */
#define AT_HUB_MAX_CARDS 4096
#define AT_HUB_MAX_PER_AREA 256
/** Most cards one lookup answers with. Same as Python's LOOKUP_MAX. */
#define AT_HUB_LOOKUP_MAX 32
/** Most areas one hub serves. Same as Python's MAX_AREAS. */
#define AT_HUB_MAX_AREAS 8

typedef struct net_hub_s net_hub_t;

/** True iff this node serves as a hub (`AT_HUB`). */
bool net_hub_enabled(void);
/** The lookup rate (`AT_HUB_RATE`, else the default). */
int net_hub_rate(void);
/** The areas in `AT_HUB_AREAS`, normalized, in order, without repeats, into
 *  @p out. @return how many. */
size_t net_hub_areas(char out[][AT_AREA_MAX + 1], size_t max);

/** A hub serving @p areas; @p rate lookups a minute (<= 0 = default). */
net_hub_t *net_hub_new(const char *const *areas, size_t n_areas, int rate);
void net_hub_free(net_hub_t *hub);
/** A holder this node distrusts is not shown. */
void net_hub_set_distrust(net_hub_t *hub, net_relay_distrust_fn fn, void *arg);
/** Tests: replace the monotonic clock (rate buckets) and the wall clock (expiry). */
void net_hub_set_clocks(net_hub_t *hub, double (*monotonic)(void), double (*wallclock)(void));

/** The replies (new references). @p uuid / @p pubkey are the registrant's,
 *  as the relay proved them (lower case). */
json_t *net_hub_publish(net_hub_t *hub, const char *uuid, const char *pubkey,
                        const json_t *wire);
json_t *net_hub_withdraw(net_hub_t *hub, const char *uuid, const char *pubkey,
                         const char *area);
json_t *net_hub_lookup(net_hub_t *hub, const char *uuid, const char *area);

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_HUB_H */
