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

/** @file The directory registry: an opt-in role on a relay (`AT_REGISTRY=1`),
 *  FIRST_CONTACT_PLAN Phase 3. C twin of Python first_contact/registry.py: same
 *  ops, same replies, same reasons.
 *
 *      client -> registry  {"op":"dir_publish","entry":{body,sig}}
 *      registry -> client  {"op":"dir_published","handle":H,"seq":N}
 *                        | {"op":"dir_refused","handle":H,"reason":R}
 *      client -> registry  {"op":"dir_withdraw","handle":H}
 *      registry -> client  {"op":"dir_withdrawn","handle":H}
 *      client -> registry  {"op":"dir_lookup","handle":H}
 *      registry -> client  {"op":"dir_entry","handle":H,"entry":{...}|null}
 *                        | {"op":"dir_limited","handle":H}
 *
 *  An entry is filed only from the registered holder of its key, only with an
 *  attestation from a trusted issuer (<cfg_dir>/registry_issuers.cfg.json),
 *  and only over a lower seq. A lookup costs one token of a per-client bucket
 *  (`AT_REGISTRY_RATE` a minute, default 10). A `published`-visibility entry is
 *  shown only to a client with an entry here itself; to anyone else, and for a
 *  distrusted holder, the answer is the null a missing handle gets.
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_REGISTRY_H
#define AUTONOMOUS_TRUST_NETWORK_NET_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "rendezvous/net_relay.h"

#define AT_REGISTRY_ISSUERS_FILE "registry_issuers.cfg.json"
#define AT_REGISTRY_RATE_ENV "AT_REGISTRY_RATE"
/** Lookups a client may make per minute, by default. Same as Python's. */
#define AT_REGISTRY_DEFAULT_RATE 10
/** Most entries one registry holds. Same as Python's MAX_ENTRIES. */
#define AT_REGISTRY_MAX_ENTRIES 4096
/** Most trusted issuers one registry reads. */
#define AT_REGISTRY_MAX_ISSUERS 64

typedef struct net_registry_s net_registry_t;

/** True iff this node serves as a registry (`AT_REGISTRY`). */
bool net_registry_enabled(void);
/** The lookup rate (`AT_REGISTRY_RATE`, else the default). */
int net_registry_rate(void);

/** Trusted issuers (lower-case hex) from @p path (NULL = the cfg dir's file)
 *  into @p out. @return how many; a missing or unreadable file is 0, logged. */
size_t net_registry_load_issuers(const char *path,
                                 char out[][2 * 32 + 1], size_t max);

/** A registry trusting @p issuers; @p rate lookups a minute (<= 0 = default). */
net_registry_t *net_registry_new(const char *const *issuers, size_t n_issuers, int rate);
void net_registry_free(net_registry_t *reg);
/** A holder this node distrusts is not served. */
void net_registry_set_distrust(net_registry_t *reg, net_relay_distrust_fn fn, void *arg);
/** Tests: replace the monotonic clock (rate buckets) and the wall clock (expiry). */
void net_registry_set_clocks(net_registry_t *reg, double (*monotonic)(void),
                             double (*wallclock)(void));

/** The replies (new references). @p uuid / @p pubkey are the registrant's,
 *  as the relay proved them (lower case). */
json_t *net_registry_publish(net_registry_t *reg, const char *uuid, const char *pubkey,
                             const json_t *wire);
json_t *net_registry_withdraw(net_registry_t *reg, const char *uuid, const char *pubkey,
                              const char *handle);
json_t *net_registry_lookup(net_registry_t *reg, const char *uuid, const char *handle);

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_REGISTRY_H */
