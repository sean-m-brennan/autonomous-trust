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

/** @file Signed relay seed list (FIRST_CONTACT_PLAN §10.1, second half). C
 *  twin of Python network/relay_seeds.py: same files, prefixes and rules.
 *
 *  The relays a node registers with when its operator named none
 *  (`AT_USE_RELAY` unset) and first contact is on. A default mirror list, not
 *  a root of trust: a seed relay still proves itself and is still
 *  reputation-gated. Two files, both `{"body": <exact signed JSON string>,
 *  "sig": <hex>}`:
 *
 *      shipped  <cfg_dir>/relay_seeds.cfg.json  (or `$AT_RELAY_SEEDS`)
 *               release key over "at-seeds-v1|" + body
 *               body = {"v":1,"typename":"at-seeds","seq":N,"relays":[hint,...]}
 *      local    <data_dir>/relay_seeds_local.cfg.json
 *               this node's own key over "at-seeds-local-v1|" + body
 *               body = {"v":1,"typename":"at-seeds-local","add":[...],"remove":[...]}
 *
 *  The shipped list changes only with a new build; the highest `seq` accepted
 *  is kept in <data_dir>/relay_seeds_seen.cfg.json and a lower one is refused.
 *  Local additions come first, removals drop a shipped entry by endpoint. A
 *  file that fails its check is ignored (logged), never half-applied; one bad
 *  entry refuses the whole file.
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_RELAY_SEEDS_H
#define AUTONOMOUS_TRUST_NETWORK_NET_RELAY_SEEDS_H

#include <stddef.h>

#include "network/net_relay.h"

/** The release key (hex ed25519) that signs the shipped list. Empty until the
 *  project's release keypair is minted: with no key no shipped list is
 *  trusted. Same as Python relay_seeds.RELEASE_KEY. */
#define AT_RELAY_SEEDS_RELEASE_KEY ""

#define AT_RELAY_SEEDS_DOMAIN "at-seeds-v1|"
#define AT_RELAY_SEEDS_LOCAL_DOMAIN "at-seeds-local-v1|"
#define AT_RELAY_SEEDS_TYPENAME "at-seeds"
#define AT_RELAY_SEEDS_LOCAL_TYPENAME "at-seeds-local"
#define AT_RELAY_SEEDS_VERSION 1
#define AT_RELAY_SEEDS_FILE "relay_seeds.cfg.json"
#define AT_RELAY_SEEDS_LOCAL_FILE "relay_seeds_local.cfg.json"
#define AT_RELAY_SEEDS_SEEN_FILE "relay_seeds_seen.cfg.json"
#define AT_RELAY_SEEDS_ENV "AT_RELAY_SEEDS"
/** Most entries one list (or one side of the edits) may hold; past it the
 *  file is refused. Same as Python relay_seeds.MAX_ENTRIES. */
#define AT_RELAY_SEEDS_MAX 64

/** A parsed list of hints. */
typedef struct {
    size_t n;
    net_relay_ep_t eps[AT_RELAY_SEEDS_MAX];
    net_relay_pin_t pins[AT_RELAY_SEEDS_MAX];
} net_relay_seed_list_t;

/** Verify the shipped list @p text against @p release_key_hex into @p seq and
 *  @p out. 0, or -1 when it is refused (for whatever reason: no key, bad
 *  signature, malformed, a bad entry). Does not apply the seq floor. Mirrors
 *  Python relay_seeds.verify_seeds. */
int net_relay_seeds_verify(const char *text, const char *release_key_hex,
                           long long *seq, net_relay_seed_list_t *out);

/** Verify the local edits @p text against this node's key @p node_key_hex
 *  into @p adds / @p removes. 0 or -1. Mirrors relay_seeds.verify_local. */
int net_relay_seeds_verify_local(const char *text, const char *node_key_hex,
                                 net_relay_seed_list_t *adds,
                                 net_relay_seed_list_t *removes);

/** Local additions, then the shipped entries not removed, one per endpoint,
 *  at most @p max (<= AT_RELAY_MAX). @return how many. */
size_t net_relay_seeds_merge(const net_relay_seed_list_t *shipped,
                             const net_relay_seed_list_t *adds,
                             const net_relay_seed_list_t *removes,
                             net_relay_ep_t *out, net_relay_pin_t *pins, size_t max);

/** This node's effective seed relays from the files, verifying the shipped
 *  list against @p release_key_hex (NULL = AT_RELAY_SEEDS_RELEASE_KEY). Every
 *  refusal is logged and leaves that file out. @p pins may be NULL. @return
 *  how many. Mirrors relay_seeds.load. */
size_t net_relay_seeds_load(const char *release_key_hex, net_relay_ep_t *out,
                            net_relay_pin_t *pins, size_t max);

/** The shipped list's path: `$AT_RELAY_SEEDS`, else <cfg_dir>/relay_seeds.cfg.json.
 *  0 or -1. */
int net_relay_seeds_path(char *out, size_t out_len);

/** This node's public signing key (hex) derived from its identity.cfg.json.
 *  0, or -1 if there is none. */
int net_relay_seeds_node_key(char *out, size_t out_len);

/** The release key currently in force (see net_relay_seeds_set_release_key). */
const char *net_relay_seeds_release_key(void);

/** The release key the node's own hints verify against. Tests point it at a
 *  test key; NULL restores AT_RELAY_SEEDS_RELEASE_KEY. */
void net_relay_seeds_set_release_key(const char *release_key_hex);

/* ---- Shared with net_relay_rosters.c --------------------------------------
 * A community relay roster is the same kind of file as the seed list, signed by
 * a different key under a different domain, so its verifier is this one. Not a
 * public API. */
struct json_t;
/** Split a `{"body","sig"}` file: the parsed body (new reference, or NULL when
 *  malformed), the parsed wire object in @p wire_out (new reference; decref
 *  both), and borrowed body / sig strings. */
struct json_t *net_relay_signed_split(const char *text, struct json_t **wire_out,
                                      const char **body_str, const char **sig_hex);
/** 0 iff @p sig_hex is @p key_hex's ed25519 signature over @p domain + @p body_str. */
int net_relay_signed_check(const char *key_hex, const char *domain, const char *body_str,
                           const char *sig_hex);
/** Parse the hint list @p field of @p body (missing = empty). 0, or -1 when it
 *  is not a list of at most AT_RELAY_SEEDS_MAX hints. */
int net_relay_signed_hints(const struct json_t *body, const char *field,
                           net_relay_seed_list_t *out);
/** A file's whole text (malloc'd, NUL-terminated), or NULL. */
char *net_relay_signed_read(const char *path);
/** <data_dir>/@p name into @p out. 0 or -1. */
int net_relay_signed_data_path(const char *name, char *out, size_t out_len);

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_RELAY_SEEDS_H */
