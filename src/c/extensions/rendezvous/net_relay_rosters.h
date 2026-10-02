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

/** @file Community relay rosters (FIRST_CONTACT_PLAN §4.2 / §4.5, "an Ethne
 *  rendezvous polity option"). C twin of Python network/relay_rosters.py:
 *  same files, prefixes and rules.
 *
 *  A community that runs rendezvous relays (an Ethne polity is the case this
 *  was built for; nothing here knows what a polity is) publishes the relays it
 *  stands behind as a signed roster, and a node whose operator pinned that
 *  community's key uses them. A list of where to look, not a root of trust:
 *  a roster relay still proves itself and is still reputation-gated.
 *
 *      roster   <cfg_dir>/relay_rosters/<any>.cfg.json  (or the dir in `$AT_RELAY_ROSTERS`)
 *               {"body": <exact signed JSON string>, "sig": <hex>}
 *               issuer key over "at-relay-roster-v1|" + body
 *               body = {"v":1,"typename":"at-relay-roster","issuer":<hex key>,
 *                       "seq":N,"relays":["relay://<uuid>:<fp>@host:port",...],
 *                       "areas":{"<a relays entry>":["u4pr",...],...}}   (optional)
 *      issuers  `$AT_RELAY_ROSTER_ISSUERS` (comma-separated hex keys), then
 *               <cfg_dir>/relay_roster_issuers.cfg.json = {"issuers":[hex,...]}
 *      seen     <data_dir>/relay_rosters_seen.cfg.json = {<issuer hex>: seq}
 *
 *  Only a pinned issuer counts; every entry must be pinned, or the whole
 *  roster is refused; a higher seq replaces that issuer's previous roster
 *  whole (an empty roster is valid) and a lower one is refused. Of two files
 *  from one issuer the higher seq wins. Relays come in issuer pin order, each
 *  roster in its own order, one per endpoint, except that an area hub
 *  (net_hub.h) serving an area one of this node's own listed buckets lies in
 *  comes first; at most AT_RELAY_MAX. `areas`, when present, must key only
 *  `relays` entries, each with 1..AT_RELAY_ROSTER_AREAS_MAX areas, or the
 *  whole roster is refused; absent, the roster keeps the bytes it had.
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H
#define AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H

#include <stddef.h>

#include "rendezvous/net_relay.h"
#include "rendezvous/net_relay_seeds.h"

#define AT_RELAY_ROSTER_DOMAIN "at-relay-roster-v1|"
#define AT_RELAY_ROSTER_TYPENAME "at-relay-roster"
#define AT_RELAY_ROSTER_VERSION 1
#define AT_RELAY_ROSTERS_DIR "relay_rosters"
#define AT_RELAY_ROSTERS_ENV "AT_RELAY_ROSTERS"
#define AT_RELAY_ROSTER_ISSUERS_FILE "relay_roster_issuers.cfg.json"
#define AT_RELAY_ROSTER_ISSUERS_ENV "AT_RELAY_ROSTER_ISSUERS"
#define AT_RELAY_ROSTERS_SEEN_FILE "relay_rosters_seen.cfg.json"
/** Most issuers one node pins. Same as Python relay_rosters.MAX_ISSUERS. */
#define AT_RELAY_ROSTER_ISSUERS_MAX 16
/** Most roster files read. Same as Python relay_rosters.MAX_FILES. */
#define AT_RELAY_ROSTER_FILES_MAX 32
#define AT_RELAY_ROSTER_KEY_HEX 64
/** Most areas one roster relay serves. Same as Python relay_rosters.MAX_AREAS. */
#define AT_RELAY_ROSTER_AREAS_MAX 8

/** The areas each verified entry serves, by the entry's index in the list. */
typedef struct {
    size_t n[AT_RELAY_SEEDS_MAX];
    char areas[AT_RELAY_SEEDS_MAX][AT_RELAY_ROSTER_AREAS_MAX][6];
} net_relay_roster_areas_t;

/** The issuer keys a node trusts rosters from, lowercase hex, in pin order. */
typedef struct {
    size_t n;
    char keys[AT_RELAY_ROSTER_ISSUERS_MAX][AT_RELAY_ROSTER_KEY_HEX + 1];
} net_relay_roster_issuers_t;

/** Verify the roster @p text against the pinned @p issuers into @p issuer_out
 *  (AT_RELAY_ROSTER_KEY_HEX + 1 bytes), @p seq and @p out. 0, or -1 when it is
 *  refused (malformed, issuer not pinned, bad signature, wrong version, seq
 *  below 1, a bad or unpinned entry). Does not apply the seq floor. Mirrors
 *  Python relay_rosters.verify_roster. */
int net_relay_roster_verify(const char *text, const net_relay_roster_issuers_t *issuers,
                            char *issuer_out, long long *seq, net_relay_seed_list_t *out);
/** net_relay_roster_verify, plus the hubs' areas into @p areas (may be NULL).
 *  Mirrors Python relay_rosters.verify_roster_areas. */
int net_relay_roster_verify_areas(const char *text, const net_relay_roster_issuers_t *issuers,
                                  char *issuer_out, long long *seq, net_relay_seed_list_t *out,
                                  net_relay_roster_areas_t *areas);

/** The pinned issuers: `$AT_RELAY_ROSTER_ISSUERS` first, then the issuers file;
 *  a key that is not 32 bytes of hex is skipped (logged). @return how many.
 *  Mirrors relay_rosters.pinned_issuers. */
size_t net_relay_rosters_pinned(net_relay_roster_issuers_t *out);

/** The roster directory: `$AT_RELAY_ROSTERS`, else <cfg_dir>/relay_rosters. 0 or -1. */
int net_relay_rosters_dir(char *out, size_t out_len);

/** The issuers file's path. 0 or -1. */
int net_relay_rosters_issuers_path(char *out, size_t out_len);

/** The roster file names (not paths) in the directory, sorted, at most
 *  AT_RELAY_ROSTER_FILES_MAX, into @p names (256 bytes each).
 *  @return how many. */
size_t net_relay_rosters_files(char names[][256], size_t max);

/** This node's roster relays from every pinned issuer's newest acceptable
 *  roster. Every refusal is logged and leaves that file out. @p pins may be
 *  NULL. @return how many. Mirrors relay_rosters.load. */
size_t net_relay_rosters_load(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max);
/** net_relay_rosters_load, with hubs for one of @p buckets first. */
size_t net_relay_rosters_load_near(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max,
                                   const char *const *buckets, size_t n_buckets);
/** The buckets this node is listed at hubs under, into @p out, from the area
 *  provider (first contact's area.cfg.json); none without one. @return how
 *  many. */
size_t net_relay_rosters_listed_buckets(char out[][8], size_t max);

/* Areas are geohash prefixes, and the roster format carries them, so their
 * syntax is rendezvous's; first contact's area cards (first_contact/area_card.h)
 * use the same. */
/** Shortest and longest area. Same as Python's. */
#define AT_RELAY_AREA_MIN 2
#define AT_RELAY_AREA_MAX 5
/** @p in folded to lower case into @p out (room for @p max_len + 1): 0, or
 *  -1 when it is not a geohash prefix of @p min_len .. @p max_len chars. */
int net_relay_area_normalize(const char *in, char *out, size_t out_len, size_t min_len,
                             size_t max_len);
/** True iff @p in is already a normalized area (AT_RELAY_AREA_MIN..MAX). */
bool net_relay_is_area(const char *in);

/** Where the buckets this node is listed under come from (FEATURE_SPLIT_PLAN
 *  Phase 7, R1): first contact's area listings, which rendezvous prefers a
 *  nearby hub for. Both members are required. */
typedef struct {
    /** The buckets, into @p out. @return how many. */
    size_t (*listed_buckets)(char out[][8], size_t max);
    /** The file they are read from, into @p out, so the hint cache can tell
     *  when they change. 0, or -1 for none. */
    int (*state_path)(char *out, size_t len);
} net_relay_area_provider_t;

/** Use @p p (static storage; NULL: none). Called from a constructor. */
void net_relay_rosters_set_area_provider(const net_relay_area_provider_t *p);
/** The area provider's state file into @p out: 0, or -1 when there is none. */
int net_relay_rosters_area_state_path(char *out, size_t len);

/** File the roster @p text and pin its issuer: the local app's choice to trust
 *  a community. It must verify under its own issuer and be no older than the
 *  seq already accepted from it. 0 (issuer into @p issuer_out), -1 when it
 *  does not verify, -2 when it is older, -3 when it cannot be written. Mirrors
 *  Python relay_rosters.install. */
int net_relay_rosters_install(const char *text, char *issuer_out, long long *seq);
/** Unpin @p issuer and delete the roster installed for it. 1 when either was
 *  there, 0 when neither, -1 for a key that is not hex. Mirrors
 *  relay_rosters.remove. */
int net_relay_rosters_remove(const char *issuer);

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H */
