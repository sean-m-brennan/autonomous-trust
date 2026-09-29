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
 *                       "seq":N,"relays":["relay://<uuid>:<fp>@host:port",...]}
 *      issuers  `$AT_RELAY_ROSTER_ISSUERS` (comma-separated hex keys), then
 *               <cfg_dir>/relay_roster_issuers.cfg.json = {"issuers":[hex,...]}
 *      seen     <data_dir>/relay_rosters_seen.cfg.json = {<issuer hex>: seq}
 *
 *  Only a pinned issuer counts; every entry must be pinned, or the whole
 *  roster is refused; a higher seq replaces that issuer's previous roster
 *  whole (an empty roster is valid) and a lower one is refused. Of two files
 *  from one issuer the higher seq wins. Relays come in issuer pin order, each
 *  roster in its own order, one per endpoint, at most AT_RELAY_MAX.
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H
#define AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H

#include <stddef.h>

#include "network/net_relay.h"
#include "network/net_relay_seeds.h"

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

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_RELAY_ROSTERS_H */
