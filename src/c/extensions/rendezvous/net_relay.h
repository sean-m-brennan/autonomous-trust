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

/** @file Rendezvous relay: reach a contact that is behind NAT
 *  (FIRST_CONTACT_PLAN §4.2). C twin of Python
 *  network/relay.py -- the two speak the same protocol and interoperate.
 *
 *  A relay is any AT node that opts in (`AT_RELAY=1`); it listens on TCP
 *  `AT_RELAY_PORT` and forwards frames between nodes that each hold one
 *  outbound connection to it, which is what a NAT keeps open. It forwards
 *  SEALED frames -- the ordinary AT envelope, end-to-end encrypted between the
 *  peers, bar the first-contact hello and ack -- and stamps `from` itself from
 *  the sender's registration, so it can neither read nor forge them.
 *
 *  Wire protocol, one JSON object per frame, each frame a 4-byte big-endian
 *  length then the bytes. The client's hello carries a fresh `nonce`, and the
 *  relay signs its challenge over "at-relay-v1|relay|<client nonce>|<nonce>|
 *  <relay uuid>|<client uuid>" (relay_uuid / relay_pubkey / relay_sig), so a
 *  client knows WHICH relay answered and a pinned link refuses anything else.
 *  Both ends gate on reputation (net_relay_distrust_fn). Framing:
 *
 *      client -> relay   {"op":"hello","uuid":U,"pubkey":<hex ed25519>}
 *      relay  -> client  {"op":"challenge","nonce":<hex>}
 *      client -> relay   {"op":"register","sig":<hex>}
 *                           sig = ed25519 over "at-relay-v1|<nonce>|<uuid>"
 *      relay  -> client  {"op":"registered"}        (or {"op":"error",...})
 *      client -> relay   {"op":"send","to":U2,"frame":<base64>}
 *      relay  -> U2      {"op":"deliver","from":U,"frame":<base64>}
 *      relay  -> client  {"op":"unreachable","to":U2}
 */
#ifndef AUTONOMOUS_TRUST_NETWORK_NET_RELAY_H
#define AUTONOMOUS_TRUST_NETWORK_NET_RELAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <uuid/uuid.h>

#include <jansson.h>

#include "identity/identity.h"
#include "utilities/logger.h"

/** Domain separation for the registration signature. Same as Python's
 *  relay.RELAY_DOMAIN. */
#define AT_RELAY_DOMAIN "at-relay-v1"
/** Default relay port; AT_RELAY_PORT overrides. */
#define AT_RELAY_DEFAULT_PORT 27790
/** Largest frame either side accepts; a longer length prefix drops the
 *  connection rather than allocating for it. Same as Python's MAX_FRAME. */
#define AT_RELAY_MAX_FRAME (4 * 1024 * 1024)
/** Seconds a connecting client has to finish registering. */
#define AT_RELAY_HANDSHAKE_TIMEOUT_MS 10000
/** URI scheme of a relay rendezvous hint in an invitation. */
#define AT_RELAY_SCHEME "relay://"
/** Longest relay host this module keeps (a numeric address of either family). */
#define AT_RELAY_HOST_LEN 64

/** True iff this node serves as a relay (`AT_RELAY`). */
bool net_relay_enabled(void);
/** The relay port (`AT_RELAY_PORT`, else the default). */
int net_relay_port(void);
/** Most relays one node registers with, or one peer's route names. Same as
 *  Python's relay.MAX_RELAYS. */
#define AT_RELAY_MAX 4

/** One relay endpoint. */
typedef struct {
    char host[AT_RELAY_HOST_LEN];
    int port;
} net_relay_ep_t;

/** Bytes of SHA-256 kept in a key fingerprint. Same as Python relay.FP_BYTES. */
#define AT_RELAY_FP_BYTES 16

/** Which relay a link means: its uuid (what reputation is keyed on) and the
 *  fingerprint of its signing key (what authenticates it). A uuid alone is
 *  only a label, so a pin always carries both. */
typedef struct {
    bool set;
    char uuid[UUID_STR_LEN + 1];
    char fp[AT_RELAY_FP_BYTES * 2 + 1];
} net_relay_pin_t;

/** The fingerprint of a hex ed25519 signing key: the first
 *  @ref AT_RELAY_FP_BYTES of its SHA-256, hex, into @p out. 0, or -1 if the
 *  key is not hex. Mirrors Python relay.key_fingerprint. */
int net_relay_key_fingerprint(const char *pubkey_hex, char *out, size_t out_len);

/** `[relay://][<uuid>:<fp>@]host:port` -> host, port and @p pin (pin->set
 *  false when unpinned; @p pin may be NULL). 0, or -1 when it is not a hint --
 *  a malformed pin included: one that cannot be checked is refused, never
 *  dropped. Mirrors Python relay.parse_hint. */
int net_relay_parse_hint(const char *text, char *host, size_t host_len,
                         int *port, net_relay_pin_t *pin);

/** The `relay://` hint naming @p host / @p port, pinned when @p pin is set
 *  (may be NULL). 0, or -1 if it does not fit. */
int net_relay_hint_for_pinned(const char *host, int port,
                              const net_relay_pin_t *pin, char *out,
                              size_t out_len);

/** Is @p uuid (lower-case), proven to hold @p pubkey_hex, someone this node
 *  distrusts? The relay gate in both directions. */
typedef bool (*net_relay_distrust_fn)(void *arg, const char *uuid,
                                      const char *pubkey_hex);

/** With `AT_USE_RELAY` blank, this switch (1/true/yes/on) lets the pinned
 *  communities' rosters and then the signed seed list stand in for it
 *  (FEATURE_SPLIT_PLAN D9). Same as Python's. */
#define AT_RELAY_SEED_FALLBACK_ENV "AT_RELAY_SEED_FALLBACK"

/** This node's own relays (`AT_USE_RELAY`, comma-separated) in preference
 *  order into @p out (room for @p max). Unusable entries and repeats are
 *  skipped; at most @ref AT_RELAY_MAX are kept. With it blank and
 *  AT_RELAY_SEED_FALLBACK_ENV on, the rosters' relays and then the seed
 *  list's. @return how many. Mirrors Python relay.own_relays. */
size_t net_relay_own_list(net_relay_ep_t *out, size_t max);

/** As @ref net_relay_own_list, with each entry's pin (`<uuid>:<fp>@host:port`
 *  in AT_USE_RELAY) into @p pins (room for @p max; unset when unpinned). */
size_t net_relay_own_hints(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max);

/** The first of this node's own relays, into @p host / @p port. 0, or -1
 *  when none is configured. */
int net_relay_own(char *host, size_t host_len, int *port);

/** `host:port`, `[v6]:port` or a `relay://` hint -> host + port. 0, or -1 when
 *  it is not one (the host is cleared). Mirrors Python relay.parse_endpoint. */
int net_relay_parse_endpoint(const char *text, char *host, size_t host_len,
                             int *port);
/** The `relay://` hint naming @p host / @p port. 0, or -1 if it does not fit. */
int net_relay_hint_for(const char *host, int port, char *out, size_t out_len);

/* ---- the relay ---------------------------------------------------------- */

typedef struct net_relay_server_s net_relay_server_t;

/** Listen on @p host / @p port (0 = any free port) and serve until stopped.
 *  NULL if the port cannot be bound. */
net_relay_server_t *net_relay_server_start(const char *host, int port,
                                           logger_t *logger);
/** The bound port (useful after asking for port 0). */
int net_relay_server_port(const net_relay_server_t *srv);
/** True iff @p uuid (lower-case string) is registered right now. */
bool net_relay_server_has(net_relay_server_t *srv, const char *uuid);
void net_relay_server_stop(net_relay_server_t *srv);

/** Prove the relay as @p self (which must stay valid): every challenge is then
 *  signed, bound to the client's nonce and both uuids. */
void net_relay_server_set_identity(net_relay_server_t *srv, const identity_t *self);
/** Refuse to register a client @p fn says is distrusted. */
void net_relay_server_set_distrust(net_relay_server_t *srv,
                                   net_relay_distrust_fn fn, void *arg);
/** Drop @p uuid's (lower-case) registration now. */
void net_relay_server_evict(net_relay_server_t *srv, const char *uuid);
/* ---- server ops (FEATURE_SPLIT_PLAN Phase 7, R2) ------------------------ */
/** Most op families one relay serves beside its own. */
#define AT_RELAY_OPS_MAX 4
/** Longest op-family prefix ("dir_", "hub_"). */
#define AT_RELAY_OP_PREFIX_LEN 15
/** Answer one request from registrant @p uuid, proven to hold @p pub (hex),
 *  whose "op" is @p op: the reply (a new reference), or NULL for none. Runs on
 *  the client's server thread. */
typedef json_t *(*net_relay_server_op_fn)(void *arg, const char *uuid, const char *pub,
                                          const char *op, const json_t *req);
/** Serve every op starting with @p prefix (e.g. "dir_") with @p fn. A feature
 *  plugs its service into a relay this way (first contact's directory and area
 *  hub). An op with an underscore that no family claims is answered
 *  {op: "<family>_refused", reason: "unknown_op"}, echoing the request's other
 *  string members. @return 0; -1 bad arguments, duplicate prefix or full. */
int net_relay_server_add_op(net_relay_server_t *srv, const char *prefix,
                            net_relay_server_op_fn fn, void *arg);

/* ---- a node's link to a relay ------------------------------------------- */

/** Called on the client's reader thread for each delivered frame. @p frame is
 *  borrowed for the call. */
typedef void (*net_relay_deliver_fn)(void *arg, const char *from_uuid,
                                     const uint8_t *frame, size_t len,
                                     const char *relay_host, int relay_port);

typedef struct net_relay_client_s net_relay_client_t;

/** Called on the client's reader thread for each peer the relay says it
 *  cannot reach (@p to_uuid lower-case). */
typedef void (*net_relay_unreachable_fn)(void *arg, const char *to_uuid,
                                         const char *relay_host, int relay_port);

/** A client for the relay at @p host / @p port, registering as @p self (which
 *  must stay valid). Does not connect yet. */
net_relay_client_t *net_relay_client_new(const char *host, int port,
                                         const identity_t *self,
                                         net_relay_deliver_fn deliver, void *arg,
                                         logger_t *logger);
/** Hear the relay's "unreachable" answers (@p fn may be NULL to stop). */
void net_relay_client_on_unreachable(net_relay_client_t *c,
                                     net_relay_unreachable_fn fn, void *arg);

/** Require the relay to prove it is @p pin (NULL or unset clears the pin);
 *  anything else answering at the address is refused. */
void net_relay_client_set_pin(net_relay_client_t *c, const net_relay_pin_t *pin);
/** Refuse a relay that proves to be someone @p fn distrusts. */
void net_relay_client_set_distrust(net_relay_client_t *c,
                                   net_relay_distrust_fn fn, void *arg);
/** Who the relay proved to be at the last connect, into @p out (and its key
 *  into @p key_hex if non-NULL). false when it proved nothing. */
bool net_relay_client_proven(net_relay_client_t *c, net_relay_pin_t *out,
                             char *key_hex, size_t key_len);
/** Why the last connect was refused ("" when it was not), into @p out. */
void net_relay_client_refused(net_relay_client_t *c, char *out, size_t out_len);
/** Hang up (the relay became distrusted); a later send reconnects. */
void net_relay_client_close(net_relay_client_t *c);

/** Most reachability records one relay holds. Same as Python's MAX_RECORDS. */
#define AT_RELAY_MAX_RECORDS 4096

/** A lookup's answer, on the reader thread: @p wire ({body, sig}, borrowed)
 *  or NULL when the relay holds no record under @p rid. */
typedef void (*net_relay_record_fn)(void *arg, const char *rid, const json_t *wire);
void net_relay_client_on_record(net_relay_client_t *c, net_relay_record_fn fn,
                                void *arg);
/** File our own reachability record (@p wire, {body, sig}) at the relay. */
int net_relay_client_publish(net_relay_client_t *c, const json_t *wire);
/** Every answer whose "op" starts with @p prefix ("dir_", "hub_"), on the
 *  reader thread, with the relay it came from (R2's client half). At most
 *  @ref AT_RELAY_OPS_MAX prefixes; a second @p fn for a prefix replaces the
 *  first. */
typedef void (*net_relay_op_fn)(void *arg, const json_t *msg, const char *host, int port);
void net_relay_client_on_op(net_relay_client_t *c, const char *prefix,
                            net_relay_op_fn fn, void *arg);
/** Send one request frame @p req (stolen), connecting first if needed: how a
 *  feature reaches the service it plugged into the relay. 0 sent; -1 not. */
int net_relay_client_request(net_relay_client_t *c, json_t *req);

/** Ask for the record filed under @p rid; on_record gets the answer. */
int net_relay_client_lookup(net_relay_client_t *c, const char *rid);

/** Connect and register if not already. 0 when registered. */
int net_relay_client_connect(net_relay_client_t *c);
bool net_relay_client_connected(net_relay_client_t *c);
/** Send @p frame to @p to through the relay (connecting first if needed).
 *  0, or -1 if the relay cannot be reached. */
int net_relay_client_send(net_relay_client_t *c, const uuid_t to,
                          const uint8_t *frame, size_t len);
/** True iff the relay last reported @p uuid (lower-case) unreachable. */
bool net_relay_client_was_unreachable(net_relay_client_t *c, const char *uuid);
void net_relay_client_free(net_relay_client_t *c);

/** Frame I/O, exposed for tests that speak the protocol by hand. */
int net_relay_send_json(int fd, const char *json_text);
/** The next frame as a malloc'd, NUL-terminated string; NULL on EOF, an
 *  oversized length, or an I/O error. */
char *net_relay_recv_json(int fd);

#endif /* AUTONOMOUS_TRUST_NETWORK_NET_RELAY_H */
