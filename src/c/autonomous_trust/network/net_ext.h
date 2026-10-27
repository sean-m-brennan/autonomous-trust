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

#ifndef NET_EXT_H
#define NET_EXT_H

/**
 * @file net_ext.h
 * @brief How an optional feature follows the network process without the core
 *        naming it, and what the core lets it ask.
 *
 * FEATURE_SPLIT_PLAN Phase 7, hooks C3 and C4. Rendezvous (the relay client
 * and server, reachability records, seeds, rosters) attaches here: it starts
 * its relays, keeps them alive on each pass of the loop, answers the local
 * verbs addressed to the network process that it owns, carries a unicast to a
 * peer that is reached through a relay, and drops a peer reputation cut off.
 * The frame filters of network/net_filter.h are a different thing (they
 * rewrite frames); a feature may use both.
 *
 * Every hook is optional, and with none registered the network process is
 * exactly the core: no relay, every unicast through the transport, an empty
 * address a broadcast. A hook decides its own gate (rendezvous reads
 * $AT_RELAY / $AT_USE_RELAY), which is why registering one from a
 * constructor turns nothing on. Filled before main(), then read-only, so
 * unlocked, as the other registries. Mirrors Python extensions.NetworkHooks.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "network/net_message.h"
#include "network/net_proc_priv.h"

/** Most network extensions. */
#define NET_EXT_MAX 8

/** One feature's view of the network process. */
typedef struct {
    /** Unique; for logs. */
    const char *name;
    /** network_run: the filters and the configuration are checked, and the
     *  receivers are about to start. */
    void (*start)(net_thread_ctx_t *ctx);
    /** The top of each pass of the network loop. */
    void (*periodic)(net_thread_ctx_t *ctx);
    /** A message addressed to the network process whose function the core
     *  does not own. Return true if this feature owns it: it then never goes
     *  on the wire. */
    bool (*local_verb)(net_thread_ctx_t *ctx, net_msg_t *nmsg);
    /** Whether @p peer, a unicast with no address, is still reachable (so is
     *  not a broadcast). */
    bool (*reachable)(const uuid_t peer);
    /** Send @p buf, already sealed for @p peer, some other way than the
     *  transport. 0 sent; -1 failed; 1 not this feature's peer. */
    int (*unicast)(const uuid_t peer, const uint8_t *buf, size_t len);
    /** Reputation cut @p uuid (lower-case) off, or readmitted it; the core
     *  has already recorded it (@ref net_is_excluded). */
    void (*exclusion)(const char *uuid, bool excluded);
    /** Network-process functions this feature accepts from the wire,
     *  NULL-terminated; NULL for none. Admitted only on a member's paths
     *  (decrypted peer, group), never from a stranger or the broadcast
     *  channel. The frame then reaches local_verb with its sender set. Every
     *  inbound frame of a declared verb (it carries a sender) must be
     *  consumed by this extension's local_verb; one it declines is treated
     *  as a local outbound message. */
    const char *const *wire_verbs;
    /** network_run, after the filters and plaintext verbs are checked: a
     *  non-zero return refuses to start the network process (the feature's
     *  configuration cannot be honoured). */
    int (*check_config)(logger_t *logger);
    /** A unicast the transport is about to send (no extension carried it
     *  through `unicast`): the frame as sealed for @p peer, with its verb.
     *  Cannot stop or alter the transport send. */
    void (*also_unicast)(const uuid_t peer, const char *process,
                         const char *function, const uint8_t *buf, size_t len);
    /** A GROUP (sealed with @p grp's key) or BROADCAST (plaintext) frame,
     *  after the transport was asked to send it, whether or not that
     *  succeeded (a fallback radio still carries it), with its verb and the
     *  node's group (may be NULL). Cannot stop or alter the transport send. */
    void (*fanout)(net_channel_t ch, const char *process, const char *function,
                   const group_t *grp, const uint8_t *buf, size_t len);
} net_ext_t;

/** Register @p ext (static storage). @return 0; -1 NULL, unnamed, duplicate or
 *  full. */
int net_ext_register(const net_ext_t *ext);

/** True iff a network extension named @p name is registered. */
bool net_ext_present(const char *name);

/* Dispatchers, called by net_proc.c. */
void net_ext_start(net_thread_ctx_t *ctx);
void net_ext_periodic(net_thread_ctx_t *ctx);
/** True iff some extension owned @p nmsg. */
bool net_ext_local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg);
/** True iff some extension can reach @p peer without an address. */
bool net_ext_reachable(const uuid_t peer);
/** The first answer that is not 1 (not mine), else 1. */
int net_ext_unicast(const uuid_t peer, const uint8_t *buf, size_t len);
/** True iff an extension declared @p function in its wire_verbs. */
bool net_ext_wire_verb_declared(const char *function);
/** Ask every extension's check_config. @return 0, or -1 if any refused. */
int net_ext_check_config(logger_t *logger);
/** Hand a unicast the transport is about to send to every also_unicast. */
void net_ext_also_unicast(const uuid_t peer, const char *process,
                          const char *function, const uint8_t *buf, size_t len);
/** Hand a GROUP or BROADCAST frame the transport was asked to send to every
 *  fanout. */
void net_ext_fanout(net_channel_t ch, const char *process, const char *function,
                    const group_t *grp, const uint8_t *buf, size_t len);

/* Who reputation cut off (C4). The network process records each exclusion
 * by uuid and by the signing key it holds for that peer, so a distrusted peer
 * gains nothing by claiming a new uuid. */

/** Record that reputation cut @p uuid off (@p excluded) or readmitted it, then
 *  tell every extension. @p pubkey_hex is the key held for it (NULL or "" if
 *  none). Mirrors Python NetworkProcess.handle_exclude / handle_readmit. */
void net_note_exclusion(const char *uuid, const char *pubkey_hex, bool excluded);

/** True iff @p uuid, or the key @p pubkey_hex (NULL or "": not asked), was cut
 *  off and not readmitted. Mirrors Python NetworkProcess.is_excluded. */
bool net_is_excluded(const char *uuid, const char *pubkey_hex);

/** Forget every exclusion (network shutdown, tests). */
void net_exclusions_reset(void);

/** Register @p ext at load time. */
#define NET_EXT_REGISTER(tag, ext)                                        \
    static void __attribute__((constructor)) net_ext_register_##tag(void) \
    {                                                                     \
        (void)net_ext_register(ext);                                      \
    }

#endif /* NET_EXT_H */
