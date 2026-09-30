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
 * at_first_contact.h -- how an application adds a friend.
 *
 * The first-contact feature's half of the flat app ABI (app_events.h is the
 * core's). Two requests and one event payload:
 *
 *   - @ref at_app_first_contact_invite asks the node to MINT an invitation.
 *     An app holds no private key, so it cannot sign one itself; the answer
 *     is an @ref AT_APP_EVENT_FC_INVITATION event carrying the link to share.
 *   - @ref at_app_first_contact_initiate hands the node a friend's link. The
 *     node records the contact, sends the hello, and answers
 *     @ref AT_APP_EVENT_FC_HELLO_SENT; @ref AT_APP_EVENT_FC_ESTABLISHED
 *     follows when the friend's node acknowledges.
 *
 * Every event echoes the @c ref the app put on its request, so an app with
 * several invitations out can tell them apart.
 *
 * A refused hello is NOT reported to the initiator: the inviter sends nothing
 * back, so a probe learns nothing from a bad ticket. The initiator sees
 * HELLO_SENT and then either ESTABLISHED or nothing; silence past
 * @ref AT_FC_PENDING_TTL_SECONDS means refused or unreachable, deliberately
 * indistinguishable. The INVITER's app does hear when a link it minted came
 * back expired or already used (@ref AT_APP_EVENT_FC_REFUSED, role inviter).
 *
 * The node side is opt-in (`AT_FIRST_CONTACT=1`); without it no handler
 * answers and no event arrives.
 *
 * Usage:
 *   at_app_first_contact_invite(ev, "extern_to_at", "my-link", -1, NULL, 0);
 *   ...
 *   const at_app_first_contact_t *fc = at_first_contact_event(&batch[i]);
 *   if (fc != NULL && batch[i].kind == AT_APP_EVENT_FC_INVITATION)
 *       share(fc->blob);
 *
 * See doc/architecture/first-contact.md.
 */

#ifndef AT_FIRST_CONTACT_PUBLIC_H
#define AT_FIRST_CONTACT_PUBLIC_H

/** @addtogroup public_api
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The two app verbs. Local IPC only: the node refuses either one arriving
 *  from the wire. Same strings as Python's first_contact.APP_INVITE /
 *  APP_INITIATE. */
#define AT_APP_FC_INVITE   "app_first_contact_invite"
#define AT_APP_FC_INITIATE "app_first_contact_initiate"
/** The address book, through the node -- which is thereby its only writer. */
#define AT_APP_FC_SAFETY_NUMBER "app_first_contact_safety_number"
#define AT_APP_FC_VERIFY        "app_first_contact_verify"
#define AT_APP_FC_LIST          "app_first_contact_list"
#define AT_APP_FC_RENAME        "app_first_contact_rename"
#define AT_APP_FC_REMOVE        "app_first_contact_remove"

/** Event kinds: first contact's block of the feature range (app_events.h).
 *  Frozen; only ever appended. */
#define AT_APP_EVENT_FC_INVITATION  1000  /**< minted; @c blob is the link */
#define AT_APP_EVENT_FC_HELLO_SENT  1001  /**< a hello left for @c peer_uuid */
#define AT_APP_EVENT_FC_REFUSED     1002  /**< see @c reason */
#define AT_APP_EVENT_FC_ESTABLISHED 1003  /**< both nodes hold each other */
/* Address-book kinds: payload @ref at_app_contact_t, read with
 * @ref at_first_contact_contact_event. */
#define AT_APP_EVENT_FC_CONTACT       1004  /**< one record (a list, a rename) */
#define AT_APP_EVENT_FC_CONTACTS_DONE 1005  /**< end of a list; see @c count */
#define AT_APP_EVENT_FC_SAFETY_NUMBER 1006  /**< @c safety_number to show */
#define AT_APP_EVENT_FC_VERIFIED      1007  /**< see @c method */
#define AT_APP_EVENT_FC_REMOVED       1008  /**< see @c peer_dropped */
/* Directory kinds (FIRST_CONTACT_PLAN Phase 3): payload
 * @ref at_app_directory_t, read with @ref at_first_contact_directory_event.
 * Same outcomes as Python's directory_contact.EVENT_* strings. */
#define AT_APP_EVENT_DIR_PUBLISHED       1009  /**< a registry filed our entry */
#define AT_APP_EVENT_DIR_REFUSED         1010  /**< see @c reason */
#define AT_APP_EVENT_DIR_WITHDRAWN       1011
#define AT_APP_EVENT_DIR_FOUND           1012  /**< a lookup found @c peer_uuid */
#define AT_APP_EVENT_DIR_NOT_FOUND       1013  /**< @c reason "", "limited" or "invalid" */
#define AT_APP_EVENT_DIR_REQUEST_SENT    1014
#define AT_APP_EVENT_DIR_CONTACT_REQUEST 1015  /**< someone asks; answer with @c ref */
#define AT_APP_EVENT_DIR_ACCEPTED        1016
#define AT_APP_EVENT_DIR_DECLINED        1017
/* One human, several devices (Phase 4): payload @ref at_app_contact_t, the
 * contact, with @c device_uuid the further device filed under it. */
#define AT_APP_EVENT_FC_DEVICE_LINKED    1018
/* One's own devices, paired (Phase 4, live pairing). SIBLING_PAIRED's payload
 * is @ref at_app_first_contact_t (@c ref, @c peer_uuid, @c nickname, @c
 * role), read with @ref at_first_contact_event; the others' is @ref
 * at_app_contact_t (@c peer_uuid, @c nickname, @c added_at; @c count on
 * SIBLINGS_DONE; @c peer_dropped on SIBLING_REMOVED), read with
 * @ref at_first_contact_contact_event. Python's sibling_sync.EVENT_*. */
#define AT_APP_EVENT_FC_SIBLING_PAIRED   1019  /**< another device of ours, paired */
#define AT_APP_EVENT_FC_SIBLING          1020  /**< one sibling (a list) */
#define AT_APP_EVENT_FC_SIBLINGS_DONE    1021  /**< end of a list; see @c count */
#define AT_APP_EVENT_FC_SIBLING_REMOVED  1022  /**< unpaired; see @c peer_dropped */
/* Area hubs (finding people nearby): payload @ref at_app_area_t, read with
 * @ref at_first_contact_area_event. Python's area_contact.EVENT_*. A contact
 * request to someone an area lookup found is the directory's
 * (AT_APP_EVENT_DIR_REQUEST_SENT .. DECLINED), with @c handle "area:<area>". */
#define AT_APP_EVENT_AREA_PUBLISHED      1023  /**< a hub listed us; @c relay, @c seq */
#define AT_APP_EVENT_AREA_REFUSED        1024  /**< see @c reason */
#define AT_APP_EVENT_AREA_WITHDRAWN      1025
#define AT_APP_EVENT_AREA_CARD           1026  /**< one person a lookup found */
#define AT_APP_EVENT_AREA_DONE           1027  /**< end of a lookup; @c count, @c reason */
#define AT_APP_EVENT_ROSTER_INSTALLED    1028  /**< @c issuer, @c seq */
#define AT_APP_EVENT_ROSTER_REFUSED      1029  /**< @c reason: bad_request | invalid | stale */
#define AT_APP_EVENT_ROSTER_REMOVED      1030  /**< @c issuer; @c count 1 if one was there */

/** The area app verbs. Local IPC only. Same strings as Python's
 *  area_contact.APP_*. */
#define AT_APP_AREA_PUBLISH    "app_area_publish"
#define AT_APP_AREA_WITHDRAW   "app_area_withdraw"
#define AT_APP_AREA_LOOKUP     "app_area_lookup"
#define AT_APP_ROSTER_INSTALL  "app_relay_roster_install"
#define AT_APP_ROSTER_REMOVE   "app_relay_roster_remove"

/** The sibling app verbs. Local IPC only. Python's sibling_sync.APP_*. */
#define AT_APP_SIBLING_LIST   "app_sibling_list"
#define AT_APP_SIBLING_REMOVE "app_sibling_remove"

/** The directory app verbs. Local IPC only. Same strings as Python's
 *  directory_contact.APP_*. */
#define AT_APP_DIR_PUBLISH  "app_directory_publish"
#define AT_APP_DIR_WITHDRAW "app_directory_withdraw"
#define AT_APP_DIR_LOOKUP   "app_directory_lookup"
#define AT_APP_FC_REQUEST   "app_first_contact_request"
#define AT_APP_FC_ACCEPT    "app_first_contact_accept"
#define AT_APP_FC_DECLINE   "app_first_contact_decline"

/** Why a request or a hello was refused. Same order as Python's
 *  first_contact.REASONS, whose strings are these names in lower case. */
typedef enum {
    AT_FC_REASON_NONE = 0,
    AT_FC_REASON_MALFORMED = 1,      /**< not an invitation at all */
    AT_FC_REASON_BAD_SIGNATURE = 2,  /**< does not verify against its identity */
    AT_FC_REASON_EXPIRED = 3,
    AT_FC_REASON_SPENT = 4,          /**< single-use, and already used */
    AT_FC_REASON_ENDPOINT = 5,       /**< no usable address to send to (C only) */
    AT_FC_REASON_BAD_REQUEST = 6,    /**< the request itself was unusable */
    AT_FC_REASON_MINT_FAILED = 7,    /**< the node could not sign one */
    AT_FC_REASON_MISMATCH = 8,       /**< typed safety number did not match */
    AT_FC_REASON_UNKNOWN_CONTACT = 9,/**< no such contact in the address book */
    AT_FC_REASON_NOT_SIBLING = 10,   /**< a pairing that did not make two siblings */
} at_fc_reason_t;

/** How a VERIFIED event was reached. */
typedef enum {
    AT_FC_METHOD_NONE = 0,
    /** The node compared digits the user typed from the OTHER person's
     *  screen. */
    AT_FC_METHOD_PRESENTED = 1,
    /** The user compared the two screens by eye and said so -- trusted as
     *  @c in_person is, on the same local channel. */
    AT_FC_METHOD_CONFIRMED = 2,
} at_fc_method_t;

/** Which side of the handshake an ESTABLISHED or REFUSED event is from. */
typedef enum {
    AT_FC_ROLE_NONE = 0,
    AT_FC_ROLE_INVITER = 1,
    AT_FC_ROLE_INITIATOR = 2,
} at_fc_role_t;

/** How long a sent hello waits for its acknowledgement. Same value as
 *  Python's first_contact.PENDING_TTL_SECONDS. */
#define AT_FC_PENDING_TTL_SECONDS 120

/** @c ref buffer: 63 bytes and a NUL. A longer ref is refused, not cut. */
#define AT_FC_REF_LEN 64
/** @c nickname buffer: the core's NAME_LEN (128) and a NUL. */
#define AT_FC_NICKNAME_LEN 129
/** @c blob buffer. An invitation is ~1.2 KB, more with ZTA credentials in the
 *  identity; one that does not fit is refused (MINT_FAILED), never cut, since
 *  a truncated link is not a shorter link but a broken one. */
#define AT_FC_BLOB_LEN 7680

/** One first-contact outcome. Every field is written on every event. */
typedef struct {
    /** The app's tag from the request this answers; empty when nothing this
     *  node's app asked for is involved. */
    char    ref[AT_FC_REF_LEN];
    /** The other party; all-zero on an INVITATION or a refused request. */
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    char    nickname[AT_FC_NICKNAME_LEN];
    /** @ref at_fc_reason_t; NONE except on a REFUSED event. */
    int32_t reason;
    /** @ref at_fc_role_t. */
    int32_t role;
    /** INVITATION only: when the link stops working, epoch seconds; 0 = never. */
    int64_t expiry;
    /** INVITATION only: the link to share (an `at+contact:` URI), NUL-terminated. */
    char    blob[AT_FC_BLOB_LEN];
} at_app_first_contact_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_first_contact_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_first_contact_t fits the app event payload");

/** A safety number: 12 groups of 5 digits, 11 spaces, and a NUL. */
#define AT_FC_SAFETY_NUMBER_LEN 72

/** One address-book answer (kinds AT_APP_EVENT_FC_CONTACT..REMOVED). Every
 *  field is written on every event; those a kind does not use are zero. */
typedef struct {
    char    ref[AT_FC_REF_LEN];
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    char    nickname[AT_FC_NICKNAME_LEN];
    /** Your local name for them; never leaves this node. */
    char    petname[AT_FC_NICKNAME_LEN];
    bool    verified;
    /** 0 in person, 1 invite link (token), 2 directory, 3 another of our
     *  own devices (sibling). */
    int32_t provenance;
    double  added_at;       /**< epoch seconds */
    double  verified_at;    /**< epoch seconds; 0 until verified */
    /** SAFETY_NUMBER only. */
    char    safety_number[AT_FC_SAFETY_NUMBER_LEN];
    /** VERIFIED only: @ref at_fc_method_t. */
    int32_t method;
    /** REMOVED only: true if a DIRECT peer was dropped. False when the
     *  contact was also a member of your cohort (its peer entry belongs to
     *  the group) or was not a peer at all. */
    bool    peer_dropped;
    /** CONTACTS_DONE only: how many CONTACT events the list sent. */
    int32_t count;
    /** DEVICE_LINKED only: the further device filed under this contact. */
    uint8_t device_uuid[AT_APP_UUID_LEN];
    /** CONTACT / REMOVED: @ref AT_FC_ORIGIN_SIBLING when the change came from
     *  another of our own devices, else @ref AT_FC_ORIGIN_LOCAL. */
    int32_t origin;
} at_app_contact_t;

#define AT_FC_ORIGIN_LOCAL   0
#define AT_FC_ORIGIN_SIBLING 1

AT_APP_STATIC_ASSERT(sizeof(at_app_contact_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_contact_t fits the app event payload");

/** @c handle buffer: 128 bytes (a handle's most) and a NUL. */
#define AT_FC_HANDLE_LEN 129
/** @c relay buffer: a relay endpoint, "host:port". */
#define AT_FC_RELAY_LEN 80
/** @c reason buffer: the reason's name, as Python's reason strings. */
#define AT_FC_REASON_LEN 32

/** One directory outcome (kinds AT_APP_EVENT_DIR_*). Every field is written
 *  on every event; those a kind does not use are zero. */
typedef struct {
    /** The app's tag; on CONTACT_REQUEST, the tag to answer it with. */
    char    ref[AT_FC_REF_LEN];
    char    handle[AT_FC_HANDLE_LEN];
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    char    nickname[AT_FC_NICKNAME_LEN];
    /** PUBLISHED / REFUSED / WITHDRAWN from a registry, and FOUND: which relay. */
    char    relay[AT_FC_RELAY_LEN];
    /** REFUSED, NOT_FOUND: why ("bad_request", "untrusted", "unknown_handle"...). */
    char    reason[AT_FC_REASON_LEN];
    /** PUBLISHED: the entry's sequence number. */
    int64_t seq;
} at_app_directory_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_directory_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_directory_t fits the app event payload");

/** @brief The directory payload of @p ev, or NULL unless @p ev is one of the
 *  AT_APP_EVENT_DIR_* kinds. */
const at_app_directory_t *at_first_contact_directory_event(const at_app_event_t *ev);

/** @c area / @c bucket buffers: a geohash prefix of at most 5 and a NUL. */
#define AT_FC_AREA_LEN 8
/** @c name buffer: 64 bytes of UTF-8 (a card name's most) and a NUL. */
#define AT_FC_AREA_NAME_LEN 65
/** @c issuer buffer: a hex ed25519 key and a NUL. */
#define AT_FC_ISSUER_LEN 65

/** One area outcome (kinds AT_APP_EVENT_AREA_* and _ROSTER_*). Every field is
 *  written on every event; those a kind does not use are zero. */
typedef struct {
    char    ref[AT_FC_REF_LEN];
    char    area[AT_FC_AREA_LEN];
    /** CARD: the person's own coarse bucket inside @c area. */
    char    bucket[AT_FC_AREA_LEN];
    /** CARD: who. Ask them with @ref at_app_area_request. */
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** CARD: the name they list under (may be empty). */
    char    name[AT_FC_AREA_NAME_LEN];
    /** PUBLISHED / REFUSED / WITHDRAWN from a hub, and CARD: which relay. */
    char    relay[AT_FC_RELAY_LEN];
    char    reason[AT_FC_REASON_LEN];
    /** ROSTER_*: the community key the roster is signed by. */
    char    issuer[AT_FC_ISSUER_LEN];
    /** PUBLISHED: the card's sequence number; CARD: theirs; ROSTER_INSTALLED:
     *  the roster's. */
    int64_t seq;
    /** DONE: how many CARD events the lookup sent; ROSTER_REMOVED: 1 if one
     *  was installed. */
    int32_t count;
} at_app_area_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_area_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_area_t fits the app event payload");

/** @brief The area payload of @p ev, or NULL unless @p ev is one of the
 *  AT_APP_EVENT_AREA_* / _ROSTER_* kinds. */
const at_app_area_t *at_first_contact_area_event(const at_app_event_t *ev);

/** @brief List us at the hubs serving @p area, under @p bucket (inside it)
 *  and @p name (NULL = none). Refreshed while listed; answered per hub. */
int at_app_area_publish(at_app_events_t *handle, const char *q_out, const char *ref,
                        const char *area, const char *bucket, const char *name);
/** @brief Stop listing us in @p area. */
int at_app_area_withdraw(at_app_events_t *handle, const char *q_out, const char *ref,
                         const char *area);
/** @brief Who else is listed in @p area (only answered while we are): one
 *  CARD per person, then DONE. */
int at_app_area_lookup(at_app_events_t *handle, const char *q_out, const char *ref,
                       const char *area);
/** @brief Ask @p peer, found by an area lookup of @p area, to become a
 *  contact. Answered as at_app_first_contact_request is. */
int at_app_area_request(at_app_events_t *handle, const char *q_out, const char *ref,
                        const char *area, const uint8_t peer[AT_APP_UUID_LEN]);
/** @brief Trust a community's relay roster (@p roster, the file's {body, sig}
 *  JSON): pin its issuer and file it. */
int at_app_relay_roster_install(at_app_events_t *handle, const char *q_out,
                                const char *ref, const char *roster);
/** @brief Stop trusting @p issuer's roster (hex key). */
int at_app_relay_roster_remove(at_app_events_t *handle, const char *q_out,
                               const char *ref, const char *issuer);

/** @brief Publish our handle: @p attestation is an issuer's {body, sig} JSON;
 *  @p visibility "anyone" or "published" (NULL = "anyone"). */
int at_app_directory_publish(at_app_events_t *handle, const char *q_out,
                             const char *ref, const char *attestation,
                             const char *visibility);
/** @brief Withdraw our entry for @p dir_handle. */
int at_app_directory_withdraw(at_app_events_t *handle, const char *q_out,
                              const char *ref, const char *dir_handle);
/** @brief Look @p dir_handle up at every relay the node is registered at. */
int at_app_directory_lookup(at_app_events_t *handle, const char *q_out,
                            const char *ref, const char *dir_handle);
/** @brief Ask the holder of @p dir_handle (looked up first) to become a contact. */
int at_app_first_contact_request(at_app_events_t *handle, const char *q_out,
                                 const char *ref, const char *dir_handle);
/** @brief Accept / decline a CONTACT_REQUEST, by the @c ref it carried. */
int at_app_first_contact_accept(at_app_events_t *handle, const char *q_out,
                                const char *request_ref);
int at_app_first_contact_decline(at_app_events_t *handle, const char *q_out,
                                 const char *request_ref);

/** @brief The first-contact payload of @p ev, or NULL unless @p ev is one of
 *  the four AT_APP_EVENT_FC_* kinds. */
const at_app_first_contact_t *at_first_contact_event(const at_app_event_t *ev);

/** @brief The address-book payload of @p ev, or NULL unless @p ev is one of
 *  AT_APP_EVENT_FC_CONTACT..REMOVED. */
const at_app_contact_t *at_first_contact_contact_event(const at_app_event_t *ev);

/**
 * @brief Ask the node to mint an invitation.
 * @param ref         echoed on the answer; NULL or at most 63 bytes.
 * @param ttl_seconds lifetime; 0 = never expires, negative = the node's
 *                    default (a week).
 * @param rendezvous  reachability hints to embed; NULL/0 = the node's own
 *                    advertised address.
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on a bad argument or a failed send.
 */
int at_app_first_contact_invite(at_app_events_t *handle, const char *q_out,
                                const char *ref, long ttl_seconds,
                                const char *const *rendezvous,
                                size_t n_rendezvous);

/**
 * @brief Hand the node a friend's invitation: record them and say hello.
 * @param invitation the link or bare blob (required).
 * @param endpoint   override where to reach them; NULL = the link's first hint.
 * @param in_person  true ONLY if the link came over a channel with no possible
 *                   man in the middle (a QR code scanned face to face). The
 *                   contact is then verified at once; otherwise it stays
 *                   unverified until the safety numbers are compared.
 * @param petname    your local name for them; NULL = one is derived.
 * @return as @ref at_app_first_contact_invite.
 */
int at_app_first_contact_initiate(at_app_events_t *handle, const char *q_out,
                                  const char *ref, const char *invitation,
                                  const char *endpoint, bool in_person,
                                  const char *petname);

/** @brief Ask for the safety number to show the user for @p peer. Both people
 *  see the same 60 digits; after comparing, call @ref at_app_first_contact_verify.
 *  Returns as @ref at_app_first_contact_invite. */
int at_app_first_contact_safety_number(at_app_events_t *handle, const char *q_out,
                                       const char *ref,
                                       const uint8_t peer[AT_APP_UUID_LEN]);

/** @brief Mark @p peer verified. Pass @p presented (digits typed from the OTHER
 *  person's screen, which the node compares) OR @p presented NULL with
 *  @p confirmed true (the user compared by eye). A typed number that does not
 *  match is refused (AT_FC_REASON_MISMATCH) and the contact stays unverified. */
int at_app_first_contact_verify(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN],
                                const char *presented, bool confirmed);

/** @brief Ask for the whole address book: one CONTACT event per record, oldest
 *  first, then CONTACTS_DONE with the count (so an empty book still answers). */
int at_app_first_contact_list(at_app_events_t *handle, const char *q_out,
                              const char *ref);

/** @brief Rename @p peer locally (at most 128 bytes, not blank). */
int at_app_first_contact_rename(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN],
                                const char *petname);

/** @brief Remove @p peer from the address book, and drop it as a direct peer
 *  at once. A contact who is also in your cohort keeps its place there. */
int at_app_first_contact_remove(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN]);

/**
 * @brief Ask the node to mint a PAIRING invitation, for another device of
 *        ours to redeem with @ref at_app_first_contact_initiate. Needs a device
 *        cert on this node (refused AT_FC_REASON_NOT_SIBLING otherwise).
 * @param ttl_seconds as at_app_first_contact_invite.
 */
int at_app_first_contact_pair_invite(at_app_events_t *handle, const char *q_out,
                                     const char *ref, long ttl_seconds);
/** @brief One AT_APP_EVENT_FC_SIBLING per paired device, then SIBLINGS_DONE. */
int at_app_sibling_list(at_app_events_t *handle, const char *q_out, const char *ref);
/** @brief Unpair @p peer here (not synced); answers SIBLING_REMOVED. */
int at_app_sibling_remove(at_app_events_t *handle, const char *q_out,
                          const char *ref, const uint8_t peer[AT_APP_UUID_LEN]);

#ifdef __cplusplus
}
#endif

/** @} */ /* end of public_api */

#endif /* AT_FIRST_CONTACT_PUBLIC_H */
