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
 * @file unencrypted_verbs_test.c
 * @brief The plaintext-verb allowlist (identity_verb_is_unencrypted).
 *
 * The point-to-point receive path attributes a frame by source address and then
 * decrypts it, so once a peer is in the peer table every frame from it takes the
 * decrypt branch. Verbs sent with encrypt=false by design cannot be decrypted,
 * so they were dropped -- and on this side ALSO annoy-tracked, meaning a peer
 * that merely followed the protocol was driven toward blacklisting. Measured on
 * the Python twin: 1-3 drops per two-peer run, all `access_granted`, and it cost
 * 3-peer convergence outright.
 *
 * The allowlist is what keeps the fallback from becoming a downgrade hole: a
 * peer already in the table must not be able to send an arbitrary verb as
 * plaintext and have it honored. The refusal cases are the load-bearing half.
 *
 * This is a RECEIVE policy, so it must accept every verb a PEER may legitimately
 * send unencrypted -- including ones this implementation never originates. The
 * set is a cross-language contract with Python's
 * identity.protocol.UNENCRYPTED_VERBS; test_unencrypted_verbs.py pins the other
 * side, and the two lists must agree verb-for-verb.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "identity/identity.h"

/* The eleven verbs, as WIRE STRINGS. Spelled literally rather than via the
 * ID_* symbols (which are file-static in id_proc.c) precisely so that renaming
 * a constant cannot silently change what this test asserts -- the wire string
 * is the contract with the Python side. */
static const char *const ALLOWED[] = {
    "request_access",
    "access_granted",
    "peer_identity_query",
    "peer_identity_response",
    "operator_attest_query",
    "operator_attest_response",
    "subtree_roster_response",
    "group_partition_probe",
    "group_partition_response",
    /* The OPTIONAL 1:1 first-contact handshake. Plaintext by necessity: the
     * first hello arrives from somebody who is not a peer yet, so no shared
     * key exists to encrypt it under. On the allowlist unconditionally --
     * the handlers are opt-in per node, but this is a RECEIVE policy, and
     * Python's UNENCRYPTED_VERBS is not gated on the opt-in either. */
    "first_contact_hello",
    "first_contact_hello_ack",
};

/* Verbs that must NEVER be acceptable in plaintext from a known peer. Each is a
 * real selector this protocol uses, so a regression here is a genuine downgrade
 * hole rather than a hypothetical one. */
static const char *const REFUSED[] = {
    "full_history",        /* carries the group key material */
    "group_key_update",
    "peer_accepted",
    "propose_peer",
    "vote_on_peer",
    "history_diff",
    "peer_caps_query",
    "peer_caps_response",
    "peer_position_query", /* opt-in position: encrypted directed, never plaintext */
    "peer_position_response",
    "peer_profile_query",  /* opt-in signed profile: encrypted directed (Increment 3) */
    "peer_profile_response",
    "peer_connection_request",  /* explicit connection: encrypted directed (Increment 5) */
    "peer_connection_response", /* signed accept/decline: encrypted directed (Increment 5) */
    "peer_dm",             /* direct message: encrypted directed (Increment 6) */
    "tier_update",         /* local IPC; never legitimate off the wire */
    "subtree_roster_query",
    "request reputation",
    "reputation response",
};

DEFINE_TEST(test_allowlisted_verbs_are_accepted)
{
    size_t n = sizeof(ALLOWED) / sizeof(ALLOWED[0]);
    for (size_t i = 0; i < n; i++)
        ck_assert(identity_verb_is_unencrypted(ALLOWED[i]));
}

DEFINE_TEST(test_access_granted_specifically)
{
    /* The verb actually measured being dropped. Named on its own because
     * `accept`'s wire form is access_granted, which is easy to miss. */
    ck_assert(identity_verb_is_unencrypted("access_granted"));
}

DEFINE_TEST(test_sensitive_verbs_are_refused)
{
    size_t n = sizeof(REFUSED) / sizeof(REFUSED[0]);
    for (size_t i = 0; i < n; i++)
        ck_assert(!identity_verb_is_unencrypted(REFUSED[i]));
}

DEFINE_TEST(test_null_and_empty_are_refused)
{
    ck_assert(!identity_verb_is_unencrypted(NULL));
    ck_assert(!identity_verb_is_unencrypted(""));
}

DEFINE_TEST(test_matching_is_exact_not_prefix)
{
    /* strcmp, not strncmp: a near-miss must not slip through. */
    ck_assert(!identity_verb_is_unencrypted("access_granted_extra"));
    ck_assert(!identity_verb_is_unencrypted("access_grante"));
    ck_assert(!identity_verb_is_unencrypted("ACCESS_GRANTED"));
    ck_assert(!identity_verb_is_unencrypted(" access_granted"));
}

DEFINE_TEST(test_allowlist_size_is_deliberate)
{
    /* Not a count for its own sake: it forces anyone widening the allowlist to
     * come here, read the cross-language contract note, and update Python too.
     * Eleven verbs, matching UNENCRYPTED_VERBS. */
    size_t n = sizeof(ALLOWED) / sizeof(ALLOWED[0]);
    ck_assert_int_eq((int)n, 11);
    size_t accepted = 0;
    for (size_t i = 0; i < n; i++)
        if (identity_verb_is_unencrypted(ALLOWED[i]))
            accepted++;
    ck_assert_int_eq((int)accepted, 11);
}

RUN_TESTS(UnencryptedVerbs,
          test_allowlisted_verbs_are_accepted,
          test_access_granted_specifically,
          test_sensitive_verbs_are_refused,
          test_null_and_empty_are_refused,
          test_matching_is_exact_not_prefix,
          test_allowlist_size_is_deliberate)
