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
 * @file connection_test.c
 * @brief Explicit-connection canonical serialization + Ed25519 signing/verify
 *        (Increment 5). The canonical-bytes + signature vectors below are PINNED
 *        and MUST match the Python twin (tests/a_unit/test_connection_exchange.py):
 *        both suites assert the same literals, which is the cross-language
 *        lockstep guard the signed connection response depends on.
 *
 * The freshness/replay gate and the request→pending→connected/declined edge
 * transitions live at the handler level and are exercised end-to-end by the
 * conformance scenarios (connection-*.yaml, both runtimes). Here we pin the
 * signed-bytes contract that those handlers stand on, and prove the signature is
 * bound to BOTH uuids, the decision, and the freshness seq — so a decline cannot
 * masquerade as an accept and a replayed response carrying a different seq will
 * not verify.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>

#include "identity/connection.h"

/* Fixed reference input shared with the Python twin:
 *   requester uuid = bytes 0..15, accepter uuid = bytes 16..31,
 *   decision = 1 (accept), seq = 7, accepter seed = bytes 1..32. */
static const char *const REF_CANON_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "010700000000000000";
static const char *const REF_SIG_HEX =
    "ae873deab8e825adae6299cf3721cc4caaf8610eba32825e2eef5323813efbc9"
    "0f9e07dbc83a4eee0e172bb8590f2aa9eb778b8c80794faf8fd147ee512cb505";

static void ref_requester(uuid_t u) { for (int i = 0; i < 16; i++) u[i] = (uint8_t)i; }
static void ref_accepter(uuid_t u)  { for (int i = 0; i < 16; i++) u[i] = (uint8_t)(16 + i); }
static void ref_seed(unsigned char s[crypto_sign_SEEDBYTES])
{ for (size_t i = 0; i < crypto_sign_SEEDBYTES; i++) s[i] = (unsigned char)(i + 1); }

DEFINE_TEST(test_state_enum_contract)
{
    /* The five edge states are a frozen ABI (they cross to the app and are
     * asserted by the conformance `connection_state` key). */
    ck_assert_int_eq(AT_CONN_NONE, 0);
    ck_assert_int_eq(AT_CONN_PENDING_OUT, 1);
    ck_assert_int_eq(AT_CONN_PENDING_IN, 2);
    ck_assert_int_eq(AT_CONN_CONNECTED, 3);
    ck_assert_int_eq(AT_CONN_DECLINED, 4);
}

DEFINE_TEST(test_canonical_matches_pinned_vector)
{
    uuid_t req; ref_requester(req);
    uuid_t acc; ref_accepter(acc);
    uint8_t canon[AT_CONNECTION_CANON_LEN];
    size_t clen = at_connection_canonical(req, acc, 1, 7, canon, sizeof(canon));
    ck_assert(clen == AT_CONNECTION_CANON_LEN);
    char hex[2 * sizeof(canon) + 1];
    sodium_bin2hex(hex, sizeof(hex), canon, clen);
    ck_assert_str_eq(hex, REF_CANON_HEX);
}

DEFINE_TEST(test_sign_matches_pinned_and_verifies)
{
    uuid_t req; ref_requester(req);
    uuid_t acc; ref_accepter(acc);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);

    char sig[AT_CONNECTION_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_connection_sign(sk, req, acc, 1, 7, sig), 0);
    /* Ed25519 is deterministic: the signature is byte-stable and cross-runtime. */
    ck_assert_str_eq(sig, REF_SIG_HEX);
    ck_assert(at_connection_verify(pk, req, acc, 1, 7, sig));
}

/* request→pending→ACCEPT→connected: an accept (decision 1) verifies, and the
 * SAME bytes signed as a decline (decision 0) do not — the decision is bound. */
DEFINE_TEST(test_accept_and_decline_paths)
{
    uuid_t req; ref_requester(req);
    uuid_t acc; ref_accepter(acc);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);

    /* Accept path → connected. */
    char sig_accept[AT_CONNECTION_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_connection_sign(sk, req, acc, 1, 7, sig_accept), 0);
    ck_assert(at_connection_verify(pk, req, acc, 1, 7, sig_accept));
    /* An accept signature must NOT verify as a decline (decision flip). */
    ck_assert(!at_connection_verify(pk, req, acc, 0, 7, sig_accept));

    /* Decline path → declined: distinct signature, verifies for decision 0. */
    char sig_decline[AT_CONNECTION_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_connection_sign(sk, req, acc, 0, 7, sig_decline), 0);
    ck_assert(strcmp(sig_decline, sig_accept) != 0);
    ck_assert(at_connection_verify(pk, req, acc, 0, 7, sig_decline));
    ck_assert(!at_connection_verify(pk, req, acc, 1, 7, sig_decline));
}

DEFINE_TEST(test_bad_signature_rejected)
{
    uuid_t req; ref_requester(req);
    uuid_t acc; ref_accepter(acc);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    char sig[AT_CONNECTION_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_connection_sign(sk, req, acc, 1, 7, sig), 0);

    /* All-zero signature (the conformance bad-signature override). */
    char zeros[AT_CONNECTION_SIG_HEX_LEN + 1];
    memset(zeros, '0', AT_CONNECTION_SIG_HEX_LEN);
    zeros[AT_CONNECTION_SIG_HEX_LEN] = '\0';
    ck_assert(!at_connection_verify(pk, req, acc, 1, 7, zeros));

    /* Re-attribution: a different accepter uuid in the canonical is rejected,
     * so a valid response cannot be relayed as another node's. */
    uuid_t acc2; ref_accepter(acc2); acc2[0] ^= 0xFF;
    ck_assert(!at_connection_verify(pk, req, acc2, 1, 7, sig));
    /* Different requester (the ordered pair is bound). */
    uuid_t req2; ref_requester(req2); req2[3] ^= 0xFF;
    ck_assert(!at_connection_verify(pk, req2, acc, 1, 7, sig));

    /* Wrong signing key. */
    unsigned char seed2[crypto_sign_SEEDBYTES]; ref_seed(seed2); seed2[0] = 0xAA;
    unsigned char pk2[crypto_sign_PUBLICKEYBYTES], sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk2, sk2, seed2);
    ck_assert(!at_connection_verify(pk2, req, acc, 1, 7, sig));

    /* Malformed hex. */
    ck_assert(!at_connection_verify(pk, req, acc, 1, 7, "not-hex"));
}

/* The freshness seq is inside the signed canonical, so a captured accept
 * REPLAYED under a different seq will not verify — the signature gate and the
 * freshness gate (exercised in conformance) both reject a replay. */
DEFINE_TEST(test_replay_seq_binding_rejected)
{
    uuid_t req; ref_requester(req);
    uuid_t acc; ref_accepter(acc);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    char sig[AT_CONNECTION_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_connection_sign(sk, req, acc, 1, 7, sig), 0);
    ck_assert(at_connection_verify(pk, req, acc, 1, 7, sig));
    /* Same bytes, older/other seq: does not verify. */
    ck_assert(!at_connection_verify(pk, req, acc, 1, 6, sig));
    ck_assert(!at_connection_verify(pk, req, acc, 1, 8, sig));
}

RUN_TESTS(Connection,
          test_state_enum_contract,
          test_canonical_matches_pinned_vector,
          test_sign_matches_pinned_and_verifies,
          test_accept_and_decline_paths,
          test_bad_signature_rejected,
          test_replay_seq_binding_rejected)
