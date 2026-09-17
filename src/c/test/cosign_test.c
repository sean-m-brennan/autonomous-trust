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
 * @file cosign_test.c
 * @brief Detached co-signing payload round-trip + shape refusals (Phase 3 P3.3).
 *
 * A co-signing ask carries the canonical bytes of a record somebody is being
 * asked to sign. crypto_box authenticates each end, so there is no signature
 * and no canonical form to pin for the MESSAGE — but there is something more
 * important than framing to pin here, and it is what the core refuses.
 *
 * The bytes exist to be reproduced EXACTLY: the signatures are over them, so a
 * payload that arrives truncated, odd-length or not-hex verifies against nothing
 * at all. That is strictly worse than a refused ask, because it costs somebody's
 * attention and produces a signature over a record nobody can rebuild. So the
 * refusals are the contract, and they are pinned here.
 *
 * What is NOT here, deliberately: any description field. The wording of what a
 * record commits to is derived on the signer's own node from these bytes (see
 * cosign.h). The freshness/replay gate and the emit-to-app path are exercised by
 * the conformance scenarios in both runtimes.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "identity/cosign.h"

DEFINE_TEST(test_bound_truncation)
{
    char out[AT_COSIGN_TOKEN_MAX + 1];
    ck_assert_int_eq((int)at_cosign_bound("guardian", out, sizeof(out),
                                          AT_COSIGN_TOKEN_MAX), 8);
    ck_assert_str_eq(out, "guardian");

    /* Over the bound is truncated to exactly the bound, never past the buffer. */
    char big[AT_COSIGN_TOKEN_MAX + 64];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ck_assert_int_eq((int)at_cosign_bound(big, out, sizeof(out), AT_COSIGN_TOKEN_MAX),
                     AT_COSIGN_TOKEN_MAX);
    ck_assert_int_eq((int)strlen(out), AT_COSIGN_TOKEN_MAX);

    /* NULL / tiny buffers stay safe and NUL-terminated. */
    ck_assert_int_eq((int)at_cosign_bound(NULL, out, sizeof(out), AT_COSIGN_TOKEN_MAX), 0);
    ck_assert_str_eq(out, "");
    char tiny[4];
    ck_assert_int_eq((int)at_cosign_bound("abcdef", tiny, sizeof(tiny),
                                          AT_COSIGN_TOKEN_MAX), 3);
    ck_assert_str_eq(tiny, "abc");
}

DEFINE_TEST(test_only_known_acts_are_carried)
{
    ck_assert(at_cosign_op_ok("membership", "admit"));
    ck_assert(at_cosign_op_ok("membership", "expel"));
    ck_assert(at_cosign_op_ok("guardian", "designate"));
    ck_assert(at_cosign_op_ok("guardian", "rotate"));
    ck_assert(at_cosign_op_ok("guardian", "release"));

    /* A voluntary departure is self-signed by the one person leaving, so it
     * needs no exchange and is deliberately not offered. */
    ck_assert(!at_cosign_op_ok("membership", "depart"));
    /* Ops do not cross classes, and an unknown class carries nothing. */
    ck_assert(!at_cosign_op_ok("membership", "designate"));
    ck_assert(!at_cosign_op_ok("guardian", "admit"));
    ck_assert(!at_cosign_op_ok("office", "confer"));
    ck_assert(!at_cosign_op_ok(NULL, "admit"));
    ck_assert(!at_cosign_op_ok("membership", NULL));
}

DEFINE_TEST(test_payload_must_look_like_exported_bytes)
{
    ck_assert(at_cosign_bytes_ok("a1626f70"));

    /* Empty, odd-length, uppercase or non-hex: nothing an exporter produced.
     * An odd count in particular is the signature of a TRUNCATED payload, which
     * is exactly the failure a bound without a check would cause. */
    ck_assert(!at_cosign_bytes_ok(""));
    ck_assert(!at_cosign_bytes_ok("a1626f7"));
    ck_assert(!at_cosign_bytes_ok("A1626F70"));
    ck_assert(!at_cosign_bytes_ok("a1 626f70"));
    ck_assert(!at_cosign_bytes_ok("not hex at all"));
    ck_assert(!at_cosign_bytes_ok(NULL));

    /* At the bound is carried; one character over is refused rather than cut. */
    char at_bound[AT_COSIGN_BYTES_MAX + 1];
    memset(at_bound, 'a', AT_COSIGN_BYTES_MAX);
    at_bound[AT_COSIGN_BYTES_MAX] = '\0';
    ck_assert(at_cosign_bytes_ok(at_bound));

    char over[AT_COSIGN_BYTES_MAX + 3];
    memset(over, 'a', AT_COSIGN_BYTES_MAX + 2);
    over[AT_COSIGN_BYTES_MAX + 2] = '\0';
    ck_assert(!at_cosign_bytes_ok(over));
}

DEFINE_TEST(test_request_round_trips)
{
    const char *bytes = "a1626f70a2646b696e64";
    json_t *env = at_cosign_request_to_json("guardian", "designate",
                                            "did:key:zPolity", "b3:deadbeef",
                                            bytes, 7, 1234.5);
    ck_assert_ptr_nonnull(env);

    char record[AT_COSIGN_TOKEN_MAX + 1], op[AT_COSIGN_TOKEN_MAX + 1];
    char polity[AT_COSIGN_DID_MAX + 1], cid[AT_COSIGN_CID_MAX + 1];
    char out[AT_COSIGN_BYTES_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;
    ck_assert_ret_ok(at_cosign_request_from_json(env, record, sizeof(record),
                                                 op, sizeof(op), polity,
                                                 sizeof(polity), cid, sizeof(cid),
                                                 out, sizeof(out), &seq, &ts));
    ck_assert_str_eq(record, "guardian");
    ck_assert_str_eq(op, "designate");
    ck_assert_str_eq(polity, "did:key:zPolity");
    ck_assert_str_eq(cid, "b3:deadbeef");
    /* The payload survives character for character — anything less would be a
     * signature over different bytes. */
    ck_assert_str_eq(out, bytes);
    ck_assert_int_eq((int)seq, 7);
    ck_assert(ts > 1234.0 && ts < 1235.0);
    json_decref(env);

    /* The emitter refuses to build an ask it knows is malformed. */
    ck_assert_ptr_null(at_cosign_request_to_json("guardian", "abolish",
                                                 "did:key:zPolity", "b3:x",
                                                 bytes, 1, 1.0));
    ck_assert_ptr_null(at_cosign_request_to_json("guardian", "designate",
                                                 "did:key:zPolity", "b3:x",
                                                 "not hex", 1, 1.0));
    ck_assert_ptr_null(at_cosign_request_to_json("guardian", "designate",
                                                 "did:key:zPolity", "",
                                                 bytes, 1, 1.0));
}

DEFINE_TEST(test_malformed_request_refused)
{
    char record[AT_COSIGN_TOKEN_MAX + 1], op[AT_COSIGN_TOKEN_MAX + 1];
    char polity[AT_COSIGN_DID_MAX + 1], cid[AT_COSIGN_CID_MAX + 1];
    char out[AT_COSIGN_BYTES_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;

#define PARSE(obj) at_cosign_request_from_json((obj), record, sizeof(record), \
        op, sizeof(op), polity, sizeof(polity), cid, sizeof(cid), out, \
        sizeof(out), &seq, &ts)

    /* A hand-built ask naming an act this build does not understand. The
     * emitter would have refused it; a peer's message did not come from our
     * emitter, which is why the parser checks too. */
    json_t *bad_op = json_object();
    json_object_set_new(bad_op, "record", json_string("guardian"));
    json_object_set_new(bad_op, "op", json_string("abolish"));
    json_object_set_new(bad_op, "polity", json_string("did:key:zPolity"));
    json_object_set_new(bad_op, "cid", json_string("b3:abc"));
    json_object_set_new(bad_op, "bytes", json_string("a1626f70"));
    json_object_set_new(bad_op, "seq", json_integer(1));
    json_object_set_new(bad_op, "ts", json_real(1.0));
    ck_assert_ret_nonzero(PARSE(bad_op));
    json_decref(bad_op);

    /* A payload that cannot be reproduced: odd-length hex. */
    json_t *odd = json_object();
    json_object_set_new(odd, "record", json_string("membership"));
    json_object_set_new(odd, "op", json_string("admit"));
    json_object_set_new(odd, "polity", json_string("did:key:zPolity"));
    json_object_set_new(odd, "cid", json_string("b3:abc"));
    json_object_set_new(odd, "bytes", json_string("a1626f7"));
    json_object_set_new(odd, "seq", json_integer(1));
    json_object_set_new(odd, "ts", json_real(1.0));
    ck_assert_ret_nonzero(PARSE(odd));
    json_decref(odd);

    /* An unstamped ask (no integer seq) — the same replay-guard rule the DM
     * path applies. */
    json_t *unstamped = json_object();
    json_object_set_new(unstamped, "record", json_string("membership"));
    json_object_set_new(unstamped, "op", json_string("admit"));
    json_object_set_new(unstamped, "polity", json_string("did:key:zPolity"));
    json_object_set_new(unstamped, "cid", json_string("b3:abc"));
    json_object_set_new(unstamped, "bytes", json_string("a1626f70"));
    json_object_set_new(unstamped, "seq", json_string("1"));
    json_object_set_new(unstamped, "ts", json_real(1.0));
    ck_assert_ret_nonzero(PARSE(unstamped));
    json_decref(unstamped);

    /* An ask with no content address at all. */
    json_t *no_cid = json_object();
    json_object_set_new(no_cid, "record", json_string("membership"));
    json_object_set_new(no_cid, "op", json_string("admit"));
    json_object_set_new(no_cid, "polity", json_string("did:key:zPolity"));
    json_object_set_new(no_cid, "cid", json_string(""));
    json_object_set_new(no_cid, "bytes", json_string("a1626f70"));
    json_object_set_new(no_cid, "seq", json_integer(1));
    json_object_set_new(no_cid, "ts", json_real(1.0));
    ck_assert_ret_nonzero(PARSE(no_cid));
    json_decref(no_cid);

    ck_assert_ret_nonzero(PARSE(NULL));
#undef PARSE
}

DEFINE_TEST(test_signature_round_trips_and_refuses_gaps)
{
    json_t *env = at_cosign_sig_to_json("b3:deadbeef", "did:key:zSigner",
                                        "0011aabb", 3, 99.5);
    ck_assert_ptr_nonnull(env);
    char cid[AT_COSIGN_CID_MAX + 1], signer[AT_COSIGN_DID_MAX + 1];
    char sig[AT_COSIGN_SIG_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;
    ck_assert_ret_ok(at_cosign_sig_from_json(env, cid, sizeof(cid), signer,
                                             sizeof(signer), sig, sizeof(sig),
                                             &seq, &ts));
    ck_assert_str_eq(cid, "b3:deadbeef");
    /* The signer is named by did:key, which EMBEDS its public key — so the
     * assembling node needs no registry, and the core needs none to carry it. */
    ck_assert_str_eq(signer, "did:key:zSigner");
    ck_assert_str_eq(sig, "0011aabb");
    ck_assert_int_eq((int)seq, 3);
    json_decref(env);

    /* An empty field means there is nothing to assemble with. */
    ck_assert_ptr_null(at_cosign_sig_to_json("", "did:key:zSigner", "00", 1, 1.0));
    ck_assert_ptr_null(at_cosign_sig_to_json("b3:abc", "", "00", 1, 1.0));
    ck_assert_ptr_null(at_cosign_sig_to_json("b3:abc", "did:key:zSigner", "", 1, 1.0));

    json_t *no_sig = json_object();
    json_object_set_new(no_sig, "cid", json_string("b3:abc"));
    json_object_set_new(no_sig, "signer", json_string("did:key:zSigner"));
    json_object_set_new(no_sig, "seq", json_integer(1));
    json_object_set_new(no_sig, "ts", json_real(1.0));
    ck_assert_ret_nonzero(at_cosign_sig_from_json(no_sig, cid, sizeof(cid), signer,
                                                  sizeof(signer), sig, sizeof(sig),
                                                  &seq, &ts));
    json_decref(no_sig);

    ck_assert_ret_nonzero(at_cosign_sig_from_json(NULL, cid, sizeof(cid), signer,
                                                  sizeof(signer), sig, sizeof(sig),
                                                  &seq, &ts));
}

RUN_TESTS(CoSign,
          test_bound_truncation,
          test_only_known_acts_are_carried,
          test_payload_must_look_like_exported_bytes,
          test_request_round_trips,
          test_malformed_request_refused,
          test_signature_round_trips_and_refuses_gaps)
