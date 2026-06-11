/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"

/*
 * Corresponds to Python tests/a_unit/test_partition_recovery.py.
 *
 * The Python tests build a minimal IdentityProcess via object.__new__
 * and invoke the handler methods directly. C can't do that — process_t
 * is opaque and handler functions are static. So this file covers the
 * externally-observable surface:
 *
 *   1. Canonical signature inputs match Python's byte format (the
 *      cross-impl-interop requirement). Without this, Python peers and
 *      C peers exchange probe/response messages whose signatures don't
 *      verify on the other side.
 *   2. Ed25519 sign + hex + verify round-trip works against the
 *      canonical inputs. Both peers use the same primitives
 *      (libsodium's crypto_sign_detached + hex), so a round-trip in C
 *      that uses the same byte input + key serialization as Python is
 *      sufficient evidence of interop.
 *   3. Partition-recovery state (id_state.partition_*) clears on
 *      identity_reset_state.
 *
 * The actual handler dispatch (probe → response → request_access) is
 * exercised end-to-end through the conformance corpus scenarios added
 * by the next task.
 */

DEFINE_TEST(test_canonical_probe_matches_python_format)
{
    /* Python: ('%s|%s' % (uuid, int(size))).encode('utf-8') */
    char out[128] = {0};
    int n = identity_partition_canonical_probe(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 1, out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out, "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7|1");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_probe_zero_size)
{
    char out[128] = {0};
    int n = identity_partition_canonical_probe(
        "00000000-0000-0000-0000-000000000000", 0, out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out, "00000000-0000-0000-0000-000000000000|0");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_probe_overflow_rejected)
{
    char out[8];  /* too small */
    int n = identity_partition_canonical_probe(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 1, out, sizeof(out));
    ck_assert_int_eq(n, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_canonical_response_matches_python_format)
{
    /* Python: ('%s|%s|%s' % (group_uuid, int(size), in_response_to))
     *         .encode('utf-8') */
    char out[256] = {0};
    int n = identity_partition_canonical_response(
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7", 5,
        "5a475006-904d-4cb8-9055-397f01931ca5",
        out, sizeof(out));
    ck_assert(n > 0);
    ck_assert_str_eq(out,
        "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7|5|5a475006-904d-4cb8-9055-397f01931ca5");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_sign_verify_roundtrip_with_canonical_input)
{
    /* Build a canonical probe input, sign it with an identity's private
     * key, hex-encode, then verify via the public key. This mirrors
     * what the Python and C handlers do over the wire — if both sides
     * agree on canonical bytes + ed25519 + hex, the cross-impl
     * signature check works. */
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.3";
    char name[] = "coord";
    char nick[] = "coord";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, &ident));

    char group_uuid_str[] = "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7";
    int group_size = 1;
    char canonical[128];
    int clen = identity_partition_canonical_probe(
        group_uuid_str, group_size, canonical, sizeof(canonical));
    ck_assert(clen > 0);

    /* Sign — detached, 64 raw bytes. */
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_ret_ok(crypto_sign_detached(sig, NULL,
                                          (unsigned char *)canonical,
                                          (size_t)clen,
                                          ident->signature.private));

    /* Hex-encode (128 ASCII chars + NUL). */
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)sig_hex);
    ck_assert_int_eq(strlen(sig_hex), crypto_sign_BYTES * 2);

    /* Publish and decode the public-identity-only form (mimics what
     * the receiver of a probe would do — parse the embedded
     * from_identity object from JSON). */
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);

    /* Verify — happy path. */
    unsigned char sig_decoded[crypto_sign_BYTES];
    ck_assert_ret_ok(unhexlify((unsigned char *)sig_hex,
                               crypto_sign_BYTES * 2, sig_decoded));
    ck_assert_ret_ok(crypto_sign_verify_detached(sig_decoded,
                                                 (unsigned char *)canonical,
                                                 (size_t)clen,
                                                 pub->signature.public));

    /* Tampered canonical — must fail. */
    char tampered[128];
    snprintf(tampered, sizeof(tampered), "%s|%d", group_uuid_str,
             group_size + 1);
    ck_assert(crypto_sign_verify_detached(sig_decoded,
                                          (unsigned char *)tampered,
                                          strlen(tampered),
                                          pub->signature.public) != 0);

    smrt_deref(pub);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_partition_state_clears_on_reset)
{
    /* identity_reset_state must purge partition_recovery_target so a
     * fresh scenario doesn't inherit stale in-flight state. */
    char target[64];

    /* Force initialization. */
    identity_reset_state();
    size_t n = identity_get_partition_recovery_target(target,
                                                       sizeof(target));
    ck_assert_int_eq(n, 0);
    ck_assert_str_eq(target, "");

    /* (We can't easily *set* the state without going through
     * handle_partition_response — which needs a process_t + queues.
     * The reset behavior on an already-clean state is the most we can
     * cover from here; the set-then-reset path is exercised by the
     * conformance corpus.) */
}
END_TEST_DEFINITION()

RUN_TESTS(PartitionRecovery,
          test_canonical_probe_matches_python_format,
          test_canonical_probe_zero_size,
          test_canonical_probe_overflow_rejected,
          test_canonical_response_matches_python_format,
          test_sign_verify_roundtrip_with_canonical_input,
          test_partition_state_clears_on_reset)
