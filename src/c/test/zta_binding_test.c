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
 * @file zta_binding_test.c
 * @brief The credential->identity binding (doc/architecture/zta-integration.md): which node a ZTA
 *        credential authorizes, and the proof.
 *
 * Three things are under test, and the first matters most.
 *
 * **The pre-image is pinned against Python's**, byte for byte, as a SHA-256 of a
 * fixed case. Two hand-written builders in two languages are exactly what drifts
 * unnoticed: a drifted pre-image does not fail loudly, it makes every binding
 * unverifiable across the runtime boundary — a mixed fleet quietly refusing each
 * other's peers with nothing in the logs but "does not verify".
 *
 * **The verification predicates**, against a PKI minted here (the
 * operator_binding_test pattern — generated, never committed), so the positive
 * path is real rather than mocked: a signature by a real leaf's private key,
 * checked through OpenSSL under that leaf's certificate.
 *
 * **The surrounding machinery** the gate leans on: credential-list dedup and
 * binding adoption, anchor bookkeeping, binding_mode parsing (where the
 * fail-closed rule lives), anchor resolution, and SAN template rendering.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include <uuid/uuid.h>

#include "identity/identity.h"
#include "utilities/util.h"   /* at_strlcpy */
#ifdef AT_ZTA_ENABLED
#include "zta/zta_binding.h"
#include "zta/zta_policy.h"
#include "zta/x509_verifier.h"
#endif

#define TEST_PKI "/tmp/at_zta_binding_pki"

/* The pinned case, shared with Python
 * (tests/a_unit/test_zta_binding.py::test_the_preimage_matches_the_c_twin):
 *   uuid        00010203-0405-0607-0809-0a0b0c0d0e0f
 *   node key    32 bytes of 0x11
 *   credential  64 bytes 0x00..0x3f
 * Recorded as a digest rather than 97 literal bytes so a mismatch reads as one
 * failure rather than a diff hunt. */
static const char PINNED_PREIMAGE_SHA256[] =
    "5e709bf6c00646e2914ecdb09d3127535876956fe3076fbc6c9c807ca8b2e778";
static const char PINNED_CRED_SHA256[] =
    "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108";

static void bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + (i * 2), "%02x", in[i]);
    out[len * 2] = '\0';
}

/* uuid and signing key set directly: what is pinned is the pre-image, not key
 * derivation. */
static void pinned_identity(public_identity_t *pub)
{
    memset(pub, 0, sizeof(*pub));
    for (size_t i = 0; i < UUID_LEN; i++)
        pub->uuid[i] = (uint8_t)i;
    memset(pub->signature.public, 0x11, crypto_sign_PUBLICKEYBYTES);
    snprintf(pub->nickname, sizeof(pub->nickname), "vector.test");
}

static void pinned_credential(uint8_t out[64])
{
    for (size_t i = 0; i < 64; i++)
        out[i] = (uint8_t)i;
}

/****************************
 * The pre-image
 ****************************/

DEFINE_TEST(test_the_preimage_matches_pythons_byte_for_byte)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64];
    pinned_credential(cred);

    uint8_t pre[ZTA_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(zta_binding_preimage(&pub, cred, sizeof(cred), pre));
    ck_assert_int_eq((int)sizeof(pre), 97);   /* 17 + 16 + 32 + 32 */

    uint8_t digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, pre, sizeof(pre));
    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    bytes_to_hex(digest, sizeof(digest), hex);
    ck_assert_str_eq(hex, PINNED_PREIMAGE_SHA256);
}

DEFINE_TEST(test_the_preimage_is_tag_then_node_then_fingerprint)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64];
    pinned_credential(cred);

    uint8_t pre[ZTA_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(zta_binding_preimage(&pub, cred, sizeof(cred), pre));

    ck_assert_mem_eq(pre, ZTA_BINDING_TAG, ZTA_BINDING_TAG_LEN);
    const uint8_t *body = pre + ZTA_BINDING_TAG_LEN;
    ck_assert_mem_eq(body, pub.uuid, UUID_LEN);
    ck_assert_mem_eq(body + UUID_LEN, pub.signature.public,
                     crypto_sign_PUBLICKEYBYTES);

    /* The trailing 32 bytes are sha256 OF THE BYTES PASSED IN — never the
     * announcer-controlled zta_credential_hash. The whole gate turns on that. */
    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    bytes_to_hex(body + UUID_LEN + crypto_sign_PUBLICKEYBYTES,
                 crypto_hash_sha256_BYTES, hex);
    ck_assert_str_eq(hex, PINNED_CRED_SHA256);
}

/* The ZTA tag must never collide with the operator one: a signature over one
 * must not verify as the other, and domain separation is the only thing
 * standing between them. */
DEFINE_TEST(test_the_zta_tag_is_distinct_from_the_operator_tag)
{
    ck_assert(strcmp(ZTA_BINDING_TAG, OPERATOR_BINDING_TAG) != 0);
    ck_assert((int)ZTA_BINDING_PREIMAGE_LEN
              != (int)OPERATOR_BINDING_PREIMAGE_LEN);
}

/* The node is inside the signed bytes, which is the whole reason a binding
 * cannot be lifted from one node onto another. */
DEFINE_TEST(test_a_different_node_or_credential_gives_a_different_preimage)
{
    public_identity_t a, b;
    pinned_identity(&a);
    uint8_t cred[64];
    pinned_credential(cred);

    uint8_t pre_a[ZTA_BINDING_PREIMAGE_LEN], pre_b[ZTA_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(zta_binding_preimage(&a, cred, sizeof(cred), pre_a));

    pinned_identity(&b);
    b.uuid[0] ^= 0xFF;                     /* same credential, different node */
    ck_assert_ret_ok(zta_binding_preimage(&b, cred, sizeof(cred), pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);

    pinned_identity(&b);
    b.signature.public[0] ^= 0xFF;         /* same uuid, rotated signing key */
    ck_assert_ret_ok(zta_binding_preimage(&b, cred, sizeof(cred), pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);

    pinned_identity(&b);                   /* same node, different credential */
    cred[63] ^= 0xFF;
    ck_assert_ret_ok(zta_binding_preimage(&b, cred, sizeof(cred), pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);
}

DEFINE_TEST(test_the_preimage_builder_refuses_null_and_empty)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64];
    pinned_credential(cred);
    uint8_t pre[ZTA_BINDING_PREIMAGE_LEN];

    ck_assert_int_eq(zta_binding_preimage(NULL, cred, sizeof(cred), pre), EINVAL);
    ck_assert_int_eq(zta_binding_preimage(&pub, NULL, 0, pre), EINVAL);
    ck_assert_int_eq(zta_binding_preimage(&pub, cred, sizeof(cred), NULL), EINVAL);
    /* An empty credential is refused rather than bound: a binding over nothing
     * is a signature nothing can verify, and the caller should hear about it. */
    ck_assert_int_eq(zta_binding_preimage(&pub, cred, 0, pre), EINVAL);
}

#ifdef AT_ZTA_ENABLED

/****************************
 * Credential list bookkeeping
 ****************************/

DEFINE_TEST(test_the_credential_list_dedups_and_adopts_a_binding)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64];
    pinned_credential(cred);
    uint8_t sig[16];
    memset(sig, 0xAB, sizeof(sig));

    /* The primary arrives first with no binding (fields 6-8 cannot carry one). */
    ck_assert_ret_ok(public_identity_add_zta_credential(&pub, cred, sizeof(cred),
                                                        NULL, 0, "peer"));
    ck_assert_int_eq((int)pub.num_zta_credentials, 1);
    ck_assert(pub.zta_credentials[0].binding == NULL);

    /* The field-16 copy of the SAME credential carries one: deduplicated by
     * fingerprint, and the binding is adopted onto the existing entry. That is
     * the case the real wire produces on every announce. */
    ck_assert_ret_ok(public_identity_add_zta_credential(&pub, cred, sizeof(cred),
                                                        sig, sizeof(sig), "peer"));
    ck_assert_int_eq((int)pub.num_zta_credentials, 1);
    ck_assert_int_eq((int)pub.zta_credentials[0].binding_len, (int)sizeof(sig));
    ck_assert_mem_eq(pub.zta_credentials[0].binding, sig, sizeof(sig));

    /* A genuinely different credential is a new entry. */
    cred[0] ^= 0xFF;
    ck_assert_ret_ok(public_identity_add_zta_credential(&pub, cred, sizeof(cred),
                                                        NULL, 0, "other"));
    ck_assert_int_eq((int)pub.num_zta_credentials, 2);

    public_identity_zta_credentials_clear(&pub);
    ck_assert_int_eq((int)pub.num_zta_credentials, 0);
    public_identity_zta_credentials_clear(&pub);   /* safe twice */
}

DEFINE_TEST(test_the_credential_list_is_bounded_and_refuses_junk)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64];
    pinned_credential(cred);

    ck_assert_int_eq(public_identity_add_zta_credential(&pub, NULL, 0, NULL, 0,
                                                        NULL), EINVAL);
    for (size_t i = 0; i < ZTA_MAX_CREDENTIALS; i++) {
        cred[0] = (uint8_t)i;
        ck_assert_ret_ok(public_identity_add_zta_credential(&pub, cred,
                                                            sizeof(cred),
                                                            NULL, 0, NULL));
    }
    cred[0] = 0xEE;
    /* Full is a bound being enforced, not a failure — callers ignore ENOSPC
     * deliberately, so it must be distinguishable from EINVAL. */
    ck_assert_int_eq(public_identity_add_zta_credential(&pub, cred, sizeof(cred),
                                                        NULL, 0, NULL), ENOSPC);
    ck_assert_int_eq((int)pub.num_zta_credentials, (int)ZTA_MAX_CREDENTIALS);

    /* An oversized BINDING drops the signature and keeps the credential: the two
     * are separately sourced, and discarding a good credential because somebody
     * padded its signature would turn a bounds check into a denial of service
     * against the honest case. */
    public_identity_zta_credentials_clear(&pub);
    uint8_t *big = malloc(ZTA_BINDING_MAX + 1);
    ck_assert(big != NULL);
    memset(big, 0x5A, ZTA_BINDING_MAX + 1);
    ck_assert_ret_ok(public_identity_add_zta_credential(&pub, cred, sizeof(cred),
                                                        big, ZTA_BINDING_MAX + 1,
                                                        NULL));
    ck_assert_int_eq((int)pub.num_zta_credentials, 1);
    ck_assert_int_eq((int)pub.zta_credentials[0].binding_len, 0);
    free(big);
    public_identity_zta_credentials_clear(&pub);
}

DEFINE_TEST(test_proved_anchors_are_recorded_and_deduped)
{
    public_identity_t pub;
    pinned_identity(&pub);

    ck_assert(!public_identity_has_zta_anchor(&pub, "dod"));
    public_identity_add_zta_anchor(&pub, "dod");
    public_identity_add_zta_anchor(&pub, "dod");     /* dedup */
    public_identity_add_zta_anchor(&pub, "");        /* ignored */
    public_identity_add_zta_anchor(&pub, NULL);      /* ignored */
    public_identity_add_zta_anchor(&pub, "dhs");
    ck_assert_int_eq((int)pub.num_zta_anchors, 2);
    ck_assert(public_identity_has_zta_anchor(&pub, "dod"));
    ck_assert(public_identity_has_zta_anchor(&pub, "dhs"));
    ck_assert(!public_identity_has_zta_anchor(&pub, "nato"));
}

/****************************
 * Policy: binding mode, anchors, SAN template
 ****************************/

DEFINE_TEST(test_an_unrecognized_binding_mode_tightens_the_gate)
{
    ck_assert_int_eq(zta_binding_mode_parse("require"), ZTA_BINDING_MODE_REQUIRE);
    ck_assert_int_eq(zta_binding_mode_parse("prefer"), ZTA_BINDING_MODE_PREFER);
    ck_assert_int_eq(zta_binding_mode_parse("off"), ZTA_BINDING_MODE_OFF);
    /* A typo must fail CLOSED. Silently becoming the most permissive setting is
     * the wrong direction to be wrong in, and matches Python's rule. */
    ck_assert_int_eq(zta_binding_mode_parse("REQUIRE"), ZTA_BINDING_MODE_REQUIRE);
    ck_assert_int_eq(zta_binding_mode_parse("offf"), ZTA_BINDING_MODE_REQUIRE);
    ck_assert_int_eq(zta_binding_mode_parse(""), ZTA_BINDING_MODE_REQUIRE);
    ck_assert_int_eq(zta_binding_mode_parse(NULL), ZTA_BINDING_MODE_REQUIRE);

    ck_assert_str_eq(zta_binding_mode_str(ZTA_BINDING_MODE_REQUIRE), "require");
    ck_assert_str_eq(zta_binding_mode_str(ZTA_BINDING_MODE_PREFER), "prefer");
    ck_assert_str_eq(zta_binding_mode_str(ZTA_BINDING_MODE_OFF), "off");

    zta_policy_t pol;
    zta_policy_defaults(&pol);
    ck_assert_int_eq(pol.binding_mode, ZTA_BINDING_MODE_REQUIRE);
}

DEFINE_TEST(test_an_empty_anchor_list_synthesizes_the_historical_pair)
{
    zta_policy_t pol;
    zta_policy_defaults(&pol);
    zta_anchor_t out[ZTA_POLICY_MAX_ANCHORS];

    /* No bundle anywhere: nothing to resolve. */
    ck_assert_int_eq((int)zta_policy_resolved_anchors(&pol, out,
                                                      ZTA_POLICY_MAX_ANCHORS), 0);

    /* The single-CA deployment that existed before anchors did resolves to
     * exactly the anchors it already had, in the same roles. That is what makes
     * the multi-anchor work additive rather than a config flag day. */
    snprintf(pol.ca_bundle_path, ZTA_PATH_LEN, "/tmp/peer.pem");
    ck_assert_int_eq((int)zta_policy_resolved_anchors(&pol, out,
                                                      ZTA_POLICY_MAX_ANCHORS), 1);
    ck_assert_str_eq(out[0].name, "peer");
    ck_assert(!out[0].is_operator);

    snprintf(pol.operator_ca_bundle_path, ZTA_PATH_LEN, "/tmp/op.pem");
    ck_assert_int_eq((int)zta_policy_resolved_anchors(&pol, out,
                                                      ZTA_POLICY_MAX_ANCHORS), 2);
    ck_assert_str_eq(out[1].name, "operator");
    ck_assert(out[1].is_operator);
}

DEFINE_TEST(test_explicit_anchors_drop_the_pathless_and_dedup_by_name)
{
    zta_policy_t pol;
    zta_policy_defaults(&pol);
    snprintf(pol.ca_bundle_path, ZTA_PATH_LEN, "/tmp/ignored.pem");

    at_strlcpy(pol.anchors[0].name, "dod", ZTA_ANCHOR_NAME_MAX);
    at_strlcpy(pol.anchors[0].ca_bundle_path, "/tmp/dod.pem", ZTA_PATH_LEN);
    at_strlcpy(pol.anchors[1].name, "nowhere", ZTA_ANCHOR_NAME_MAX);
    /* no bundle path: an anchor that trusts nothing can verify nothing */
    at_strlcpy(pol.anchors[2].name, "dod", ZTA_ANCHOR_NAME_MAX);
    at_strlcpy(pol.anchors[2].ca_bundle_path, "/tmp/dup.pem", ZTA_PATH_LEN);
    at_strlcpy(pol.anchors[3].name, "dhs", ZTA_ANCHOR_NAME_MAX);
    at_strlcpy(pol.anchors[3].ca_bundle_path, "/tmp/dhs.pem", ZTA_PATH_LEN);
    pol.num_anchors = 4;

    zta_anchor_t out[ZTA_POLICY_MAX_ANCHORS];
    size_t n = zta_policy_resolved_anchors(&pol, out, ZTA_POLICY_MAX_ANCHORS);
    /* Explicit anchors REPLACE the synthesized pair; "nowhere" is dropped and the
     * repeated "dod" cannot make a credential count twice toward gateway
     * authority. */
    ck_assert_int_eq((int)n, 2);
    ck_assert_str_eq(out[0].name, "dod");
    ck_assert_str_eq(out[0].ca_bundle_path, "/tmp/dod.pem");
    ck_assert_str_eq(out[1].name, "dhs");
}

DEFINE_TEST(test_the_san_template_uses_pythons_placeholder)
{
    char out[256];
    /* Python's `{uuid}` spelling, not printf's %s: ONE policy file is read by
     * both runtimes, so a C-only spelling would render literally and silently
     * match nothing. */
    ck_assert_ret_ok(zta_render_san_uri(ZTA_SAN_URI_TEMPLATE,
                                        "00010203-0405-0607-0809-0a0b0c0d0e0f",
                                        out, sizeof(out)));
    ck_assert_str_eq(out, "at://00010203-0405-0607-0809-0a0b0c0d0e0f");

    ck_assert_ret_ok(zta_render_san_uri("spiffe://x/{uuid}/n", "abc", out,
                                        sizeof(out)));
    ck_assert_str_eq(out, "spiffe://x/abc/n");

    /* No placeholder: copied through. Strange, not an error. */
    ck_assert_ret_ok(zta_render_san_uri("at://fixed", "abc", out, sizeof(out)));
    ck_assert_str_eq(out, "at://fixed");

    /* A stray '%' must not reach a format string. */
    ck_assert_ret_ok(zta_render_san_uri("at://%s-{uuid}", "abc", out,
                                        sizeof(out)));
    ck_assert_str_eq(out, "at://%s-abc");

    ck_assert_int_eq(zta_render_san_uri(NULL, "abc", out, sizeof(out)), EINVAL);
    ck_assert_int_eq(zta_render_san_uri("at://{uuid}", "abc", out, 4), EINVAL);
}

/****************************
 * Verification, against a real PKI
 ****************************/

static int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (n <= 0) { fclose(fp); return -1; }
    *buf = malloc((size_t)n);
    size_t got = (*buf != NULL) ? fread(*buf, 1, (size_t)n, fp) : 0;
    fclose(fp);
    if (*buf == NULL || got != (size_t)n) { free(*buf); *buf = NULL; return -1; }
    *len = (size_t)n;
    return 0;
}

/* One CA, two leaves, and a SAN-bearing third. `holder` signs the pre-image for
 * the pinned identity; `impostor` signs the same bytes with a different key. */
static bool pki_setup(void)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred_stub[64];
    pinned_credential(cred_stub);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", TEST_PKI);
    if (system(cmd) != 0)
        return false;

    /* RSA + PKCS#1 v1.5 + SHA-256: the scheme a PIV uses and the one Python's
     * PivVerifier accepts, so a signature made here is one the other runtime
     * would accept. */
    snprintf(cmd, sizeof(cmd),
             "cd %s && "
             "openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key "
             "  -out ca.crt -days 3650 -subj '/CN=ZTA Binding Root' "
             "  -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 && "
             "for who in holder impostor; do "
             "  openssl req -newkey rsa:2048 -nodes -keyout $who.key "
             "    -out $who.csr -subj \"/CN=zta-$who\" >/dev/null 2>&1 && "
             "  openssl x509 -req -in $who.csr -CA ca.crt -CAkey ca.key "
             "    -CAcreateserial -days 3650 -out $who.crt >/dev/null 2>&1 && "
             "  openssl x509 -in $who.crt -outform DER -out $who.der "
             "    >/dev/null 2>&1; "
             "done && "
             "openssl req -newkey rsa:2048 -nodes -keyout san.key -out san.csr "
             "  -subj '/CN=zta-san' >/dev/null 2>&1 && "
             "printf 'subjectAltName=URI:at://%%s\\n' "
             "  '00010203-0405-0607-0809-0a0b0c0d0e0f' > san.ext && "
             "openssl x509 -req -in san.csr -CA ca.crt -CAkey ca.key "
             "  -CAcreateserial -days 3650 -extfile san.ext -out san.crt "
             "  >/dev/null 2>&1 && "
             "openssl x509 -in san.crt -outform DER -out san.der >/dev/null 2>&1",
             TEST_PKI);
    if (system(cmd) != 0)
        return false;

    /* The pre-image binds the pinned identity to the HOLDER's own certificate —
     * the credential is the cert, which is what the real path does. */
    char path[256];
    uint8_t *holder_der = NULL;
    size_t holder_len = 0;
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    if (read_file(path, &holder_der, &holder_len) != 0)
        return false;
    uint8_t pre[ZTA_BINDING_PREIMAGE_LEN];
    int rc = zta_binding_preimage(&pub, holder_der, holder_len, pre);
    free(holder_der);
    if (rc != 0)
        return false;

    snprintf(path, sizeof(path), "%s/preimage.bin", TEST_PKI);
    FILE *fp = fopen(path, "wb");
    if (fp == NULL)
        return false;
    size_t n = fwrite(pre, 1, sizeof(pre), fp);
    fclose(fp);
    if (n != sizeof(pre))
        return false;

    snprintf(cmd, sizeof(cmd),
             "cd %s && for who in holder impostor; do "
             "  openssl dgst -sha256 -sign $who.key -out $who.sig preimage.bin "
             "    >/dev/null 2>&1; done", TEST_PKI);
    if (system(cmd) != 0)
        return false;
    snprintf(path, sizeof(path), "%s/impostor.sig", TEST_PKI);
    fp = fopen(path, "rb");
    if (fp == NULL)
        return false;
    fclose(fp);
    return true;
}

DEFINE_TEST(test_a_real_binding_verifies_and_a_forged_one_does_not)
{
    if (!pki_setup()) {
        printf("  SKIP: could not mint a test PKI (openssl missing?)\n");
        return;
    }
    public_identity_t pub;
    pinned_identity(&pub);

    char path[256];
    uint8_t *cert = NULL, *sig = NULL, *bad = NULL;
    size_t cert_len = 0, sig_len = 0, bad_len = 0;
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &cert, &cert_len));
    snprintf(path, sizeof(path), "%s/holder.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &sig, &sig_len));
    snprintf(path, sizeof(path), "%s/impostor.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &bad, &bad_len));

    ck_assert(zta_verify_binding(&pub, cert, cert_len, sig, sig_len));

    /* A real signature over the right bytes — by the wrong holder. */
    ck_assert(!zta_verify_binding(&pub, cert, cert_len, bad, bad_len));

    free(cert); free(sig); free(bad);
}

/* The harvested credential: the pair is genuine, the identity presenting it is
 * not. This is the case doc/architecture/zta-integration.md exists for, so it gets its own test rather than
 * riding along in the one above. */
DEFINE_TEST(test_a_harvested_binding_does_not_verify_under_another_identity)
{
    if (!pki_setup()) {
        printf("  SKIP: could not mint a test PKI\n");
        return;
    }
    char path[256];
    uint8_t *cert = NULL, *sig = NULL;
    size_t cert_len = 0, sig_len = 0;
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &cert, &cert_len));
    snprintf(path, sizeof(path), "%s/holder.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &sig, &sig_len));

    public_identity_t thief;
    pinned_identity(&thief);
    thief.uuid[0] ^= 0xFF;                  /* same credential, new uuid */
    ck_assert(!zta_verify_binding(&thief, cert, cert_len, sig, sig_len));

    pinned_identity(&thief);
    thief.signature.public[0] ^= 0xFF;      /* same uuid, different signing key */
    ck_assert(!zta_verify_binding(&thief, cert, cert_len, sig, sig_len));

    free(cert); free(sig);
}

DEFINE_TEST(test_verify_refuses_missing_oversized_and_junk_without_crashing)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t cred[64], sig[16];
    pinned_credential(cred);
    memset(sig, 0xAB, sizeof(sig));

    ck_assert(!zta_verify_binding(NULL, cred, sizeof(cred), sig, sizeof(sig)));
    ck_assert(!zta_verify_binding(&pub, NULL, 0, sig, sizeof(sig)));
    ck_assert(!zta_verify_binding(&pub, cred, sizeof(cred), NULL, 0));
    /* Absence and forgery both return false: they differ enormously in meaning,
     * so the admission gate distinguishes them by asking whether a binding was
     * offered — not by this return value. */
    ck_assert(!zta_verify_binding(&pub, cred, sizeof(cred), sig, 0));

    uint8_t *big = malloc(ZTA_BINDING_MAX + 1);
    ck_assert(big != NULL);
    memset(big, 0x5A, ZTA_BINDING_MAX + 1);
    ck_assert(!zta_verify_binding(&pub, cred, sizeof(cred), big,
                                  ZTA_BINDING_MAX + 1));
    free(big);

    /* `cred` is not a certificate at all — must be refused, not parsed. */
    ck_assert(!zta_verify_binding(&pub, cred, sizeof(cred), sig, sizeof(sig)));
}

DEFINE_TEST(test_a_uri_san_binds_the_identity_the_ca_named)
{
    if (!pki_setup()) {
        printf("  SKIP: could not mint a test PKI\n");
        return;
    }
    char path[256];
    uint8_t *san = NULL, *plain = NULL;
    size_t san_len = 0, plain_len = 0;
    snprintf(path, sizeof(path), "%s/san.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &san, &san_len));
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &plain, &plain_len));

    public_identity_t pub;
    pinned_identity(&pub);
    /* The CA-asserted binding: no blob carried, the certificate names the node. */
    ck_assert(zta_san_binds_identity(san, san_len, &pub, ZTA_SAN_URI_TEMPLATE));
    /* ...and only that node. */
    public_identity_t other;
    pinned_identity(&other);
    other.uuid[15] ^= 0xFF;
    ck_assert(!zta_san_binds_identity(san, san_len, &other,
                                      ZTA_SAN_URI_TEMPLATE));
    /* A certificate with no SAN names nobody. */
    ck_assert(!zta_san_binds_identity(plain, plain_len, &pub,
                                      ZTA_SAN_URI_TEMPLATE));
    /* An empty template disables the path, leaving holder-asserted signatures
     * as the only accepted proof. */
    ck_assert(!zta_san_binds_identity(san, san_len, &pub, ""));
    ck_assert(!zta_san_binds_identity(san, san_len, &pub, NULL));

    free(san); free(plain);
}

/* Any one mechanism suffices, and the SAN route is checked when the holder
 * signature is absent — which is what keeps `require` from being a flag day for
 * credentials AT issues itself. */
DEFINE_TEST(test_any_one_mechanism_is_enough)
{
    if (!pki_setup()) {
        printf("  SKIP: could not mint a test PKI\n");
        return;
    }
    char path[256];
    uint8_t *holder = NULL, *sig = NULL, *san = NULL;
    size_t holder_len = 0, sig_len = 0, san_len = 0;
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &holder, &holder_len));
    snprintf(path, sizeof(path), "%s/holder.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &sig, &sig_len));
    snprintf(path, sizeof(path), "%s/san.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &san, &san_len));

    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t no_key[crypto_sign_PUBLICKEYBYTES] = {0};

    /* Holder-asserted alone. */
    ck_assert(zta_identity_is_bound(&pub, holder, holder_len, sig, sig_len,
                                    ZTA_SAN_URI_TEMPLATE, no_key, NULL, 0));
    /* CA-asserted alone: no binding blob at all. */
    ck_assert(zta_identity_is_bound(&pub, san, san_len, NULL, 0,
                                    ZTA_SAN_URI_TEMPLATE, no_key, NULL, 0));
    /* Neither: a chain-valid credential this node cannot prove entitlement to. */
    ck_assert(!zta_identity_is_bound(&pub, holder, holder_len, NULL, 0,
                                     ZTA_SAN_URI_TEMPLATE, no_key, NULL, 0));

    free(holder); free(sig); free(san);
}

/* The operator-key binding is already a signature by the credential's key over
 * bytes naming this node, so it answers this question too — an opted-in node
 * needs no second signature and no second operator session. */
DEFINE_TEST(test_an_operator_key_binding_also_binds_the_credential)
{
    if (!pki_setup()) {
        printf("  SKIP: could not mint a test PKI\n");
        return;
    }
    public_identity_t pub;
    pinned_identity(&pub);

    char path[256];
    uint8_t *holder = NULL;
    size_t holder_len = 0;
    snprintf(path, sizeof(path), "%s/holder.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &holder, &holder_len));

    uint8_t guardian[crypto_sign_PUBLICKEYBYTES];
    for (size_t i = 0; i < sizeof(guardian); i++)
        guardian[i] = (uint8_t)(0x40 + i);
    uint8_t op_pre[OPERATOR_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(operator_binding_preimage(&pub, guardian, op_pre));

    snprintf(path, sizeof(path), "%s/op_preimage.bin", TEST_PKI);
    FILE *fp = fopen(path, "wb");
    ck_assert(fp != NULL);
    fwrite(op_pre, 1, sizeof(op_pre), fp);
    fclose(fp);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "cd %s && openssl dgst -sha256 -sign holder.key -out op.sig "
             "op_preimage.bin >/dev/null 2>&1", TEST_PKI);
    ck_assert_int_eq(system(cmd), 0);

    uint8_t *op_sig = NULL;
    size_t op_sig_len = 0;
    snprintf(path, sizeof(path), "%s/op.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &op_sig, &op_sig_len));

    ck_assert(zta_operator_binding_binds_identity(&pub, holder, holder_len,
                                                  guardian, op_sig, op_sig_len));
    /* And it satisfies the any-of gate with no credential binding present. */
    ck_assert(zta_identity_is_bound(&pub, holder, holder_len, NULL, 0,
                                    ZTA_SAN_URI_TEMPLATE, guardian,
                                    op_sig, op_sig_len));
    /* An absent guardian key is the ordinary opted-out node, and costs nothing:
     * it just does not help. */
    uint8_t empty[crypto_sign_PUBLICKEYBYTES] = {0};
    ck_assert(!zta_operator_binding_binds_identity(&pub, holder, holder_len,
                                                   empty, op_sig, op_sig_len));
    /* Lifted onto another identity, it names somebody else. */
    public_identity_t thief;
    pinned_identity(&thief);
    thief.uuid[0] ^= 0xFF;
    ck_assert(!zta_operator_binding_binds_identity(&thief, holder, holder_len,
                                                   guardian, op_sig,
                                                   op_sig_len));
    free(holder); free(op_sig);
}

/****************************
 * The wire (proto field 16)
 ****************************/

/* The credential LIST is the first variable-length thing on an identity, so
 * sync_out ALLOCATES (protobuf-c models a repeated message as an array of
 * pointers) and public_identity_proto_free releases it. Nothing else exercises
 * that pair — the conformance harness attaches from_whom in-process with no wire
 * round trip — so it gets a test of its own. */
DEFINE_TEST(test_the_credential_list_survives_a_proto_roundtrip)
{
    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.16";
    char name[] = "Field Sixteen";
    char nick[] = "F16";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, &ident));
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));

    uint8_t cred_a[64], cred_b[48], sig[24];
    pinned_credential(cred_a);
    memset(cred_b, 0x7C, sizeof(cred_b));
    memset(sig, 0x3D, sizeof(sig));
    ck_assert_ret_ok(public_identity_add_zta_credential(pub, cred_a,
                                                        sizeof(cred_a),
                                                        sig, sizeof(sig), "dod"));
    ck_assert_ret_ok(public_identity_add_zta_credential(pub, cred_b,
                                                        sizeof(cred_b),
                                                        NULL, 0, "dhs"));
    /* Anchors are OUR finding about a peer, so they must NOT cross the wire —
       a peer able to state them would assert the authority it should earn. */
    public_identity_add_zta_anchor(pub, "dod");

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(peer_to_proto(pub, &data, &data_len));
    ck_assert(data_len > 0);

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(proto_to_peer((uint8_t *)data, data_len, &back));

    ck_assert_int_eq((int)back.num_zta_credentials, 2);
    ck_assert_int_eq((int)back.zta_credentials[0].der_len, (int)sizeof(cred_a));
    ck_assert_mem_eq(back.zta_credentials[0].der, cred_a, sizeof(cred_a));
    ck_assert_int_eq((int)back.zta_credentials[0].binding_len, (int)sizeof(sig));
    ck_assert_mem_eq(back.zta_credentials[0].binding, sig, sizeof(sig));
    ck_assert_str_eq(back.zta_credentials[0].issuer, "dod");
    ck_assert_int_eq((int)back.zta_credentials[1].der_len, (int)sizeof(cred_b));
    ck_assert_int_eq((int)back.zta_credentials[1].binding_len, 0);
    ck_assert_int_eq((int)back.num_zta_anchors, 0);

    /* A binding signed over cred_a still verifies against the credential that
       came back — i.e. the bytes are intact, not merely the right length. */
    uint8_t pre_before[ZTA_BINDING_PREIMAGE_LEN];
    uint8_t pre_after[ZTA_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(zta_binding_preimage(pub, cred_a, sizeof(cred_a),
                                          pre_before));
    ck_assert_ret_ok(zta_binding_preimage(pub, back.zta_credentials[0].der,
                                          back.zta_credentials[0].der_len,
                                          pre_after));
    ck_assert_mem_eq(pre_before, pre_after, ZTA_BINDING_PREIMAGE_LEN);

    public_identity_zta_credentials_clear(&back);
    public_identity_zta_credentials_clear(pub);
    free(data);
}

#endif /* AT_ZTA_ENABLED */

#ifdef AT_ZTA_ENABLED
RUN_TESTS(Zta_Binding,
          test_the_preimage_matches_pythons_byte_for_byte,
          test_the_preimage_is_tag_then_node_then_fingerprint,
          test_the_zta_tag_is_distinct_from_the_operator_tag,
          test_a_different_node_or_credential_gives_a_different_preimage,
          test_the_preimage_builder_refuses_null_and_empty,
          test_the_credential_list_dedups_and_adopts_a_binding,
          test_the_credential_list_is_bounded_and_refuses_junk,
          test_proved_anchors_are_recorded_and_deduped,
          test_an_unrecognized_binding_mode_tightens_the_gate,
          test_an_empty_anchor_list_synthesizes_the_historical_pair,
          test_explicit_anchors_drop_the_pathless_and_dedup_by_name,
          test_the_san_template_uses_pythons_placeholder,
          test_a_real_binding_verifies_and_a_forged_one_does_not,
          test_a_harvested_binding_does_not_verify_under_another_identity,
          test_verify_refuses_missing_oversized_and_junk_without_crashing,
          test_a_uri_san_binds_the_identity_the_ca_named,
          test_any_one_mechanism_is_enough,
          test_an_operator_key_binding_also_binds_the_credential,
          test_the_credential_list_survives_a_proto_roundtrip)
#else
/* Without ZTA there is no verifier and no credential list — but the pre-image is
 * not ZTA-gated (identity.c defines it unconditionally, like the operator one),
 * so its cases still run. */
RUN_TESTS(Zta_Binding,
          test_the_preimage_matches_pythons_byte_for_byte,
          test_the_preimage_is_tag_then_node_then_fingerprint,
          test_the_zta_tag_is_distinct_from_the_operator_tag,
          test_a_different_node_or_credential_gives_a_different_preimage,
          test_the_preimage_builder_refuses_null_and_empty)
#endif
