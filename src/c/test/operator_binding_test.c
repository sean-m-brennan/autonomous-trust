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
 * @file operator_binding_test.c
 * @brief The opt-in operator key: the pre-image, and the signature check that
 *        earns a guardian identity.
 *
 * Two things are under test, and the first matters more.
 *
 * **The pre-image is pinned against Python's**, byte for byte, including the
 * SHA-256 of a fixed case. Two hand-written builders in two languages are exactly
 * what drifts unnoticed: a drifted pre-image does not fail loudly, it just makes
 * every binding unverifiable across the boundary — a live node quietly losing its
 * guardian edge with nothing in the logs but "does not verify".
 *
 * **The signature check** runs against a PKI minted here (the `zta_ocsp_test`
 * pattern — generated, never committed), so the positive path is real: an operator
 * key signed by a real leaf's private key, verified through OpenSSL under the
 * leaf's certificate.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "identity/identity.h"
#ifdef AT_ZTA_ENABLED
#include "zta/x509_verifier.h"
#endif

#define TEST_PKI "/tmp/at_operator_binding_pki"

/* The pinned case, shared with Python
 * (tests/a_unit/test_operator_binding.py::test_the_preimage_is_the_tag_...):
 *   uuid    00010203-0405-0607-0809-0a0b0c0d0e0f
 *   node    the ed25519 public key derived from hex seed "11" * 32
 *   guardian 00 01 02 .. 1f
 * Recorded as a digest rather than 102 literal bytes so a mismatch reads as one
 * failure, not a diff hunt. */
static const char PINNED_PREIMAGE_SHA256[] =
    "e511d0e9f040643a2fcfba97981f945d7eb5dc0fb9d9d7e2acc9c9e3cedd42f1";
static const char PINNED_NODE_PUBKEY_HEX[] =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++)
    {
        unsigned int b = 0;
        sscanf(hex + (i * 2), "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + (i * 2), "%02x", in[i]);
    out[len * 2] = '\0';
}

/* The pinned identity: uuid and signing key set directly, since what is being
 * pinned is the pre-image, not key derivation. */
static void pinned_identity(public_identity_t *pub)
{
    memset(pub, 0, sizeof(*pub));
    for (size_t i = 0; i < UUID_LEN; i++)
        pub->uuid[i] = (uint8_t)i;
    hex_to_bytes(PINNED_NODE_PUBKEY_HEX, pub->signature.public,
                 crypto_sign_PUBLICKEYBYTES);
    snprintf(pub->nickname, sizeof(pub->nickname), "vector.test");
}

static void guardian_key(uint8_t out[crypto_sign_PUBLICKEYBYTES])
{
    for (size_t i = 0; i < crypto_sign_PUBLICKEYBYTES; i++)
        out[i] = (uint8_t)i;
}

/****************************
 * The pre-image
 ****************************/

DEFINE_TEST(test_the_preimage_matches_pythons_byte_for_byte)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t key[crypto_sign_PUBLICKEYBYTES];
    guardian_key(key);

    uint8_t pre[OPERATOR_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(operator_binding_preimage(&pub, key, pre));
    ck_assert_int_eq((int)sizeof(pre), 102);

    uint8_t digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, pre, sizeof(pre));
    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    bytes_to_hex(digest, sizeof(digest), hex);
    ck_assert_str_eq(hex, PINNED_PREIMAGE_SHA256);
}

DEFINE_TEST(test_the_preimage_is_tag_then_node_then_guardian)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t key[crypto_sign_PUBLICKEYBYTES];
    guardian_key(key);

    uint8_t pre[OPERATOR_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(operator_binding_preimage(&pub, key, pre));

    ck_assert_mem_eq(pre, OPERATOR_BINDING_TAG, OPERATOR_BINDING_TAG_LEN);
    const uint8_t *body = pre + OPERATOR_BINDING_TAG_LEN;
    ck_assert_mem_eq(body, pub.uuid, UUID_LEN);
    ck_assert_mem_eq(body + UUID_LEN, pub.signature.public,
                     crypto_sign_PUBLICKEYBYTES);
    ck_assert_mem_eq(body + UUID_LEN + crypto_sign_PUBLICKEYBYTES, key,
                     crypto_sign_PUBLICKEYBYTES);
}

/* The node is inside the signed bytes, which is the whole reason a binding cannot
 * be lifted from one node onto another. */
DEFINE_TEST(test_a_different_node_gives_a_different_preimage)
{
    public_identity_t a, b;
    pinned_identity(&a);
    pinned_identity(&b);
    uint8_t key[crypto_sign_PUBLICKEYBYTES];
    guardian_key(key);

    uint8_t pre_a[OPERATOR_BINDING_PREIMAGE_LEN];
    uint8_t pre_b[OPERATOR_BINDING_PREIMAGE_LEN];
    ck_assert_ret_ok(operator_binding_preimage(&a, key, pre_a));

    b.uuid[0] ^= 0xFF;                     /* same key, different node */
    ck_assert_ret_ok(operator_binding_preimage(&b, key, pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);

    pinned_identity(&b);
    b.signature.public[0] ^= 0xFF;         /* same uuid, rotated signing key */
    ck_assert_ret_ok(operator_binding_preimage(&b, key, pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);

    pinned_identity(&b);                   /* same node, different guardian */
    uint8_t other[crypto_sign_PUBLICKEYBYTES];
    guardian_key(other);
    other[31] ^= 0xFF;
    ck_assert_ret_ok(operator_binding_preimage(&b, other, pre_b));
    ck_assert(memcmp(pre_a, pre_b, sizeof(pre_a)) != 0);
}

DEFINE_TEST(test_the_empty_key_sentinel)
{
    uint8_t key[crypto_sign_PUBLICKEYBYTES] = {0};
    ck_assert(at_operator_pubkey_empty(key));
    ck_assert(at_operator_pubkey_empty(NULL));
    key[crypto_sign_PUBLICKEYBYTES - 1] = 1;   /* the last byte counts too */
    ck_assert(!at_operator_pubkey_empty(key));
    guardian_key(key);
    ck_assert(!at_operator_pubkey_empty(key));
}

DEFINE_TEST(test_the_preimage_builder_refuses_null)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t key[crypto_sign_PUBLICKEYBYTES];
    guardian_key(key);
    uint8_t pre[OPERATOR_BINDING_PREIMAGE_LEN];
    ck_assert_ret_nonzero(operator_binding_preimage(NULL, key, pre));
    ck_assert_ret_nonzero(operator_binding_preimage(&pub, NULL, pre));
    ck_assert_ret_nonzero(operator_binding_preimage(&pub, key, NULL));
}

/****************************
 * The signature check
 ****************************/

#ifdef AT_ZTA_ENABLED

static int read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return -1; }
    *out = malloc((size_t)sz);
    if (*out == NULL) { fclose(fp); return -1; }
    *out_len = fread(*out, 1, (size_t)sz, fp);
    fclose(fp);
    return (*out_len == (size_t)sz) ? 0 : -1;
}

/* Mint an operator leaf and a second, unrelated one, and sign the pinned
 * pre-image with each — the "generated, never committed" pattern zta_ocsp_test
 * uses. A signature made by leaf B is the forgery case: real signature, wrong
 * hands. */
static bool pki_setup(void)
{
    public_identity_t pub;
    pinned_identity(&pub);
    uint8_t key[crypto_sign_PUBLICKEYBYTES];
    guardian_key(key);
    uint8_t pre[OPERATOR_BINDING_PREIMAGE_LEN];
    if (operator_binding_preimage(&pub, key, pre) != 0)
        return false;

    char pre_path[256];
    snprintf(pre_path, sizeof(pre_path), "%s/preimage.bin", TEST_PKI);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", TEST_PKI);
    if (system(cmd) != 0)
        return false;
    FILE *fp = fopen(pre_path, "wb");
    if (fp == NULL)
        return false;
    size_t n = fwrite(pre, 1, sizeof(pre), fp);
    fclose(fp);
    if (n != sizeof(pre))
        return false;

    /* Two leaves, one CA. RSA + PKCS#1 v1.5 + SHA-256: the scheme a PIV uses and
     * the one Python's SoftwareToken/PivVerifier pair implements. */
    snprintf(cmd, sizeof(cmd),
             "cd %s && "
             "openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key "
             "  -out ca.crt -days 3650 -subj '/CN=Operator Root' "
             "  -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 && "
             "for who in alpha beta; do "
             "  openssl req -newkey rsa:2048 -nodes -keyout $who.key "
             "    -out $who.csr -subj \"/CN=operator-$who\" >/dev/null 2>&1 && "
             "  openssl x509 -req -in $who.csr -CA ca.crt -CAkey ca.key "
             "    -CAcreateserial -days 3650 -out $who.crt >/dev/null 2>&1 && "
             "  openssl x509 -in $who.crt -outform DER -out $who.der "
             "    >/dev/null 2>&1 && "
             "  openssl dgst -sha256 -sign $who.key -out $who.sig preimage.bin "
             "    >/dev/null 2>&1; "
             "done", TEST_PKI);
    if (system(cmd) != 0)
        return false;

    char check[256];
    snprintf(check, sizeof(check), "%s/beta.sig", TEST_PKI);
    fp = fopen(check, "rb");
    if (fp == NULL)
        return false;
    fclose(fp);
    return true;
}

DEFINE_TEST(test_a_real_signature_verifies_under_its_own_certificate)
{
    if (!pki_setup())
    {
        printf("  SKIP: could not mint a test PKI (openssl missing?)\n");
        return;
    }
    char path[256];
    uint8_t *cert = NULL, *sig = NULL, *pre = NULL;
    size_t cert_len = 0, sig_len = 0, pre_len = 0;

    snprintf(path, sizeof(path), "%s/alpha.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &cert, &cert_len));
    snprintf(path, sizeof(path), "%s/alpha.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &sig, &sig_len));
    snprintf(path, sizeof(path), "%s/preimage.bin", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &pre, &pre_len));
    ck_assert_int_eq((int)pre_len, OPERATOR_BINDING_PREIMAGE_LEN);

    ck_assert(x509_verify_data_signature(cert, cert_len, pre, pre_len,
                                         sig, sig_len));

    /* The same signature over one flipped byte of the pre-image: this is what a
     * lifted binding looks like from here. */
    pre[0] ^= 0xFF;
    ck_assert(!x509_verify_data_signature(cert, cert_len, pre, pre_len,
                                          sig, sig_len));
    pre[0] ^= 0xFF;

    /* A real signature by a real operator — just not this certificate's holder. */
    uint8_t *other_sig = NULL;
    size_t other_sig_len = 0;
    snprintf(path, sizeof(path), "%s/beta.sig", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &other_sig, &other_sig_len));
    ck_assert(!x509_verify_data_signature(cert, cert_len, pre, pre_len,
                                          other_sig, other_sig_len));
    /* ...and it verifies under ITS certificate, so the refusal above is about the
     * holder and not about a broken fixture. */
    uint8_t *other_cert = NULL;
    size_t other_cert_len = 0;
    snprintf(path, sizeof(path), "%s/beta.der", TEST_PKI);
    ck_assert_ret_ok(read_file(path, &other_cert, &other_cert_len));
    ck_assert(x509_verify_data_signature(other_cert, other_cert_len, pre, pre_len,
                                         other_sig, other_sig_len));

    free(cert); free(sig); free(pre); free(other_sig); free(other_cert);
}

DEFINE_TEST(test_the_signature_check_refuses_junk_rather_than_crashing)
{
    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));
    /* Every argument missing, in turn, then a certificate that is not one. */
    ck_assert(!x509_verify_data_signature(NULL, 0, buf, sizeof(buf), buf, sizeof(buf)));
    ck_assert(!x509_verify_data_signature(buf, sizeof(buf), NULL, 0, buf, sizeof(buf)));
    ck_assert(!x509_verify_data_signature(buf, sizeof(buf), buf, sizeof(buf), NULL, 0));
    ck_assert(!x509_verify_data_signature(buf, sizeof(buf), buf, sizeof(buf),
                                          buf, sizeof(buf)));
}

#endif /* AT_ZTA_ENABLED */

#ifdef AT_ZTA_ENABLED
RUN_TESTS(Operator_Binding,
          test_the_preimage_matches_pythons_byte_for_byte,
          test_the_preimage_is_tag_then_node_then_guardian,
          test_a_different_node_gives_a_different_preimage,
          test_the_empty_key_sentinel,
          test_the_preimage_builder_refuses_null,
          test_a_real_signature_verifies_under_its_own_certificate,
          test_the_signature_check_refuses_junk_rather_than_crashing)
#else
/* Without ZTA there is no verifier to test — but the pre-image is not ZTA-gated
 * (a node carries the fields in any build), so its cases still run. */
RUN_TESTS(Operator_Binding,
          test_the_preimage_matches_pythons_byte_for_byte,
          test_the_preimage_is_tag_then_node_then_guardian,
          test_a_different_node_gives_a_different_preimage,
          test_the_empty_key_sentinel,
          test_the_preimage_builder_refuses_null)
#endif
