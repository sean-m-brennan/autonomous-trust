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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "zta/zta_verifier.h"
#include "zta/x509_verifier.h"
#include "zta/oidc_verifier.h"

/* Shared test PKI (same location//generator the OCSP suite uses). */
#define TEST_PKI "/tmp/zta_test_pki"
#ifndef GEN_CA_SCRIPT
#define GEN_CA_SCRIPT "../test/zta_test_ca/generate_test_ca.sh"
#endif
#define TMP_PREFIX "/tmp/zta_bundle_fmt"

/*
 * Tests for the ZTA verifier interface:
 * - Null verifier always returns VERIFIED
 * - X.509 verifier rejects empty credentials
 * - OIDC stub returns UNAVAILABLE
 * - credential_hash is deterministic
 * - zta_status_str returns correct strings
 */

DEFINE_TEST(test_null_verifier_verify)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));
    ck_assert_ptr_nonnull(v);

    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_null_verifier_revocation)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));

    uint8_t fake_hash[ZTA_HASH_LEN] = {0};
    zta_result_t result;
    ck_assert_ret_ok(v->check_revocation(v, fake_hash, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    ck_assert(v->is_available(v) == true);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_null_verifier_hash)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));

    uint8_t hash[ZTA_HASH_LEN];
    ck_assert_ret_ok(v->credential_hash(v, NULL, 0, hash));

    /* Null verifier returns all zeros */
    uint8_t expected[ZTA_HASH_LEN] = {0};
    ck_assert_mem_eq(hash, expected, ZTA_HASH_LEN);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_verifier_no_credential)
{
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Use system default CA (empty path triggers default) */
    cfg.connect_timeout_ms = 1000;

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));
    ck_assert_ptr_nonnull(v);

    /* Verify with no credential data -> REJECTED */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_verifier_garbage_data)
{
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.connect_timeout_ms = 1000;

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    /* Verify with garbage data -> REJECTED (can't parse) */
    uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF};
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, garbage, sizeof(garbage), &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_oidc_stub_unavailable)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(oidc_verifier_create(&v));
    ck_assert_ptr_nonnull(v);

    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_UNAVAILABLE);

    ck_assert_ret_ok(v->check_revocation(v, NULL, &result));
    ck_assert_int_eq(result.status, ZTA_UNAVAILABLE);

    ck_assert(v->is_available(v) == false);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_zta_status_str)
{
    ck_assert_str_eq(zta_status_str(ZTA_VERIFIED), "VERIFIED");
    ck_assert_str_eq(zta_status_str(ZTA_REJECTED), "REJECTED");
    ck_assert_str_eq(zta_status_str(ZTA_DEFERRED), "DEFERRED");
    ck_assert_str_eq(zta_status_str(ZTA_EXPIRED), "EXPIRED");
    ck_assert_str_eq(zta_status_str(ZTA_REVOKED), "REVOKED");
    ck_assert_str_eq(zta_status_str(ZTA_UNAVAILABLE), "UNAVAILABLE");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_zta_result_set)
{
    zta_result_t result;
    zta_result_set(&result, ZTA_VERIFIED, "test reason");
    ck_assert_int_eq(result.status, ZTA_VERIFIED);
    ck_assert_str_eq(result.reason, "test reason");
    ck_assert(result.timestamp.tv_sec > 0);
}
END_TEST_DEFINITION()

/* ---------- CA bundle / CRL encodings (Python parity: zta-python-parity.md §2.1)
 *
 * PKCS#7 (.p7b) is how agency PKI ships chains, and agency CRLs are DER; both
 * used to fail -- the .p7b as a corrupt bundle, the DER CRL silently as no CRL at
 * all. These pin both encodings plus the wrong-kind-of-file diagnosis.
 * ---------------------------------------------------------------------------- */

static bool ensure_test_pki(void)
{
    struct stat st;
    if (stat(TEST_PKI "/ca-bundle.pem", &st) == 0)
        return true;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "bash %s %s >/dev/null 2>&1",
             GEN_CA_SCRIPT, TEST_PKI);
    return system(cmd) == 0 && stat(TEST_PKI "/ca-bundle.pem", &st) == 0;
}

static size_t read_all(const char *path, uint8_t *buf, size_t cap)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, cap, fp);
    fclose(fp);
    return n;
}

/* Write the test CA bundle out as a PKCS#7 container (DER or PEM-wrapped). */
static bool write_ca_as_pkcs7(const char *out_path, bool der)
{
    BIO *in = BIO_new_file(TEST_PKI "/ca-bundle.pem", "r");
    if (in == NULL) return false;
    STACK_OF(X509) *certs = sk_X509_new_null();
    X509 *c = NULL;
    while ((c = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL)
        sk_X509_push(certs, c);
    BIO_free(in);
    if (sk_X509_num(certs) < 1) { sk_X509_pop_free(certs, X509_free); return false; }

    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);
    for (int i = 0; i < sk_X509_num(certs); i++)
        PKCS7_add_certificate(p7, sk_X509_value(certs, i));  /* ups ref */
    sk_X509_pop_free(certs, X509_free);

    BIO *out = BIO_new_file(out_path, "wb");
    if (out == NULL) { PKCS7_free(p7); return false; }
    int ok = der ? i2d_PKCS7_bio(out, p7) : PEM_write_bio_PKCS7(out, p7);
    BIO_free(out);
    PKCS7_free(p7);
    return ok == 1;
}

/* Re-encode the test CRL as DER, the form agency CRLs actually arrive in. */
static bool write_crl_as_der(const char *out_path)
{
    BIO *in = BIO_new_file(TEST_PKI "/crl/intermediate-revoked.crl.pem", "r");
    if (in == NULL)
        in = BIO_new_file(TEST_PKI "/crl/intermediate.crl.pem", "r");
    if (in == NULL) return false;
    X509_CRL *crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    BIO_free(in);
    if (crl == NULL) return false;
    BIO *out = BIO_new_file(out_path, "wb");
    if (out == NULL) { X509_CRL_free(crl); return false; }
    int ok = i2d_X509_CRL_bio(out, crl);
    BIO_free(out);
    X509_CRL_free(crl);
    return ok == 1;
}

static bool write_bytes(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    size_t n = len ? fwrite(data, 1, len, fp) : 0;
    fclose(fp);
    return n == len;
}

DEFINE_TEST(test_x509_bundle_pkcs7_der)
{
    if (!ensure_test_pki()) return;
    ck_assert(write_ca_as_pkcs7(TMP_PREFIX "_ca.p7b", true));

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s", TMP_PREFIX "_ca.p7b");

    zta_verifier_t *v = NULL;
    /* previously EX509_CALOAD: the bulk loader does not understand PKCS#7 */
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));
    ck_assert_ptr_nonnull(v);

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    ck_assert(len > 0);
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_bundle_pkcs7_pem_wrapped)
{
    if (!ensure_test_pki()) return;
    ck_assert(write_ca_as_pkcs7(TMP_PREFIX "_ca_pem.p7b", false));

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s", TMP_PREFIX "_ca_pem.p7b");

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));
    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_bundle_pkcs7_rejects_stranger)
{
    /* p7b support must not make everything verify */
    if (!ensure_test_pki()) return;
    ck_assert(write_ca_as_pkcs7(TMP_PREFIX "_ca.p7b", true));

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s", TMP_PREFIX "_ca.p7b");
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/unknown_ca.der", der, sizeof(der));
    ck_assert(len > 0);
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_bundle_pem_still_works)
{
    if (!ensure_test_pki()) return;
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s/ca-bundle.pem", TEST_PKI);
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));
    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_bundle_wrong_kind_is_distinguished)
{
    if (!ensure_test_pki()) return;
    /* A CRL in the CA-bundle slot is a config mix-up -> its own error code,
     * not the generic "failed to load". */
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN,
             "%s/crl/intermediate.crl.pem", TEST_PKI);
    zta_verifier_t *v = NULL;
    ck_assert_int_eq(x509_verifier_create(&cfg, &v), EX509_CAKIND);

    /* A DER CRL likewise (no PEM marker to key off). */
    ck_assert(write_crl_as_der(TMP_PREFIX "_der.crl"));
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s", TMP_PREFIX "_der.crl");
    ck_assert_int_eq(x509_verifier_create(&cfg, &v), EX509_CAKIND);

    /* A private key too. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN,
             "%s/certs/drone_alpha.key", TEST_PKI);
    ck_assert_int_eq(x509_verifier_create(&cfg, &v), EX509_CAKIND);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_bundle_garbage_is_caload)
{
    /* unrecognizable content stays the generic load error */
    ck_assert(write_bytes(TMP_PREFIX "_junk.pem", (const uint8_t *)"hello", 5));
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s", TMP_PREFIX "_junk.pem");
    zta_verifier_t *v = NULL;
    ck_assert_int_eq(x509_verifier_create(&cfg, &v), EX509_CALOAD);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_crl_der_is_loaded)
{
    if (!ensure_test_pki()) return;
    ck_assert(write_crl_as_der(TMP_PREFIX "_rev.crl"));

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s/ca-bundle.pem", TEST_PKI);
    snprintf(cfg.crl_path, X509_PATH_LEN, "%s", TMP_PREFIX "_rev.crl");
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    /* The DER CRL must actually be consulted -- it used to parse as nothing and
     * report "no revocation check method configured". */
    zta_result_t rev;
    ck_assert_ret_ok(v->check_revocation(v, result.credential_hash, &rev));
    ck_assert(rev.status == ZTA_VERIFIED || rev.status == ZTA_REVOKED);
    ck_assert(strstr(rev.reason, "no revocation check method") == NULL);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_crl_unusable_is_unavailable)
{
    if (!ensure_test_pki()) return;
    ck_assert(write_bytes(TMP_PREFIX "_junk.crl", (const uint8_t *)"junk", 4));

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s/ca-bundle.pem", TEST_PKI);
    snprintf(cfg.crl_path, X509_PATH_LEN, "%s", TMP_PREFIX "_junk.crl");
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    zta_result_t rev;
    ck_assert_ret_ok(v->check_revocation(v, result.credential_hash, &rev));
    /* fail-closed: a check that cannot run must not read as "not revoked" */
    ck_assert_int_eq(rev.status, ZTA_UNAVAILABLE);
    ck_assert(strstr(rev.reason, "could not be parsed") != NULL);
    ck_assert(strstr(rev.reason, "no revocation check method") == NULL);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_crl_missing_file_is_unavailable)
{
    if (!ensure_test_pki()) return;
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s/ca-bundle.pem", TEST_PKI);
    snprintf(cfg.crl_path, X509_PATH_LEN, "%s", TMP_PREFIX "_absent.crl");
    remove(TMP_PREFIX "_absent.crl");
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    zta_result_t rev;
    ck_assert_ret_ok(v->check_revocation(v, result.credential_hash, &rev));
    ck_assert_int_eq(rev.status, ZTA_UNAVAILABLE);
    ck_assert(strstr(rev.reason, "could not be read") != NULL);
    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_crl_pem_still_works)
{
    if (!ensure_test_pki()) return;
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, X509_PATH_LEN, "%s/ca-bundle.pem", TEST_PKI);
    snprintf(cfg.crl_path, X509_PATH_LEN, "%s/crl/intermediate.crl.pem", TEST_PKI);
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    uint8_t der[8192];
    size_t len = read_all(TEST_PKI "/certs/drone_alpha.der", der, sizeof(der));
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, der, len, &result));
    zta_result_t rev;
    ck_assert_ret_ok(v->check_revocation(v, result.credential_hash, &rev));
    ck_assert_int_eq(rev.status, ZTA_VERIFIED);
    ck_assert_str_eq(rev.reason, "CRL loaded; not revoked");
    v->destroy(v);
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Verifier,
    test_null_verifier_verify,
    test_null_verifier_revocation,
    test_null_verifier_hash,
    test_x509_verifier_no_credential,
    test_x509_verifier_garbage_data,
    test_oidc_stub_unavailable,
    test_zta_status_str,
    test_zta_result_set,
    test_x509_bundle_pkcs7_der,
    test_x509_bundle_pkcs7_pem_wrapped,
    test_x509_bundle_pkcs7_rejects_stranger,
    test_x509_bundle_pem_still_works,
    test_x509_bundle_wrong_kind_is_distinguished,
    test_x509_bundle_garbage_is_caload,
    test_x509_crl_der_is_loaded,
    test_x509_crl_unusable_is_unavailable,
    test_x509_crl_missing_file_is_unavailable,
    test_x509_crl_pem_still_works)
