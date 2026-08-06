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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/select.h>
#include <time.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>

#include "x509_verifier.h"

/* ---------- internal state ---------- */

#define CERT_CACHE_SIZE 64

/**
 * @brief Cached DER-encoded certificate, keyed by SHA-256 hash.
 *
 * When verify_credential parses a cert, we cache its DER encoding so that
 * check_revocation can later retrieve it for OCSP queries (which require
 * the full cert, not just the hash).
 */
typedef struct {
    uint8_t hash[ZTA_HASH_LEN];
    uint8_t *der;
    int der_len;
    bool valid;
} cert_cache_entry_t;

/* Max number of intermediate CA certificates between the leaf and the trust
 * anchor (root). MUST stay in lockstep with Python `_MAX_CHAIN_DEPTH`
 * (identity/zta/zta_verifier.py). OpenSSL's X509_VERIFY_PARAM_set_depth bounds
 * exactly this quantity. Pinned by conformance zta-x509-reject-chain-depth. */
#define AT_X509_MAX_CHAIN_DEPTH 8

typedef struct {
    x509_verifier_config_t cfg;
    X509_STORE *ca_store;
    /* Non-self-signed certs from the bundle, kept as UNTRUSTED intermediates and
     * handed to X509_STORE_CTX_init at verify time. Only self-signed certs go
     * into ca_store as trusted anchors -- otherwise OpenSSL would treat a bundled
     * intermediate as a root and short-circuit the chain to depth 0, defeating
     * the depth bound (matches Python: only a self-signed root terminates). */
    STACK_OF(X509) *untrusted;
    cert_cache_entry_t cert_cache[CERT_CACHE_SIZE];
    int cert_cache_count;
    bool ocsp_reachable;                /* Last-known OCSP reachability */
    time_t ocsp_reachable_checked_at;   /* When we last probed */
} x509_impl_t;

/* ---------- helpers ---------- */

/**
 * @brief Try to parse credential bytes as X.509, attempting DER then PEM
 */
static X509 *parse_cert(const uint8_t *data, size_t len)
{
    /* Try DER first */
    const unsigned char *p = data;
    X509 *cert = d2i_X509(NULL, &p, (long)len);
    if (cert)
        return cert;

    /* Try PEM */
    if (len > INT_MAX)
        return NULL;
    BIO *bio = BIO_new_mem_buf(data, (int)len);
    if (!bio)
        return NULL;
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

/* Frama-C: skipped — [syscall] OpenSSL EVP signature verification */
bool x509_verify_data_signature(const uint8_t *cert_der, size_t cert_len,
                                const uint8_t *data, size_t data_len,
                                const uint8_t *sig, size_t sig_len)
{
    if (cert_der == NULL || cert_len == 0 || data == NULL || data_len == 0
        || sig == NULL || sig_len == 0)
        return false;

    X509 *cert = parse_cert(cert_der, cert_len);
    if (cert == NULL)
        return false;

    bool ok = false;
    EVP_PKEY *pub = X509_get_pubkey(cert);
    EVP_MD_CTX *ctx = NULL;
    if (pub == NULL)
        goto out;

    /* Only the two key types a PIV/CAC actually carries, and the same pairings
     * Python's verifier uses: RSA => PKCS#1 v1.5, EC => ECDSA, SHA-256 either
     * way. Anything else is refused rather than guessed at — a signature scheme
     * inferred wrongly fails closed here, but silently accepting an unexpected
     * key type is how a verifier ends up verifying nothing. */
    int kind = EVP_PKEY_base_id(pub);
    if (kind != EVP_PKEY_RSA && kind != EVP_PKEY_EC)
        goto out;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) != 1)
        goto out;
    /* One-shot: the pre-image is ~100 bytes, so there is nothing to stream. */
    ok = EVP_DigestVerify(ctx, sig, sig_len, data, data_len) == 1;

out:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    if (pub != NULL)
        EVP_PKEY_free(pub);
    X509_free(cert);
    return ok;
}

/* Frama-C: skipped — [syscall] OpenSSL SAN extension parsing */
bool x509_cert_has_uri_san(const uint8_t *cert_der, size_t cert_len,
                           const char *uri)
{
    if (cert_der == NULL || cert_len == 0 || uri == NULL || uri[0] == '\0')
        return false;
    X509 *cert = parse_cert(cert_der, cert_len);
    if (cert == NULL)
        return false;

    bool found = false;
    GENERAL_NAMES *names = X509_get_ext_d2i(cert, NID_subject_alt_name,
                                            NULL, NULL);
    if (names != NULL) {
        int n = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < n && !found; i++) {
            const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);
            if (gn == NULL || gn->type != GEN_URI)
                continue;
            const unsigned char *val = ASN1_STRING_get0_data(
                gn->d.uniformResourceIdentifier);
            int val_len = ASN1_STRING_length(gn->d.uniformResourceIdentifier);
            if (val == NULL || val_len <= 0)
                continue;
            /* Length-checked rather than strcasecmp: an ASN1_STRING is not
             * required to be NUL-terminated, and one containing an embedded NUL
             * would otherwise compare equal on its prefix — the classic way a
             * SAN check is defeated. */
            if ((size_t)val_len != strlen(uri))
                continue;
            if (strncasecmp((const char *)val, uri, (size_t)val_len) == 0)
                found = true;
        }
        GENERAL_NAMES_free(names);
    }
    X509_free(cert);
    return found;
}

/**
 * @brief Compute SHA-256 of a DER-encoded certificate
 */
static int cert_sha256(X509 *cert, uint8_t hash_out[ZTA_HASH_LEN])
{
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len <= 0)
        return EX509_PARSE;

    unsigned int md_len = 0;
    EVP_Digest(der, (size_t)der_len, hash_out, &md_len, EVP_sha256(), NULL);
    OPENSSL_free(der);
    return (md_len == ZTA_HASH_LEN) ? 0 : EZTA_INTERNAL;
}

/**
 * @brief Get a one-line reason from OpenSSL's verification error
 */
/* Frama-C: skipped — [solver-timeout] OpenSSL error string lookup */
static void openssl_verify_reason(X509_STORE_CTX *ctx, char *reason, size_t reason_len)
{
    int err = X509_STORE_CTX_get_error(ctx);
    snprintf(reason, reason_len, "%s", X509_verify_cert_error_string(err));
}

/* ---------- cert cache ---------- */

/* Frama-C: skipped — [solver-timeout] OpenSSL + map preconditions */
static void _cache_cert(x509_impl_t *impl, X509 *cert, const uint8_t hash[ZTA_HASH_LEN])
{
    /* Check if already cached */
    for (int i = 0; i < impl->cert_cache_count; i++) {
        if (impl->cert_cache[i].valid &&
            memcmp(impl->cert_cache[i].hash, hash, ZTA_HASH_LEN) == 0)
            return;
    }

    /* DER-encode */
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len <= 0)
        return;

    int slot = -1;
    for (int i = 0; i < impl->cert_cache_count; i++) {
        if (!impl->cert_cache[i].valid) { slot = i; break; }
    }
    if (slot < 0) {
        if (impl->cert_cache_count < CERT_CACHE_SIZE)
            slot = impl->cert_cache_count++;
        else {
            /* Evict slot 0 (simple FIFO) */
            slot = 0;
            OPENSSL_free(impl->cert_cache[0].der);
        }
    }

    cert_cache_entry_t *e = &impl->cert_cache[slot];
    memcpy(e->hash, hash, ZTA_HASH_LEN);
    e->der = der;
    e->der_len = der_len;
    e->valid = true;
}

/* Frama-C: skipped — [solver-timeout] map lookup preconditions */
static X509 *_cache_lookup(const x509_impl_t *impl, const uint8_t hash[ZTA_HASH_LEN])
{
    for (int i = 0; i < impl->cert_cache_count; i++) {
        if (impl->cert_cache[i].valid &&
            memcmp(impl->cert_cache[i].hash, hash, ZTA_HASH_LEN) == 0) {
            const unsigned char *p = impl->cert_cache[i].der;
            return d2i_X509(NULL, &p, impl->cert_cache[i].der_len);
        }
    }
    return NULL;
}

/* ---------- OCSP helpers ---------- */

/**
 * @brief Parse a URL into host, port, path components.
 * Caller must free host, port, path with OPENSSL_free.
 */
/* Frama-C: skipped — [solver-timeout] string parsing preconditions */
static int _parse_ocsp_url(const char *url, char **host, char **port,
                           char **path, int *use_ssl)
{
    *host = NULL; *port = NULL; *path = NULL; *use_ssl = 0;

    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) {
        *use_ssl = 1;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else {
        return -1;
    }

    /* Find end of host[:port] */
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    size_t host_len;
    if (colon && (!slash || colon < slash)) {
        host_len = (size_t)(colon - p);
        const char *port_start = colon + 1;
        size_t port_len = slash ? (size_t)(slash - port_start) : strlen(port_start);
        *port = OPENSSL_strndup(port_start, port_len);
    } else {
        host_len = slash ? (size_t)(slash - p) : strlen(p);
        *port = OPENSSL_strdup(*use_ssl ? "443" : "80");
    }

    *host = OPENSSL_strndup(p, host_len);
    *path = OPENSSL_strdup(slash ? slash : "/");
    return 0;
}

/**
 * @brief Perform an OCSP query over HTTP.
 *
 * Connects to the OCSP responder, sends a DER-encoded request as an
 * HTTP POST, and returns the parsed OCSP_RESPONSE.
 *
 * @return OCSP_RESPONSE on success (caller frees), NULL on failure
 */
/* Frama-C: skipped — [solver-timeout] OpenSSL OCSP query preconditions */
static OCSP_RESPONSE *_ocsp_query(const char *url, OCSP_REQUEST *req,
                                  int timeout_ms)
{
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;
    OCSP_RESPONSE *resp = NULL;
    BIO *cbio = NULL;
    SSL_CTX *ssl_ctx = NULL;

    if (_parse_ocsp_url(url, &host, &port, &path, &use_ssl) != 0)
        return NULL;

    /* Build host:port string for BIO_new_connect */
    char host_port[512];
    int hp_written = snprintf(host_port, sizeof(host_port), "%s:%s", host, port);
    if (hp_written < 0 || (size_t)hp_written >= sizeof(host_port))
        goto cleanup;

    cbio = BIO_new_connect(host_port);
    if (!cbio)
        goto cleanup;

    /* Set connection timeout */
    if (timeout_ms > 0) {
        BIO_set_nbio(cbio, 1);
    }

    if (BIO_do_connect(cbio) <= 0) {
        /* For non-blocking, retry with select */
        if (timeout_ms > 0) {
            int fd = BIO_get_fd(cbio, NULL);
            if (fd < 0) goto cleanup;

            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv = {
                .tv_sec = timeout_ms / 1000,
                .tv_usec = (timeout_ms % 1000) * 1000
            };
            if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0)
                goto cleanup;

            /* Switch back to blocking for the HTTP exchange */
            BIO_set_nbio(cbio, 0);
        } else {
            goto cleanup;
        }
    }

    if (use_ssl) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) goto cleanup;
        SSL_CTX_set_default_verify_paths(ssl_ctx);

        BIO *sbio = BIO_new_ssl(ssl_ctx, 1);
        if (!sbio) goto cleanup;
        cbio = BIO_push(sbio, cbio);

        if (BIO_do_handshake(cbio) <= 0)
            goto cleanup;
    }

    /* DER-encode the OCSP request */
    unsigned char *req_der = NULL;
    int req_len = i2d_OCSP_REQUEST(req, &req_der);
    if (req_len <= 0)
        goto cleanup;

    /* Build HTTP POST */
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "POST %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        path, host, req_len);

    if (BIO_write(cbio, header, hlen) != hlen ||
        BIO_write(cbio, req_der, req_len) != req_len) {
        OPENSSL_free(req_der);
        goto cleanup;
    }
    OPENSSL_free(req_der);
    (void)BIO_flush(cbio);

    /* Read HTTP response — skip headers, parse body as OCSP response */
    unsigned char buf[8192];
    int total = 0;
    int n;

    /* Read all available data */
    while ((n = BIO_read(cbio, buf + total,
                         (int)(sizeof(buf) - (size_t)total))) > 0) {
        total += n;
        if ((size_t)total >= sizeof(buf) - 1)
            break;
    }

    if (total <= 0)
        goto cleanup;

    /* Find end of HTTP headers (blank line) */
    unsigned char *body = NULL;
    for (int i = 0; i < total - 3; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n') {
            body = buf + i + 4;
            break;
        }
    }

    if (!body)
        goto cleanup;

    int body_len = total - (int)(body - buf);
    if (body_len <= 0)
        goto cleanup;

    const unsigned char *pp = body;
    resp = d2i_OCSP_RESPONSE(NULL, &pp, body_len);

cleanup:
    BIO_free_all(cbio);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    return resp;
}

/**
 * @brief Get the issuer certificate from the CA store for a given cert.
 * Caller must X509_free the returned issuer.
 */
static X509 *_get_issuer(X509_STORE *store, X509 *cert)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) return NULL;

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        return NULL;
    }

    X509 *issuer = NULL;
    X509_STORE_CTX_get1_issuer(&issuer, ctx, cert);
    X509_STORE_CTX_free(ctx);
    return issuer;
}

/* ---------- vtable implementations ---------- */

/* Frama-C: skipped — [solver-timeout] OpenSSL verify preconditions */
static int x509_verify_credential(zta_verifier_t *self,
                                  const uint8_t *cred_data, size_t cred_len,
                                  zta_result_t *result)
{
    x509_impl_t *impl = (x509_impl_t *)self->impl_data;

    if (!cred_data || cred_len == 0) {
        zta_result_set(result, ZTA_REJECTED, "no credential data");
        return 0;
    }

    X509 *cert = parse_cert(cred_data, cred_len);
    if (!cert) {
        zta_result_set(result, ZTA_REJECTED, "failed to parse X.509 certificate");
        return 0;
    }

    /* Compute hash for identity binding */
    cert_sha256(cert, result->credential_hash);

    /* Check expiry explicitly for distinct status */
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (X509_cmp_current_time(not_after) < 0) {
        uint8_t saved_hash[ZTA_HASH_LEN];
        memcpy(saved_hash, result->credential_hash, ZTA_HASH_LEN);
        zta_result_set(result, ZTA_EXPIRED, "certificate has expired");
        memcpy(result->credential_hash, saved_hash, ZTA_HASH_LEN);
        X509_free(cert);
        return 0;
    }

    /* Verify certificate chain against CA store */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_free(cert);
        zta_result_set(result, ZTA_UNAVAILABLE, "failed to allocate verification context");
        return EZTA_INTERNAL;
    }

    if (X509_STORE_CTX_init(ctx, impl->ca_store, cert, impl->untrusted) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_free(cert);
        zta_result_set(result, ZTA_UNAVAILABLE, "failed to init verification context");
        return EZTA_INTERNAL;
    }

    int verify_rc = X509_verify_cert(ctx);
    if (verify_rc == 1) {
        zta_result_set(result, ZTA_VERIFIED, "certificate chain verified");
        cert_sha256(cert, result->credential_hash);
        /* Cache the cert so check_revocation can retrieve it for OCSP */
        _cache_cert(impl, cert, result->credential_hash);
    } else {
        char reason[ZTA_REASON_LEN];
        openssl_verify_reason(ctx, reason, sizeof(reason));
        zta_result_set(result, ZTA_REJECTED, reason);
        cert_sha256(cert, result->credential_hash);
    }

    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return 0;
}

/**
 * @brief Load a CRL as PEM **or DER** (agency CRLs are normally DER).
 *
 * Only PEM was accepted before, so a DER CRL parsed as nothing and the caller
 * silently proceeded as though no CRL were configured -- revocation checking
 * looked wired up while doing nothing. Python parity: `X509Verifier._load_crl`.
 *
 * @param path      CRL file path.
 * @param readable  Out: whether the file could be opened at all.
 * @return the CRL (caller frees), or NULL.
 */
static X509_CRL *_load_crl_file(const char *path, bool *readable)
{
    *readable = false;
    BIO *bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        ERR_clear_error();
        return NULL;
    }
    *readable = true;
    X509_CRL *crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (crl != NULL)
        return crl;

    ERR_clear_error();
    bio = BIO_new_file(path, "rb");  /* reopen; see _bundle_load_pkcs7 */
    if (bio == NULL) {
        ERR_clear_error();
        return NULL;
    }
    crl = d2i_X509_CRL_bio(bio, NULL);
    BIO_free(bio);
    if (crl == NULL)
        ERR_clear_error();
    return crl;
}

/* Frama-C: skipped — [solver-timeout] OpenSSL + OCSP preconditions */
static int x509_check_revocation(zta_verifier_t *self,
                                 const uint8_t *cred_hash,
                                 zta_result_t *result)
{
    x509_impl_t *impl = (x509_impl_t *)self->impl_data;
    (void)cred_hash;

    /* CRL-based revocation check */
    if (impl->cfg.crl_path[0] != '\0') {
        bool readable = false;
        X509_CRL *crl = _load_crl_file(impl->cfg.crl_path, &readable);
        if (crl == NULL) {
            /* A configured-but-unusable CRL must NOT fall through to the OCSP /
             * "no revocation method configured" tail: that is indistinguishable
             * from having no CRL at all, and is exactly how a DER CRL used to
             * disappear. UNAVAILABLE, never VERIFIED -- a check that cannot run
             * must not read as "not revoked". */
            /* The path is bounded (%.190s) so a long path cannot crowd the
             * explanation out of the fixed reason buffer. */
            char reason[ZTA_REASON_LEN];
            if (readable)
                snprintf(reason, sizeof(reason),
                         "CRL %.190s could not be parsed (expected PEM or DER X.509 CRL)",
                         impl->cfg.crl_path);
            else
                snprintf(reason, sizeof(reason), "CRL %.190s could not be read",
                         impl->cfg.crl_path);
            zta_result_set(result, ZTA_UNAVAILABLE, reason);
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }
        /*
         * Match the previously-verified cert's serial against the CRL,
         * mirroring Python X509Verifier.check_revocation
         * (crl.get_revoked_certificate_by_serial_number). The cert was
         * cached by verify_credential keyed on cred_hash; without it we
         * cannot match a serial, so fall through to "not revoked"
         * (matching Python, whose cache miss likewise yields a non-
         * revoked verdict). This explicit serial match — rather than the
         * old "CRL loaded => reachable" stub — is what lets the admission
         * gate reject a revoked-but-chain-valid cert; pinned cross-impl
         * by conformance zta-x509-reject-revoked-credential.
         */
        X509 *cert = _cache_lookup(impl, cred_hash);
        bool revoked = false;
        if (cert != NULL) {
            X509_REVOKED *rev = NULL;
            if (X509_CRL_get0_by_cert(crl, &rev, cert) == 1)
                revoked = true;
            X509_free(cert);
        }
        X509_CRL_free(crl);
        if (revoked) {
            zta_result_set(result, ZTA_REVOKED, "certificate revoked (CRL)");
        } else {
            zta_result_set(result, ZTA_VERIFIED, "CRL loaded; not revoked");
        }
        memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
        return 0;
    }

    /* OCSP-based revocation check */
    if (impl->cfg.ocsp_url[0] != '\0') {
        /* Retrieve the cached certificate (needed for OCSP request) */
        X509 *cert = _cache_lookup(impl, cred_hash);
        if (!cert) {
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP: certificate not in cache (verify first)");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        /* Get issuer from CA store */
        X509 *issuer = _get_issuer(impl->ca_store, cert);
        if (!issuer) {
            X509_free(cert);
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP: issuer certificate not found in CA store");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        /* Build OCSP request */
        OCSP_REQUEST *ocsp_req = OCSP_REQUEST_new();
        if (!ocsp_req) {
            X509_free(cert);
            X509_free(issuer);
            zta_result_set(result, ZTA_UNAVAILABLE, "OCSP: failed to create request");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        OCSP_CERTID *cid = OCSP_cert_to_id(EVP_sha256(), cert, issuer);
        if (!cid) {
            OCSP_REQUEST_free(ocsp_req);
            X509_free(cert);
            X509_free(issuer);
            zta_result_set(result, ZTA_UNAVAILABLE, "OCSP: failed to create cert ID");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }
        OCSP_request_add0_id(ocsp_req, cid);  /* req takes ownership of cid */

        /* Send OCSP query */
        int timeout = impl->cfg.connect_timeout_ms > 0
                      ? impl->cfg.connect_timeout_ms : 2000;
        OCSP_RESPONSE *ocsp_resp = _ocsp_query(impl->cfg.ocsp_url, ocsp_req,
                                               timeout);
        OCSP_REQUEST_free(ocsp_req);

        if (!ocsp_resp) {
            impl->ocsp_reachable = false;
            impl->ocsp_reachable_checked_at = time(NULL);
            X509_free(cert);
            X509_free(issuer);
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP responder unreachable");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        /* Mark OCSP as reachable */
        impl->ocsp_reachable = true;
        impl->ocsp_reachable_checked_at = time(NULL);

        int resp_status = OCSP_response_status(ocsp_resp);
        if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            OCSP_RESPONSE_free(ocsp_resp);
            X509_free(cert);
            X509_free(issuer);
            char reason[ZTA_REASON_LEN];
            snprintf(reason, sizeof(reason),
                     "OCSP responder error (status %d)", resp_status);
            zta_result_set(result, ZTA_UNAVAILABLE, reason);
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        OCSP_BASICRESP *basic = OCSP_response_get1_basic(ocsp_resp);
        OCSP_RESPONSE_free(ocsp_resp);

        if (!basic) {
            X509_free(cert);
            X509_free(issuer);
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP: failed to parse basic response");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }

        /* Look up the status for our cert.  lookup_id is freed once per
         * control-flow path: in the error branch below (before return 0),
         * OR in the success branch after the if.  Not a double-free. */
        OCSP_CERTID *lookup_id = OCSP_cert_to_id(EVP_sha256(), cert, issuer);
        int cert_status = -1, revoke_reason = 0;
        ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
        if (OCSP_resp_find_status(basic, lookup_id, &cert_status,
                                  &revoke_reason, &revtime,
                                  &thisupd, &nextupd) != 1) {
            OCSP_CERTID_free(lookup_id);
            OCSP_BASICRESP_free(basic);
            X509_free(cert);
            X509_free(issuer);
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP: certificate not found in response");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }
        OCSP_CERTID_free(lookup_id);
        OCSP_BASICRESP_free(basic);
        X509_free(cert);
        X509_free(issuer);

        memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);

        switch (cert_status) {
        case V_OCSP_CERTSTATUS_GOOD:
            zta_result_set(result, ZTA_VERIFIED, "OCSP: certificate is good");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        case V_OCSP_CERTSTATUS_REVOKED:
            zta_result_set(result, ZTA_REVOKED, "OCSP: certificate is revoked");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        default:
            zta_result_set(result, ZTA_UNAVAILABLE,
                           "OCSP: certificate status unknown");
            memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
            return 0;
        }
    }

    zta_result_set(result, ZTA_UNAVAILABLE,
                   "no revocation check method configured (no CRL path, no OCSP URL)");
    memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] OpenSSL availability check */
static bool x509_is_available(zta_verifier_t *self)
{
    x509_impl_t *impl = (x509_impl_t *)self->impl_data;
    /* The CA store is always local, so chain verification is always available.
     * Revocation checking availability depends on CRL/OCSP reachability. */
    if (impl->cfg.crl_path[0] != '\0') {
        FILE *fp = fopen(impl->cfg.crl_path, "r");
        if (fp) {
            fclose(fp);
            return true;
        }
    }
    if (impl->cfg.ocsp_url[0] != '\0') {
        /* Use cached reachability if checked within the last 60 seconds */
        time_t now = time(NULL);
        if (impl->ocsp_reachable_checked_at > 0 &&
            (now - impl->ocsp_reachable_checked_at) < 60)
            return impl->ocsp_reachable;
        /* No recent probe — assume unavailable until next check_revocation */
        return false;
    }
    /* No revocation method configured; chain verification is still available */
    return true;
}

/* Frama-C: skipped — [solver-timeout] OpenSSL hash preconditions */
static int x509_credential_hash(zta_verifier_t *self,
                                const uint8_t *cred_data, size_t cred_len,
                                uint8_t hash_out[ZTA_HASH_LEN])
{
    (void)self;
    if (!cred_data || cred_len == 0) {
        memset(hash_out, 0, ZTA_HASH_LEN);
        return EZTA_NOCRED;
    }

    X509 *cert = parse_cert(cred_data, cred_len);
    if (!cert) {
        memset(hash_out, 0, ZTA_HASH_LEN);
        return EX509_PARSE;
    }

    int rc = cert_sha256(cert, hash_out);
    X509_free(cert);
    return rc;
}

/* Frama-C: skipped — [solver-timeout] OpenSSL cleanup preconditions */
static void x509_destroy(zta_verifier_t *self)
{
    if (!self)
        return;
    x509_impl_t *impl = (x509_impl_t *)self->impl_data;
    if (impl) {
        /* Free cached certificates */
        for (int i = 0; i < impl->cert_cache_count; i++) {
            if (impl->cert_cache[i].valid && impl->cert_cache[i].der)
                OPENSSL_free(impl->cert_cache[i].der);
        }
        if (impl->untrusted)
            sk_X509_pop_free(impl->untrusted, X509_free);
        if (impl->ca_store)
            X509_STORE_free(impl->ca_store);
        free(impl);
    }
    free(self);
}

/* ---------- CA bundle loading ---------- */

/**
 * @brief File a bundle certificate as a trusted anchor or an intermediate.
 *
 * Self-signed goes into the store as a trust anchor; everything else onto the
 * untrusted stack, so X509_STORE_set_depth actually bounds intermediates (see
 * the constructor's comment). Consumes the caller's reference to @p c.
 */
static void _bundle_add_cert(X509_STORE *store, STACK_OF(X509) **untrusted,
                             X509 *c)
{
    if (X509_NAME_cmp(X509_get_subject_name(c), X509_get_issuer_name(c)) == 0) {
        X509_STORE_add_cert(store, c);  /* ups its own ref */
        X509_free(c);
    } else {
        if (*untrusted == NULL)
            *untrusted = sk_X509_new_null();
        if (*untrusted != NULL)
            sk_X509_push(*untrusted, c); /* stack takes our ref */
        else
            X509_free(c);
    }
}

/**
 * @brief Load the certificates from a PKCS#7 bundle (.p7b/.p7c), DER or PEM.
 *
 * PKCS#7 is the format agency PKI (incl. DoD) ships chains in; without this the
 * bundle had to be converted with `openssl pkcs7 -print_certs` out of band, and
 * an unconverted .p7b failed as a corrupt bundle. Python parity:
 * `X509Verifier._load_bundle_certs`.
 *
 * @return number of certificates filed into the store/untrusted stack.
 */
static int _bundle_load_pkcs7(X509_STORE *store, STACK_OF(X509) **untrusted,
                              const char *path)
{
    PKCS7 *p7 = NULL;
    BIO *bio = BIO_new_file(path, "rb");
    if (bio != NULL) {
        p7 = d2i_PKCS7_bio(bio, NULL);
        BIO_free(bio);
    }
    if (p7 == NULL) {
        /* Not DER; a PEM-wrapped ("-----BEGIN PKCS7-----") container is also
         * issued in practice. Reopen rather than BIO_reset: file-BIO reset
         * semantics differ from the usual 1-on-success convention. */
        ERR_clear_error();
        bio = BIO_new_file(path, "r");
        if (bio != NULL) {
            p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    }
    if (p7 == NULL) {
        ERR_clear_error();
        return 0;
    }

    STACK_OF(X509) *certs = NULL;
    int type = OBJ_obj2nid(p7->type);
    if (type == NID_pkcs7_signed && p7->d.sign != NULL)
        certs = p7->d.sign->cert;
    else if (type == NID_pkcs7_signedAndEnveloped &&
             p7->d.signed_and_enveloped != NULL)
        certs = p7->d.signed_and_enveloped->cert;

    int added = 0;
    int count = (certs != NULL) ? sk_X509_num(certs) : 0;
    for (int i = 0; i < count; i++) {
        X509 *c = sk_X509_value(certs, i);
        if (c == NULL)
            continue;
        /* The stack belongs to p7; take our own ref before handing it on. */
        if (X509_up_ref(c) != 1)
            continue;
        _bundle_add_cert(store, untrusted, c);
        added++;
    }
    PKCS7_free(p7);
    return added;
}

/* Never prompt for a passphrase while probing a file's kind. */
static int _no_password_cb(char *buf, int size, int rwflag, void *u)
{
    (void)buf; (void)size; (void)rwflag; (void)u;
    return 0;
}

/**
 * @brief Whether the bundle path holds an identifiable non-certificate object.
 *
 * A CRL, CSR, or private key handed to ca_bundle_path is a configuration mix-up,
 * worth EX509_CAKIND rather than the generic "failed to load" -- the same
 * distinction Python draws in `_classify_bundle`. Best-effort: an encrypted key
 * is not identified (we never prompt), and simply falls back to EX509_CALOAD.
 */
static bool _bundle_wrong_kind(const char *path)
{
    bool wrong = false;
    BIO *bio;

    if ((bio = BIO_new_file(path, "r")) != NULL) {
        X509_CRL *crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (crl != NULL) { X509_CRL_free(crl); wrong = true; }
    }
    if (!wrong && (bio = BIO_new_file(path, "rb")) != NULL) {
        X509_CRL *crl = d2i_X509_CRL_bio(bio, NULL);
        BIO_free(bio);
        if (crl != NULL) { X509_CRL_free(crl); wrong = true; }
    }
    if (!wrong && (bio = BIO_new_file(path, "r")) != NULL) {
        X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (req != NULL) { X509_REQ_free(req); wrong = true; }
    }
    if (!wrong && (bio = BIO_new_file(path, "r")) != NULL) {
        EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, _no_password_cb, NULL);
        BIO_free(bio);
        if (key != NULL) { EVP_PKEY_free(key); wrong = true; }
    }
    ERR_clear_error();  /* probing failures are expected; don't leak them */
    return wrong;
}

/* ---------- constructor ---------- */

/* Frama-C: skipped — [solver-timeout] OpenSSL init + allocation */
int x509_verifier_create(const x509_verifier_config_t *cfg,
                         zta_verifier_t **out)
{
    if (!cfg || !out)
        return EZTA_INTERNAL;

    /* Build CA store from bundle */
    X509_STORE *store = X509_STORE_new();
    if (!store)
        return EX509_CALOAD;

    /* Bound the chain depth (max intermediate CAs) so a pathologically deep
     * chain is rejected -- C parity with Python _MAX_CHAIN_DEPTH. */
    X509_STORE_set_depth(store, AT_X509_MAX_CHAIN_DEPTH);

    STACK_OF(X509) *untrusted = NULL;
    if (cfg->ca_bundle_path[0] != '\0') {
        /* Load the bundle cert-by-cert, classifying self-signed certs as trusted
         * roots (into the store) and the rest as UNTRUSTED intermediates. If we
         * instead trusted every bundled cert (X509_STORE_load_locations), OpenSSL
         * would treat a bundled intermediate as a valid anchor and the chain
         * would verify at depth 0, making set_depth a no-op. Falls back to the
         * bulk load for a directory / non-PEM path (no intermediates to bound).*/
        BIO *bio = BIO_new_file(cfg->ca_bundle_path, "r");
        int loaded = 0;
        if (bio != NULL) {
            X509 *c = NULL;
            while ((c = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
                loaded++;
                _bundle_add_cert(store, &untrusted, c);
            }
            BIO_free(bio);
            ERR_clear_error();  /* the loop always ends on a read failure */
        }
        if (loaded == 0) {
            /* A single DER certificate: the bulk loader below is PEM-only, so
             * without this a DER bundle failed (Python accepts one). */
            BIO *dbio = BIO_new_file(cfg->ca_bundle_path, "rb");
            if (dbio != NULL) {
                X509 *dc = d2i_X509_bio(dbio, NULL);
                BIO_free(dbio);
                if (dc != NULL) {
                    _bundle_add_cert(store, &untrusted, dc);
                    loaded = 1;
                } else {
                    ERR_clear_error();
                }
            }
        }
        if (loaded == 0) {
            /* PKCS#7 (.p7b) before the bulk loader, which does not understand it */
            loaded = _bundle_load_pkcs7(store, &untrusted, cfg->ca_bundle_path);
        }
        if (loaded == 0) {
            /* directory bundle: fall back to the bulk loader */
            bool bulk_ok =
                X509_STORE_load_locations(store, cfg->ca_bundle_path, NULL) == 1;
            if (bulk_ok) {
                /* load_locations reports success even when the file yielded no
                 * *certificates*, leaving a trust store in which nothing can ever
                 * verify -- the same silent-empty-store trap Python's
                 * bundle_error closes. Count certs specifically: it loads a PEM
                 * file's CRLs as well, so a CRL handed to this slot otherwise
                 * looks like a successful load with zero anchors. */
                STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
                int n_certs = 0;
                for (int i = 0; objs != NULL && i < sk_X509_OBJECT_num(objs); i++) {
                    X509_OBJECT *o = sk_X509_OBJECT_value(objs, i);
                    if (o != NULL && X509_OBJECT_get_type(o) == X509_LU_X509)
                        n_certs++;
                }
                if (n_certs == 0)
                    bulk_ok = false;
            }
            if (!bulk_ok) {
                /* Distinguish a wrong-kind file from an unreadable one, so a CRL
                 * or key in this slot is diagnosable (Python parity: the reject
                 * reason names it). */
                int err = _bundle_wrong_kind(cfg->ca_bundle_path)
                          ? EX509_CAKIND : EX509_CALOAD;
                ERR_clear_error();
                if (untrusted != NULL) sk_X509_pop_free(untrusted, X509_free);
                X509_STORE_free(store);
                return err;
            }
        }
    } else {
        /* Use system default CA paths */
        if (X509_STORE_set_default_paths(store) != 1) {
            X509_STORE_free(store);
            return EX509_CALOAD;
        }
    }

    x509_impl_t *impl = calloc(1, sizeof(x509_impl_t));
    if (!impl) {
        if (untrusted != NULL) sk_X509_pop_free(untrusted, X509_free);
        X509_STORE_free(store);
        return EZTA_INTERNAL;
    }
    memcpy(&impl->cfg, cfg, sizeof(x509_verifier_config_t));
    impl->ca_store = store;
    impl->untrusted = untrusted;

    zta_verifier_t *v = calloc(1, sizeof(zta_verifier_t));
    if (!v) {
        if (untrusted != NULL) sk_X509_pop_free(untrusted, X509_free);
        X509_STORE_free(store);
        free(impl);
        return EZTA_INTERNAL;
    }

    v->verify_credential = x509_verify_credential;
    v->check_revocation  = x509_check_revocation;
    v->is_available      = x509_is_available;
    v->credential_hash   = x509_credential_hash;
    v->destroy           = x509_destroy;
    v->impl_data         = impl;

    *out = v;
    return 0;
}
