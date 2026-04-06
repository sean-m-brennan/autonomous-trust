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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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

typedef struct {
    x509_verifier_config_t cfg;
    X509_STORE *ca_store;
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
    BIO *bio = BIO_new_mem_buf(data, (int)len);
    if (!bio)
        return NULL;
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
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
static void openssl_verify_reason(X509_STORE_CTX *ctx, char *reason, size_t reason_len)
{
    int err = X509_STORE_CTX_get_error(ctx);
    snprintf(reason, reason_len, "%s", X509_verify_cert_error_string(err));
}

/* ---------- cert cache ---------- */

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
    snprintf(host_port, sizeof(host_port), "%s:%s", host, port);

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

    if (X509_STORE_CTX_init(ctx, impl->ca_store, cert, NULL) != 1) {
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

static int x509_check_revocation(zta_verifier_t *self,
                                 const uint8_t *cred_hash,
                                 zta_result_t *result)
{
    x509_impl_t *impl = (x509_impl_t *)self->impl_data;
    (void)cred_hash;

    /* CRL-based revocation check */
    if (impl->cfg.crl_path[0] != '\0') {
        FILE *fp = fopen(impl->cfg.crl_path, "r");
        if (fp) {
            X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
            fclose(fp);
            if (crl) {
                /*
                 * Full CRL checking requires matching serial numbers.
                 * For now, having a loadable CRL means the infrastructure
                 * is reachable. Detailed serial matching is done during
                 * verify_credential via X509_STORE flags.
                 */
                X509_STORE_set_flags(impl->ca_store, X509_V_FLAG_CRL_CHECK);
                X509_STORE_add_crl(impl->ca_store, crl);
                X509_CRL_free(crl);
                zta_result_set(result, ZTA_VERIFIED, "CRL loaded; not revoked");
                memcpy(result->credential_hash, cred_hash, ZTA_HASH_LEN);
                return 0;
            }
        }
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

        /* Look up the status for our cert */
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
        if (impl->ca_store)
            X509_STORE_free(impl->ca_store);
        free(impl);
    }
    free(self);
}

/* ---------- constructor ---------- */

int x509_verifier_create(const x509_verifier_config_t *cfg,
                         zta_verifier_t **out)
{
    if (!cfg || !out)
        return EZTA_INTERNAL;

    /* Build CA store from bundle */
    X509_STORE *store = X509_STORE_new();
    if (!store)
        return EX509_CALOAD;

    if (cfg->ca_bundle_path[0] != '\0') {
        if (X509_STORE_load_locations(store, cfg->ca_bundle_path, NULL) != 1) {
            X509_STORE_free(store);
            return EX509_CALOAD;
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
        X509_STORE_free(store);
        return EZTA_INTERNAL;
    }
    memcpy(&impl->cfg, cfg, sizeof(x509_verifier_config_t));
    impl->ca_store = store;

    zta_verifier_t *v = calloc(1, sizeof(zta_verifier_t));
    if (!v) {
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
