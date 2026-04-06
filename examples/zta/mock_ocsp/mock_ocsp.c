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

/**
 * mock_ocsp.c — Mock OCSP responder for ZTA demo.
 *
 * A lightweight HTTP server that speaks real OCSP protocol (DER-encoded
 * requests/responses) using OpenSSL's OCSP API:
 *
 *   POST /          — DER OCSP request → DER OCSP response
 *
 * Control endpoints (JSON, for test orchestration):
 *   POST /control/revoke/<hex_serial>   — mark serial as revoked
 *   POST /control/unrevoke/<hex_serial> — remove revocation
 *   POST /control/shutdown              — graceful exit
 *   GET  /control/status                — list revoked serials
 *
 * Requires:
 *   - CA cert (--ca-cert) and CA key (--ca-key) for signing responses
 *   - Responder cert (--resp-cert) and key (--resp-key) — optional,
 *     defaults to CA cert/key
 *
 * Usage:
 *   mock_ocsp -p 8888 --ca-cert ca.pem --ca-key ca.key
 *
 * Build:
 *   gcc -o mock_ocsp mock_ocsp.c -Wall -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define DEFAULT_PORT 8888
#define MAX_REVOKED 256
#define SERIAL_HEX_LEN 64
#define BUF_SIZE 65536

/* ---------- state ---------- */

static volatile sig_atomic_t g_running = 1;
static char g_revoked[MAX_REVOKED][SERIAL_HEX_LEN + 1];
static int g_revoked_count = 0;
static int g_port = DEFAULT_PORT;
static X509 *g_ca_cert = NULL;
static EVP_PKEY *g_ca_key = NULL;
static X509 *g_resp_cert = NULL;  /* responder cert (defaults to CA cert) */
static EVP_PKEY *g_resp_key = NULL;

static void sig_handler(int sig) { (void)sig; g_running = 0; }

/* ---------- revocation list ---------- */

static bool is_revoked_serial(const char *serial_hex)
{
    for (int i = 0; i < g_revoked_count; i++) {
        if (strcasecmp(g_revoked[i], serial_hex) == 0)
            return true;
    }
    return false;
}

static bool is_revoked_asn1(ASN1_INTEGER *serial)
{
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) return false;
    char *hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex) return false;
    bool result = is_revoked_serial(hex);
    OPENSSL_free(hex);
    return result;
}

static void add_revoked(const char *serial)
{
    if (g_revoked_count >= MAX_REVOKED) return;
    if (is_revoked_serial(serial)) return;
    snprintf(g_revoked[g_revoked_count], SERIAL_HEX_LEN, "%s", serial);
    g_revoked_count++;
    printf("mock_ocsp: revoked serial %s\n", serial);
}

static void remove_revoked(const char *serial)
{
    for (int i = 0; i < g_revoked_count; i++) {
        if (strcasecmp(g_revoked[i], serial) == 0) {
            if (i < g_revoked_count - 1)
                strncpy(g_revoked[i], g_revoked[g_revoked_count - 1], SERIAL_HEX_LEN);
            g_revoked_count--;
            printf("mock_ocsp: unrevoked serial %s\n", serial);
            return;
        }
    }
}

/* ---------- HTTP helpers ---------- */

static void send_http(int fd, int status, const char *content_type,
                      const unsigned char *body, int body_len)
{
    const char *status_text = (status == 200) ? "OK" : "Not Found";
    char header[512];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.0 %d %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: close\r\n\r\n",
                        status, status_text, content_type, body_len);
    write(fd, header, hlen);
    if (body_len > 0)
        write(fd, body, body_len);
}

static void send_json(int fd, int status, const char *json)
{
    send_http(fd, status, "application/json",
              (const unsigned char *)json, (int)strlen(json));
}

static bool starts_with(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* ---------- OCSP response builder ---------- */

static void handle_ocsp_request(int client_fd, const unsigned char *body, int body_len)
{
    const unsigned char *p = body;
    OCSP_REQUEST *req = d2i_OCSP_REQUEST(NULL, &p, body_len);
    if (!req) {
        fprintf(stderr, "mock_ocsp: failed to parse OCSP request\n");
        send_json(client_fd, 400, "{\"error\":\"bad OCSP request\"}\n");
        return;
    }

    OCSP_BASICRESP *basic = OCSP_BASICRESP_new();
    if (!basic) {
        OCSP_REQUEST_free(req);
        send_json(client_fd, 500, "{\"error\":\"internal error\"}\n");
        return;
    }

    /* Process each single-request in the OCSP request */
    int count = OCSP_request_onereq_count(req);
    for (int i = 0; i < count; i++) {
        OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, i);
        OCSP_CERTID *cid = OCSP_onereq_get0_id(one);

        /* Extract serial to check revocation */
        ASN1_INTEGER *serial = NULL;
        ASN1_OCTET_STRING *name_hash = NULL;
        ASN1_OCTET_STRING *key_hash = NULL;
        ASN1_OBJECT *hash_alg = NULL;
        OCSP_id_get0_info(&name_hash, &hash_alg, &key_hash, &serial, cid);

        int cert_status;
        if (serial && is_revoked_asn1(serial)) {
            cert_status = V_OCSP_CERTSTATUS_REVOKED;
        } else {
            cert_status = V_OCSP_CERTSTATUS_GOOD;
        }

        /* Build the single response */
        OCSP_CERTID *resp_cid = OCSP_CERTID_dup(cid);
        ASN1_TIME *thisupd = X509_gmtime_adj(NULL, 0);
        ASN1_TIME *nextupd = X509_gmtime_adj(NULL, 3600);

        if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
            ASN1_TIME *revtime = X509_gmtime_adj(NULL, -60);
            OCSP_basic_add1_status(basic, resp_cid, cert_status,
                                   OCSP_REVOKED_STATUS_UNSPECIFIED,
                                   revtime, thisupd, nextupd);
            ASN1_TIME_free(revtime);
        } else {
            OCSP_basic_add1_status(basic, resp_cid, cert_status,
                                   0, NULL, thisupd, nextupd);
        }

        ASN1_TIME_free(thisupd);
        ASN1_TIME_free(nextupd);
        OCSP_CERTID_free(resp_cid);
    }

    /* Sign the basic response */
    X509 *signer = g_resp_cert ? g_resp_cert : g_ca_cert;
    EVP_PKEY *signer_key = g_resp_key ? g_resp_key : g_ca_key;
    OCSP_basic_sign(basic, signer, signer_key, EVP_sha256(), NULL, 0);

    /* Wrap in OCSP_RESPONSE */
    OCSP_RESPONSE *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    OCSP_BASICRESP_free(basic);
    OCSP_REQUEST_free(req);

    if (!resp) {
        send_json(client_fd, 500, "{\"error\":\"failed to create response\"}\n");
        return;
    }

    /* DER-encode and send */
    unsigned char *resp_der = NULL;
    int resp_len = i2d_OCSP_RESPONSE(resp, &resp_der);
    OCSP_RESPONSE_free(resp);

    if (resp_len <= 0) {
        send_json(client_fd, 500, "{\"error\":\"failed to encode response\"}\n");
        return;
    }

    send_http(client_fd, 200, "application/ocsp-response", resp_der, resp_len);
    OPENSSL_free(resp_der);
}

/* ---------- request handling ---------- */

static void handle_request(int client_fd, const char *request, int request_len)
{
    char method[8] = {0}, path[256] = {0};
    sscanf(request, "%7s %255s", method, path);

    /* Real OCSP request (POST to / with application/ocsp-request) */
    if (strcmp(method, "POST") == 0 &&
        (strcmp(path, "/") == 0 || strcmp(path, "/ocsp") == 0)) {
        /* Find body after HTTP headers */
        const char *body_start = strstr(request, "\r\n\r\n");
        if (!body_start) {
            send_json(client_fd, 400, "{\"error\":\"no body\"}\n");
            return;
        }
        body_start += 4;
        int body_len = request_len - (int)(body_start - request);
        if (body_len > 0) {
            handle_ocsp_request(client_fd, (const unsigned char *)body_start,
                                body_len);
        } else {
            send_json(client_fd, 400, "{\"error\":\"empty body\"}\n");
        }
        return;
    }

    /* Control: revoke */
    if (strcmp(method, "POST") == 0 && starts_with(path, "/control/revoke/")) {
        const char *serial = path + 16;
        add_revoked(serial);
        char body[128];
        snprintf(body, sizeof(body),
                 "{\"action\":\"revoked\",\"serial\":\"%s\"}\n", serial);
        send_json(client_fd, 200, body);
        return;
    }

    /* Control: unrevoke */
    if (strcmp(method, "POST") == 0 && starts_with(path, "/control/unrevoke/")) {
        const char *serial = path + 18;
        remove_revoked(serial);
        char body[128];
        snprintf(body, sizeof(body),
                 "{\"action\":\"unrevoked\",\"serial\":\"%s\"}\n", serial);
        send_json(client_fd, 200, body);
        return;
    }

    /* Control: shutdown */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/control/shutdown") == 0) {
        send_json(client_fd, 200, "{\"action\":\"shutting_down\"}\n");
        g_running = 0;
        return;
    }

    /* Control: status */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/control/status") == 0) {
        char body[4096] = "{\"revoked\":[";
        size_t pos = strlen(body);
        for (int i = 0; i < g_revoked_count; i++) {
            if (i > 0) body[pos++] = ',';
            pos += snprintf(body + pos, sizeof(body) - pos,
                            "\"%s\"", g_revoked[i]);
        }
        snprintf(body + pos, sizeof(body) - pos,
                 "],\"count\":%d}\n", g_revoked_count);
        send_json(client_fd, 200, body);
        return;
    }

    send_json(client_fd, 404, "{\"error\":\"not found\"}\n");
}

/* ---------- PEM loading ---------- */

static X509 *load_cert(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { perror(path); return NULL; }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

static EVP_PKEY *load_key(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { perror(path); return NULL; }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

/* ---------- main ---------- */

int main(int argc, char *argv[])
{
    const char *ca_cert_path = NULL;
    const char *ca_key_path = NULL;
    const char *resp_cert_path = NULL;
    const char *resp_key_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            g_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc)
            ca_cert_path = argv[++i];
        else if (strcmp(argv[i], "--ca-key") == 0 && i + 1 < argc)
            ca_key_path = argv[++i];
        else if (strcmp(argv[i], "--resp-cert") == 0 && i + 1 < argc)
            resp_cert_path = argv[++i];
        else if (strcmp(argv[i], "--resp-key") == 0 && i + 1 < argc)
            resp_key_path = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "Usage: %s -p PORT --ca-cert CA.pem --ca-key CA.key "
                    "[--resp-cert RESP.pem --resp-key RESP.key]\n", argv[0]);
            return 0;
        }
    }

    if (!ca_cert_path || !ca_key_path) {
        fprintf(stderr, "mock_ocsp: --ca-cert and --ca-key are required\n");
        return 1;
    }

    g_ca_cert = load_cert(ca_cert_path);
    g_ca_key = load_key(ca_key_path);
    if (!g_ca_cert || !g_ca_key) {
        fprintf(stderr, "mock_ocsp: failed to load CA cert/key\n");
        return 1;
    }

    if (resp_cert_path && resp_key_path) {
        g_resp_cert = load_cert(resp_cert_path);
        g_resp_key = load_key(resp_key_path);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_fd); return 1;
    }
    if (listen(server_fd, 8) < 0) {
        perror("listen"); close(server_fd); return 1;
    }

    printf("mock_ocsp: listening on port %d (real OCSP DER protocol)\n", g_port);

    while (g_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        if (select(server_fd + 1, &readfds, NULL, NULL, &tv) <= 0)
            continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept"); continue;
        }

        char buf[BUF_SIZE] = {0};
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0)
            handle_request(client_fd, buf, (int)n);

        close(client_fd);
    }

    close(server_fd);
    X509_free(g_ca_cert);
    EVP_PKEY_free(g_ca_key);
    if (g_resp_cert) X509_free(g_resp_cert);
    if (g_resp_key) EVP_PKEY_free(g_resp_key);
    printf("mock_ocsp: shutdown\n");
    return 0;
}
