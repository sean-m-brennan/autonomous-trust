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

#include "identity/cosign.h"
#include "utilities/msg_types.h"

#include <string.h>

/* The bounds are spelled once per header (self-contained, like the DM and
 * profile bounds); a drift between them would corrupt the app-boundary buffer,
 * so tie them here where both are visible. */
_Static_assert(AT_COSIGN_BYTES_MAX == AT_COSIGN_BYTES_LEN,
               "AT_COSIGN_BYTES_MAX (cosign.h) out of sync with AT_COSIGN_BYTES_LEN (msg_types.h)");
_Static_assert(AT_COSIGN_DID_MAX == AT_COSIGN_DID_LEN,
               "AT_COSIGN_DID_MAX (cosign.h) out of sync with AT_COSIGN_DID_LEN (msg_types.h)");
_Static_assert(AT_COSIGN_CID_MAX == AT_COSIGN_CID_LEN,
               "AT_COSIGN_CID_MAX (cosign.h) out of sync with AT_COSIGN_CID_LEN (msg_types.h)");
_Static_assert(AT_COSIGN_SIG_MAX == AT_COSIGN_SIG_LEN,
               "AT_COSIGN_SIG_MAX (cosign.h) out of sync with AT_COSIGN_SIG_LEN (msg_types.h)");
_Static_assert(AT_COSIGN_TOKEN_MAX == AT_COSIGN_TOKEN_LEN,
               "AT_COSIGN_TOKEN_MAX (cosign.h) out of sync with AT_COSIGN_TOKEN_LEN (msg_types.h)");

size_t at_cosign_bound(const char *in, char *out, size_t out_sz, size_t max)
{
    if (out == NULL || out_sz == 0) return 0;
    if (in == NULL) { out[0] = '\0'; return 0; }
    size_t cap = max;
    if (out_sz - 1 < cap) cap = out_sz - 1;
    size_t n = strnlen(in, cap);
    memcpy(out, in, n);
    out[n] = '\0';
    return n;
}

bool at_cosign_bytes_ok(const char *s)
{
    if (s == NULL) return false;
    size_t n = strnlen(s, (size_t)AT_COSIGN_BYTES_MAX + 1);
    /* Over the bound, empty, or an odd count: never something an exporter
     * produced. Carrying it would hand the app a payload that reproduces to
     * nothing, which is worse than refusing the ask. */
    if (n == 0 || n > (size_t)AT_COSIGN_BYTES_MAX || (n % 2) != 0) return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool at_cosign_op_ok(const char *record, const char *op)
{
    if (record == NULL || op == NULL) return false;
    if (strcmp(record, "membership") == 0) {
        /* A voluntary departure is self-signed by the one person leaving, so it
         * needs no exchange and is deliberately not offered here. */
        return strcmp(op, "admit") == 0 || strcmp(op, "expel") == 0;
    }
    if (strcmp(record, "guardian") == 0) {
        return strcmp(op, "designate") == 0 || strcmp(op, "rotate") == 0
            || strcmp(op, "release") == 0;
    }
    return false;
}

json_t *at_cosign_request_to_json(const char *record, const char *op,
                                  const char *polity, const char *cid,
                                  const char *bytes, int64_t seq, double ts)
{
    char r[AT_COSIGN_TOKEN_MAX + 1], o[AT_COSIGN_TOKEN_MAX + 1];
    char p[AT_COSIGN_DID_MAX + 1], c[AT_COSIGN_CID_MAX + 1];
    at_cosign_bound(record, r, sizeof(r), AT_COSIGN_TOKEN_MAX);
    at_cosign_bound(op, o, sizeof(o), AT_COSIGN_TOKEN_MAX);
    at_cosign_bound(polity, p, sizeof(p), AT_COSIGN_DID_MAX);
    at_cosign_bound(cid, c, sizeof(c), AT_COSIGN_CID_MAX);
    if (!at_cosign_op_ok(r, o) || !at_cosign_bytes_ok(bytes) || c[0] == '\0')
        return NULL;
    json_t *env = json_object();
    if (env == NULL) return NULL;
    if (json_object_set_new(env, "record", json_string(r)) != 0
        || json_object_set_new(env, "op", json_string(o)) != 0
        || json_object_set_new(env, "polity", json_string(p)) != 0
        || json_object_set_new(env, "cid", json_string(c)) != 0
        || json_object_set_new(env, "bytes", json_string(bytes)) != 0
        || json_object_set_new(env, "seq", json_integer((json_int_t)seq)) != 0
        || json_object_set_new(env, "ts", json_real(ts)) != 0) {
        json_decref(env);
        return NULL;
    }
    return env;
}

int at_cosign_request_from_json(const json_t *obj,
                                char *record_out, size_t record_sz,
                                char *op_out, size_t op_sz,
                                char *polity_out, size_t polity_sz,
                                char *cid_out, size_t cid_sz,
                                char *bytes_out, size_t bytes_sz,
                                int64_t *seq_out, double *ts_out)
{
    if (record_out != NULL && record_sz > 0) record_out[0] = '\0';
    if (op_out != NULL && op_sz > 0) op_out[0] = '\0';
    if (polity_out != NULL && polity_sz > 0) polity_out[0] = '\0';
    if (cid_out != NULL && cid_sz > 0) cid_out[0] = '\0';
    if (bytes_out != NULL && bytes_sz > 0) bytes_out[0] = '\0';
    if (obj == NULL || !json_is_object(obj)) return -1;
    const json_t *j_record = json_object_get(obj, "record");
    const json_t *j_op     = json_object_get(obj, "op");
    const json_t *j_polity = json_object_get(obj, "polity");
    const json_t *j_cid    = json_object_get(obj, "cid");
    const json_t *j_bytes  = json_object_get(obj, "bytes");
    const json_t *j_seq    = json_object_get(obj, "seq");
    const json_t *j_ts     = json_object_get(obj, "ts");
    if (!json_is_string(j_record) || !json_is_string(j_op)
        || !json_is_string(j_polity) || !json_is_string(j_cid)
        || !json_is_string(j_bytes) || !json_is_integer(j_seq)
        || !json_is_number(j_ts))
        return -1;
    /* Shape-checked here rather than only app-side: an unknown op or a payload
     * that is not even hex cannot become a record anywhere downstream, and the
     * app should not have to distinguish a hostile ask from a truncated one. */
    if (!at_cosign_op_ok(json_string_value(j_record), json_string_value(j_op)))
        return -1;
    if (!at_cosign_bytes_ok(json_string_value(j_bytes)))
        return -1;
    if (json_string_value(j_cid)[0] == '\0')
        return -1;
    at_cosign_bound(json_string_value(j_record), record_out, record_sz, AT_COSIGN_TOKEN_MAX);
    at_cosign_bound(json_string_value(j_op), op_out, op_sz, AT_COSIGN_TOKEN_MAX);
    at_cosign_bound(json_string_value(j_polity), polity_out, polity_sz, AT_COSIGN_DID_MAX);
    at_cosign_bound(json_string_value(j_cid), cid_out, cid_sz, AT_COSIGN_CID_MAX);
    at_cosign_bound(json_string_value(j_bytes), bytes_out, bytes_sz, AT_COSIGN_BYTES_MAX);
    if (seq_out != NULL) *seq_out = (int64_t)json_integer_value(j_seq);
    if (ts_out != NULL) *ts_out = json_number_value(j_ts);
    return 0;
}

json_t *at_cosign_sig_to_json(const char *cid, const char *signer,
                              const char *sig, int64_t seq, double ts)
{
    char c[AT_COSIGN_CID_MAX + 1], d[AT_COSIGN_DID_MAX + 1];
    char s[AT_COSIGN_SIG_MAX + 1];
    at_cosign_bound(cid, c, sizeof(c), AT_COSIGN_CID_MAX);
    at_cosign_bound(signer, d, sizeof(d), AT_COSIGN_DID_MAX);
    at_cosign_bound(sig, s, sizeof(s), AT_COSIGN_SIG_MAX);
    if (c[0] == '\0' || d[0] == '\0' || s[0] == '\0') return NULL;
    json_t *env = json_object();
    if (env == NULL) return NULL;
    if (json_object_set_new(env, "cid", json_string(c)) != 0
        || json_object_set_new(env, "signer", json_string(d)) != 0
        || json_object_set_new(env, "sig", json_string(s)) != 0
        || json_object_set_new(env, "seq", json_integer((json_int_t)seq)) != 0
        || json_object_set_new(env, "ts", json_real(ts)) != 0) {
        json_decref(env);
        return NULL;
    }
    return env;
}

int at_cosign_sig_from_json(const json_t *obj,
                            char *cid_out, size_t cid_sz,
                            char *signer_out, size_t signer_sz,
                            char *sig_out, size_t sig_sz,
                            int64_t *seq_out, double *ts_out)
{
    if (cid_out != NULL && cid_sz > 0) cid_out[0] = '\0';
    if (signer_out != NULL && signer_sz > 0) signer_out[0] = '\0';
    if (sig_out != NULL && sig_sz > 0) sig_out[0] = '\0';
    if (obj == NULL || !json_is_object(obj)) return -1;
    const json_t *j_cid    = json_object_get(obj, "cid");
    const json_t *j_signer = json_object_get(obj, "signer");
    const json_t *j_sig    = json_object_get(obj, "sig");
    const json_t *j_seq    = json_object_get(obj, "seq");
    const json_t *j_ts     = json_object_get(obj, "ts");
    if (!json_is_string(j_cid) || !json_is_string(j_signer)
        || !json_is_string(j_sig) || !json_is_integer(j_seq)
        || !json_is_number(j_ts))
        return -1;
    if (json_string_value(j_cid)[0] == '\0'
        || json_string_value(j_signer)[0] == '\0'
        || json_string_value(j_sig)[0] == '\0')
        return -1;
    at_cosign_bound(json_string_value(j_cid), cid_out, cid_sz, AT_COSIGN_CID_MAX);
    at_cosign_bound(json_string_value(j_signer), signer_out, signer_sz, AT_COSIGN_DID_MAX);
    at_cosign_bound(json_string_value(j_sig), sig_out, sig_sz, AT_COSIGN_SIG_MAX);
    if (seq_out != NULL) *seq_out = (int64_t)json_integer_value(j_seq);
    if (ts_out != NULL) *ts_out = json_number_value(j_ts);
    return 0;
}
