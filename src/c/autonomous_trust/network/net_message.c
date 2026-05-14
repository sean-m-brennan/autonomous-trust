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

#include <string.h>
#include <stdlib.h>
#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "network/net_message.h"
#include "identity/identity_priv.h"
#include "utilities/exception.h"

/* Fill `out` (33 bytes) with a fresh 32-char hex uuid4 + NUL, matching
 * Python's `uuid.uuid4().hex` shape (no hyphens, lowercase). */
static void generate_trace_id(char out[NET_TRACE_ID_LEN + 1])
{
    uuid_t u;
    uuid_generate(u);
    /* uuid_unparse_lower writes 36 bytes + NUL; rebuild without hyphens. */
    char tmp[UUID_STRING_LEN + 1];
    uuid_unparse_lower(u, tmp);
    size_t oi = 0;
    for (size_t i = 0; i < UUID_STRING_LEN && oi < NET_TRACE_ID_LEN; ++i) {
        if (tmp[i] == '-') continue;
        out[oi++] = tmp[i];
    }
    out[NET_TRACE_ID_LEN] = '\0';
}

#define ENET_WIRE 232
DEFINE_ERROR(ENET_WIRE, "Wire message serialization error");

/* Frama-C: skipped —
 * [serialization] net_message_to_wire: 11x json_object_set_new/json_string + 2x
 * crypto_sign_detached + strlen/snprintf/sodium_bin2base64 cascade.
 */
int net_message_to_wire(const net_wire_msg_t *msg, const identity_t *signer,
                        uint8_t **wire_out, size_t *wire_len)
{
    if (msg == NULL || wire_out == NULL || wire_len == NULL)
        return EXCEPTION(EINVAL);

    json_t *root = json_object();
    if (root == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set_new(root, "process", json_string(msg->process));
    json_object_set_new(root, "function",
                        json_string(msg->function ? msg->function : ""));
    json_object_set_new(root, "encrypt", json_boolean(msg->encrypt));

    /* base64-encode binary data */
    char *data_b64 = NULL;
    if (msg->data != NULL && msg->data_len > 0)
    {
        /* WHY sodium_base64_VARIANT_ORIGINAL and not _URLSAFE or _NOPAD:
         *
         * The Python side (autonomous_trust/network/net_message.py) uses
         * stdlib `base64.b64encode`, which produces the "standard" alphabet
         * with `+` and `/` and mandatory `=` padding. libsodium's ORIGINAL
         * variant matches that byte-for-byte. The other variants differ in
         * either alphabet (URLSAFE: `-` `_`) or padding (NOPAD: none), and
         * even a single differing byte would cause the signature below to
         * verify against a different canonical string on the Python side
         * and fail every verification. Do not change this variant without
         * also updating the Python encoder. */
        size_t b64_len = sodium_base64_encoded_len(msg->data_len,
                                                    sodium_base64_VARIANT_ORIGINAL);
        data_b64 = malloc(b64_len);
        if (data_b64 == NULL)
        {
            json_decref(root);
            return EXCEPTION(ENOMEM);
        }
        sodium_bin2base64(data_b64, b64_len, msg->data, msg->data_len,
                          sodium_base64_VARIANT_ORIGINAL);
        json_object_set_new(root, "data", json_string(data_b64));
    }
    else
    {
        json_object_set_new(root, "data", json_string(""));
    }

    /* WHY the signed content is "<process>|<function>|<base64(data)>" in
     * THIS exact order:
     *
     * This string is the canonical pre-image the Python side signs and
     * verifies (`_content_str` in net_message.py). The order and the `|`
     * separator are part of the protocol; if we reorder fields or use a
     * different separator the peer's Ed25519 verifier will see a different
     * byte sequence and reject every message with a "bad signature" that
     * is NOT a bug in crypto but a canonicalization mismatch.
     *
     * `data` here is the *base64-encoded* bytes, not the raw payload —
     * again matching Python. An empty data field contributes an empty
     * string (not absent), so the trailing `|` is always present. */
    if (signer != NULL)
    {
        const char *func_str = msg->function ? msg->function : "";
        const char *data_str = data_b64 ? data_b64 : "";
        size_t content_len = strlen(msg->process) + 1 + strlen(func_str) + 1 + strlen(data_str);
        char *content = malloc(content_len + 1);
        if (content != NULL)
        {
            snprintf(content, content_len + 1, "%s|%s|%s", msg->process, func_str, data_str);
            unsigned char sig[crypto_sign_BYTES];
            if (crypto_sign_detached(sig, NULL,
                                     (const unsigned char *)content, content_len,
                                     signer->signature.private) == 0)
            {
                char sig_hex[crypto_sign_BYTES * 2 + 1];
                sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, crypto_sign_BYTES);
                json_object_set_new(root, "signature", json_string(sig_hex));
            }
            free(content);
        }
    }

    if (data_b64 != NULL)
        free(data_b64);

    /* trace_id: preserve the caller's choice if set, else mint a fresh one.
     * Must match Python's `uuid.uuid4().hex` shape (32 lowercase hex chars,
     * no hyphens) so byte-for-byte conformance vectors round-trip. */
    char trace_buf[NET_TRACE_ID_LEN + 1];
    if (msg->trace_id[0] != '\0') {
        memcpy(trace_buf, msg->trace_id, NET_TRACE_ID_LEN);
        trace_buf[NET_TRACE_ID_LEN] = '\0';
    } else {
        generate_trace_id(trace_buf);
    }
    json_object_set_new(root, "trace_id", json_string(trace_buf));

    /* from_uuid: emit empty string when from_whom is unset (all-zero uuid),
     * matching Python's `from_whom is None` branch which writes "".  Without
     * this check the C side would emit the canonical nil-UUID string
     * ("00000000-...") and diverge byte-for-byte from Python on every
     * unsigned wire vector. */
    char uuid_str[UUID_STRING_LEN + 1];
    if (uuid_is_null(msg->from_whom.uuid)) {
        uuid_str[0] = '\0';
    } else {
        uuid_unparse_lower(msg->from_whom.uuid, uuid_str);
    }
    json_object_set_new(root, "from_uuid", json_string(uuid_str));
    json_object_set_new(root, "from_name", json_string(msg->from_whom.fullname));
    json_object_set_new(root, "from_address", json_string(msg->from_whom.address));
    json_object_set_new(root, "from_sig_hex",
                        json_string((const char *)msg->from_whom.signature.public_hex));
    json_object_set_new(root, "from_enc_hex",
                        json_string((const char *)msg->from_whom.encryptor.public_hex));

    char *json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (json_str == NULL)
        return EXCEPTION(ENET_WIRE);

    *wire_len = strlen(json_str);
    *wire_out = (uint8_t *)json_str;
    return 0;
}

/* Frama-C: skipped —
 * [serialization] net_message_from_wire: json_loadb spec dropped by kernel ("Cannot use a
 * pointer to void here.
 */
int net_message_from_wire(const uint8_t *data, size_t len,
                          const public_identity_t *peer, net_wire_msg_t *msg_out)
{
    if (data == NULL || msg_out == NULL)
        return EXCEPTION(EINVAL);

    memset(msg_out, 0, sizeof(net_wire_msg_t));

    /* Envelope-level size cap (parser-side defense-in-depth). The TCP
     * transport already enforces NET_MSG_MAX_DATA on inbound bytes
     * (net_transport_tcp.c:173), but this function is also called on
     * in-process or alternate-transport bytes; mirroring the cap here
     * means oversized envelopes never reach json_loadb regardless of
     * arrival path. Python's Message.parse carries the same cap on
     * its side (network.py: Network.max_wire_bytes). Change both
     * together. */
    if (len > NET_MSG_MAX_DATA)
        return EXCEPTION(ENET_WIRE);

    json_error_t err;
    json_t *root = json_loadb((const char *)data, len, 0, &err);
    if (root == NULL)
        return EXCEPTION(ENET_WIRE);

    const char *process = json_string_value(json_object_get(root, "process"));
    const char *function = json_string_value(json_object_get(root, "function"));
    json_t *encrypt_val = json_object_get(root, "encrypt");
    const char *data_b64 = json_string_value(json_object_get(root, "data"));

    if (process == NULL || function == NULL)
    {
        json_decref(root);
        return EXCEPTION(ENET_WIRE);
    }

    strncpy(msg_out->process, process, PROC_NAME_LEN);
    msg_out->process[PROC_NAME_LEN] = '\0';
    msg_out->function = strdup(function);
    msg_out->encrypt = encrypt_val ? json_boolean_value(encrypt_val) : false;

    /* trace_id: preserved verbatim across the hop when the peer sent one;
     * minted fresh when absent (backward-compat with pre-trace_id peers). */
    const char *trace_str = json_string_value(json_object_get(root, "trace_id"));
    if (trace_str != NULL && strlen(trace_str) == NET_TRACE_ID_LEN) {
        memcpy(msg_out->trace_id, trace_str, NET_TRACE_ID_LEN);
        msg_out->trace_id[NET_TRACE_ID_LEN] = '\0';
    } else {
        generate_trace_id(msg_out->trace_id);
    }

    if (data_b64 != NULL && strlen(data_b64) > 0)
    {
        size_t b64_len = strlen(data_b64);
        size_t bin_maxlen = b64_len;
        uint8_t *bin = malloc(bin_maxlen);
        if (bin == NULL)
        {
            json_decref(root);
            free(msg_out->function);
            msg_out->function = NULL;
            return EXCEPTION(ENOMEM);
        }
        size_t bin_len = 0;
        if (sodium_base642bin(bin, bin_maxlen, data_b64, b64_len,
                              NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            free(bin);
            json_decref(root);
            free(msg_out->function);
            msg_out->function = NULL;
            return EXCEPTION(ENET_WIRE);
        }
        msg_out->data = bin;
        msg_out->data_len = bin_len;
    }

    if (peer != NULL)
    {
        memcpy(&msg_out->from_whom, peer, sizeof(public_identity_t));
    }
    else
    {
        const char *from_uuid = json_string_value(json_object_get(root, "from_uuid"));
        const char *from_name = json_string_value(json_object_get(root, "from_name"));
        const char *from_addr = json_string_value(json_object_get(root, "from_address"));
        if (from_uuid != NULL)
            uuid_parse(from_uuid, msg_out->from_whom.uuid);
        if (from_name != NULL)
            strncpy(msg_out->from_whom.fullname, from_name, NAME_LEN);
        if (from_addr != NULL)
            strncpy(msg_out->from_whom.address, from_addr, ADDR_LEN);
        const char *from_sig = json_string_value(json_object_get(root, "from_sig_hex"));
        if (from_sig != NULL && from_sig[0] != '\0')
            (void)public_signature_init(&msg_out->from_whom.signature,
                                        (const unsigned char *)from_sig, strlen(from_sig));
        const char *from_enc = json_string_value(json_object_get(root, "from_enc_hex"));
        if (from_enc != NULL && from_enc[0] != '\0')
            (void)public_encryptor_init(&msg_out->from_whom.encryptor,
                                        (const unsigned char *)from_enc, strlen(from_enc));
    }

    /* extract and verify signature if present */
    msg_out->has_signature = false;
    msg_out->verified = false;
    const char *sig_hex = json_string_value(json_object_get(root, "signature"));
    if (sig_hex != NULL && strlen(sig_hex) == crypto_sign_BYTES * 2)
    {
        sodium_hex2bin(msg_out->signature, crypto_sign_BYTES,
                       sig_hex, crypto_sign_BYTES * 2,
                       NULL, NULL, NULL);
        msg_out->has_signature = true;

        /* reconstruct content string: "process|function|data" */
        const char *func_str = msg_out->function ? msg_out->function : "";
        size_t content_len = strlen(msg_out->process) + 1 + strlen(func_str) + 1 +
                             (data_b64 ? strlen(data_b64) : 0);
        char *content = malloc(content_len + 1);
        if (content != NULL)
        {
            snprintf(content, content_len + 1, "%s|%s|%s",
                     msg_out->process, func_str, data_b64 ? data_b64 : "");
            if (crypto_sign_verify_detached(msg_out->signature,
                                            (const unsigned char *)content, content_len,
                                            msg_out->from_whom.signature.public) == 0)
            {
                msg_out->verified = true;
            }
            free(content);
        }
    }

    json_decref(root);
    return 0;
}

void net_wire_msg_free(net_wire_msg_t *msg)
{
    if (msg == NULL)
        return;
    if (msg->function != NULL)
    {
        free(msg->function);
        msg->function = NULL;
    }
    if (msg->data != NULL)
    {
        free(msg->data);
        msg->data = NULL;
    }
}
