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

#include <string.h>
#include <stdlib.h>
#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "network/net_message.h"
#include "identity/identity_priv.h"
#include "utilities/exception.h"
#include "network/net_message.pb-c.h"

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

/* ENET_WIRE_FORMAT is declared in net_message.h -- callers compare against it
 * (see the header for why the distinction is theirs to make). */
DEFINE_ERROR(ENET_WIRE_FORMAT, "Wire message format not spoken here");

const char *net_wire_format_name(net_wire_format_t fmt)
{
    switch (fmt) {
    case NET_WIRE_PROTO: return "proto";
    case NET_WIRE_JSON:
    default:             return "json";
    }
}

net_wire_format_t net_wire_format_from_name(const char *name)
{
    if (name != NULL && strcmp(name, "proto") == 0)
        return NET_WIRE_PROTO;
    return NET_WIRE_JSON;
}

/* The canonical signature pre-image, shared by both envelope encodings:
 * "<process>|<function>|<base64(data)>". Callers own the returned buffer.
 *
 * Factored out when the proto envelope landed. The pre-image MUST stay
 * byte-identical across formats and runtimes (Python
 * Message._signable_content), which is exactly the sort of invariant that
 * rots when it exists twice -- the proto path signs base64 of its RAW payload,
 * so the two encodings agree on the signature and re-encoding one as the other
 * cannot invalidate it. */
static char *wire_signable_content(const char *process, const char *function,
                                   const char *data_b64, size_t *len_out)
{
    const char *func_str = function ? function : "";
    const char *data_str = data_b64 ? data_b64 : "";
    size_t content_len = strlen(process) + 1 + strlen(func_str) + 1 + strlen(data_str);
    char *content = malloc(content_len + 1);
    if (content == NULL)
        return NULL;
    snprintf(content, content_len + 1, "%s|%s|%s", process, func_str, data_str);
    if (len_out != NULL) *len_out = content_len;
    return content;
}

/* base64 (ORIGINAL variant, matching Python's stdlib b64encode) of `data`.
 * Returns NULL on allocation failure; an empty payload yields an empty string,
 * never NULL, because the pre-image's trailing '|' is always present. */
static char *wire_data_b64(const uint8_t *data, size_t data_len)
{
    if (data == NULL || data_len == 0) {
        char *empty = malloc(1);
        if (empty != NULL) empty[0] = '\0';
        return empty;
    }
    size_t b64_len = sodium_base64_encoded_len(data_len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = malloc(b64_len);
    if (b64 == NULL)
        return NULL;
    sodium_bin2base64(b64, b64_len, data, data_len, sodium_base64_VARIANT_ORIGINAL);
    return b64;
}

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
        size_t content_len = 0;
        char *content = wire_signable_content(msg->process, msg->function,
                                              data_b64, &content_len);
        if (content != NULL)
        {
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
    json_object_set_new(root, "from_name", json_string(msg->from_whom.nickname));
    json_object_set_new(root, "from_address", json_string(msg->from_whom.address));
    json_object_set_new(root, "from_sig_hex",
                        json_string((const char *)msg->from_whom.signature.public_hex));
    json_object_set_new(root, "from_enc_hex",
                        json_string((const char *)msg->from_whom.encryptor.public_hex));
    /* Sender topology rank (mirrors Python Message.__bytes__'s from_rank).
     * Outside the signed pre-image (process|function|data) and the ciphertext,
     * so it neither breaks signatures nor encryption. A receiver captures it
     * into peer_ranks for rank-based child-gateway discovery. */
    json_object_set_new(root, "from_rank", json_integer(msg->from_rank));

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
            strncpy(msg_out->from_whom.nickname, from_name, NAME_LEN);
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
    /* Sender topology rank (default 0 when the field is absent — older peers
     * or unsigned/anonymous senders). Read regardless of the transport-`peer`
     * branch: rank is the sender's claim on the envelope, not a transport fact. */
    msg_out->from_rank = (int)json_integer_value(json_object_get(root, "from_rank"));

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

        /* reconstruct the canonical pre-image: "process|function|base64(data)" */
        size_t content_len = 0;
        char *content = wire_signable_content(msg_out->process, msg_out->function,
                                              data_b64, &content_len);
        if (content != NULL)
        {
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

/****************************
 * Protobuf envelope (doc/architecture/network-wire-format.md)
 *
 * Same envelope as the JSON path above, field for field; only the encoding of
 * each field differs. Everything security-relevant is deliberately shared with
 * that path rather than reimplemented: the signature pre-image
 * (wire_signable_content), the base64 of the payload it covers
 * (wire_data_b64), and the size cap. Two copies of a canonicalization rule is
 * how the runtimes drift apart, and this one decides whether signatures verify.
 ****************************/

/* Frama-C: skipped —
 * [serialization] net_message_to_wire_proto: protobuf-c pack + crypto_sign_detached.
 */
int net_message_to_wire_proto(const net_wire_msg_t *msg, const identity_t *signer,
                              uint8_t **wire_out, size_t *wire_len)
{
    if (msg == NULL || wire_out == NULL || wire_len == NULL)
        return EXCEPTION(EINVAL);

    AutonomousTrust__Core__Protobuf__Network__NetMessage proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__NETWORK__NET_MESSAGE__INIT;

    proto.process  = (char *)msg->process;
    proto.function = msg->function ? msg->function : (char *)"";
    proto.encrypt  = msg->encrypt;

    /* RAW payload -- the whole point of this encoding. The JSON path base64s
     * exactly these bytes, and so does the signature below. */
    if (msg->data != NULL && msg->data_len > 0) {
        proto.data.data = msg->data;
        proto.data.len  = msg->data_len;
    }

    /* trace_id: preserve the caller's, else mint one, exactly as the JSON path
     * does -- a trace that survives one encoding and not the other would be
     * worse than no trace at all. */
    char trace_buf[NET_TRACE_ID_LEN + 1];
    if (msg->trace_id[0] != '\0') {
        memcpy(trace_buf, msg->trace_id, NET_TRACE_ID_LEN);
        trace_buf[NET_TRACE_ID_LEN] = '\0';
    } else {
        generate_trace_id(trace_buf);
    }
    proto.trace_id = trace_buf;

    /* Sender identity, binary rather than the JSON form's hyphenated uuid and
     * hex keys. An unset sender leaves from_uuid EMPTY (proto3 omits it),
     * mirroring the JSON path's empty string -- emitting the nil uuid's 16 zero
     * bytes would make "no sender" indistinguishable from "the nil-uuid node"
     * on the receiving side. */
    if (!uuid_is_null(msg->from_whom.uuid)) {
        proto.from_uuid.data = (uint8_t *)msg->from_whom.uuid;
        proto.from_uuid.len  = sizeof(uuid_t);
    }
    proto.from_name    = (char *)msg->from_whom.nickname;
    proto.from_address = (char *)msg->from_whom.address;
    proto.from_rank    = msg->from_rank;
    /* The raw 32 bytes behind public_hex. public_signature_init / _encryptor_init
     * on the read side take the hex form, so the parser re-hexes these; the
     * binary is what rides the wire. */
    if (!sodium_is_zero(msg->from_whom.signature.public, crypto_sign_PUBLICKEYBYTES)) {
        proto.from_sig_key.data = (uint8_t *)msg->from_whom.signature.public;
        proto.from_sig_key.len  = crypto_sign_PUBLICKEYBYTES;
    }
    if (!sodium_is_zero(msg->from_whom.encryptor.public, crypto_box_PUBLICKEYBYTES)) {
        proto.from_enc_key.data = (uint8_t *)msg->from_whom.encryptor.public;
        proto.from_enc_key.len  = crypto_box_PUBLICKEYBYTES;
    }

    /* Sign over the SHARED canonical pre-image, which needs base64 of the raw
     * payload even here. This is what lets a peer verify a message whichever
     * encoding it arrived in. */
    unsigned char sig[crypto_sign_BYTES];
    bool signed_ok = false;
    if (signer != NULL) {
        char *data_b64 = wire_data_b64(msg->data, msg->data_len);
        if (data_b64 == NULL)
            return EXCEPTION(ENOMEM);
        size_t content_len = 0;
        char *content = wire_signable_content(msg->process, msg->function,
                                             data_b64, &content_len);
        free(data_b64);
        if (content == NULL)
            return EXCEPTION(ENOMEM);
        if (crypto_sign_detached(sig, NULL, (const unsigned char *)content,
                                 content_len, signer->signature.private) == 0) {
            proto.signature.data = sig;
            proto.signature.len  = crypto_sign_BYTES;
            signed_ok = true;
        }
        free(content);
    }
    (void)signed_ok;  /* an unsigned envelope is legitimate (see the JSON path) */

    size_t packed_len =
        autonomous_trust__core__protobuf__network__net_message__get_packed_size(&proto);
    /* +1 for the format marker. It is OUTSIDE the protobuf, not a field in it:
     * a receiver has to know which parser is even eligible before it decodes
     * anything (net_message.h NET_WIRE_PROTO_MAGIC). */
    uint8_t *buf = malloc(packed_len + 1);
    if (buf == NULL)
        return EXCEPTION(ENOMEM);
    buf[0] = (uint8_t)NET_WIRE_PROTO_MAGIC;
    autonomous_trust__core__protobuf__network__net_message__pack(&proto, buf + 1);

    *wire_out = buf;
    *wire_len = packed_len + 1;
    return 0;
}

/* Frama-C: skipped —
 * [serialization] net_message_from_wire_proto: protobuf-c unpack + crypto_sign_verify.
 */
int net_message_from_wire_proto(const uint8_t *data, size_t len,
                                const public_identity_t *peer,
                                net_wire_msg_t *msg_out)
{
    if (data == NULL || msg_out == NULL)
        return EXCEPTION(EINVAL);

    memset(msg_out, 0, sizeof(net_wire_msg_t));

    /* Same envelope-level cap as the JSON path, for the same reason: this
     * function is also reachable from in-process and alternate-transport
     * bytes, so the bound cannot live only in the transport. */
    if (len > NET_MSG_MAX_DATA)
        return EXCEPTION(ENET_WIRE);
    if (len < 2 || data[0] != (uint8_t)NET_WIRE_PROTO_MAGIC)
        return EXCEPTION(ENET_WIRE_FORMAT);

    AutonomousTrust__Core__Protobuf__Network__NetMessage *proto =
        autonomous_trust__core__protobuf__network__net_message__unpack(NULL, len - 1, data + 1);
    if (proto == NULL)
        return EXCEPTION(ENET_WIRE);

    /* An empty process/function is refused where the JSON path only requires
     * the keys to be present. Not gratuitous: protobuf decodes plenty of
     * arbitrary byte strings into an all-defaults message, so without this a
     * corrupt frame becomes a message addressed to process "" that is routed
     * nowhere with no diagnostic. Every real encoder sets both. */
    if (proto->process == NULL || proto->process[0] == '\0' ||
        proto->function == NULL || proto->function[0] == '\0') {
        autonomous_trust__core__protobuf__network__net_message__free_unpacked(proto, NULL);
        return EXCEPTION(ENET_WIRE);
    }

    at_strlcpy(msg_out->process, proto->process, sizeof(msg_out->process));
    msg_out->function = strdup(proto->function);
    if (msg_out->function == NULL) {
        autonomous_trust__core__protobuf__network__net_message__free_unpacked(proto, NULL);
        return EXCEPTION(ENOMEM);
    }
    msg_out->encrypt = proto->encrypt;

    /* trace_id: verbatim when well-formed, minted otherwise -- the JSON path's
     * rule, including the length check (a peer that sends a short id gets a
     * fresh one rather than a truncated buffer). */
    if (proto->trace_id != NULL && strlen(proto->trace_id) == NET_TRACE_ID_LEN) {
        memcpy(msg_out->trace_id, proto->trace_id, NET_TRACE_ID_LEN);
        msg_out->trace_id[NET_TRACE_ID_LEN] = '\0';
    } else {
        generate_trace_id(msg_out->trace_id);
    }

    if (proto->data.len > 0 && proto->data.data != NULL) {
        uint8_t *bin = malloc(proto->data.len);
        if (bin == NULL) {
            free(msg_out->function);
            msg_out->function = NULL;
            autonomous_trust__core__protobuf__network__net_message__free_unpacked(proto, NULL);
            return EXCEPTION(ENOMEM);
        }
        memcpy(bin, proto->data.data, proto->data.len);
        msg_out->data     = bin;
        msg_out->data_len = proto->data.len;
    }

    /* Transport-supplied peer wins over the envelope's claim, exactly as in the
     * JSON path. */
    if (peer != NULL) {
        memcpy(&msg_out->from_whom, peer, sizeof(public_identity_t));
    } else {
        if (proto->from_uuid.len == sizeof(uuid_t) && proto->from_uuid.data != NULL)
            memcpy(msg_out->from_whom.uuid, proto->from_uuid.data, sizeof(uuid_t));
        if (proto->from_name != NULL)
            at_strlcpy(msg_out->from_whom.nickname, proto->from_name,
                       sizeof(msg_out->from_whom.nickname));
        if (proto->from_address != NULL)
            at_strlcpy(msg_out->from_whom.address, proto->from_address,
                       sizeof(msg_out->from_whom.address));
        /* The public_*_init entry points take the HEX form (they are the same
         * ones the JSON path uses, and the same ones a config load uses), so
         * re-hex the raw bytes rather than adding a second way to install a
         * key. */
        if (proto->from_sig_key.len == crypto_sign_PUBLICKEYBYTES) {
            char sig_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
            sodium_bin2hex(sig_hex, sizeof(sig_hex), proto->from_sig_key.data,
                           crypto_sign_PUBLICKEYBYTES);
            (void)public_signature_init(&msg_out->from_whom.signature,
                                        (const unsigned char *)sig_hex, strlen(sig_hex));
        }
        if (proto->from_enc_key.len == crypto_box_PUBLICKEYBYTES) {
            char enc_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
            sodium_bin2hex(enc_hex, sizeof(enc_hex), proto->from_enc_key.data,
                           crypto_box_PUBLICKEYBYTES);
            (void)public_encryptor_init(&msg_out->from_whom.encryptor,
                                        (const unsigned char *)enc_hex, strlen(enc_hex));
        }
    }
    /* Rank is the sender's envelope claim in both formats, read regardless of
     * the transport-peer branch. */
    msg_out->from_rank = proto->from_rank;

    msg_out->has_signature = false;
    msg_out->verified      = false;
    if (proto->signature.len == crypto_sign_BYTES && proto->signature.data != NULL) {
        memcpy(msg_out->signature, proto->signature.data, crypto_sign_BYTES);
        msg_out->has_signature = true;

        /* Verify over the SHARED pre-image, which is base64 of the payload we
         * just received raw. */
        char *data_b64 = wire_data_b64(msg_out->data, msg_out->data_len);
        if (data_b64 != NULL) {
            size_t content_len = 0;
            char *content = wire_signable_content(msg_out->process, msg_out->function,
                                                  data_b64, &content_len);
            if (content != NULL) {
                if (crypto_sign_verify_detached(msg_out->signature,
                                                (const unsigned char *)content, content_len,
                                                msg_out->from_whom.signature.public) == 0)
                    msg_out->verified = true;
                free(content);
            }
            free(data_b64);
        }
    }

    autonomous_trust__core__protobuf__network__net_message__free_unpacked(proto, NULL);
    return 0;
}

int net_message_to_wire_fmt(const net_wire_msg_t *msg, const identity_t *signer,
                            net_wire_format_t fmt,
                            uint8_t **wire_out, size_t *wire_len)
{
    if (fmt == NET_WIRE_PROTO)
        return net_message_to_wire_proto(msg, signer, wire_out, wire_len);
    return net_message_to_wire(msg, signer, wire_out, wire_len);
}

int net_message_from_wire_fmt(const uint8_t *data, size_t len,
                              const public_identity_t *peer,
                              net_wire_format_t fmt, net_wire_msg_t *msg_out)
{
    if (data == NULL || msg_out == NULL)
        return EXCEPTION(EINVAL);
    if (fmt == NET_WIRE_PROTO)
        return net_message_from_wire_proto(data, len, peer, msg_out);
    /* JSON expected: refuse a proto frame HERE, before json_loadb, and with a
     * distinguishable error. The alternative -- letting the JSON parser fail on
     * binary and reporting "malformed" -- loses the one fact an operator needs,
     * which is that the peer is speaking a format this group does not. */
    if (len > 0 && data[0] == (uint8_t)NET_WIRE_PROTO_MAGIC) {
        memset(msg_out, 0, sizeof(net_wire_msg_t));
        return EXCEPTION(ENET_WIRE_FORMAT);
    }
    return net_message_from_wire(data, len, peer, msg_out);
}
