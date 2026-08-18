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
#include <stdlib.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "network/net_message.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"

DEFINE_TEST(test_wire_roundtrip)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    const uint8_t payload[] = {0x01, 0x02, 0x03};
    const char   *func_name = "func";

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function = (char *)func_name;
    msg.data      = (uint8_t *)payload;
    msg.data_len  = sizeof(payload);
    msg.encrypt   = false;
    msg.to_whom.type = RECIPIENT_BROADCAST;

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, NULL, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);
    ck_assert(wire_len > 0);

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &out));

    ck_assert_str_eq(out.process, "test");
    ck_assert_ptr_nonnull(out.function);
    ck_assert_str_eq(out.function, "func");
    ck_assert_ptr_nonnull(out.data);
    ck_assert_uint_eq(out.data_len, sizeof(payload));
    ck_assert_mem_eq(out.data, payload, sizeof(payload));

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wire_empty_data)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function  = (char *)"func";
    msg.data      = NULL;
    msg.data_len  = 0;
    msg.encrypt   = false;
    msg.to_whom.type = RECIPIENT_BROADCAST;

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, NULL, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);
    ck_assert(wire_len > 0);

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &out));

    ck_assert_str_eq(out.process, "test");
    ck_assert_str_eq(out.function, "func");
    ck_assert_uint_eq(out.data_len, 0);

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wire_roundtrip_with_identity)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = (char *)"request_access";
    msg.data     = NULL;
    msg.data_len = 0;
    msg.encrypt  = false;
    msg.to_whom.type = RECIPIENT_BROADCAST;

    /* Set from_whom with UUID, name, address, and topology rank */
    uuid_generate(msg.from_whom.uuid);
    strncpy(msg.from_whom.nickname, "Node Alpha", NAME_LEN);
    strncpy(msg.from_whom.address, "172.27.3.14", ADDR_LEN);
    msg.from_rank = 7;

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, NULL, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);

    /* Deserialize without peer (broadcast path) */
    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &out));

    ck_assert_str_eq(out.process, "identity");
    ck_assert_str_eq(out.function, "request_access");
    ck_assert_str_eq(out.from_whom.nickname, "Node Alpha");
    ck_assert_str_eq(out.from_whom.address, "172.27.3.14");
    /* Envelope from_rank survives the round-trip (the seam that carries peer
     * topology rank for rank-based child-gateway discovery). */
    ck_assert_int_eq(out.from_rank, 7);

    /* UUID must match */
    ck_assert_mem_eq(out.from_whom.uuid, msg.from_whom.uuid, sizeof(uuid_t));

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wire_peer_overrides_json_identity)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = (char *)"access_granted";
    msg.data     = NULL;
    msg.data_len = 0;
    msg.encrypt  = true;

    uuid_generate(msg.from_whom.uuid);
    strncpy(msg.from_whom.nickname, "Wire Name", NAME_LEN);
    strncpy(msg.from_whom.address, "1.2.3.4", ADDR_LEN);

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, NULL, &wire, &wire_len));

    /* When peer is provided, from_whom should come from peer, not JSON */
    public_identity_t peer;
    memset(&peer, 0, sizeof(peer));
    uuid_generate(peer.uuid);
    strncpy(peer.nickname, "Known Peer", NAME_LEN);
    strncpy(peer.address, "10.0.0.99", ADDR_LEN);

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, &peer, &out));

    /* from_whom should be the peer, not the wire data */
    ck_assert_str_eq(out.from_whom.nickname, "Known Peer");
    ck_assert_str_eq(out.from_whom.address, "10.0.0.99");
    ck_assert_mem_eq(out.from_whom.uuid, peer.uuid, sizeof(uuid_t));

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_wire_signed_message)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    /* create a full identity for signing */
    identity_t *signer = NULL;
    ck_assert_ret_ok(identity_create(NULL, "127.0.0.1", "Signer",
                                     "signer", &signer));

    const uint8_t payload[] = {0xAA, 0xBB};
    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function = (char *)"check";
    msg.data     = (uint8_t *)payload;
    msg.data_len = sizeof(payload);
    msg.encrypt  = false;
    memcpy(&msg.from_whom, (public_identity_t *)signer, sizeof(public_identity_t));

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, signer, &wire, &wire_len));

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &out));

    /* signature should be present and verified */
    ck_assert(out.has_signature);
    ck_assert(out.verified);
    ck_assert_str_eq(out.process, "test");
    ck_assert_str_eq(out.function, "check");

    free(wire);
    net_wire_msg_free(&out);
    smrt_deref(signer);
}
END_TEST_DEFINITION()

/* A wire envelope from an older peer omits "from_rank"; the parser must
 * default it to 0 (unknown), not choke. Backward-compat for mixed versions. */
DEFINE_TEST(test_wire_missing_from_rank_defaults_zero)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);
    const char *legacy =
        "{\"process\":\"identity\",\"function\":\"request_access\","
        "\"encrypt\":false,\"data\":\"\",\"trace_id\":\"\","
        "\"from_uuid\":\"\",\"from_name\":\"\",\"from_address\":\"\","
        "\"from_sig_hex\":\"\",\"from_enc_hex\":\"\"}";
    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire((const uint8_t *)legacy,
                                           strlen(legacy), NULL, &out));
    ck_assert_int_eq(out.from_rank, 0);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

/* ---- Protobuf envelope (doc/architecture/network-wire-format.md)
 * ---------------------------------- */

/* The proto envelope carries every field the JSON one does, through a full
 * round trip, and identifies itself with the format marker. */
DEFINE_TEST(test_wire_proto_roundtrip)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    const uint8_t payload[] = {0x00, 0xFF, 0x10, 0x7B};  /* incl. 0x7B ('{') and a NUL */
    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function  = (char *)"func";
    msg.data      = (uint8_t *)payload;
    msg.data_len  = sizeof(payload);
    msg.encrypt   = true;
    msg.from_rank = 7;
    memcpy(msg.trace_id, "0123456789abcdef0123456789abcdef", NET_TRACE_ID_LEN);
    msg.to_whom.type = RECIPIENT_BROADCAST;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_PROTO,
                                             &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);
    /* The marker is OUTSIDE the protobuf, and is what makes a foreign frame
     * refusable without running the other parser. */
    ck_assert_int_eq(wire[0], (int)NET_WIRE_PROTO_MAGIC);

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire_fmt(wire, wire_len, NULL,
                                               NET_WIRE_PROTO, &out));
    ck_assert_str_eq(out.process, "test");
    ck_assert_str_eq(out.function, "func");
    ck_assert_uint_eq(out.data_len, sizeof(payload));
    ck_assert_mem_eq(out.data, payload, sizeof(payload));
    ck_assert(out.encrypt);
    ck_assert_int_eq(out.from_rank, 7);
    ck_assert_str_eq(out.trace_id, "0123456789abcdef0123456789abcdef");

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

/* The payload rides RAW in the proto form, so it must be SMALLER than the JSON
 * form's base64 -- that saving is the entire reason this encoding exists, and a
 * regression that quietly base64'd it would otherwise pass every other test. */
DEFINE_TEST(test_wire_proto_smaller_than_json)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    uint8_t payload[512];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i & 0xFF);

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function = (char *)"bulk";
    msg.data     = payload;
    msg.data_len = sizeof(payload);
    msg.to_whom.type = RECIPIENT_BROADCAST;

    uint8_t *jwire = NULL, *pwire = NULL;
    size_t jlen = 0, plen = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_JSON, &jwire, &jlen));
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_PROTO, &pwire, &plen));
    ck_assert(plen < jlen);
    /* base64 costs 4 bytes per 3, so the raw form must be at least a quarter
     * smaller on a payload this size. Bounding it (rather than just "smaller")
     * is what makes this a measurement instead of a tautology. */
    ck_assert(plen < jlen - (sizeof(payload) / 4));

    free(jwire);
    free(pwire);
}
END_TEST_DEFINITION()

/* A signature made on one encoding verifies on the other. This is the
 * load-bearing invariant of the whole design: the pre-image is
 * "<process>|<function>|<base64(data)>" in BOTH forms, so re-encoding a message
 * cannot invalidate it. */
DEFINE_TEST(test_wire_proto_signature_matches_json)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    identity_t *signer = NULL;
    ck_assert_ret_ok(identity_create(NULL, "127.0.0.1", "Signer", "signer", &signer));

    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};
    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function = (char *)"check";
    msg.data     = (uint8_t *)payload;
    msg.data_len = sizeof(payload);
    memcpy(&msg.from_whom, (public_identity_t *)signer, sizeof(public_identity_t));

    uint8_t *jwire = NULL, *pwire = NULL;
    size_t jlen = 0, plen = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, signer, NET_WIRE_JSON, &jwire, &jlen));
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, signer, NET_WIRE_PROTO, &pwire, &plen));

    net_wire_msg_t jout, pout;
    memset(&jout, 0, sizeof(jout));
    memset(&pout, 0, sizeof(pout));
    ck_assert_ret_ok(net_message_from_wire_fmt(jwire, jlen, NULL, NET_WIRE_JSON, &jout));
    ck_assert_ret_ok(net_message_from_wire_fmt(pwire, plen, NULL, NET_WIRE_PROTO, &pout));
    ck_assert(jout.has_signature);
    ck_assert(pout.has_signature);
    ck_assert(jout.verified);
    ck_assert(pout.verified);
    /* Ed25519 is deterministic, so the SAME pre-image yields the same 64 bytes
     * -- which is how we know both paths signed the same thing rather than each
     * verifying its own private convention. */
    ck_assert_mem_eq(jout.signature, pout.signature, crypto_sign_BYTES);

    free(jwire);
    free(pwire);
    net_wire_msg_free(&jout);
    net_wire_msg_free(&pout);
    smrt_deref(signer);
}
END_TEST_DEFINITION()

/* The strict format gate, both directions. A node is TOLD which format to
 * expect and refuses the other with a distinguishable error, so the parser it
 * does not speak never sees peer-supplied bytes (2.3; detection is 2.5). */
DEFINE_TEST(test_wire_format_mismatch_refused)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "test", PROC_NAME_LEN);
    msg.function = (char *)"func";
    msg.to_whom.type = RECIPIENT_BROADCAST;

    uint8_t *jwire = NULL, *pwire = NULL;
    size_t jlen = 0, plen = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_JSON, &jwire, &jlen));
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_PROTO, &pwire, &plen));

    net_wire_msg_t out;
    /* proto bytes offered to a JSON-format node */
    memset(&out, 0, sizeof(out));
    ck_assert_ret_nonzero(net_message_from_wire_fmt(pwire, plen, NULL,
                                                    NET_WIRE_JSON, &out));
    /* JSON bytes offered to a proto-format node */
    memset(&out, 0, sizeof(out));
    ck_assert_ret_nonzero(net_message_from_wire_fmt(jwire, jlen, NULL,
                                                    NET_WIRE_PROTO, &out));
    /* And each still parses in its own format, so the refusals above are the
     * gate doing its job rather than two broken encoders. */
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire_fmt(jwire, jlen, NULL, NET_WIRE_JSON, &out));
    net_wire_msg_free(&out);
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire_fmt(pwire, plen, NULL, NET_WIRE_PROTO, &out));
    net_wire_msg_free(&out);

    free(jwire);
    free(pwire);
}
END_TEST_DEFINITION()

/* Arbitrary bytes behind a forged marker must be REFUSED, not decoded into an
 * all-defaults message addressed to process "" (protobuf decodes plenty of
 * garbage happily, which is why the parser requires process and function). */
DEFINE_TEST(test_wire_proto_garbage_refused)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    /* A marker followed by a valid but EMPTY NetMessage (zero bytes). */
    uint8_t empty_msg[1] = { (uint8_t)NET_WIRE_PROTO_MAGIC };
    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_nonzero(net_message_from_wire_fmt(empty_msg, sizeof(empty_msg),
                                                    NULL, NET_WIRE_PROTO, &out));

    /* A marker followed by bytes that are not a valid protobuf at all. */
    uint8_t junk[] = { (uint8_t)NET_WIRE_PROTO_MAGIC, 0xFF, 0xFF, 0xFF, 0xFF };
    memset(&out, 0, sizeof(out));
    ck_assert_ret_nonzero(net_message_from_wire_fmt(junk, sizeof(junk), NULL,
                                                    NET_WIRE_PROTO, &out));

    /* A bare marker with nothing after it. */
    uint8_t lone[1] = { (uint8_t)NET_WIRE_PROTO_MAGIC };
    memset(&out, 0, sizeof(out));
    ck_assert_ret_nonzero(net_message_from_wire_fmt(lone, 1, NULL,
                                                    NET_WIRE_PROTO, &out));
}
END_TEST_DEFINITION()

/* The sender identity survives the proto form's binary encoding of it: 16 raw
 * uuid bytes and 32-byte keys, where JSON carries a hyphenated string and hex.
 * An unset sender must stay unset rather than becoming the nil uuid. */
DEFINE_TEST(test_wire_proto_identity_roundtrip)
{
    ck_assert_int_eq(sodium_init() >= 0 ? 0 : -1, 0);

    identity_t *me = NULL;
    ck_assert_ret_ok(identity_create(NULL, "10.0.0.5", "Nick", "pet", &me));

    net_wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "identity", PROC_NAME_LEN);
    msg.function = (char *)"request_access";
    msg.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(&msg.from_whom, (public_identity_t *)me, sizeof(public_identity_t));

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, NULL, NET_WIRE_PROTO, &wire, &wire_len));

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire_fmt(wire, wire_len, NULL, NET_WIRE_PROTO, &out));
    ck_assert_mem_eq(out.from_whom.uuid, ((public_identity_t *)me)->uuid, sizeof(uuid_t));
    ck_assert_str_eq(out.from_whom.address, "10.0.0.5");
    ck_assert_str_eq(out.from_whom.nickname, "Nick");
    ck_assert_mem_eq(out.from_whom.signature.public,
                     ((public_identity_t *)me)->signature.public,
                     crypto_sign_PUBLICKEYBYTES);
    ck_assert_mem_eq(out.from_whom.encryptor.public,
                     ((public_identity_t *)me)->encryptor.public,
                     crypto_box_PUBLICKEYBYTES);
    free(wire);
    net_wire_msg_free(&out);

    /* No sender: from_uuid must be omitted, so the parse yields the nil uuid
     * from a ZEROED struct rather than "the nil-uuid node" having sent it. The
     * distinction matters because the JSON path writes "" for this case. */
    net_wire_msg_t anon;
    memset(&anon, 0, sizeof(anon));
    strncpy(anon.process, "identity", PROC_NAME_LEN);
    anon.function = (char *)"ping";
    anon.to_whom.type = RECIPIENT_BROADCAST;
    wire = NULL; wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&anon, NULL, NET_WIRE_PROTO, &wire, &wire_len));
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire_fmt(wire, wire_len, NULL, NET_WIRE_PROTO, &out));
    ck_assert(uuid_is_null(out.from_whom.uuid));
    free(wire);
    net_wire_msg_free(&out);

    smrt_deref(me);
}
END_TEST_DEFINITION()

/* The format names that ride the group wire form, including the refusal rule:
 * an unknown name tightens to JSON rather than failing a config load. */
DEFINE_TEST(test_wire_format_names)
{
    ck_assert_str_eq(net_wire_format_name(NET_WIRE_JSON), "json");
    ck_assert_str_eq(net_wire_format_name(NET_WIRE_PROTO), "proto");
    ck_assert_int_eq((int)net_wire_format_from_name("proto"), (int)NET_WIRE_PROTO);
    ck_assert_int_eq((int)net_wire_format_from_name("json"), (int)NET_WIRE_JSON);
    ck_assert_int_eq((int)net_wire_format_from_name("PROTO"), (int)NET_WIRE_JSON);
    ck_assert_int_eq((int)net_wire_format_from_name("bogus"), (int)NET_WIRE_JSON);
    ck_assert_int_eq((int)net_wire_format_from_name(NULL), (int)NET_WIRE_JSON);
}
END_TEST_DEFINITION()

RUN_TESTS(NetMessage, test_wire_roundtrip, test_wire_empty_data,
          test_wire_roundtrip_with_identity, test_wire_peer_overrides_json_identity,
          test_wire_signed_message, test_wire_missing_from_rank_defaults_zero,
          test_wire_proto_roundtrip, test_wire_proto_smaller_than_json,
          test_wire_proto_signature_matches_json, test_wire_format_mismatch_refused,
          test_wire_proto_garbage_refused, test_wire_proto_identity_roundtrip,
          test_wire_format_names)
