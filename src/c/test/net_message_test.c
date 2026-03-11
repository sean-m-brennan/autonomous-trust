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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "network/net_message.h"

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
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));
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
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));
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

    /* Set from_whom with UUID, name, and address */
    uuid_generate(msg.from_whom.uuid);
    strncpy(msg.from_whom.fullname, "Node Alpha", NAME_LEN);
    strncpy(msg.from_whom.address, "172.27.3.14", ADDR_LEN);

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);

    /* Deserialize without peer (broadcast path) */
    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, NULL, &out));

    ck_assert_str_eq(out.process, "identity");
    ck_assert_str_eq(out.function, "request_access");
    ck_assert_str_eq(out.from_whom.fullname, "Node Alpha");
    ck_assert_str_eq(out.from_whom.address, "172.27.3.14");

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
    strncpy(msg.from_whom.fullname, "Wire Name", NAME_LEN);
    strncpy(msg.from_whom.address, "1.2.3.4", ADDR_LEN);

    uint8_t *wire    = NULL;
    size_t   wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&msg, &wire, &wire_len));

    /* When peer is provided, from_whom should come from peer, not JSON */
    public_identity_t peer;
    memset(&peer, 0, sizeof(peer));
    uuid_generate(peer.uuid);
    strncpy(peer.fullname, "Known Peer", NAME_LEN);
    strncpy(peer.address, "10.0.0.99", ADDR_LEN);

    net_wire_msg_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(net_message_from_wire(wire, wire_len, &peer, &out));

    /* from_whom should be the peer, not the wire data */
    ck_assert_str_eq(out.from_whom.fullname, "Known Peer");
    ck_assert_str_eq(out.from_whom.address, "10.0.0.99");
    ck_assert_mem_eq(out.from_whom.uuid, peer.uuid, sizeof(uuid_t));

    free(wire);
    net_wire_msg_free(&out);
}
END_TEST_DEFINITION()

RUN_TESTS(NetMessage, test_wire_roundtrip, test_wire_empty_data,
          test_wire_roundtrip_with_identity, test_wire_peer_overrides_json_identity)
