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

#ifndef NET_MESSAGE_H
#define NET_MESSAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "identity/identity.h"
#include "utilities/util.h"

#define NET_MSG_MAX_DATA (1024 * 1024)  /* 1 MB max wire message */

typedef enum {
    RECIPIENT_PEER = 0,
    RECIPIENT_BROADCAST = 1
} recipient_type_t;

typedef struct {
    recipient_type_t type;
    union {
        public_identity_t peer;
    } target;
} net_recipient_t;

typedef struct {
    char process[PROC_NAME_LEN + 1];
    char *function;
    uint8_t *data;
    size_t data_len;
    net_recipient_t to_whom;
    public_identity_t from_whom;
    bool encrypt;
    uint8_t signature[crypto_sign_BYTES];
    bool has_signature;
    bool verified;
} net_wire_msg_t;

/**
 * @brief Serialize a wire message to JSON, optionally signing it.
 * @param signer If non-NULL, the message is signed with this identity's private key.
 */
/*@
  requires msg == \null || \valid(msg);
  requires \valid(wire_out);
  requires \valid(wire_len);
  allocates *wire_out;
  behavior null_msg:
    assumes msg == \null;
    ensures \result != 0;
  behavior success:
    assumes msg != \null;
    ensures \result == 0 ==> *wire_out != \null && *wire_len > 0;
  behavior failure:
    assumes msg != \null;
    ensures \result != 0;
  disjoint behaviors null_msg, success;
*/
int net_message_to_wire(const net_wire_msg_t *msg, const identity_t *signer,
                        uint8_t **wire_out, size_t *wire_len);

/*@
  requires data == \null || \valid_read(data + (0 .. len - 1));
  requires msg_out == \null || \valid(msg_out);
  assigns *msg_out;
  behavior null_args:
    assumes data == \null || msg_out == \null;
    ensures \result != 0;
  behavior success:
    assumes data != \null && msg_out != \null;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int net_message_from_wire(const uint8_t *data, size_t len,
                          const public_identity_t *peer, net_wire_msg_t *msg_out);

/*@
  requires msg == \null || \valid(msg);
  behavior null_msg:
    assumes msg == \null;
    assigns \nothing;
  behavior valid_msg:
    assumes msg != \null;
    assigns msg->function, msg->data;
    frees msg->function, msg->data;
    ensures msg->function == \null;
    ensures msg->data == \null;
  disjoint behaviors;
  complete behaviors;
*/
void net_wire_msg_free(net_wire_msg_t *msg);

#endif  /* NET_MESSAGE_H */
