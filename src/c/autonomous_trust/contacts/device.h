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
#ifndef AT_CONTACTS_DEVICE_H
#define AT_CONTACTS_DEVICE_H

/**
 * @file device.h
 * @brief One human, several devices (FIRST_CONTACT_PLAN Phase 4). C twin of
 * Python contacts/device.py: same format, same checks in the same order, same
 * refusal reasons.
 *
 *     DeviceCert := operator over "at-device-v1|" + body
 *       body := {v, typename: "at-device-cert", operator, uuid, key, issued_at}
 *
 * Each device is its own node. The operator key (the human's ed25519 key,
 * never in a node's config) signs a cert per device; a contact learns it from
 * a cert its own first device presented (at_adopt_operator), and a further
 * device under the same key joins a VERIFIED contact (at_link_device). No PIV,
 * X.509 or CA is involved in checking one.
 */

#include <stdbool.h>

#include <jansson.h>

#include "contacts/contacts.h"
#include "contacts/directory.h"
#include "identity/identity.h"

#define AT_DEVICE_DOMAIN "at-device-v1|"
#define AT_DEVICE_TYPENAME "at-device-cert"
#define AT_DEVICE_VERSION 1

/** Refusal reasons; -status indexes Python's device.REASONS. */
typedef enum {
    AT_DEVICE_OK = 0,
    AT_DEVICE_MALFORMED = -1,
    AT_DEVICE_BAD_SIGNATURE = -2,
    AT_DEVICE_MISMATCH = -3,
    AT_DEVICE_UNKNOWN_OPERATOR = -4,
    AT_DEVICE_UNVERIFIED = -5,
    AT_DEVICE_KNOWN = -6,
    AT_DEVICE_FULL = -7,
} at_device_status_t;

/** The reason word for an at_device_status_t ("" for OK). */
const char *at_device_reason(int status);

/** Sign the cert the operator keypair's 64-byte secret key @p operator_sk
 *  gives the node @p id, dated @p issued_at. For tests and operator tooling. */
int at_device_cert_create(const unsigned char *operator_sk, const public_identity_t *id,
                          long long issued_at, at_dir_signed_t *out);
/** AT_DEVICE_OK iff well formed and signed by its operator. A cert does not
 *  expire: it is withdrawn, not outlived. */
int at_device_cert_verify(const at_dir_signed_t *cert);
/** Whether @p cert is for @p id (its uuid and signing key). */
bool at_device_cert_names(const at_dir_signed_t *cert, const public_identity_t *id);
/** The operator key (hex) @p cert names, or NULL. */
const char *at_device_cert_operator(const at_dir_signed_t *cert);

/** Learn @p c's operator key from @p cert, which its own first device
 *  presented. The key never changes once learned, and belongs to one contact
 *  in @p store (NULL = do not check). An at_device_status_t. */
int at_adopt_operator(contact_t *c, const at_dir_signed_t *cert, contacts_t *store);
/** File @p id as another device of the VERIFIED contact whose operator signed
 *  @p cert; that contact into @p out (may be NULL). Linking a device the
 *  contact already lists is OK. An at_device_status_t. */
int at_link_device(contacts_t *store, const public_identity_t *id,
                   const at_dir_signed_t *cert, contact_t **out);

/** Fill @p c's devices from the stored array @p devices, keeping only those
 *  whose cert verifies for their own identity UNDER c's operator key, never
 *  the first device again or a duplicate, at most AT_CONTACT_DEVICES_MAX.
 *  The store is plain JSON: a hand-added device must not load. */
void at_contact_load_devices(contact_t *c, const json_t *devices);
/** A device's public identity, parsed into @p out (free its operator binding
 *  with free()). 0, or -1. */
int at_contact_device_identity(const at_contact_device_t *d, public_identity_t *out);

#endif /* AT_CONTACTS_DEVICE_H */
