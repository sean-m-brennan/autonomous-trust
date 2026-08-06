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

#include <stdio.h>
#include <string.h>

#include <uuid/uuid.h>

#include "zta_binding.h"
#include "zta_policy.h"     /* zta_render_san_uri, ZTA_PATH_LEN */
#include "x509_verifier.h"

bool zta_verify_binding(const public_identity_t *ident,
                        const uint8_t *cred, size_t cred_len,
                        const uint8_t *binding, size_t binding_len)
{
    if (ident == NULL || cred == NULL || cred_len == 0
        || binding == NULL || binding_len == 0 || binding_len > ZTA_BINDING_MAX)
        return false;
    uint8_t preimage[ZTA_BINDING_PREIMAGE_LEN];
    if (zta_binding_preimage(ident, cred, cred_len, preimage) != 0)
        return false;
    /* Same generic verifier the operator-key binding uses: RSA => PKCS#1 v1.5,
     * EC => ECDSA, SHA-256 either way, matching Python's PivVerifier — which is
     * what signs these on the other side. */
    return x509_verify_data_signature(cred, cred_len, preimage, sizeof(preimage),
                                      binding, binding_len);
}

bool zta_san_binds_identity(const uint8_t *cred, size_t cred_len,
                            const public_identity_t *ident,
                            const char *san_format)
{
    if (cred == NULL || cred_len == 0 || ident == NULL
        || san_format == NULL || san_format[0] == '\0')
        return false;
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower((const unsigned char *)ident->uuid, uuid_str);
    char uri[ZTA_PATH_LEN + UUID_STRING_LEN + 1];
    /* Placeholder substitution, NOT snprintf: the template comes from a policy
       file shared with Python and is spelled `at://{uuid}`. Handing it to printf
       renders it literally and matches nothing — a binding check that silently
       never fires, which is worse than one that errors. */
    if (zta_render_san_uri(san_format, uuid_str, uri, sizeof(uri)) != 0)
        return false;
    return x509_cert_has_uri_san(cred, cred_len, uri);
}

bool zta_operator_binding_binds_identity(const public_identity_t *ident,
                                         const uint8_t *cred, size_t cred_len,
                                         const uint8_t *operator_pubkey,
                                         const uint8_t *binding,
                                         size_t binding_len)
{
    if (ident == NULL || cred == NULL || cred_len == 0
        || operator_pubkey == NULL || binding == NULL || binding_len == 0
        || binding_len > OPERATOR_BINDING_MAX)
        return false;
    if (at_operator_pubkey_empty(operator_pubkey))
        return false;
    uint8_t preimage[OPERATOR_BINDING_PREIMAGE_LEN];
    if (operator_binding_preimage(ident, operator_pubkey, preimage) != 0)
        return false;
    return x509_verify_data_signature(cred, cred_len, preimage, sizeof(preimage),
                                      binding, binding_len);
}

bool zta_identity_is_bound(const public_identity_t *ident,
                           const uint8_t *cred, size_t cred_len,
                           const uint8_t *binding, size_t binding_len,
                           const char *san_format,
                           const uint8_t *operator_pubkey,
                           const uint8_t *operator_binding,
                           size_t operator_binding_len)
{
    if (zta_verify_binding(ident, cred, cred_len, binding, binding_len))
        return true;
    if (zta_san_binds_identity(cred, cred_len, ident, san_format))
        return true;
    return zta_operator_binding_binds_identity(ident, cred, cred_len,
                                               operator_pubkey,
                                               operator_binding,
                                               operator_binding_len);
}
