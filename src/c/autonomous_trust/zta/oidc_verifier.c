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
#include <sodium.h>

#include "oidc_verifier.h"

/* ---------- stub implementations ---------- */

/*@
  requires \valid(result);
  assigns result->status, result->reason[0 .. ZTA_REASON_LEN - 1], result->timestamp;
  ensures \result == 0;
*/
static int oidc_verify_credential(zta_verifier_t *self,
                                  const uint8_t *cred_data, size_t cred_len,
                                  zta_result_t *result)
{
    (void)self;
    (void)cred_data;
    (void)cred_len;
    zta_result_set(result, ZTA_UNAVAILABLE, "OIDC verifier not yet implemented");
    return 0;
}

/*@
  requires \valid(result);
  assigns result->status, result->reason[0 .. ZTA_REASON_LEN - 1], result->timestamp;
  ensures \result == 0;
*/
static int oidc_check_revocation(zta_verifier_t *self,
                                 const uint8_t *cred_hash,
                                 zta_result_t *result)
{
    (void)self;
    (void)cred_hash;
    zta_result_set(result, ZTA_UNAVAILABLE, "OIDC verifier not yet implemented");
    return 0;
}

static bool oidc_is_available(zta_verifier_t *self)
{
    (void)self;
    return false;
}

/* Frama-C: skipped — [solver-timeout] sodium_memzero void-ptr/uint8-ptr cast cascade */
/*@
  requires \valid(hash_out + (0 .. ZTA_HASH_LEN - 1));
  assigns hash_out[0 .. ZTA_HASH_LEN - 1];
  ensures \result == EZTA_UNSUPPORTED;
*/
static int oidc_credential_hash(zta_verifier_t *self,
                                const uint8_t *cred_data, size_t cred_len,
                                uint8_t hash_out[ZTA_HASH_LEN])
{
    (void)self;
    (void)cred_data;
    (void)cred_len;
    sodium_memzero(hash_out, ZTA_HASH_LEN);
    return EZTA_UNSUPPORTED;
}

/* Frama-C: skipped — [solver-timeout] stub preconditions */
static void oidc_destroy(zta_verifier_t *self)
{
    free(self);
}

/* Frama-C: skipped — [solver-timeout] stub preconditions */
int oidc_verifier_create(zta_verifier_t **out)
{
    if (!out)
        return EZTA_INTERNAL;

    zta_verifier_t *v = calloc(1, sizeof(zta_verifier_t));
    if (!v)
        return EZTA_INTERNAL;

    v->verify_credential = oidc_verify_credential;
    v->check_revocation  = oidc_check_revocation;
    v->is_available      = oidc_is_available;
    v->credential_hash   = oidc_credential_hash;
    v->destroy           = oidc_destroy;
    v->impl_data         = NULL;

    *out = v;
    return 0;
}
