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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "zta_verifier.h"

/* ---------- helpers ---------- */

void zta_result_set(zta_result_t *result, zta_status_t status, const char *reason)
{
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    result->status = status;
    gettimeofday(&result->timestamp, NULL);
    if (reason)
        snprintf(result->reason, ZTA_REASON_LEN, "%s", reason);
}

const char *zta_status_str(zta_status_t status)
{
    switch (status) {
    case ZTA_VERIFIED:    return "VERIFIED";
    case ZTA_REJECTED:    return "REJECTED";
    case ZTA_DEFERRED:    return "DEFERRED";
    case ZTA_EXPIRED:     return "EXPIRED";
    case ZTA_REVOKED:     return "REVOKED";
    case ZTA_UNAVAILABLE: return "UNAVAILABLE";
    default:              return "UNKNOWN";
    }
}

/* ---------- null verifier ---------- */

static int null_verify_credential(zta_verifier_t *self,
                                  const uint8_t *cred_data, size_t cred_len,
                                  zta_result_t *result)
{
    (void)self;
    (void)cred_data;
    (void)cred_len;
    zta_result_set(result, ZTA_VERIFIED, "null verifier: always verified");
    return 0;
}

static int null_check_revocation(zta_verifier_t *self,
                                 const uint8_t *cred_hash,
                                 zta_result_t *result)
{
    (void)self;
    (void)cred_hash;
    zta_result_set(result, ZTA_VERIFIED, "null verifier: revocation check skipped");
    return 0;
}

static bool null_is_available(zta_verifier_t *self)
{
    (void)self;
    return true;
}

static int null_credential_hash(zta_verifier_t *self,
                                const uint8_t *cred_data, size_t cred_len,
                                uint8_t hash_out[ZTA_HASH_LEN])
{
    (void)self;
    (void)cred_data;
    (void)cred_len;
    memset(hash_out, 0, ZTA_HASH_LEN);
    return 0;
}

static void null_destroy(zta_verifier_t *self)
{
    free(self);
}

int zta_null_verifier_create(zta_verifier_t **out)
{
    if (!out)
        return EZTA_INTERNAL;

    zta_verifier_t *v = calloc(1, sizeof(zta_verifier_t));
    if (!v)
        return EZTA_INTERNAL;

    v->verify_credential = null_verify_credential;
    v->check_revocation  = null_check_revocation;
    v->is_available      = null_is_available;
    v->credential_hash   = null_credential_hash;
    v->destroy           = null_destroy;
    v->impl_data         = NULL;

    *out = v;
    return 0;
}
