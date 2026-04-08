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

#ifndef ZTA_VERIFIER_H
#define ZTA_VERIFIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZTA_HASH_LEN 32       /* SHA-256 */
#define ZTA_REASON_LEN 256

/**
 * @brief Result status of a ZTA credential verification
 */
typedef enum {
    ZTA_VERIFIED,       /* Credential is valid and verified */
    ZTA_REJECTED,       /* Credential is invalid (bad signature, unknown issuer) */
    ZTA_DEFERRED,       /* Verification deferred (infrastructure unreachable, DDIL) */
    ZTA_EXPIRED,        /* Credential has expired */
    ZTA_REVOKED,        /* Credential has been revoked */
    ZTA_UNAVAILABLE     /* Verifier cannot perform this operation */
} zta_status_t;

/**
 * @brief Result of a ZTA credential verification operation
 */
typedef struct {
    zta_status_t status;
    struct timeval timestamp;
    char reason[ZTA_REASON_LEN];
    uint8_t credential_hash[ZTA_HASH_LEN];
    int ttl_sec;        /* Seconds until re-verification needed; 0 = use policy default */
} zta_result_t;

/**
 * @brief Pluggable verifier interface (vtable pattern)
 *
 * All function pointers may be NULL for unsupported operations.
 * A NULL function pointer is treated as returning ZTA_UNAVAILABLE.
 */
typedef struct zta_verifier_s {
    /**
     * @brief Verify a credential (check signature chain, expiry, revocation)
     *
     * @param self      Verifier instance
     * @param cred_data Raw credential bytes (DER, PEM, token, etc.)
     * @param cred_len  Length of credential data
     * @param result    Output: verification result
     * @return 0 on success, error code on internal failure
     */
    int (*verify_credential)(struct zta_verifier_s *self,
                             const uint8_t *cred_data, size_t cred_len,
                             zta_result_t *result);

    /**
     * @brief Check if a previously verified credential has been revoked
     *
     * @param self      Verifier instance
     * @param cred_hash SHA-256 hash of the credential
     * @param result    Output: revocation check result
     * @return 0 on success, error code on internal failure
     */
    int (*check_revocation)(struct zta_verifier_s *self,
                            const uint8_t *cred_hash,
                            zta_result_t *result);

    /**
     * @brief Check if verification infrastructure is currently reachable
     *
     * @param self Verifier instance
     * @return true if infrastructure is reachable
     */
    bool (*is_available)(struct zta_verifier_s *self);

    /**
     * @brief Compute a deterministic hash of a credential for identity binding
     *
     * @param self      Verifier instance
     * @param cred_data Raw credential bytes
     * @param cred_len  Length of credential data
     * @param hash_out  Output: SHA-256 hash (ZTA_HASH_LEN bytes)
     * @return 0 on success, error code on failure
     */
    int (*credential_hash)(struct zta_verifier_s *self,
                           const uint8_t *cred_data, size_t cred_len,
                           uint8_t hash_out[ZTA_HASH_LEN]);

    /**
     * @brief Destroy verifier and free resources
     *
     * @param self Verifier instance (will be freed)
     */
    void (*destroy)(struct zta_verifier_s *self);

    void *impl_data;    /* Verifier-specific state */
} zta_verifier_t;

/**
 * @brief Create a null verifier that always returns ZTA_VERIFIED
 *
 * Used when ZTA is compiled in but disabled at runtime.
 *
 * @param out Output: newly allocated verifier (caller must destroy)
 * @return 0 on success
 */
/*@
  requires \valid(out);
  allocates *out;
  ensures \result == 0;
  ensures *out != \null;
*/
int zta_null_verifier_create(zta_verifier_t **out);

/**
 * @brief Fill a zta_result_t with the given status and reason
 */
/*@
  requires \valid(result);
  assigns result->status, result->reason[0 .. ZTA_REASON_LEN - 1],
          result->timestamp;
  ensures result->status == status;
*/
void zta_result_set(zta_result_t *result, zta_status_t status, const char *reason);

/**
 * @brief Return a human-readable string for a zta_status_t
 */
/*@
  assigns \nothing;
  ensures \result != \null && \valid_read(\result);
*/
const char *zta_status_str(zta_status_t status);

/* Error codes */
#define EZTA_NOCRED  280
DECLARE_ERROR(EZTA_NOCRED, "No credential data provided");

#define EZTA_INTERNAL 281
DECLARE_ERROR(EZTA_INTERNAL, "Internal ZTA verifier error");

#define EZTA_UNSUPPORTED 282
DECLARE_ERROR(EZTA_UNSUPPORTED, "Operation not supported by this verifier");

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTA_VERIFIER_H */
