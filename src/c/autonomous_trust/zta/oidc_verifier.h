/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef OIDC_VERIFIER_H
#define OIDC_VERIFIER_H

/** @addtogroup internal_zta
 *  @{
 */

#include "zta_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create an OIDC verifier stub
 *
 * This is a placeholder that returns ZTA_UNAVAILABLE for all operations.
 * It validates the verifier interface design for token-based credential
 * types without implementing the full OIDC flow.
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
int oidc_verifier_create(zta_verifier_t **out);

#ifdef __cplusplus
} /* extern "C" */
#endif


/** @} */ /* end of internal_zta */

#endif /* OIDC_VERIFIER_H */
