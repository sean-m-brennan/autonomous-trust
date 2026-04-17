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

#ifndef ZTA_PROTOCOL_H
#define ZTA_PROTOCOL_H

/** @addtogroup internal_zta
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ZTA protocol message function names
 *
 * These are used in the network message 'function' field to identify
 * ZTA-specific protocol messages exchanged between peers.
 */
#define ZTA_PROTO_REVOCATION_ALERT  "zta_revoked"     /* Alert group about a revocation */
#define ZTA_PROTO_VERIFICATION      "zta_verified"    /* Share verification result */
#define ZTA_PROTO_REVERIFY_REQ      "zta_reverify"    /* Request peers to re-verify a peer */

#ifdef __cplusplus
} /* extern "C" */
#endif


/** @} */ /* end of internal_zta */

#endif /* ZTA_PROTOCOL_H */
