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

#ifndef AT_ZTA_H
#define AT_ZTA_H

/**
 * @file at_zta.h
 * @brief Zero Trust credential integration as an extension library
 *        (libat_zta, FEATURE_SPLIT_PLAN Phase 6).
 *
 * Linking libat_zta registers, from constructors:
 *   - the identity extension "zta" (zta_identity.c): the admission gate, the
 *     join and gateway checks, the operator-credential re-verify and the
 *     co-signer anchor check reputation asks for (identity/id_ext.h);
 *   - the "zta_policy" configuration section (zta_policy.c);
 *   - the zta_verify process (zta_process.c);
 *   - the ZTA message types (zta_msg_types.c) and its errors.
 *
 * Linking it changes nothing on its own: a node enforces ZTA only when its
 * zta_policy.cfg.json enables it. A node whose policy enables ZTA without
 * this library refuses to start (identity_ext_check_config).
 *
 * A shared link registers everything when the library loads. A static link
 * keeps the objects only if something references them, so a program that
 * links at_zta_static without --whole-archive calls at_zta_link() once.
 *
 * See doc/architecture/extensions.md and zta-integration.md.
 */

/** Keeps every ZTA registration in a static link. No-op at run time. */
void at_zta_link(void);

#endif /* AT_ZTA_H */
