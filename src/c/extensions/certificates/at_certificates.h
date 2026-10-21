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

#ifndef AT_CERTIFICATES_LINK_H
#define AT_CERTIFICATES_LINK_H

/**
 * @file at_certificates.h
 * @brief The R+D.md §12.3 certificate-carrying interfaces layer
 *        (libat_certificates).
 *
 * Linking libat_certificates registers, through negotiation/neg_oracle.h, the
 * "certificates.check" scorer arm (order 300). The witness wire format
 * (negotiation/neg_certified.h) stays in the core. It speaks only when its
 * declaration ($AT_CERTIFICATES) names a model, so linking or loading it
 * changes nothing on its own; a node that declares the layer without it refuses
 * to start (neg_oracles_check_env).
 *
 * A shared link registers it when the library loads. A static link keeps the
 * registration only if something references the object, so a program that links
 * at_certificates_static without --whole-archive calls at_certificates_link()
 * once.
 *
 * See doc/architecture/extensions.md and
 * doc/architecture/certificate-interfaces.md.
 */

/** Keeps the layer's registration constructor in a static link. No-op at run
 *  time. */
void at_certificates_link(void);

#endif /* AT_CERTIFICATES_LINK_H */
