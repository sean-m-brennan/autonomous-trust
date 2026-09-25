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

#ifndef AT_PHYSICS_LINK_H
#define AT_PHYSICS_LINK_H

/**
 * @file at_physics.h
 * @brief The R+D.md §12.2 physical consistency layer (libat_physics).
 *
 * Linking libat_physics registers, through negotiation/neg_oracle.h, the
 * "physics.check" scorer arm (order 100) and the capability ->
 * reported-quantity lookup the calibration and prequential layers settle
 * through. It speaks only when its declaration ($AT_PHYSICS) names a model, so
 * linking or loading it changes nothing on its own; a node that declares the
 * layer without it refuses to start (neg_oracles_check_env).
 *
 * A shared link registers it when the library loads. A static link keeps the
 * registration only if something references the object, so a program that
 * links at_physics_static without --whole-archive calls at_physics_link() once.
 *
 * See doc/architecture/extensions.md and
 * doc/architecture/physical-consistency.md.
 */

/** Keeps the layer's registration constructor in a static link. No-op at run
 *  time. */
void at_physics_link(void);

#endif /* AT_PHYSICS_LINK_H */
