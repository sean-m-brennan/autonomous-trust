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

#ifndef AT_DTN_H
#define AT_DTN_H

/**
 * @file at_dtn.h
 * @brief The DTN / Bundle Protocol extension (libat_dtn).
 *
 * Linking libat_dtn adds the "dtn_bp" network transport and its process
 * runner to the core; nothing in the core names them. A shared link
 * registers them when the library loads. A static link keeps them only if
 * something references the object, so a program that links at_dtn_static
 * without --whole-archive calls at_dtn_link() once.
 *
 * See doc/architecture/extensions.md and at-over-dtn.md.
 */

/** Keeps DTN's registration constructors in a static link. No-op at run
 *  time. */
void at_dtn_link(void);

#endif /* AT_DTN_H */
