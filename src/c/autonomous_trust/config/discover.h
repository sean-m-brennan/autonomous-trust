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

#ifndef DISCOVER_H
#define DISCOVER_H

/** @addtogroup internal_config
 *  @{
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Filename suffix identifying a config file on disk. */
#define CFG_FILE_EXT ".cfg.json"

/**
 * @brief Extract the config section name embedded in a config-file path.
 *
 * Given a path ending in @ref CFG_FILE_EXT, copies the leading
 * filename stem (the section name) into @p type_out.
 *
 * @param[in]  path      Absolute or relative path to a config file.
 * @param[out] type_out  Destination buffer for the section name.
 * @param[in]  type_len  Size of @p type_out.
 * @return 0 on success, non-zero if @p path does not match the expected
 *         pattern or @p type_out is too small.
 */
int get_cfg_type(const char *path, char *type_out, size_t type_len);

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_config */

#endif  // DISCOVER_H
