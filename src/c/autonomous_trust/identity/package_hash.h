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

#ifndef AT_PACKAGE_HASH_H
#define AT_PACKAGE_HASH_H

/**
 * @file package_hash.h
 * @brief What software a node says it runs, and the allowlist admission
 *        checks it against (doc/architecture/identity-protocol.md,
 *        "Package-hash verification").
 *
 * A hash travels in slot 0 of request_access and access_granted, tagged by
 * runtime: this runtime sends "c:<hex>", blake2b-256 over the file that holds
 * libautonomous_trust's code (the shared library, or the executable it is
 * statically linked into); a Python node sends its source digest as bytes,
 * read here as "py:<hex>". Hashes from different runtimes never compare
 * equal, so equality alone cannot gate a mixed group.
 *
 * The gate is an allowlist, `etc/at/package_hashes.cfg.json`:
 * `{"accepted": ["c:...", "py:..."]}`. When the file is present a peer must
 * present a listed hash, and an empty one is refused. When it is absent this
 * runtime admits as it always did (it had no check), so turning the gate on is
 * a deployment decision, made by shipping the file.
 *
 * What it does and does not prove: the hash is SELF-REPORTED. It turns away a
 * modified build that reports what it is; a build modified to report the
 * honest hash is admitted. What holds against that build is that nothing it
 * signs can raise its own standing or erase a finding against it
 * (doc/architecture/reputation.md, "Verifier-attested scores").
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

/** "c:" + 64 hex. */
#define AT_PACKAGE_HASH_LEN (2 + 64)
#define AT_PACKAGE_HASHES_FILE "package_hashes.cfg.json"

/**
 * @brief This node's tagged package hash, computed once and cached.
 * @return the tagged hash, or "" when the image could not be read.
 */
const char *at_package_hash(void);

/**
 * @brief A peer's slot-0 value as a tagged hash: a JSON string as is (an
 *        untagged one is left untagged, and so never listed), Python's
 *        `{"__type__": "bytes", "__value__": <base64>}` as "py:<hex>",
 *        anything else as "".
 */
void at_package_hash_of_json(const json_t *slot, char *out, size_t cap);

/**
 * @brief Whether @p tagged is in @p allowlist, the parsed
 *        package_hashes.cfg.json. Pure; exposed for tests.
 */
bool at_package_hash_listed(const json_t *allowlist, const char *tagged);

/**
 * @brief The admission decision for a peer that presented @p tagged.
 *
 * True with no allowlist file (the old behaviour). With one, true only for a
 * listed hash; otherwise false with the reason in @p why.
 */
bool at_package_hash_admissible(const char *tagged, char *why, size_t why_cap);

#endif /* AT_PACKAGE_HASH_H */
