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

#ifndef AUTONOMOUS_TRUST_IDENTITY_SOCIAL_STORE_H
#define AUTONOMOUS_TRUST_IDENTITY_SOCIAL_STORE_H

/**
 * @file social_store.h
 * @brief Durable local moderation state: `etc/at/social.cfg.json`.
 *
 * WHY THIS EXISTS. Until Phase 4 P4.1 no social state was persisted at all —
 * the five files `doc/architecture/persistent-cohort.md` lists do not include
 * one, and `connection_edges` is equally in-memory. A block could live with
 * that only for as long as a block did nothing; now that it gates every
 * inbound path, a restart silently restoring a blocked peer's reach is a
 * moderation failure, not a cache miss. The person blocked someone and the
 * daemon forgot.
 *
 * WHY IN THE CORE AND NOT THE APP. Every enforcement point is inside the core.
 * An app-side store (the `TieSettingsStore` idiom, which is right for tie
 * weights and the attention budget) would leave a window between `agorad`
 * starting and the app's first replay, during which a blocked peer's DMs and
 * posts land — and `agorad` is a standalone daemon the GUI spawns, so that
 * window is real. It must also work headless, and the conformance harness runs
 * the core with no Dart at all, which would make an app-side store unpinnable.
 * A block is a core enforcement INPUT, not an app-domain value.
 *
 * NOT ENCRYPTED: it sits beside `peers.cfg.json`, which already carries the
 * peer roster, so it discloses nothing that directory does not.
 *
 * Both runtimes must write this file BYTE-IDENTICALLY for the same block set —
 * `JSON_INDENT(2) | JSON_SORT_KEYS` here, `indent=2, sort_keys=True` in Python.
 * `test/social_store_test.c` and `tests/a_unit/test_social_store.py` hold the
 * same golden document, so a drift on either side fails exactly one of them.
 * NOT a conformance case: a live block stamps the wall clock, so two runtimes
 * blocking the same peer legitimately write different `at` values, and
 * comparing live files would be comparing clocks.
 */

#include <stdbool.h>
#include <stddef.h>

#include "structures/map.h"

/** The file, beside the other config documents in `etc/at`. */
#define AT_SOCIAL_FILENAME "social.cfg.json"

/** Schema version written into the document.
 *
 * The shape is `{"version": 1, "blocks": {"<uuid>": {"at": <epoch>,
 * "reason": ""}}}`. A MAP rather than an array so an unblock is a delete and a
 * rewrite is idempotent; a top-level `blocks` key beside `version` so box 5's
 * per-community content policy can add a sibling without a migration.
 */
#define AT_SOCIAL_STORE_VERSION 1

/**
 * Load the block set from `<cfg_dir>/social.cfg.json` into @p blocks.
 *
 * @p blocks is REPLACED, not merged. A missing file yields an empty store and
 * returns 0 — that is the ordinary first-boot case, not an error. A malformed
 * file returns -1 and leaves @p blocks empty, so a corrupt store fails toward
 * "nobody is blocked" rather than toward an arbitrary subset; the caller logs
 * it, and the operator can see their blocks are gone rather than having some
 * of them silently work.
 *
 * @return 0 on success (including "no file"), -1 on a malformed document.
 */
int social_store_load(const char *cfg_dir, map_t *blocks);

/**
 * Write @p blocks to `<cfg_dir>/social.cfg.json`.
 *
 * Atomic: dumped to a temp sibling and renamed over the target, so a reader or
 * a crash never sees a torn file. Called on every mutation rather than at
 * shutdown — the C identity process has no tail-of-loop flush (the Python
 * SIGTERM path `persistent-cohort.md` §3 describes has no C twin), and a block
 * that survives only a graceful stop is not much of a block.
 *
 * @return 0 on success, -1 on any failure.
 */
int social_store_save(const map_t *blocks, const char *cfg_dir);

#endif /* AUTONOMOUS_TRUST_IDENTITY_SOCIAL_STORE_H */
