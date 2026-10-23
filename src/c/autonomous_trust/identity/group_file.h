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

/** @file The group and its identity history in Python's schema.
 *
 *  `group.cfg.json` is what a node keeps of the group it belongs to, so a
 *  restarted node can rejoin it (RD_14.4 plan, D10). Python writes it through
 *  ConfigJSONEncoder: `[group, {"step_dag": [...], "blacklist": [...]}]`, the
 *  group with underscored fields and a `__type__` tag, each step a tagged
 *  LinkedStep whose uuid, timestamp and payload are themselves tagged. C writes
 *  the same file (the user's call, 2026-10-23), so a config directory is
 *  runtime-neutral, and reads either runtime's.
 *
 *  The same tagged step form is what Python sends as `history_diff`, so the
 *  converters serve that verb too.
 */

#ifndef GROUP_FILE_H
#define GROUP_FILE_H

#include <stdbool.h>
#include <jansson.h>

#include "group.h"
#include "history.h"

/** @p step in Python's tagged LinkedStep form (a new reference), or NULL. */
json_t *step_to_tagged_json(const linked_step_t *step);

/** A step from Python's tagged form or C's plain {uuid, timestamp, payload}
 *  form. @return 0, or an errno-style code. */
int step_from_any_json(const json_t *obj, linked_step_t **step_out);

/** @p g in Python's tagged Group form (a new reference), or NULL. */
json_t *group_to_tagged_json(const group_t *g);

/** A group from Python's tagged form or C's flat canonical form, into
 *  @p out (zeroed first). @return 0, or -1 when it is neither. */
int group_from_any_json(const json_t *obj, group_t *out);

/** The path of `group.cfg.json` in the config directory into @p out.
 *  @return 0, or -1 when it does not fit. */
int group_file_path(char *out, size_t cap);

/** Write `[group, {"step_dag": steps, "blacklist": []}]` to @p path, atomically
 *  (write then rename). @p steps is a JSON array of tagged steps (borrowed).
 *  The blacklist is not carried: C's {uuid, address} entries have no form
 *  Python reads back. @return 0, or -1. */
int group_file_write(const char *path, const group_t *g, json_t *steps);

/** Read @p path into @p g_out and @p steps_out (a new reference to the
 *  `step_dag` array, as written, possibly empty). @return 0, or -1 when the
 *  file is absent or unreadable. */
int group_file_read(const char *path, group_t *g_out, json_t **steps_out);

#endif /* GROUP_FILE_H */
