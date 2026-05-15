/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

#ifndef AT_PROBES_H
#define AT_PROBES_H

/** @addtogroup internal_probes
 *  @{
 *
 *  Optional debug-probes facade — C port of `_probes/` in
 *  `core/_python/`.
 *
 *  All public functions become no-ops when the `AT_PROBES` env var is
 *  unset (or set to a falsy value: empty / "0" / "false" / "no" /
 *  "off"). Call sites pay only the cost of a function-call indirection
 *  in that case, so it is safe to leave instrumentation in production
 *  builds.
 *
 *  When enabled, events are written as JSON Lines (one JSON object per
 *  line) to a per-process file in `$AT_PROBES_DIR`
 *  (default `/var/at-probes`):
 *
 *      probes_<host>_pid<pid>_<YYYYmmddTHHMMSS>.jsonl
 *
 *  Counters aggregate `(layer, event, reason)` tuples in-process and
 *  emit deltas as a single 'counters'/'snapshot' record every
 *  `AT_PROBES_COUNTER_SEC` seconds (default 5.0). Downstream tools sum
 *  deltas to recover totals — this keeps file size proportional to
 *  event activity rather than to wall time.
 *
 *  Failures are silent. A probe must never break the run it is
 *  observing; if the writer thread dies, the rest of the system keeps
 *  going.
 */

#include <stdbool.h>
#include <stddef.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

/** True iff `AT_PROBES` is set to a truthy value at process start.
 *  Cached once on first call; subsequent calls return the cached value. */
bool probes_enabled(void);

/** Emit a structured event with extra fields supplied as a JSON object.
 *  The caller retains ownership of @p fields (this function takes a
 *  reference) — callers may pass NULL. Layer and event must be
 *  non-NULL. */
void probes_emit(const char *layer, const char *event, json_t *fields);

/** Emit a structured event with key/value string pairs, terminated by a
 *  trailing NULL. Both keys and values must be C strings:
 *
 *      probes_emit_kv("peer.set", "add_request",
 *                     "peer_uuid", uuid_str,
 *                     "source", "peer_accepted",
 *                     NULL);
 *
 *  Mirrors Python's `_probes.emit(layer, event, **kwargs)` ergonomic. */
void probes_emit_kv(const char *layer, const char *event, ...);

/** Increment the `(layer, event, reason)` counter. `reason` may be
 *  NULL — it is normalized to the empty string. Counters snapshot
 *  automatically every `AT_PROBES_COUNTER_SEC` seconds. */
void probes_counter(const char *layer, const char *event, const char *reason);

/** Increment the counter by @p n. */
void probes_counter_n(const char *layer, const char *event,
                      const char *reason, long n);

/** Force-emit the current counter bag and drain the writer queue.
 *  Useful on shutdown or before a hard transition. */
void probes_flush(void);

/** @} */ /* end of internal_probes */

#ifdef __cplusplus
}
#endif

#endif  /* AT_PROBES_H */
