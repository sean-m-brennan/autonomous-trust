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

#include "identity/dm.h"
#include "utilities/msg_types.h"

#include <string.h>

/* The DM body bound is spelled once per header (self-contained like profile.h);
 * a drift between them would corrupt the app-boundary buffer, so tie them here
 * where both are visible (the profile bounds rely on a matching "MUST match"
 * comment; the DM bound is small enough to also pin at compile time). */
_Static_assert(AT_DM_TEXT_MAX == AT_DM_TEXT_LEN,
               "AT_DM_TEXT_MAX (dm.h) out of sync with AT_DM_TEXT_LEN (msg_types.h)");

size_t at_dm_bound_text(const char *in, char *out, size_t out_sz)
{
    if (out == NULL || out_sz == 0) return 0;
    if (in == NULL) { out[0] = '\0'; return 0; }
    size_t cap = AT_DM_TEXT_MAX;
    if (out_sz - 1 < cap) cap = out_sz - 1;
    size_t n = strnlen(in, cap);
    memcpy(out, in, n);
    out[n] = '\0';
    return n;
}

json_t *at_dm_to_json(const char *text, int64_t seq, double ts)
{
    char bounded[AT_DM_TEXT_MAX + 1];
    at_dm_bound_text(text, bounded, sizeof(bounded));
    json_t *env = json_object();
    if (env == NULL) return NULL;
    if (json_object_set_new(env, "text", json_string(bounded)) != 0
        || json_object_set_new(env, "seq", json_integer((json_int_t)seq)) != 0
        || json_object_set_new(env, "ts", json_real(ts)) != 0) {
        json_decref(env);
        return NULL;
    }
    return env;
}

int at_dm_from_json(const json_t *obj, char *text_out, size_t text_sz,
                    int64_t *seq_out, double *ts_out)
{
    if (text_out != NULL && text_sz > 0) text_out[0] = '\0';
    if (obj == NULL || !json_is_object(obj)) return -1;
    const json_t *j_text = json_object_get(obj, "text");
    const json_t *j_seq  = json_object_get(obj, "seq");
    const json_t *j_ts   = json_object_get(obj, "ts");
    /* seq must be a real integer (a stripped/unstamped DM is refused, mirroring
     * the profile/connection responses); ts must be numeric; text a string. */
    if (!json_is_string(j_text) || !json_is_integer(j_seq)
        || !json_is_number(j_ts))
        return -1;
    at_dm_bound_text(json_string_value(j_text), text_out, text_sz);
    if (seq_out != NULL) *seq_out = (int64_t)json_integer_value(j_seq);
    if (ts_out != NULL) *ts_out = json_number_value(j_ts);
    return 0;
}
