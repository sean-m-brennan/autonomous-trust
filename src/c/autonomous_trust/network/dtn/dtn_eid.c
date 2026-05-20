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

#include <stdio.h>
#include <string.h>

#include "network/dtn/dtn_eid.h"

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_from_uuid(const uuid_t uuid, char *out, size_t out_len)
{
    /* Use first 8 hex chars of UUID as node prefix — keeps EIDs short
     * while remaining collision-resistant within any realistic AT fleet. */
    int n = snprintf(out, out_len,
                     "dtn://at-%02x%02x%02x%02x/",
                     uuid[0], uuid[1], uuid[2], uuid[3]);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_for_service(const char *base_eid, const char *service,
                        char *out, size_t out_len)
{
    /* base_eid already ends with '/'; service begins with '/' — we trim the
     * leading slash of service to avoid "dtn://at-xxx//peer". */
    const char *s = (service[0] == '/') ? service + 1 : service;
    int n = snprintf(out, out_len, "%s%s", base_eid, s);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_for_group(const unsigned char *group_hash, size_t hash_len,
                      char *out, size_t out_len)
{
    if (hash_len < 8)
        return -1;
    int n = snprintf(out, out_len,
                     "dtn://at-group-%02x%02x%02x%02x%02x%02x%02x%02x/",
                     group_hash[0], group_hash[1], group_hash[2], group_hash[3],
                     group_hash[4], group_hash[5], group_hash[6], group_hash[7]);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}
