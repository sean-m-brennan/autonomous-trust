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

#include "identity/social_tx.h"

#include <string.h>
#include <sodium.h>

int at_social_task_uuid(const char *domain, const uuid_t a, const uuid_t b,
                        const uint8_t *tail, size_t tail_len, uuid_t out)
{
    if (domain == NULL || out == NULL) return -1;
    if (tail == NULL && tail_len != 0) return -1;

    /* Order the two uuids so the derivation is independent of which peer runs it. */
    const unsigned char *lo = a;
    const unsigned char *hi = b;
    if (uuid_compare(a, b) > 0) { lo = b; hi = a; }

    /* canonical = domain || 0x00 || uuid_min[16] || uuid_max[16] || tail */
    size_t dlen = strlen(domain);
    size_t need = dlen + 1 + sizeof(uuid_t) + sizeof(uuid_t) + tail_len;
    uint8_t canon[128];
    if (need > sizeof(canon)) return -1;

    size_t off = 0;
    memcpy(canon + off, domain, dlen); off += dlen;
    canon[off++] = 0x00;
    memcpy(canon + off, lo, sizeof(uuid_t)); off += sizeof(uuid_t);
    memcpy(canon + off, hi, sizeof(uuid_t)); off += sizeof(uuid_t);
    if (tail_len > 0) { memcpy(canon + off, tail, tail_len); off += tail_len; }

    unsigned char digest[crypto_generichash_BYTES];   /* 32 */
    crypto_generichash(digest, sizeof(digest), canon, off, NULL, 0);
    memcpy(out, digest, sizeof(uuid_t));              /* first 16 bytes */
    return 0;
}

double at_social_pos_score(int count)
{
    if (count < 1) count = 1;
    double s = AT_SOCIAL_POS_BASELINE + AT_SOCIAL_POS_DELTA / (double)count;
    if (s > 1.0) s = 1.0;
    if (s < 0.0) s = 0.0;
    return s;
}
