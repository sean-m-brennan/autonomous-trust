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

#include "negotiation/neg_replay.h"

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "utilities/util.h"   /* at_strlcpy */

void neg_trace_free(neg_trace_t *trace)
{
    if (trace == NULL)
        return;
    for (int i = 0; i < trace->n; i++)
        free(trace->states[i]);
    free(trace->states);
    trace->states = NULL;
    trace->n = 0;
}

static int _push(neg_trace_t *trace, const char *state)
{
    char *copy = strdup(state);
    if (copy == NULL)
        return -1;
    trace->states[trace->n++] = copy;
    return 0;
}

int neg_replay_run(const capability_replay_t *replay, const char *kwargs_json,
                   neg_trace_t *trace, char *result, size_t result_len)
{
    if (replay == NULL || replay->init == NULL || replay->step == NULL
        || trace == NULL || result == NULL || result_len == 0)
        return -1;
    trace->n = 0;
    trace->states = calloc(NEG_REPLAY_MAX_STEPS, sizeof(char *));
    char *cur = calloc(1, NEG_REPLAY_STATE_MAX + 1);
    char *next = calloc(1, NEG_REPLAY_STATE_MAX + 1);
    int rc = -1;
    if (trace->states == NULL || cur == NULL || next == NULL)
        goto out;
    if (replay->init(kwargs_json, cur, NEG_REPLAY_STATE_MAX + 1) != 0
        || _push(trace, cur) != 0)
        goto out;
    for (int i = 1;; i++)
    {
        next[0] = '\0';
        int more = replay->step(cur, i, next, NEG_REPLAY_STATE_MAX + 1);
        if (more < 0)
            goto out;
        if (more == 0)
            break;
        if (trace->n >= NEG_REPLAY_MAX_STEPS || _push(trace, next) != 0)
            goto out;   /* past the game's bound: not a replayable answer */
        char *t = cur;
        cur = next;
        next = t;
    }
    if (replay->result != NULL)
        rc = replay->result(cur, result, result_len) == 0 ? 0 : -1;
    else
        rc = at_strlcpy(result, cur, result_len) < result_len ? 0 : -1;
out:
    free(cur);
    free(next);
    if (rc != 0)
        neg_trace_free(trace);
    return rc;
}

bool neg_trace_digest(const neg_trace_t *trace, int index,
                      char out[NEG_REPLAY_HASH_HEX_LEN + 1])
{
    if (trace == NULL || index < 0 || index >= trace->n)
        return false;
    char prev[NEG_REPLAY_HASH_HEX_LEN + 1] = {0};
    for (int i = 0; i <= index; i++)
    {
        crypto_generichash_state st;
        unsigned char digest[32];
        crypto_generichash_init(&st, NULL, 0, sizeof(digest));
        if (i > 0)
            crypto_generichash_update(&st, (const unsigned char *)prev,
                                      NEG_REPLAY_HASH_HEX_LEN);
        crypto_generichash_update(&st, (const unsigned char *)trace->states[i],
                                  strlen(trace->states[i]));
        crypto_generichash_final(&st, digest, sizeof(digest));
        sodium_bin2hex(prev, sizeof(prev), digest, sizeof(digest));
    }
    memcpy(out, prev, sizeof(prev));
    return true;
}
