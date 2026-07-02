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

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bootstrap/bootstrap_capabilities.h"

const char *const BOOTSTRAP_CAPABILITY_NAMES[BOOTSTRAP_CAPABILITY_COUNT] = {
    "at.handshake",
    "at.time-attest",
    "at.echo-challenge",
};

/* ---------------------------------------------------------------
 * Server-side capability functions.
 * --------------------------------------------------------------- */

long at_handshake(long nonce)
{
    return nonce + 1;
}

double at_time_attest(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (double)time(NULL);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

char *at_echo_challenge(const char *payload)
{
    const char *src = (payload != NULL) ? payload : "";
    size_t n = strlen(src);
    char *out = malloc(n + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, src, n + 1);
    return out;
}

/* ---------------------------------------------------------------
 * Client-side verifiers.
 * --------------------------------------------------------------- */

double verify_handshake(long result, long sent_nonce)
{
    return (result == sent_nonce + 1) ? 0.9 : 0.1;
}

double verify_time_attest(double result, double requestor_now, double tolerance)
{
    /* Non-finite inputs are the C analog of Python's unparseable result. */
    if (!isfinite(result) || !isfinite(requestor_now))
        return 0.1;
    double delta = fabs(result - requestor_now);
    return (delta < tolerance) ? 0.9 : 0.5;
}

double verify_echo(const char *result, const char *sent_payload)
{
    if (result == NULL || sent_payload == NULL)
        return 0.1;
    return (strcmp(result, sent_payload) == 0) ? 0.9 : 0.1;
}

/* ---------------------------------------------------------------
 * Registration.
 * --------------------------------------------------------------- */

int register_bootstrap_capabilities(bootstrap_capability_t *out)
{
    if (out == NULL)
        return -1;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++) {
        out[i].name = BOOTSTRAP_CAPABILITY_NAMES[i];
        out[i].required_tier = 0;
        out[i].transaction_weight = 1;
    }
    return BOOTSTRAP_CAPABILITY_COUNT;
}
