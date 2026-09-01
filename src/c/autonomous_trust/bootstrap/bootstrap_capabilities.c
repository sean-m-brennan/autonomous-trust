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

#include <jansson.h>

#include "bootstrap/bootstrap_capabilities.h"
#include "processes/capabilities.h"   /* DECLARE_CAPABILITY */
#include "utilities/util.h"           /* at_strlcpy */

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
 * Probe dispatch (R+D.md §12.7)
 * --------------------------------------------------------------- */

bool is_probe_capability(const char *cap_name)
{
    if (cap_name == NULL)
        return false;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        if (strcmp(cap_name, BOOTSTRAP_CAPABILITY_NAMES[i]) == 0)
            return true;
    return false;
}

double time_attest_tolerance(void)
{
    const char *raw = getenv("AT_TIME_ATTEST_TOLERANCE_SEC");
    if (raw == NULL || raw[0] == '\0')
        return AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC;
    char *end = NULL;
    double value = strtod(raw, &end);
    /* Reject trailing garbage, non-finite, and non-positive alike: a
     * tolerance of 0 or below would score every peer 0.5 forever, which is
     * a quieter failure than falling back to the documented default. */
    if (end == raw || !isfinite(value) || value <= 0.0)
        return AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC;
    return value;
}

bool verify_bootstrap_result(const char *cap_name,
                            double result_num, const char *result_str,
                            const probe_challenge_t *challenge,
                            double requestor_now, double *score_out)
{
    if (cap_name == NULL || score_out == NULL)
        return false;

    if (strcmp(cap_name, "at.handshake") == 0) {
        /* A missing challenge means a nonce of 0, matching at_handshake's own
         * default, so an unstamped probe still expects 1 rather than
         * accepting anything. */
        long sent = (challenge != NULL) ? challenge->nonce : 0;
        /* The answer is an integer on the wire; a non-integral or non-finite
         * numeric result is the C analog of Python's unparseable and cannot
         * equal sent+1, so it lands on 0.1 through the same comparison. */
        if (!isfinite(result_num)) {
            *score_out = 0.1;
            return true;
        }
        *score_out = verify_handshake((long)result_num, sent);
        return true;
    }
    if (strcmp(cap_name, "at.time-attest") == 0) {
        double now_sec = (requestor_now > 0.0) ? requestor_now : at_time_attest();
        *score_out = verify_time_attest(result_num, now_sec,
                                        time_attest_tolerance());
        return true;
    }
    if (strcmp(cap_name, "at.echo-challenge") == 0) {
        const char *sent = (challenge != NULL) ? challenge->payload : NULL;
        /* An empty expected payload is what at_echo_challenge(NULL) echoes,
         * so treat an absent challenge string as "" rather than refusing to
         * score -- otherwise a probe issued with no payload is unverifiable. */
        *score_out = verify_echo(result_str, (sent != NULL) ? sent : "");
        return true;
    }
    return false;
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

/* ---------------------------------------------------------------
 * Responder-side executors + capability-table declarations.
 * --------------------------------------------------------------- */

bool bootstrap_capabilities_enabled(void)
{
    const char *dis = getenv("AT_BOOTSTRAP_DISABLED");
    return !(dis != NULL && dis[0] != '\0' && strcmp(dis, "0") != 0);
}

/* Read one keyword argument out of the compact-JSON blob the invitation
 * carried. Absent, unparseable, or the wrong type all read as "not supplied",
 * which each executor turns into its documented default -- a responder that
 * cannot see the challenge answers the default one and is scored for a wrong
 * answer, which is the honest outcome and not something to paper over. */
static json_t *_kwarg(const char *kwargs_json, const char *key, json_t **root)
{
    *root = NULL;
    if (kwargs_json == NULL || kwargs_json[0] == '\0')
        return NULL;
    json_error_t jerr;
    json_t *kw = json_loads(kwargs_json, 0, &jerr);
    if (kw == NULL)
        return NULL;
    if (!json_is_object(kw)) {
        json_decref(kw);
        return NULL;
    }
    *root = kw;
    return json_object_get(kw, key);   /* borrowed from *root */
}

int at_handshake_exec(const char *kwargs_json, char *result_out,
                      size_t result_len)
{
    if (result_out == NULL || result_len == 0)
        return -1;
    json_t *root = NULL;
    json_t *j_nonce = _kwarg(kwargs_json, "nonce", &root);
    long nonce = 0;
    if (j_nonce != NULL && json_is_integer(j_nonce))
        nonce = (long)json_integer_value(j_nonce);
    if (root != NULL)
        json_decref(root);
    int n = snprintf(result_out, result_len, "%ld", at_handshake(nonce));
    return (n > 0 && (size_t)n < result_len) ? 0 : -1;
}

int at_time_attest_exec(const char *kwargs_json, char *result_out,
                        size_t result_len)
{
    (void)kwargs_json;
    if (result_out == NULL || result_len == 0)
        return -1;
    /* Milliseconds: the requestor compares against its own clock with a
     * tolerance measured in tenths of a second (AT_TIME_ATTEST_TOLERANCE_SEC),
     * so more precision than this would be noise -- and %f's six decimals
     * would spend bytes on it. */
    int n = snprintf(result_out, result_len, "%.3f", at_time_attest());
    return (n > 0 && (size_t)n < result_len) ? 0 : -1;
}

int at_echo_challenge_exec(const char *kwargs_json, char *result_out,
                           size_t result_len)
{
    if (result_out == NULL || result_len == 0)
        return -1;
    json_t *root = NULL;
    json_t *j_payload = _kwarg(kwargs_json, "payload", &root);
    const char *payload = "";
    if (j_payload != NULL && json_is_string(j_payload))
        payload = json_string_value(j_payload);
    int rc = 0;
    char *echoed = at_echo_challenge(payload);
    if (echoed == NULL) {
        rc = -1;
    } else if (strlen(echoed) >= result_len) {
        /* Refuse rather than echo a prefix: a truncated echo is a wrong
         * answer, and the requestor would score it 0.1 as tampering when the
         * real fault is on this side. */
        rc = -1;
    } else {
        at_strlcpy(result_out, echoed, result_len);
    }
    free(echoed);
    if (root != NULL)
        json_decref(root);
    return rc;
}

/* Advertise the three bootstrap capabilities so a peer's capability matrix
 * shows them and an invitation can be accepted and executed. Python registers
 * these at runtime in Automate.__init__ (gated on AT_BOOTSTRAP_DISABLED); C's
 * table is generated statically by preprocess.py from these call sites, so the
 * gate lives in build_local_capabilities and the job drain instead.
 *
 * NULL void-function, executor supplied: these produce an answer, and an
 * answer is the whole point of a known-answer probe. */
DECLARE_CAPABILITY(at.handshake, NULL, at_handshake_exec);
DECLARE_CAPABILITY(at.time-attest, NULL, at_time_attest_exec);
DECLARE_CAPABILITY(at.echo-challenge, NULL, at_echo_challenge_exec);
