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

#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "negotiation/neg_certified.h"
#include "utilities/util.h"   /* at_strlcpy */

uint64_t at_cert_verifier_seed(void)
{
    uint64_t seed = 0;
    randombytes_buf(&seed, sizeof(seed));
    return seed;
}

/****************************
 * Producing a witness
 ****************************/

#define AT_CERT_WRAPPER_KEY "at_certified"

bool at_cert_split_result(const char *result_json,
                          char *value_out, size_t value_len,
                          char *cert_out, size_t cert_len)
{
    if (value_out != NULL && value_len > 0)
        value_out[0] = '\0';
    if (cert_out != NULL && cert_len > 0)
        cert_out[0] = '\0';
    if (result_json == NULL || result_json[0] == '\0')
        return false;

    /* Unwrapped is the overwhelmingly common case and must cost nothing: a
     * result that is not even JSON is an ordinary answer, not an error. */
    json_error_t jerr;
    json_t *root = json_loads(result_json, JSON_DECODE_ANY, &jerr);
    json_t *wrapper = json_is_object(root)
        ? json_object_get(root, AT_CERT_WRAPPER_KEY) : NULL;
    if (!json_is_object(wrapper))
    {
        if (root != NULL)
            json_decref(root);
        if (value_out != NULL && value_len > 0)
            at_strlcpy(value_out, result_json, value_len);
        return false;
    }

    bool ok = true;
    json_t *value = json_object_get(wrapper, "value");
    json_t *cert = json_object_get(wrapper, "certificate");
    if (value_out != NULL && value_len > 0)
    {
        char *dumped = (value != NULL)
            ? json_dumps(value, JSON_COMPACT | JSON_ENCODE_ANY) : NULL;
        if (dumped != NULL)
        {
            if (strlen(dumped) >= value_len)
                ok = false;
            else
                at_strlcpy(value_out, dumped, value_len);
            free(dumped);
        }
    }
    if (cert_out != NULL && cert_len > 0 && json_is_object(cert))
    {
        char *dumped = json_dumps(cert, JSON_COMPACT);
        if (dumped != NULL)
        {
            if (strlen(dumped) >= cert_len)
                ok = false;
            else
                at_strlcpy(cert_out, dumped, cert_len);
            free(dumped);
        }
    }
    json_decref(root);
    return ok;
}

bool at_cert_wrap_result(const char *value_json, const char *certificate_json,
                         char *out, size_t out_len)
{
    if (out == NULL || out_len == 0)
        return false;
    out[0] = '\0';
    json_error_t jerr;
    json_t *value = (value_json != NULL && value_json[0] != '\0')
        ? json_loads(value_json, JSON_DECODE_ANY, &jerr) : json_null();
    json_t *cert = (certificate_json != NULL && certificate_json[0] != '\0')
        ? json_loads(certificate_json, 0, &jerr) : NULL;
    if (value == NULL)
    {
        if (cert != NULL)
            json_decref(cert);
        return false;
    }
    json_t *wrapper = json_object();
    json_t *root = json_object();
    if (wrapper == NULL || root == NULL)
    {
        json_decref(value);
        if (cert != NULL)
            json_decref(cert);
        if (wrapper != NULL)
            json_decref(wrapper);
        if (root != NULL)
            json_decref(root);
        return false;
    }
    json_object_set_new(wrapper, "value", value);
    if (cert != NULL)
        json_object_set_new(wrapper, "certificate", cert);
    json_object_set_new(root, AT_CERT_WRAPPER_KEY, wrapper);
    char *dumped = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (dumped == NULL)
        return false;
    bool ok = strlen(dumped) < out_len;
    if (ok)
        at_strlcpy(out, dumped, out_len);
    free(dumped);
    return ok;
}
