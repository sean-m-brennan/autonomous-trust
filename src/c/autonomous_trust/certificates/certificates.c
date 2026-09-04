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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "certificates/certificates.h"
#include "certificates/checkers.h"
#include "utilities/util.h"   /* at_strlcpy */

#define AT_CERTIFICATES_ENV "AT_CERTIFICATES"

const char *const at_cert_checker_kinds[] = {
    "lp",
    "sat",
    "path",
    "linear_solve",
    "matrix_product",
    "schedule",
    "flow",
    "state_estimation",
    NULL,
};

int at_cert_checker_kind_count(void)
{
    int n = 0;
    while (at_cert_checker_kinds[n] != NULL)
        n++;
    return n;
}

bool at_cert_checker_known(const char *kind)
{
    if (kind == NULL)
        return false;
    for (int i = 0; at_cert_checker_kinds[i] != NULL; i++)
    {
        if (strcmp(at_cert_checker_kinds[i], kind) == 0)
            return true;
    }
    return false;
}

static void _err(char *buf, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _err(char *buf, size_t len, const char *fmt, ...)
{
    if (buf == NULL || len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);
}

static bool _num_field(json_t *obj, const char *key, double *out)
{
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v) || json_is_boolean(v))
        return false;
    if (json_is_real(v))
        *out = json_real_value(v);
    else if (json_is_integer(v))
        *out = (double)json_integer_value(v);
    else
        return false;
    return true;
}

/* An optional boolean, defaulting to @p dflt. Returns false when the key is
 * present but is NOT a boolean, which is a declaration error rather than a
 * value to coerce -- "required": "yes" must not read as true. */
static bool _bool_field(json_t *obj, const char *key, bool dflt, bool *out,
                        bool *malformed)
{
    *malformed = false;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v))
    {
        *out = dflt;
        return true;
    }
    if (!json_is_boolean(v))
    {
        *malformed = true;
        return false;
    }
    *out = json_is_true(v);
    return true;
}

bool at_cert_model_parse(const char *json_text, at_cert_model_t *out,
                         char *err, size_t errlen)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    if (json_text == NULL || json_text[0] == '\0')
        return true;

    json_error_t jerr;
    json_t *root = json_loads(json_text, 0, &jerr);
    if (root == NULL)
    {
        _err(err, errlen, "cannot parse: %s (line %d)", jerr.text, jerr.line);
        return false;
    }
    bool ok = false;
    do
    {
        if (!json_is_object(root))
        {
            _err(err, errlen, "certificate declaration must be an object");
            break;
        }
        json_t *ver = json_object_get(root, "version");
        if (ver != NULL && (!json_is_integer(ver) || json_integer_value(ver) != 1))
        {
            _err(err, errlen, "unsupported declaration version");
            break;
        }
        json_t *caps = json_object_get(root, "capabilities");
        if (caps == NULL || json_is_null(caps))
        {
            ok = true;
            break;
        }
        if (!json_is_object(caps))
        {
            _err(err, errlen, "\"capabilities\" must be an object");
            break;
        }

        bool failed = false;
        const char *name;
        json_t *spec;
        json_object_foreach(caps, name, spec)
        {
            if (out->n_capabilities >= AT_CERT_MAX_CAPABILITIES)
            {
                _err(err, errlen, "more than %d capabilities declared",
                     AT_CERT_MAX_CAPABILITIES);
                failed = true;
                break;
            }
            if (!json_is_object(spec))
            {
                _err(err, errlen, "capability '%s': must be an object", name);
                failed = true;
                break;
            }
            at_cert_capability_t *cap = &out->capabilities[out->n_capabilities];
            memset(cap, 0, sizeof(*cap));
            at_strlcpy(cap->name, name, sizeof(cap->name));

            json_t *checker = json_object_get(spec, "checker");
            if (checker != NULL && !json_is_null(checker))
            {
                if (!json_is_string(checker) ||
                    !at_cert_checker_known(json_string_value(checker)))
                {
                    /* Refused, never degraded to "uncertifiable": a typo that
                     * quietly turned a certified capability into an unchecked
                     * one would be the worst possible failure of this layer,
                     * and it would look exactly like a deliberate null. */
                    _err(err, errlen,
                         "capability '%s': unknown checker '%s'", name,
                         json_is_string(checker) ? json_string_value(checker)
                                                 : "(not a string)");
                    failed = true;
                    break;
                }
                at_strlcpy(cap->checker, json_string_value(checker),
                           sizeof(cap->checker));
            }
            const char *note = json_string_value(json_object_get(spec, "note"));
            if (note != NULL)
                at_strlcpy(cap->note, note, sizeof(cap->note));

            bool malformed = false;
            if (!_bool_field(spec, "required", true, &cap->required, &malformed))
            {
                _err(err, errlen,
                     "capability '%s': \"required\" must be true or false", name);
                failed = true;
                break;
            }
            if (!_bool_field(spec, "require_optimal", true, &cap->require_optimal,
                             &malformed))
            {
                _err(err, errlen,
                     "capability '%s': \"require_optimal\" must be true or false",
                     name);
                failed = true;
                break;
            }

            cap->tolerance = AT_CERT_DEFAULT_TOLERANCE;
            cap->repetitions = 3;
            cap->max_lag = 5;
            cap->bound = 0.2;
            cap->max_proof_len = 100000;
            double v;
            if (_num_field(spec, "tolerance", &v))
            {
                if (v < 0)
                {
                    _err(err, errlen, "capability '%s': tolerance must be >= 0",
                         name);
                    failed = true;
                    break;
                }
                cap->tolerance = v;
            }
            if (_num_field(spec, "repetitions", &v))
            {
                if (v < 1)
                {
                    _err(err, errlen, "capability '%s': repetitions must be >= 1",
                         name);
                    failed = true;
                    break;
                }
                cap->repetitions = (int)v;
            }
            if (_num_field(spec, "max_lag", &v))
            {
                if (v < 1)
                {
                    _err(err, errlen, "capability '%s': max_lag must be >= 1",
                         name);
                    failed = true;
                    break;
                }
                cap->max_lag = (int)v;
            }
            if (_num_field(spec, "bound", &v))
            {
                if (v < 0)
                {
                    _err(err, errlen, "capability '%s': bound must be >= 0", name);
                    failed = true;
                    break;
                }
                cap->bound = v;
            }
            if (_num_field(spec, "max_proof_len", &v))
            {
                if (v < 1)
                {
                    _err(err, errlen,
                         "capability '%s': max_proof_len must be >= 1", name);
                    failed = true;
                    break;
                }
                cap->max_proof_len = (int)v;
            }
            out->n_capabilities++;
        }
        if (failed)
            break;
        ok = true;
    } while (0);

    json_decref(root);
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}

bool at_cert_model_load(const char *path, at_cert_model_t *out,
                        char *err, size_t errlen)
{
    if (out == NULL)
        return false;
    if (path == NULL || path[0] == '\0')
        path = getenv(AT_CERTIFICATES_ENV);
    if (path == NULL || path[0] == '\0')
        return at_cert_model_parse(NULL, out, err, errlen);

    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        _err(err, errlen, "%s names %s, which cannot be opened",
             AT_CERTIFICATES_ENV, path);
        memset(out, 0, sizeof(*out));
        return false;
    }
    char *text = NULL;
    size_t len = 0;
    bool read_ok = false;
    if (fseek(fp, 0, SEEK_END) == 0)
    {
        long size = ftell(fp);
        if (size >= 0 && size < (1 << 22) && fseek(fp, 0, SEEK_SET) == 0)
        {
            text = calloc((size_t)size + 1, 1);
            if (text != NULL)
            {
                len = fread(text, 1, (size_t)size, fp);
                text[len] = '\0';
                read_ok = true;
            }
        }
    }
    fclose(fp);
    if (!read_ok)
    {
        _err(err, errlen, "%s: cannot read the declaration", path);
        free(text);
        memset(out, 0, sizeof(*out));
        return false;
    }
    bool ok = at_cert_model_parse(text, out, err, errlen);
    free(text);
    return ok;
}

const at_cert_capability_t *at_cert_for_capability(const at_cert_model_t *model,
                                                   const char *capability)
{
    if (model == NULL || capability == NULL || capability[0] == '\0')
        return NULL;
    for (int i = 0; i < model->n_capabilities; i++)
    {
        if (strcmp(model->capabilities[i].name, capability) == 0)
            return &model->capabilities[i];
    }
    return NULL;
}

bool at_cert_model_enabled(const at_cert_model_t *model)
{
    return model != NULL && model->n_capabilities > 0;
}

double at_cert_score(at_cert_verdict_t verdict)
{
    switch (verdict)
    {
    case AT_CERT_VALID:
        return AT_CERT_VALID_SCORE;
    case AT_CERT_INVALID:
        return AT_CERT_INVALID_SCORE;
    case AT_CERT_ABSENT:
        return AT_CERT_ABSENT_SCORE;
    case AT_CERT_INDETERMINATE:
    case AT_CERT_NONE:
        break;
    }
    return 0.0;
}

const char *at_cert_verdict_name(at_cert_verdict_t verdict)
{
    switch (verdict)
    {
    case AT_CERT_VALID:
        return "valid";
    case AT_CERT_INVALID:
        return "invalid";
    case AT_CERT_ABSENT:
        return "absent";
    case AT_CERT_INDETERMINATE:
        return "indeterminate";
    case AT_CERT_NONE:
        break;
    }
    return "none";
}

at_cert_verdict_t at_cert_evaluate(const at_cert_model_t *model,
                                   const char *capability,
                                   const char *result_json,
                                   const char *certificate_json,
                                   const char *kwargs_json,
                                   uint64_t seed,
                                   char *reason, size_t reason_len)
{
    if (reason != NULL && reason_len > 0)
        reason[0] = '\0';
    if (!at_cert_model_enabled(model))
        return AT_CERT_NONE;
    const at_cert_capability_t *decl = at_cert_for_capability(model, capability);
    if (decl == NULL)
    {
        _err(reason, reason_len, "'%s' is not declared",
             capability ? capability : "(none)");
        return AT_CERT_NONE;
    }
    if (decl->checker[0] == '\0')
    {
        /* An acknowledged expensive case. Deliberately not a verdict: the
         * declaration records that nobody can check this, which is what the
         * inventory reports, and the completion arms score it as before. */
        _err(reason, reason_len, "'%s' is declared uncertifiable%s%s",
             decl->name, decl->note[0] ? ": " : "", decl->note);
        return AT_CERT_NONE;
    }

    at_cert_checker_fn checker = at_cert_checker_for(decl->checker);
    if (checker == NULL)
    {
        _err(reason, reason_len, "no checker for kind '%s'", decl->checker);
        return AT_CERT_INDETERMINATE;
    }

    json_error_t jerr;
    json_t *inputs = (kwargs_json != NULL && kwargs_json[0] != '\0')
        ? json_loads(kwargs_json, 0, &jerr) : NULL;
    json_t *answer = (result_json != NULL && result_json[0] != '\0')
        ? json_loads(result_json, JSON_DECODE_ANY, &jerr) : NULL;
    json_t *certificate = (certificate_json != NULL && certificate_json[0] != '\0')
        ? json_loads(certificate_json, 0, &jerr) : NULL;

    bool has_certificate = json_is_object(certificate) &&
                           json_object_size(certificate) > 0;
    at_cert_verdict_t out;
    if (!has_certificate && !at_cert_self_certifying(decl->checker))
    {
        if (decl->required)
        {
            _err(reason, reason_len,
                 "'%s' declares a %s witness and none was presented",
                 decl->name, decl->checker);
            out = AT_CERT_ABSENT;
        }
        else
        {
            _err(reason, reason_len,
                 "no witness presented, and none is required");
            out = AT_CERT_NONE;
        }
        goto done;
    }

    {
        json_t *empty_inputs = NULL;
        json_t *empty_cert = NULL;
        if (inputs == NULL)
            inputs = empty_inputs = json_object();
        if (certificate == NULL || !json_is_object(certificate))
            certificate = empty_cert = json_object();
        out = checker(inputs, answer, certificate, decl, seed,
                      reason, reason_len);
        if (empty_inputs != NULL)
        {
            json_decref(empty_inputs);
            inputs = NULL;
        }
        if (empty_cert != NULL)
        {
            json_decref(empty_cert);
            certificate = NULL;
        }
    }

done:
    if (inputs != NULL)
        json_decref(inputs);
    if (answer != NULL)
        json_decref(answer);
    if (certificate != NULL)
        json_decref(certificate);
    return out;
}

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

/****************************
 * Inventory
 ****************************/

const char *at_cert_inv_state_name(at_cert_inv_state_t state)
{
    switch (state)
    {
    case AT_CERT_INV_UNCERTIFIABLE:
        return "uncertifiable";
    case AT_CERT_INV_OPTIONAL:
        return "optional";
    case AT_CERT_INV_CERTIFIED:
        return "certified";
    case AT_CERT_INV_UNEXAMINED:
        break;
    }
    return "unexamined";
}

static int _cmp_rows(const void *pa, const void *pb)
{
    const at_cert_inv_row_t *a = pa, *b = pb;
    /* Worst-known first, so the line an operator most needs is not at the
     * bottom of an alphabetical list; then by name for reproducibility. */
    if (a->state != b->state)
        return (a->state > b->state) - (a->state < b->state);
    return strcmp(a->name, b->name);
}

int at_cert_inventory(const at_cert_model_t *model,
                      const char *const *registered, int n_registered,
                      at_cert_inv_row_t *out, int out_cap)
{
    if (out == NULL || out_cap < 1)
        return -1;
    int n = 0;

    for (int i = 0; i < (model ? model->n_capabilities : 0); i++)
    {
        const at_cert_capability_t *cap = &model->capabilities[i];
        if (n >= out_cap)
            return -1;
        memset(&out[n], 0, sizeof(out[n]));
        at_strlcpy(out[n].name, cap->name, sizeof(out[n].name));
        at_strlcpy(out[n].note, cap->note, sizeof(out[n].note));
        if (cap->checker[0] == '\0')
            out[n].state = AT_CERT_INV_UNCERTIFIABLE;
        else
        {
            at_strlcpy(out[n].checker, cap->checker, sizeof(out[n].checker));
            out[n].state = cap->required ? AT_CERT_INV_CERTIFIED
                                         : AT_CERT_INV_OPTIONAL;
        }
        n++;
    }

    for (int i = 0; i < n_registered; i++)
    {
        if (registered[i] == NULL)
            continue;
        bool seen = false;
        for (int k = 0; k < n; k++)
        {
            if (strcmp(out[k].name, registered[i]) == 0)
            {
                seen = true;
                break;
            }
        }
        if (seen)
            continue;
        if (n >= out_cap)
            return -1;
        memset(&out[n], 0, sizeof(out[n]));
        at_strlcpy(out[n].name, registered[i], sizeof(out[n].name));
        out[n].state = AT_CERT_INV_UNEXAMINED;
        n++;
    }

    qsort(out, (size_t)n, sizeof(*out), _cmp_rows);
    return n;
}

void at_cert_inventory_format(const at_cert_inv_row_t *rows, int n,
                              char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
    buf[0] = '\0';
    int counts[4] = {0, 0, 0, 0};
    for (int i = 0; i < n; i++)
    {
        if ((int)rows[i].state >= 0 && (int)rows[i].state < 4)
            counts[rows[i].state]++;
    }
    /* Self-diagnosing rather than a bare tally: the header says what the
     * numbers mean, so the reader does not have to know the vocabulary. */
    size_t used = (size_t)snprintf(
        buf, len,
        "certificate inventory: %d exactly checkable, %d optional, "
        "%d acknowledged uncertifiable, %d never examined",
        counts[AT_CERT_INV_CERTIFIED], counts[AT_CERT_INV_OPTIONAL],
        counts[AT_CERT_INV_UNCERTIFIABLE], counts[AT_CERT_INV_UNEXAMINED]);
    if (used >= len)
        return;
    for (int i = 0; i < n; i++)
    {
        const char *why = rows[i].note[0] ? rows[i].note
            : (rows[i].state == AT_CERT_INV_UNEXAMINED
                   ? "not mentioned in the declaration" : "");
        int wrote = snprintf(buf + used, len - used, "\n  %-14s %s%s%s%s%s",
                             at_cert_inv_state_name(rows[i].state),
                             rows[i].name,
                             rows[i].checker[0] ? " via " : "",
                             rows[i].checker,
                             why[0] ? " -- " : "", why);
        if (wrote < 0 || (size_t)wrote >= len - used)
            return;
        used += (size_t)wrote;
    }
}
