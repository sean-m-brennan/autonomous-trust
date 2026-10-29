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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <jansson.h>

#include "utilities/float_selftest.h"
#include "utilities/numfmt.h"

/* Expected results are glibc's, which are correctly rounded. Every value here
 * is one uClibc-ng got wrong on SPARC (or, for pow, one the protocol computes)
 * when this was written. */
typedef struct
{
    const char *text;
    uint64_t bits;
} parse_case_t;

static const parse_case_t parse_cases[] = {
    { "0.007",               0x3f7cac083126e979ull },
    { "0.013",               0x3f8a9fbe76c8b439ull },
    { "0.11345034205715454", 0x3fbd0b14e4db0188ull },
};

typedef struct
{
    uint64_t bits;
    const char *g17;
} format_case_t;

static const format_case_t format_cases[] = {
    { 0x3fd3333333333334ull, "0.30000000000000004" },   /* 0.1 + 0.2 */
    { 0x3fe6666666666666ull, "0.69999999999999996" },   /* 0.7 */
    { 0x3f7cac083126e979ull, "0.0070000000000000001" }, /* 0.007 */
};

/* pow(0.5, num / den): the consensus EMA's alpha (1/CONSENSUS_EMA_HALF_LIFE,
 * which is 20) and decay factors of the shape elapsed / REP_DECAY_HALF_LIFE. */
typedef struct
{
    double num, den;
    uint64_t bits;
} pow_case_t;

static const pow_case_t pow_cases[] = {
    { 1.0,     20.0,     0x3feee8f34dd8042full },
    { 1.0,     8.0,      0x3fed5818dcfba487ull },
    { 3.7,     3600.0,   0x3feffa2a84af12a5ull },
    { 86400.0, 604800.0, 0x3fecfbb031a741a5ull },
};

#define N_CASES(a) (sizeof(a) / sizeof((a)[0]))

static uint64_t _bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof(u));
    return u;
}

static double _double(uint64_t u)
{
    double d;
    memcpy(&d, &u, sizeof(d));
    return d;
}

/* Append "; <msg>" to @p buf, keeping whatever fits. */
static void _note(char *buf, size_t len, const char *msg)
{
    size_t used = strlen(buf);
    if (used + 1 >= len)
        return;
    snprintf(buf + used, len - used, "%s%s", used > 0 ? "; " : "", msg);
}

static bool _override(void)
{
    const char *val = getenv(AT_FLOAT_SELFTEST_OVERRIDE_ENV);
    if (val == NULL)
        return false;
    return strcasecmp(val, "1") == 0 || strcasecmp(val, "true") == 0 ||
           strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0;
}

/* The conversions the protocol depends on. Returns the number of failures. */
static int _check_protocol(char *why, size_t len)
{
    int bad = 0;
    char msg[160];

    for (size_t i = 0; i < N_CASES(parse_cases); i++)
    {
        const parse_case_t *c = &parse_cases[i];
        double got = at_strtod(c->text, NULL);
        if (_bits(got) != c->bits)
        {
            snprintf(msg, sizeof(msg), "at_strtod(\"%s\") is 0x%016llx, not 0x%016llx",
                     c->text, (unsigned long long)_bits(got), (unsigned long long)c->bits);
            _note(why, len, msg);
            bad++;
        }

        char doc[64];
        snprintf(doc, sizeof(doc), "[%s]", c->text);
        json_t *arr = json_loads(doc, 0, NULL);
        double jgot = json_real_value(json_array_get(arr, 0));
        json_decref(arr);
        if (_bits(jgot) != c->bits)
        {
            snprintf(msg, sizeof(msg), "jansson parses %s as 0x%016llx, not 0x%016llx",
                     c->text, (unsigned long long)_bits(jgot), (unsigned long long)c->bits);
            _note(why, len, msg);
            bad++;
        }
    }

    for (size_t i = 0; i < N_CASES(format_cases); i++)
    {
        const format_case_t *c = &format_cases[i];
        double v = _double(c->bits);
        char g17[AT_G17_LEN];
        if (strcmp(at_fmt_g17(v, g17), c->g17) != 0)
        {
            snprintf(msg, sizeof(msg), "at_fmt_g17 gives %s, not %s", g17, c->g17);
            _note(why, len, msg);
            bad++;
        }

        /* jansson's spelling is not fixed (the vendored one writes the
         * shortest digits that read back exactly, a system one may write
         * %.17g); what matters is that its text reads back as the same
         * double. Read with at_strtod, which does not depend on jansson. */
        json_t *arr = json_array();
        json_array_append_new(arr, json_real(v));
        char *dumped = json_dumps(arr, JSON_COMPACT);
        json_decref(arr);
        double back = 0.0;
        if (dumped != NULL && dumped[0] == '[')
            back = at_strtod(dumped + 1, NULL);
        if (dumped == NULL || _bits(back) != c->bits)
        {
            snprintf(msg, sizeof(msg), "jansson writes %s as %s, which reads back as "
                     "0x%016llx", c->g17, dumped != NULL ? dumped : "(nothing)",
                     (unsigned long long)_bits(back));
            _note(why, len, msg);
            bad++;
        }
        free(dumped);
    }

    for (size_t i = 0; i < N_CASES(pow_cases); i++)
    {
        const pow_case_t *c = &pow_cases[i];
        double got = pow(0.5, c->num / c->den);
        if (_bits(got) != c->bits)
        {
            snprintf(msg, sizeof(msg), "pow(0.5, %g/%g) is 0x%016llx, not 0x%016llx",
                     c->num, c->den, (unsigned long long)_bits(got),
                     (unsigned long long)c->bits);
            _note(why, len, msg);
            bad++;
        }
    }
    return bad;
}

/* The raw libc conversions, which AT routes around. Returns the number of failures. */
static int _check_libc(char *why, size_t len)
{
    int bad = 0;
    char msg[128];
    for (size_t i = 0; i < N_CASES(parse_cases); i++)
        if (_bits(strtod(parse_cases[i].text, NULL)) != parse_cases[i].bits)
        {
            snprintf(msg, sizeof(msg), "strtod(\"%s\")", parse_cases[i].text);
            _note(why, len, msg);
            bad++;
        }
    for (size_t i = 0; i < N_CASES(format_cases); i++)
    {
        char buf[48];
        snprintf(buf, sizeof(buf), "%.17g", _double(format_cases[i].bits));
        if (strcmp(buf, format_cases[i].g17) != 0)
        {
            snprintf(msg, sizeof(msg), "printf(\"%%.17g\") of %s", format_cases[i].g17);
            _note(why, len, msg);
            bad++;
        }
    }
    return bad;
}

/* Frama-C: skipped — [external] jansson, libm, getenv */
int at_float_selftest(logger_t *logger)
{
    char libc_why[512] = "";
    if (_check_libc(libc_why, sizeof(libc_why)) > 0)
    {
        if (logger != NULL)
            log_warn(logger, "float self-test: this libc is not correctly rounded "
                     "(%s). AT formats and parses its own numbers, so this is "
                     "informational.\n", libc_why);
        else
            fprintf(stderr, "float self-test: this libc is not correctly rounded "
                    "(%s); informational.\n", libc_why);
    }

    char why[1024] = "";
    int bad = _check_protocol(why, sizeof(why));
    if (bad == 0)
    {
        if (logger != NULL)
            log_info(logger, "float self-test: number formatting, parsing and pow "
                     "agree with a correctly rounded reference\n");
        return 0;
    }

    /* One message, both modes: what failed, why it matters, and what fixes it */
    const char *fix = "a node that converts numbers differently signs and hashes "
                      "different bytes and rejects valid data from its peers. "
                      "Build with the vendored jansson (AT_SYSTEM_JANSSON=OFF, "
                      "the default), which converts numbers through dtoa";
    if (!_override())
    {
        if (logger != NULL)
            log_critical(logger, "float self-test: %d check(s) failed: %s. %s. "
                         "[refusing to start; set %s=1 to run anyway]\n",
                         bad, why, fix, AT_FLOAT_SELFTEST_OVERRIDE_ENV);
        else
            fprintf(stderr, "float self-test: %d check(s) failed: %s. %s. "
                    "[refusing to start; set %s=1 to run anyway]\n",
                    bad, why, fix, AT_FLOAT_SELFTEST_OVERRIDE_ENV);
        return -1;
    }
    if (logger != NULL)
        log_critical(logger, "float self-test: %d check(s) failed: %s. %s. "
                     "[%s is set: RUNNING ANYWAY -- this node may disagree with "
                     "the fleet]\n", bad, why, fix, AT_FLOAT_SELFTEST_OVERRIDE_ENV);
    else
        fprintf(stderr, "float self-test: %d check(s) failed: %s. [%s is set: "
                "RUNNING ANYWAY]\n", bad, why, AT_FLOAT_SELFTEST_OVERRIDE_ENV);
    return 0;
}
