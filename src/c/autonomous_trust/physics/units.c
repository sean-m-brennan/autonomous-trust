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

#include <ctype.h>
#include <math.h>     /* fpclassify, for the affine-unit test */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "physics/units.h"
#include "utilities/util.h"   /* at_strlcpy */

const char *const at_base_unit_names[AT_N_BASE_UNITS] = {
    "m", "kg", "s", "A", "K", "mol", "cd"};

/* One row of the symbol table. Every scale is the defining conversion,
 * written to full double precision so this and the Python twin's literal
 * parse to the same bits.
 *
 * Entries are deliberately few. A symbol that is not here is REFUSED rather
 * than guessed at, because guessing is how a checker starts accepting claims
 * it cannot actually check.
 *
 * Two collisions worth naming, both resolved toward SI:
 *   - "C" is the coulomb, NOT Celsius — Celsius is "degC". The services
 *     layer's Reading.unit uses "C" for Celsius as a DISPLAY string; it never
 *     reaches this parser (the carrier here is a task result), and a
 *     declaration that means Celsius must say "degC".
 *   - "T" is the tesla and "t" the tonne. The table is case-sensitive
 *     throughout, as SI is. */
typedef struct
{
    const char *symbol;
    int8_t exponents[AT_N_BASE_UNITS];
    double scale;
    double offset;
} unit_row_t;

/*                                    m  kg   s   A   K mol  cd */
static const unit_row_t UNIT_TABLE[] = {
    /* -- dimensionless -------------------------------------------------- */
    {"",      { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"1",     { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"-",     { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"%",     { 0,  0,  0,  0,  0,  0,  0}, 0.01,                   0.0},
    {"ppm",   { 0,  0,  0,  0,  0,  0,  0}, 1e-6,                   0.0},
    {"rad",   { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"sr",    { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"deg",   { 0,  0,  0,  0,  0,  0,  0}, 0.017453292519943295,   0.0},
    {"count", { 0,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    /* -- length ---------------------------------------------------------- */
    {"m",     { 1,  0,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"km",    { 1,  0,  0,  0,  0,  0,  0}, 1e3,                    0.0},
    {"cm",    { 1,  0,  0,  0,  0,  0,  0}, 1e-2,                   0.0},
    {"mm",    { 1,  0,  0,  0,  0,  0,  0}, 1e-3,                   0.0},
    {"um",    { 1,  0,  0,  0,  0,  0,  0}, 1e-6,                   0.0},
    {"nm",    { 1,  0,  0,  0,  0,  0,  0}, 1e-9,                   0.0},
    {"ft",    { 1,  0,  0,  0,  0,  0,  0}, 0.3048,                 0.0},
    {"mi",    { 1,  0,  0,  0,  0,  0,  0}, 1609.344,               0.0},
    {"nmi",   { 1,  0,  0,  0,  0,  0,  0}, 1852.0,                 0.0},
    /* -- mass ------------------------------------------------------------ */
    {"kg",    { 0,  1,  0,  0,  0,  0,  0}, 1.0,                    0.0},
    {"g",     { 0,  1,  0,  0,  0,  0,  0}, 1e-3,                   0.0},
    {"mg",    { 0,  1,  0,  0,  0,  0,  0}, 1e-6,                   0.0},
    {"ug",    { 0,  1,  0,  0,  0,  0,  0}, 1e-9,                   0.0},
    {"t",     { 0,  1,  0,  0,  0,  0,  0}, 1e3,                    0.0},
    /* -- time ------------------------------------------------------------ */
    {"s",     { 0,  0,  1,  0,  0,  0,  0}, 1.0,                    0.0},
    {"ms",    { 0,  0,  1,  0,  0,  0,  0}, 1e-3,                   0.0},
    {"us",    { 0,  0,  1,  0,  0,  0,  0}, 1e-6,                   0.0},
    {"ns",    { 0,  0,  1,  0,  0,  0,  0}, 1e-9,                   0.0},
    {"min",   { 0,  0,  1,  0,  0,  0,  0}, 60.0,                   0.0},
    {"h",     { 0,  0,  1,  0,  0,  0,  0}, 3600.0,                 0.0},
    {"d",     { 0,  0,  1,  0,  0,  0,  0}, 86400.0,                0.0},
    /* -- current ---------------------------------------------------------- */
    {"A",     { 0,  0,  0,  1,  0,  0,  0}, 1.0,                    0.0},
    {"mA",    { 0,  0,  0,  1,  0,  0,  0}, 1e-3,                   0.0},
    {"uA",    { 0,  0,  0,  1,  0,  0,  0}, 1e-6,                   0.0},
    /* -- temperature ------------------------------------------------------ */
    {"K",     { 0,  0,  0,  0,  1,  0,  0}, 1.0,                    0.0},
    {"degC",  { 0,  0,  0,  0,  1,  0,  0}, 1.0,                    273.15},
    {"degF",  { 0,  0,  0,  0,  1,  0,  0}, 0.5555555555555556,
                                                            255.3722222222222},
    /* -- amount / luminous ------------------------------------------------ */
    {"mol",   { 0,  0,  0,  0,  0,  1,  0}, 1.0,                    0.0},
    {"mmol",  { 0,  0,  0,  0,  0,  1,  0}, 1e-3,                   0.0},
    {"cd",    { 0,  0,  0,  0,  0,  0,  1}, 1.0,                    0.0},
    /* -- coherent derived -------------------------------------------------- */
    {"Hz",    { 0,  0, -1,  0,  0,  0,  0}, 1.0,                    0.0},
    {"N",     { 1,  1, -2,  0,  0,  0,  0}, 1.0,                    0.0},
    {"Pa",    {-1,  1, -2,  0,  0,  0,  0}, 1.0,                    0.0},
    {"kPa",   {-1,  1, -2,  0,  0,  0,  0}, 1e3,                    0.0},
    {"bar",   {-1,  1, -2,  0,  0,  0,  0}, 1e5,                    0.0},
    {"J",     { 2,  1, -2,  0,  0,  0,  0}, 1.0,                    0.0},
    {"kJ",    { 2,  1, -2,  0,  0,  0,  0}, 1e3,                    0.0},
    {"W",     { 2,  1, -3,  0,  0,  0,  0}, 1.0,                    0.0},
    {"mW",    { 2,  1, -3,  0,  0,  0,  0}, 1e-3,                   0.0},
    {"kW",    { 2,  1, -3,  0,  0,  0,  0}, 1e3,                    0.0},
    {"MW",    { 2,  1, -3,  0,  0,  0,  0}, 1e6,                    0.0},
    {"C",     { 0,  0,  1,  1,  0,  0,  0}, 1.0,                    0.0},
    {"V",     { 2,  1, -3, -1,  0,  0,  0}, 1.0,                    0.0},
    {"mV",    { 2,  1, -3, -1,  0,  0,  0}, 1e-3,                   0.0},
    {"ohm",   { 2,  1, -3, -2,  0,  0,  0}, 1.0,                    0.0},
    {"F",     {-2, -1,  4,  2,  0,  0,  0}, 1.0,                    0.0},
    {"H",     { 2,  1, -2, -2,  0,  0,  0}, 1.0,                    0.0},
    {"Wb",    { 2,  1, -2, -1,  0,  0,  0}, 1.0,                    0.0},
    {"T",     { 0,  1, -2, -1,  0,  0,  0}, 1.0,                    0.0},
    {"Ah",    { 0,  0,  1,  1,  0,  0,  0}, 3600.0,                 0.0},
    {"Wh",    { 2,  1, -2,  0,  0,  0,  0}, 3600.0,                 0.0},
};

static const size_t UNIT_TABLE_LEN = sizeof(UNIT_TABLE) / sizeof(UNIT_TABLE[0]);

static void _fail(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _fail(char *err, size_t errlen, const char *fmt, ...)
{
    if (err == NULL || errlen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static const unit_row_t *_lookup(const char *symbol, size_t len)
{
    for (size_t i = 0; i < UNIT_TABLE_LEN; i++)
    {
        if (strlen(UNIT_TABLE[i].symbol) == len &&
            strncmp(UNIT_TABLE[i].symbol, symbol, len) == 0)
            return &UNIT_TABLE[i];
    }
    return NULL;
}

void at_dimension_dimensionless(at_dimension_t *out)
{
    if (out == NULL)
        return;
    memset(out->exponents, 0, sizeof(out->exponents));
    out->scale = 1.0;
    out->offset = 0.0;
}

bool at_same_dimension(const at_dimension_t *a, const at_dimension_t *b)
{
    if (a == NULL || b == NULL)
        return false;
    return memcmp(a->exponents, b->exponents, sizeof(a->exponents)) == 0;
}

double at_dimension_to_si(const at_dimension_t *dim, double value)
{
    if (dim == NULL)
        return value;
    return value * dim->scale + dim->offset;
}

const char *at_dimension_str(const at_dimension_t *dim, char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return buf;
    buf[0] = '\0';
    if (dim == NULL)
        return buf;
    size_t used = 0;
    bool any = false;
    for (int i = 0; i < AT_N_BASE_UNITS; i++)
    {
        if (dim->exponents[i] == 0)
            continue;
        int n = snprintf(buf + used, len - used, "%s%s^%d", any ? "*" : "",
                         at_base_unit_names[i], (int)dim->exponents[i]);
        if (n < 0 || (size_t)n >= len - used)
            break;
        used += (size_t)n;
        any = true;
    }
    if (!any)
        at_strlcpy(buf, "1", len);
    return buf;
}

bool at_parse_unit(const char *text, at_dimension_t *out,
                   char *err, size_t errlen)
{
    if (out == NULL)
        return false;
    if (text == NULL)
    {
        at_dimension_dimensionless(out);
        return true;
    }

    /* Trim, into a bounded buffer: the fast path below needs a NUL-terminated
     * trimmed copy, and a unit string longer than this is not in the grammar
     * whatever it says. */
    char trimmed[AT_UNIT_ERR_LEN];
    {
        const char *begin = text;
        while (*begin != '\0' && isspace((unsigned char)*begin))
            begin++;
        const char *end = begin + strlen(begin);
        while (end > begin && isspace((unsigned char)*(end - 1)))
            end--;
        size_t n = (size_t)(end - begin);
        if (n >= sizeof(trimmed))
        {
            _fail(err, errlen, "unit is too long (%zu bytes)", n);
            return false;
        }
        memcpy(trimmed, begin, n);
        trimmed[n] = '\0';
    }

    /* Fast path, and the ONLY path for an affine unit: degC and degF are
     * accepted as a whole expression and refused inside one. */
    const unit_row_t *whole = _lookup(trimmed, strlen(trimmed));
    if (whole != NULL)
    {
        memcpy(out->exponents, whole->exponents, sizeof(out->exponents));
        out->scale = whole->scale;
        out->offset = whole->offset;
        return true;
    }

    int exponents[AT_N_BASE_UNITS] = {0};
    double scale = 1.0;
    int sign = 1; /* +1 after '*', -1 after '/' */
    bool seen_term = false;
    size_t pos = 0;
    const size_t len = strlen(trimmed);

    while (pos < len)
    {
        char ch = trimmed[pos];
        if (isspace((unsigned char)ch))
        {
            pos++;
            continue;
        }
        if (ch == '*' || ch == '/')
        {
            if (!seen_term)
            {
                _fail(err, errlen, "unit '%s': operator before any term", trimmed);
                return false;
            }
            sign = (ch == '*') ? 1 : -1;
            pos++;
            continue;
        }
        if (ch == '1' && (pos + 1 >= len || !isdigit((unsigned char)trimmed[pos + 1])))
        {
            /* A bare 1 numerator, as in "1/s". Contributes nothing. */
            pos++;
            seen_term = true;
            continue;
        }

        /* Symbol: letters and '%'. A digit ends it, because a trailing digit
         * is the exponent. */
        size_t start = pos;
        while (pos < len && (isalpha((unsigned char)trimmed[pos]) || trimmed[pos] == '%'))
            pos++;
        if (pos == start)
        {
            _fail(err, errlen, "unit '%s': unexpected '%c' at %zu", trimmed,
                  trimmed[pos], pos);
            return false;
        }
        const unit_row_t *row = _lookup(trimmed + start, pos - start);
        if (row == NULL)
        {
            _fail(err, errlen, "unit '%s': unknown symbol '%.*s'", trimmed,
                  (int)(pos - start), trimmed + start);
            return false;
        }
        /* Affine, i.e. a unit whose conversion has an additive term: degC
         * and degF are the only two in the table, and every other row's
         * offset is a literal 0.0, so this is an exact test and not an
         * approximate one. Written with fpclassify rather than `!= 0.0`
         * because the host build is -Werror=float-equal -- and an epsilon
         * would be the wrong fix here, since the question is genuinely
         * "is this field zero", not "is it near zero". */
        if (fpclassify(row->offset) != FP_ZERO)
        {
            _fail(err, errlen,
                  "unit '%s': affine unit '%s' cannot appear in a compound "
                  "expression (its offset does not distribute)",
                  trimmed, row->symbol);
            return false;
        }

        /* Optional exponent: '^-2', '-2', '3' or nothing. */
        int power = 1;
        {
            if (pos < len && trimmed[pos] == '^')
                pos++;
            int esign = 1;
            if (pos < len && trimmed[pos] == '-')
            {
                esign = -1;
                pos++;
            }
            size_t dstart = pos;
            int value = 0;
            while (pos < len && isdigit((unsigned char)trimmed[pos]))
            {
                value = value * 10 + (trimmed[pos] - '0');
                if (value > 64)
                {
                    _fail(err, errlen, "unit '%s': exponent out of range", trimmed);
                    return false;
                }
                pos++;
            }
            if (pos == dstart)
            {
                if (esign < 0)
                {
                    _fail(err, errlen, "unit '%s': \"-\" with no exponent digits",
                          trimmed);
                    return false;
                }
                power = 1;
            }
            else
                power = esign * value;
        }
        power *= sign;

        for (int i = 0; i < AT_N_BASE_UNITS; i++)
            exponents[i] += (int)row->exponents[i] * power;

        /* Repeated multiplication, then one divide for a negative exponent,
         * rather than pow(). Not pedantry: the Python twin must land on the
         * same bits, and a loop plus a divide is the one spelling both
         * languages compute identically. The exponents are small integers by
         * construction (bounded just above). */
        double term_scale = 1.0;
        int reps = power < 0 ? -power : power;
        for (int i = 0; i < reps; i++)
            term_scale *= row->scale;
        if (power < 0)
            scale /= term_scale;
        else
            scale *= term_scale;
        seen_term = true;
    }

    if (!seen_term)
    {
        _fail(err, errlen, "unit '%s': no terms", trimmed);
        return false;
    }
    for (int i = 0; i < AT_N_BASE_UNITS; i++)
    {
        if (exponents[i] > INT8_MAX || exponents[i] < INT8_MIN)
        {
            _fail(err, errlen, "unit '%s': exponent out of range", trimmed);
            return false;
        }
        out->exponents[i] = (int8_t)exponents[i];
    }
    out->scale = scale;
    out->offset = 0.0;
    return true;
}
