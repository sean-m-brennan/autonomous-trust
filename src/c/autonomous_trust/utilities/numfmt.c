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
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "ryu/ryu.h"
#include "ryu/ryu_parse.h"

#include "utilities/numfmt.h"

/* %g with precision P picks its style from X, the decimal exponent of the
 * value rounded to P significant digits: fixed when -4 <= X < P, exponential
 * otherwise. Either way trailing fractional zeros and a bare decimal point are
 * dropped. d2exp(v, P - 1) is exactly that rounding, as "d.ddd...e[+-]XX", so
 * all that is left here is the layout. */

/* Frama-C: skipped — [external] Ryu d2exp */
int at_fmt_g(double v, int precision, char *out, size_t len)
{
    if (out == NULL || len == 0 || precision > AT_G_MAX_PRECISION)
        return -1;
    if (precision < 1)
        precision = 1;  /* as printf: a precision of 0 means 1 */

    char buf[AT_G_MAX_LEN];
    char *o = buf;
    if (isnan(v) || isinf(v))
    {
        strcpy(buf, isnan(v) ? (signbit(v) ? "-nan" : "nan") : (v < 0 ? "-inf" : "inf"));
        o = buf + strlen(buf);
    }
    else
    {
        char e[AT_G_MAX_LEN];
        e[d2exp_buffered_n(v, (uint32_t)(precision - 1), e)] = '\0';  /* _n does not terminate */

        const char *p = e;
        bool neg = (*p == '-');
        if (neg)
            p++;
        char digits[AT_G_MAX_PRECISION];
        memset(digits, '0', sizeof(digits));
        int nd = 0;
        for (; *p != 'e' && *p != '\0'; p++)
            if (*p != '.' && nd < precision)
                digits[nd++] = *p;
        int x = (*p == 'e') ? atoi(p + 1) : 0;

        /* Significant digits after the last nonzero one are the zeros %g strips */
        int last = nd - 1;
        while (last > 0 && digits[last] == '0')
            last--;

        if (neg)
            *o++ = '-';
        if (x < -4 || x >= precision)
        {
            *o++ = digits[0];
            if (last > 0)
            {
                *o++ = '.';
                memcpy(o, digits + 1, (size_t)last);
                o += last;
            }
            *o++ = 'e';
            *o++ = (x < 0) ? '-' : '+';
            int ax = abs(x);
            if (ax >= 100)
                *o++ = (char)('0' + ax / 100);
            *o++ = (char)('0' + (ax / 10) % 10);
            *o++ = (char)('0' + ax % 10);
        }
        else if (x >= 0)
        {
            /* digits[0..x] are the integer part, the rest the fraction */
            memcpy(o, digits, (size_t)x + 1);
            o += x + 1;
            if (last > x)
            {
                *o++ = '.';
                memcpy(o, digits + x + 1, (size_t)(last - x));
                o += last - x;
            }
        }
        else
        {
            *o++ = '0';
            *o++ = '.';
            for (int i = 0; i < -x - 1; i++)
                *o++ = '0';
            memcpy(o, digits, (size_t)last + 1);
            o += last + 1;
        }
    }
    *o = '\0';
    size_t n = (size_t)(o - buf);
    if (n >= len)
        return -1;
    memcpy(out, buf, n + 1);
    return (int)n;
}

const char *at_fmt_g17(double v, char out[AT_G17_LEN])
{
    if (at_fmt_g(v, 17, out, AT_G17_LEN) < 0)
        out[0] = '\0';  /* cannot happen: AT_G17_LEN fits every %.17g */
    return out;
}

/* Longest decimal-float prefix Ryu can be handed; anything longer goes to libc */
#define S2D_MAX 64

/* Frama-C: skipped — [external] Ryu s2d */
double at_strtod(const char *s, char **end)
{
    const char *p = s;
    while (isspace((unsigned char)*p))
        p++;
    bool neg = false;
    if (*p == '+' || *p == '-')
        neg = (*p++ == '-');

    /* Hex floats, inf and nan are libc's to parse */
    if ((p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) ||
        strncasecmp(p, "inf", 3) == 0 || strncasecmp(p, "nan", 3) == 0)
        return strtod(s, end);

    /* The prefix strtod would take: digits [. digits] [e [sign] digits] */
    const char *m = p;
    int ndigits = 0;
    bool nonzero = false;
    while (isdigit((unsigned char)*p))
    {
        nonzero |= (*p != '0');
        p++;
        ndigits++;
    }
    const char *frac_end = p;
    if (*p == '.')
    {
        p++;
        while (isdigit((unsigned char)*p))
        {
            nonzero |= (*p != '0');
            p++;
            ndigits++;
        }
        frac_end = p;
        /* Trailing fractional zeros are not significant, and s2d counts them */
        while (frac_end[-1] == '0')
            frac_end--;
    }
    if (ndigits == 0)
        return strtod(s, end);  /* no number: let libc set *end = s */
    const char *exp = NULL;
    if ((*p == 'e' || *p == 'E'))
    {
        const char *q = p + 1;
        if (*q == '+' || *q == '-')
            q++;
        if (isdigit((unsigned char)*q))
        {
            exp = p;
            while (isdigit((unsigned char)*q))
                q++;
            p = q;
        }
    }

    char buf[S2D_MAX];
    size_t mlen = (size_t)(frac_end - m);
    size_t elen = exp != NULL ? (size_t)(p - exp) : 0;
    if (1 + mlen + elen >= sizeof(buf))
        return strtod(s, end);
    char *b = buf;
    if (neg)
        *b++ = '-';
    memcpy(b, m, mlen);
    b += mlen;
    if (exp != NULL)
    {
        memcpy(b, exp, elen);
        b += elen;
    }

    double result;
    if (s2d_n(buf, (int)(b - buf), &result) != SUCCESS)
        return strtod(s, end);
    /* s2d saturates silently; leave overflow and underflow to libc so the
     * caller still sees ERANGE. */
    if (isinf(result) || (fpclassify(result) == FP_ZERO && nonzero))
        return strtod(s, end);
    if (end != NULL)
        *end = (char *)p;
    return result;
}
