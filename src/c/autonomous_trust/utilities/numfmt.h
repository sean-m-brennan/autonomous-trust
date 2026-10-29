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

#ifndef AT_NUMFMT_H
#define AT_NUMFMT_H

/**
 * @file numfmt.h
 * @brief Format and parse doubles the same way on every libc.
 *
 * Entry hashes, signed payloads and conformance results carry doubles as
 * "%.17g" text, and the bytes have to agree between nodes. glibc's printf and
 * strtod are correctly rounded; uClibc-ng's are not (measured on the SPARC
 * LEON3 sysroot: 0.1 prints as "0.1" rather than "0.10000000000000001", and
 * 0.1 + 0.2 prints a string that does not parse back to the same double), so
 * a node on such a libc hashes the same entry to a different digest. These
 * two functions use Ryu instead of libc and match glibc byte for byte.
 */

#include <stddef.h>

/** Buffer size for at_fmt_g17: "-1.2345678901234567e-308" plus NUL, rounded up. */
#define AT_G17_LEN 32

/** Largest precision at_fmt_g accepts (jansson's JSON_REAL_PRECISION limit). */
#define AT_G_MAX_PRECISION 31

/** Buffer that holds any at_fmt_g result: sign, 31 digits, ".", "0.000", "e-308", NUL. */
#define AT_G_MAX_LEN 48

/**
 * @brief Format @p v exactly as glibc's snprintf("%.*g", precision) does.
 *
 * @param v          Value to format.
 * @param precision  Significant digits, 1..AT_G_MAX_PRECISION (0 means 1).
 * @param out        Destination.
 * @param len        Size of @p out.
 * @return Length written (without the NUL), or -1 if it does not fit or
 *         @p precision is out of range.
 */
int at_fmt_g(double v, int precision, char *out, size_t len);

/**
 * @brief Format @p v exactly as glibc's snprintf("%.17g") does.
 *
 * Includes glibc's spellings of the non-finite values ("inf", "-inf", "nan",
 * "-nan") and of negative zero ("-0").
 *
 * @param v    Value to format.
 * @param out  Buffer of at least AT_G17_LEN bytes.
 * @return @p out, so the call can sit in a printf argument list.
 */
const char *at_fmt_g17(double v, char out[AT_G17_LEN]);

/**
 * @brief at_fmt_g17 into a temporary, for a "%s" printf argument.
 *
 * The compound literal lives until the end of the enclosing block, so
 * several may sit in one argument list: printf("%s vs %s", AT_G17(a), AT_G17(b)).
 */
#define AT_G17(v) at_fmt_g17((v), (char[AT_G17_LEN]){0})

/**
 * @brief strtod, correctly rounded on every libc.
 *
 * Consumes the same prefix strtod would and sets @p end the same way.
 * Decimal input of up to 17 significant digits (everything at_fmt_g17 and
 * Ryu's shortest form produce) is converted by Ryu's s2d. Anything else -- a
 * longer mantissa, hex floats, "inf"/"nan", or an exponent outside s2d's
 * range -- falls back to the libc strtod, ERANGE and all.
 *
 * @param s    String to parse.
 * @param end  If non-NULL, receives the first unconsumed character.
 * @return The parsed value; 0 with *end == s when nothing parses.
 */
double at_strtod(const char *s, char **end);

#endif /* AT_NUMFMT_H */
