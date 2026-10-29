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

#ifndef AT_FLOAT_SELFTEST_H
#define AT_FLOAT_SELFTEST_H

/**
 * @file float_selftest.h
 * @brief Refuse to start on a platform whose float conversions would make
 *        this node disagree with the fleet.
 *
 * Nodes exchange doubles as JSON text and build signed bytes from values
 * derived with pow(). Two nodes that format, parse or exponentiate the same
 * value differently compute different bytes, and each then rejects the
 * other's valid data -- silently, as "bad signature" or "chain does not
 * verify". This happened on SPARC: uClibc-ng's printf("%.17g") and strtod
 * are not correctly rounded, and stock jansson parses with strtod (and,
 * before 2.15, formatted with printf).
 *
 * The check runs known values through every conversion the protocol depends
 * on and compares bit patterns with glibc's (correctly rounded) results:
 *
 *   - at_fmt_g17 / at_strtod (utilities/numfmt.h)
 *   - jansson's number parsing, and that its number output reads back exactly
 *   - pow(0.5, x), which decay and the consensus EMA use
 *
 * Any mismatch is fatal unless AT_FLOAT_SELFTEST_OVERRIDE_ENV is set. The raw
 * libc printf and strtod are checked too but only reported: AT does not
 * depend on them for anything signed or hashed.
 */

#include "utilities/logger.h"

/** Set to 1/true/yes/on to run despite a failed check (diagnosis only). */
#define AT_FLOAT_SELFTEST_OVERRIDE_ENV "AT_ALLOW_INEXACT_FLOAT"

/**
 * @brief Run the checks and log the outcome.
 *
 * @param logger  Where to report; NULL reports on stderr.
 * @return 0 when every protocol-relevant conversion is exact, or when one is
 *         not but the override is set; -1 to refuse to start.
 */
int at_float_selftest(logger_t *logger);

#endif /* AT_FLOAT_SELFTEST_H */
