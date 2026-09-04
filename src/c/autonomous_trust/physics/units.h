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

#ifndef AT_UNITS_H
#define AT_UNITS_H

/** @addtogroup internal_physics
 *  @{
 *
 * Dimensional analysis over the SI base quantities (R+D.md §12.2, layer 1).
 *
 * A unit string parses to seven integer exponents plus the affine map
 * (scale, offset) carrying a value in that unit to the SI coherent unit. Two
 * units are dimensionally EQUAL when their exponent vectors match, whatever
 * their scales; that equality is the whole of the coherence check, and it is a
 * refutation rather than a statistic — a claim of 40 kilograms of thermal
 * margin is not improbable, it is meaningless.
 *
 * The table is CODE, not configuration. physics.json declares which quantity a
 * capability reports and what bounds it obeys; it does not get to say what a
 * newton is. An operator who could redefine the units could refute any peer by
 * declaration, which is the failure mode this layer exists to avoid.
 *
 * The Python twin is
 * src/autonomous-trust/autonomous_trust/core/_python/physics/units.py and MUST
 * parse identically: both runtimes grade the same peers off the same
 * declarations, and a unit one accepts and the other refuses would make a
 * peer's reputation depend on which implementation happened to ask. The
 * conformance protocol `physics` pins the table and the grammar rather than
 * trusting the mirror.
 *
 * Grammar, deliberately tiny so two implementations can agree:
 *
 *     expr     := term (('*' | '/') term)*
 *     term     := '1' | symbol exponent?
 *     exponent := '^'? '-'? digit+
 *
 * "m/s", "kg*m/s^2", "ug/m3" and "1/s" are all accepted; "m3" is "m^3" because
 * no symbol in the table ends in a digit. Whitespace is insignificant. An empty
 * string, "1" and "-" are all the dimensionless unit.
 *
 * Affine units (degC, degF) carry a non-zero offset and are accepted ONLY as a
 * whole expression: degC is a temperature, degC/s is not a rate of anything,
 * because the offset does not distribute over the quotient. Refusing it is the
 * point — silently dropping the offset would turn a 20 degC claim into 20 K and
 * refute an honest peer.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Number of SI base quantities: m, kg, s, A, K, mol, cd — in that order.
 *  The Python twin indexes the same array positions and the conformance
 *  vectors spell the exponents out in this order. */
#define AT_N_BASE_UNITS 7

/** Longest unit symbol accepted, plus room for a NUL. */
#define AT_UNIT_SYMBOL_LEN 15

/** Buffer size callers should use for the error detail out-parameters. */
#define AT_UNIT_ERR_LEN 160

/** A parsed unit: exponents over the base quantities, plus its affine map.
 *
 * `scale` and `offset` convert TO the SI coherent unit:
 *
 *     si_value = value * scale + offset
 *
 * so "km" is scale 1000, offset 0 and "degC" is scale 1, offset 273.15.
 * Dimensional equality ignores both: that is what makes a unit mismatch a
 * refutation and a mere prefix difference a conversion. */
typedef struct
{
    int8_t exponents[AT_N_BASE_UNITS];
    double scale;
    double offset;
} at_dimension_t;

/** Names of the base quantities, in exponent order. */
extern const char *const at_base_unit_names[AT_N_BASE_UNITS];

/**
 * @brief Parse a unit string.
 *
 * @param text   Unit string; NULL or empty is the dimensionless unit.
 * @param out    Receives the parsed dimension. Untouched on failure.
 * @param err    Optional buffer (AT_UNIT_ERR_LEN) for the reason; may be NULL.
 * @param errlen Size of @p err.
 * @return true on success; false for an unknown symbol, a malformed
 *         expression, or an affine unit used inside a compound expression.
 */
bool at_parse_unit(const char *text, at_dimension_t *out,
                   char *err, size_t errlen);

/** @brief True when two parsed units have the same exponent vector. */
bool at_same_dimension(const at_dimension_t *a, const at_dimension_t *b);

/** @brief Carry @p value, expressed in @p dim, to the SI coherent unit. */
double at_dimension_to_si(const at_dimension_t *dim, double value);

/** @brief The dimensionless unit (all exponents zero, scale 1, offset 0). */
void at_dimension_dimensionless(at_dimension_t *out);

/**
 * @brief Render a dimension as "m^1*s^-1" (or "1") for logs and errors.
 * @return @p buf.
 */
const char *at_dimension_str(const at_dimension_t *dim, char *buf, size_t len);

/** @} */
#endif /* AT_UNITS_H */
