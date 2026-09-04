# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""Dimensional analysis over the SI base quantities (R+D.md §12.2, layer 1).

A unit string parses to a :class:`Dimension`: seven integer exponents over the
SI base quantities plus the affine map (``scale``, ``offset``) that carries a
value in that unit to the SI coherent unit. Two units are *dimensionally
equal* when their exponent vectors match, whatever their scales; that equality
is the whole of the coherence check, and it is a refutation rather than a
statistic --- a claim of 40 kilograms of thermal margin is not improbable, it
is meaningless.

**The table is code, not configuration.** ``physics.json`` declares which
quantity a capability reports and what bounds it obeys; it does not get to say
what a newton is. That is the sense in which this axiom set is "small, closed
and uncontested" (doc/verification_oracle.md) --- an operator who could
redefine the units could refute anything by declaration, which is precisely
the failure mode the layer exists to avoid.

The C twin is ``src/c/autonomous_trust/physics/units.{h,c}`` and MUST parse
identically: both runtimes grade the same peers off the same declarations, and
a unit one accepts and the other refuses would make a peer's reputation depend
on which implementation happened to ask. The conformance protocol ``physics``
pins the table and the grammar rather than trusting the mirror.

Grammar, deliberately tiny so two implementations can agree::

    expr   := term (('*' | '/') term)*
    term   := '1' | symbol exponent?
    exponent := '^'? '-'? digit+

``m/s``, ``kg*m/s^2``, ``ug/m3`` and ``1/s`` are all accepted; ``m3`` is
``m^3`` because no symbol in the table ends in a digit. Whitespace is
insignificant. An empty string, ``1``, and ``-`` are all the dimensionless
unit.

Affine units (``degC``, ``degF``) carry a non-zero offset and are accepted
ONLY as a whole expression: ``degC`` is a temperature, ``degC/s`` is not a
rate of anything, because the offset does not distribute over the quotient.
Refusing it is the point --- silently dropping the offset would turn a
20 degC claim into 20 K and refute an honest peer.
"""

from __future__ import annotations

from typing import NamedTuple, Optional

#: Order of the SI base quantities in every exponent vector. Fixed: the C twin
#: indexes the same array positions, and the conformance vectors spell the
#: exponents out in this order.
BASE_UNITS: tuple[str, ...] = ('m', 'kg', 's', 'A', 'K', 'mol', 'cd')

#: Number of base quantities. Named because the C mirror is a fixed-size array.
N_BASE: int = len(BASE_UNITS)

_ZERO: tuple[int, ...] = (0,) * N_BASE


class Dimension(NamedTuple):
    """A parsed unit: exponents over :data:`BASE_UNITS`, plus its affine map.

    ``scale`` and ``offset`` convert TO the SI coherent unit::

        si_value = value * scale + offset

    so ``km`` is ``scale=1000, offset=0`` and ``degC`` is ``scale=1,
    offset=273.15``. Dimensional equality ignores both: that is what makes a
    unit mismatch a refutation and a mere prefix difference a conversion.
    """

    exponents: tuple[int, ...]
    scale: float = 1.0
    offset: float = 0.0

    def same_dimension(self, other: 'Dimension') -> bool:
        """True when the exponent vectors match, whatever the scales."""
        return self.exponents == other.exponents

    @property
    def dimensionless(self) -> bool:
        return self.exponents == _ZERO

    def to_si(self, value: float) -> float:
        """Carry ``value``, expressed in this unit, to the SI coherent unit."""
        return value * self.scale + self.offset

    def __str__(self) -> str:  # pragma: no cover - diagnostics only
        parts = [f'{b}^{e}' for b, e in zip(BASE_UNITS, self.exponents) if e]
        return '*'.join(parts) if parts else '1'


class UnitError(ValueError):
    """A unit string that is not in the grammar or names an unknown symbol.

    Raised at DECLARATION load time and at claim-check time alike, but the two
    are handled differently: a bad declaration is an operator error and is
    fatal, a bad unit on a peer's claim is evidence about that peer.
    """


def _d(m=0, kg=0, s=0, A=0, K=0, mol=0, cd=0, scale=1.0, offset=0.0):
    return Dimension((m, kg, s, A, K, mol, cd), scale, offset)


#: Symbol table: unit symbol -> :class:`Dimension`.
#:
#: Every entry is exact in the sense that matters: the scale is the defining
#: conversion, written to full double precision so the C mirror's literal
#: parses to the same bits. Entries are deliberately few. A symbol that is not
#: here is refused rather than guessed at, because guessing is how a checker
#: starts accepting claims it cannot actually check.
#:
#: Two collisions worth naming, both resolved toward SI:
#:  * ``C`` is the coulomb, NOT Celsius --- Celsius is ``degC``. The services
#:    layer's ``Reading.unit`` uses ``"C"`` for Celsius as a DISPLAY string;
#:    it never reaches this parser (the carrier here is a task result), and a
#:    declaration that means Celsius must say ``degC``.
#:  * ``T`` is the tesla and ``t`` the tonne. The table is case-sensitive
#:    throughout, as SI is.
UNITS: dict[str, Dimension] = {
    # -- dimensionless ---------------------------------------------------
    '': _d(),
    '1': _d(),
    '-': _d(),
    '%': _d(scale=0.01),
    'ppm': _d(scale=1e-6),
    'rad': _d(),
    'sr': _d(),
    'deg': _d(scale=0.017453292519943295),   # pi/180
    'count': _d(),
    # -- length ----------------------------------------------------------
    'm': _d(m=1),
    'km': _d(m=1, scale=1e3),
    'cm': _d(m=1, scale=1e-2),
    'mm': _d(m=1, scale=1e-3),
    'um': _d(m=1, scale=1e-6),
    'nm': _d(m=1, scale=1e-9),
    'ft': _d(m=1, scale=0.3048),
    'mi': _d(m=1, scale=1609.344),
    'nmi': _d(m=1, scale=1852.0),
    # -- mass ------------------------------------------------------------
    'kg': _d(kg=1),
    'g': _d(kg=1, scale=1e-3),
    'mg': _d(kg=1, scale=1e-6),
    'ug': _d(kg=1, scale=1e-9),
    't': _d(kg=1, scale=1e3),
    # -- time ------------------------------------------------------------
    's': _d(s=1),
    'ms': _d(s=1, scale=1e-3),
    'us': _d(s=1, scale=1e-6),
    'ns': _d(s=1, scale=1e-9),
    'min': _d(s=1, scale=60.0),
    'h': _d(s=1, scale=3600.0),
    'd': _d(s=1, scale=86400.0),
    # -- current ---------------------------------------------------------
    'A': _d(A=1),
    'mA': _d(A=1, scale=1e-3),
    'uA': _d(A=1, scale=1e-6),
    # -- temperature -----------------------------------------------------
    'K': _d(K=1),
    'degC': _d(K=1, offset=273.15),
    'degF': _d(K=1, scale=0.5555555555555556, offset=255.3722222222222),
    # -- amount / luminous ------------------------------------------------
    'mol': _d(mol=1),
    'mmol': _d(mol=1, scale=1e-3),
    'cd': _d(cd=1),
    # -- coherent derived --------------------------------------------------
    'Hz': _d(s=-1),
    'N': _d(m=1, kg=1, s=-2),
    'Pa': _d(m=-1, kg=1, s=-2),
    'kPa': _d(m=-1, kg=1, s=-2, scale=1e3),
    'bar': _d(m=-1, kg=1, s=-2, scale=1e5),
    'J': _d(m=2, kg=1, s=-2),
    'kJ': _d(m=2, kg=1, s=-2, scale=1e3),
    'W': _d(m=2, kg=1, s=-3),
    'mW': _d(m=2, kg=1, s=-3, scale=1e-3),
    'kW': _d(m=2, kg=1, s=-3, scale=1e3),
    'MW': _d(m=2, kg=1, s=-3, scale=1e6),
    'C': _d(s=1, A=1),
    'V': _d(m=2, kg=1, s=-3, A=-1),
    'mV': _d(m=2, kg=1, s=-3, A=-1, scale=1e-3),
    'ohm': _d(m=2, kg=1, s=-3, A=-2),
    'F': _d(m=-2, kg=-1, s=4, A=2),
    'H': _d(m=2, kg=1, s=-2, A=-2),
    'Wb': _d(m=2, kg=1, s=-2, A=-1),
    'T': _d(kg=1, s=-2, A=-1),
    'Ah': _d(s=1, A=1, scale=3600.0),
    'Wh': _d(m=2, kg=1, s=-2, scale=3600.0),
}

#: The dimensionless unit, as a constant, for the common no-unit case.
DIMENSIONLESS: Dimension = UNITS['']


def _parse_symbol(text: str, pos: int) -> tuple[str, int]:
    """Longest run of symbol characters starting at ``pos``.

    Letters, ``%`` and ``-`` (only as the whole dimensionless symbol) make up
    a symbol; a digit ends it, because a trailing digit is the exponent.
    """
    start = pos
    while pos < len(text) and (text[pos].isalpha() or text[pos] == '%'):
        pos += 1
    return text[start:pos], pos


def _parse_exponent(text: str, pos: int) -> tuple[int, int]:
    """Optional exponent after a symbol: ``^-2``, ``-2``, ``3`` or nothing."""
    if pos < len(text) and text[pos] == '^':
        pos += 1
    sign = 1
    if pos < len(text) and text[pos] == '-':
        sign = -1
        pos += 1
    start = pos
    while pos < len(text) and text[pos].isdigit():
        pos += 1
    if pos == start:
        if sign < 0:
            raise UnitError(f'unit {text!r}: "-" with no exponent digits')
        return 1, pos
    return sign * int(text[start:pos]), pos


def parse_unit(text: Optional[str]) -> Dimension:
    """Parse a unit string to a :class:`Dimension`.

    Raises :class:`UnitError` for an unknown symbol or a malformed
    expression, and for an affine unit used inside a compound expression ---
    see the module docstring for why that one is an error rather than a
    silent offset drop.
    """
    if text is None:
        return DIMENSIONLESS
    text = text.strip()
    if text in UNITS:               # fast path, and the only path for degC
        return UNITS[text]
    if not text:
        return DIMENSIONLESS

    exponents = [0] * N_BASE
    scale = 1.0
    pos = 0
    sign = 1                        # +1 after '*', -1 after '/'
    seen_term = False
    while pos < len(text):
        ch = text[pos]
        if ch.isspace():
            pos += 1
            continue
        if ch in '*/':
            if not seen_term:
                raise UnitError(f'unit {text!r}: operator before any term')
            sign = 1 if ch == '*' else -1
            pos += 1
            continue
        if ch == '1' and (pos + 1 >= len(text) or not text[pos + 1].isdigit()):
            # A bare 1 numerator, as in "1/s". Contributes nothing.
            pos += 1
            seen_term = True
            continue
        sym, pos = _parse_symbol(text, pos)
        if not sym:
            raise UnitError(f'unit {text!r}: unexpected {text[pos]!r} at {pos}')
        dim = UNITS.get(sym)
        if dim is None:
            raise UnitError(f'unit {text!r}: unknown symbol {sym!r}')
        if dim.offset != 0.0:
            raise UnitError(
                f'unit {text!r}: affine unit {sym!r} cannot appear in a '
                f'compound expression (its offset does not distribute)')
        power, pos = _parse_exponent(text, pos)
        power *= sign
        for i in range(N_BASE):
            exponents[i] += dim.exponents[i] * power
        # Repeated multiplication, then one divide for a negative exponent,
        # rather than `dim.scale ** power`. Not pedantry: `1e-3 ** -1` is
        # 999.9999999999999 while `1 / 1e-3` is exactly 1000.0, and the C twin
        # would have to reproduce whichever one this chose. A loop and a
        # divide is the one spelling both languages compute identically, and
        # the exponents here are small integers by construction.
        term_scale = 1.0
        for _ in range(abs(power)):
            term_scale *= dim.scale
        if power < 0:
            scale /= term_scale
        else:
            scale *= term_scale
        seen_term = True
    if not seen_term:
        raise UnitError(f'unit {text!r}: no terms')
    return Dimension(tuple(exponents), scale, 0.0)


def same_dimension(a: Optional[str], b: Optional[str]) -> bool:
    """True when two unit strings denote the same physical dimension.

    Raises :class:`UnitError` if either is unparseable --- the caller decides
    whether that is an operator error or evidence about a peer.
    """
    return parse_unit(a).same_dimension(parse_unit(b))
