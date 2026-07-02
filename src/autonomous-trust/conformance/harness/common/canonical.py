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

"""RFC 8785 JSON Canonicalization (JCS) for the AT conformance harness.

Wire-byte pinning across Python and C requires both sides to emit bytes that
are equal at the byte level. JSON map-key ordering and number formatting are
implementation-defined, so a canonical form is required. JCS specifies one:
lexicographic key sort (by UTF-16 code unit), no insignificant whitespace,
and ES6 "shortest decimal" number formatting.

Python uses the upstream `jcs` package. The C harness implements the same
algorithm via Ryu (see `src/c/conformance/jcs.c`); parity is enforced by
`src/c/test/jcs_test.c`.
"""

from __future__ import annotations

import json
from typing import Any, Union

import jcs


def canonicalize(value: Union[bytes, str, dict, list, int, float, bool, None]) -> bytes:
    """Return JCS-canonical UTF-8 bytes for `value`.

    Accepts either a Python value (dict/list/etc.) or pre-serialised JSON
    bytes/str. In the latter case the bytes are parsed and re-emitted in
    canonical form — useful for canonicalising an implementation's wire output
    before byte-comparing it to a pinned fixture.
    """
    if isinstance(value, (bytes, bytearray)):
        value = json.loads(value.decode('utf-8'))
    elif isinstance(value, str):
        value = json.loads(value)
    return jcs.canonicalize(value)


def canonical_equals(a: Union[bytes, str, dict, list], b: Union[bytes, str, dict, list]) -> bool:
    """Byte-compare two values after canonicalisation."""
    return canonicalize(a) == canonicalize(b)
