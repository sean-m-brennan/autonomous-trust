# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

"""Parity tests for the JCS canonicalize() helper. These are also the C-side
reference vectors: src/c/test/jcs_test.c asserts identical output."""

from __future__ import annotations

from ..canonical import canonical_equals, canonicalize


def test_sorts_keys() -> None:
    assert canonicalize({'b': 2, 'a': 1}) == b'{"a":1,"b":2}'


def test_nested_objects_sorted() -> None:
    obj = {'outer': {'z': 1, 'a': {'y': 2, 'x': 3}}}
    assert canonicalize(obj) == b'{"outer":{"a":{"x":3,"y":2},"z":1}}'


def test_integer_vs_float_keeps_dot_only_when_needed() -> None:
    # JCS / ES6: integer-valued doubles emit as integers, no trailing .0
    assert canonicalize({'n': 1.0}) == b'{"n":1}'
    assert canonicalize({'n': 0.8}) == b'{"n":0.8}'


def test_negative_zero_normalised() -> None:
    # ES6 §7.1.12.1 emits -0 as "0"
    assert canonicalize({'n': -0.0}) == b'{"n":0}'


def test_strings_preserved_utf8() -> None:
    # ASCII unaffected; non-ASCII is emitted as raw UTF-8 (JCS §3.2.2.2)
    assert canonicalize({'s': 'hello'}) == b'{"s":"hello"}'
    assert canonicalize({'s': 'héllo'}) == '{"s":"héllo"}'.encode('utf-8')


def test_array_order_preserved() -> None:
    # Arrays are NOT sorted; element order is semantically significant
    assert canonicalize([3, 1, 2]) == b'[3,1,2]'


def test_accepts_bytes_input() -> None:
    raw = b'{"b":2,"a":1}'
    assert canonicalize(raw) == b'{"a":1,"b":2}'


def test_accepts_str_input() -> None:
    raw = '{"b":2,"a":1}'
    assert canonicalize(raw) == b'{"a":1,"b":2}'


def test_canonical_equals_across_formats() -> None:
    assert canonical_equals({'a': 1, 'b': 2}, b'{"b":2,"a":1}')
    assert not canonical_equals({'a': 1}, {'a': 2})


def test_booleans_and_null() -> None:
    assert canonicalize({'t': True, 'f': False, 'n': None}) == b'{"f":false,"n":null,"t":true}'
