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
"""Tests for `scripts/audit-ffi-drift.py`'s struct field-name check (ISSUES §9.2).

The auditor is the gate that was supposed to catch `public_identity_t` drifting
twice in seven days and did not, because it compared only function arity. These
tests pin the parser against the two spellings that made a naive text comparison
useless -- anonymous embedded members and `#ifdef`-guarded fields -- plus the
shapes of both real recurrences.
"""
import importlib.util
import os

import pytest

_SCRIPT = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..',
                       'scripts', 'audit-ffi-drift.py')
_SCRIPT = os.path.abspath(_SCRIPT)

if not os.path.exists(_SCRIPT):        # installed package, not a source checkout
    pytest.skip('audit-ffi-drift.py not present', allow_module_level=True)

_spec = importlib.util.spec_from_file_location('audit_ffi_drift', _SCRIPT)
aud = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aud)


class TestParseStructs:
    def test_a_typedef_struct_is_found_with_its_body(self):
        structs = aud.parse_structs('typedef struct { int a; char b; } thing_t;')
        assert list(structs) == ['thing_t']

    def test_a_tagged_typedef_is_found(self):
        structs = aud.parse_structs('typedef struct tag_s { int a; } tag_t;')
        assert 'tag_t' in structs

    def test_an_opaque_typedef_has_no_body_to_compare(self):
        assert aud.parse_structs('typedef struct opaque_s opaque_t;') == {}

    def test_nested_braces_do_not_end_the_struct_early(self):
        structs = aud.parse_structs(
            'typedef struct { int a; union { int x; float y; } u; int b; } n_t;')
        assert aud.struct_fields('n_t', structs) == ['a', 'u', 'b']

    def test_the_first_definition_wins(self):
        """A stale copy must not shadow the real header."""
        structs = aud.parse_structs('typedef struct { int a; } d_t;'
                                    'typedef struct { int b; } d_t;')
        assert aud.struct_fields('d_t', structs) == ['a']


class TestFieldNames:
    def _fields(self, body, extra=''):
        structs = aud.parse_structs('typedef struct {%s} s_t;%s' % (body, extra))
        return aud.struct_fields('s_t', structs)

    def test_pointers_and_arrays_yield_the_field_name(self):
        assert self._fields('uint8_t *data; char name[65];') == ['data', 'name']

    def test_a_multi_dimensional_array(self):
        assert self._fields('char anchors[8][64];') == ['anchors']

    def test_a_function_pointer_yields_its_name_not_its_args(self):
        assert self._fields(
            'int (*to_json)(const void *d, void **o); size_t len;'
        ) == ['to_json', 'len']

    def test_several_declarators_in_one_member(self):
        assert self._fields('int a, *b, c[4];') == ['a', 'b', 'c']

    def test_a_bitfield_width_is_not_a_field(self):
        assert self._fields('unsigned flags : 3;') == ['flags']

    def test_an_anonymous_embedded_typedef_contributes_its_fields(self):
        """C writes `smrt_ptr_t;` with no name (-fms-extensions); the cdef writes
        the fields out. Both must reduce to the same list or every struct with a
        smart pointer reads as drift."""
        assert self._fields(
            'smrt_ptr_t; int rest;',
            extra='typedef struct { bool alloc; size_t refs; } smrt_ptr_t;'
        ) == ['alloc', 'refs', 'rest']

    def test_an_anonymous_nested_struct_is_flattened(self):
        assert self._fields('struct { int x; int y; }; int z;') == ['x', 'y', 'z']

    def test_a_named_nested_union_is_one_field(self):
        assert self._fields('union { int a; float b; } target;') == ['target']

    def test_an_anonymous_system_struct_uses_the_documented_field_list(self):
        """`datetime_t` embeds glibc's `struct tm;`, which we do not parse."""
        assert self._fields('struct tm; unsigned long tm_nsec;') == \
            aud.EXTERNAL_ANON['tm'] + ['tm_nsec']

    def test_a_self_reference_does_not_recurse_forever(self):
        structs = aud.parse_structs('typedef struct { loop_t; int a; } loop_t;')
        assert aud.struct_fields('loop_t', structs) is not None


class TestConditionals:
    def test_a_defined_guard_keeps_its_fields(self):
        text = ('typedef struct { int a;\n#ifdef AT_ZTA_ENABLED\n'
                'int zta;\n#endif\nint b; } s_t;')
        resolved, unknown = aud.resolve_conditionals(text)
        structs = aud.parse_structs(resolved)
        assert aud.struct_fields('s_t', structs) == ['a', 'zta', 'b']
        assert not unknown

    def test_an_undefined_guard_drops_its_fields(self):
        text = ('typedef struct { int a;\n#ifdef AT_SOMETHING_ELSE\n'
                'int nope;\n#endif\nint b; } s_t;')
        resolved, unknown = aud.resolve_conditionals(text)
        assert aud.struct_fields('s_t', aud.parse_structs(resolved)) == ['a', 'b']
        assert 'AT_SOMETHING_ELSE' in unknown       # reported, not assumed

    def test_ifndef_is_inverted(self):
        text = ('typedef struct { int a;\n#ifndef AT_ZTA_ENABLED\nint nope;\n'
                '#else\nint yes;\n#endif\n } s_t;')
        resolved, _ = aud.resolve_conditionals(text)
        assert aud.struct_fields('s_t', aud.parse_structs(resolved)) == ['a', 'yes']

    def test_if_defined_expression(self):
        text = ('typedef struct { int a;\n#if defined(AT_ZTA_ENABLED)\nint z;\n'
                '#endif\n } s_t;')
        resolved, _ = aud.resolve_conditionals(text)
        assert aud.struct_fields('s_t', aud.parse_structs(resolved)) == ['a', 'z']

    def test_nested_guards(self):
        text = ('typedef struct { int a;\n#ifdef AT_ZTA_ENABLED\n'
                '#ifdef AT_NOPE\nint no;\n#endif\nint yes;\n#endif\n } s_t;')
        resolved, _ = aud.resolve_conditionals(text)
        assert aud.struct_fields('s_t', aud.parse_structs(resolved)) == ['a', 'yes']

    def test_cplusplus_guards_do_not_eat_the_declarations(self):
        """`#ifdef __cplusplus extern "C" {` must drop with its brace."""
        text = ('#ifdef __cplusplus\nextern "C" {\n#endif\n'
                'typedef struct { int a; } s_t;\n')
        resolved, _ = aud.resolve_conditionals(text)
        assert aud.struct_fields('s_t', aud.parse_structs(resolved)) == ['a']


class TestAuditStructs:
    """The comparison itself, including the DANGEROUS / LATENT split."""

    C_TEXT = ('typedef struct { bool alloc; size_t refs; } smrt_ptr_t;'
              'typedef struct { smrt_ptr_t; int a; int b; } used_t;'
              'typedef struct { int x; int y; } unused_t;')

    def test_an_exact_mirror_is_clean(self):
        cdef = ('typedef struct { bool alloc; size_t refs; } smrt_ptr_t;'
                'typedef struct { bool alloc; size_t refs; int a; int b; } used_t;'
                'typedef struct { int x; int y; } unused_t;')
        dangerous, latent, unmirrored, _ = aud.audit_structs(cdef, self.C_TEXT, '')
        assert (dangerous, latent) == ([], [])

    def test_a_missing_trailing_field_is_reported(self):
        """The shape of both real recurrences."""
        cdef = ('typedef struct { bool alloc; size_t refs; int a; } used_t;')
        dangerous, latent, _, _ = aud.audit_structs(cdef, self.C_TEXT, '')
        assert [row[0] for row in latent] == ['used_t']
        assert 'b' in aud.describe_field_drift(latent[0][1], latent[0][2])

    def test_allocation_from_python_makes_it_dangerous(self):
        cdef = 'typedef struct { bool alloc; size_t refs; int a; } used_t;'
        pynative = """ptr = ffi.new('used_t *')"""
        dangerous, latent, _, _ = aud.audit_structs(cdef, self.C_TEXT, pynative)
        assert [row[0] for row in dangerous] == ['used_t']
        assert latent == []

    def test_sizing_from_python_also_counts(self):
        cdef = 'typedef struct { bool alloc; size_t refs; int a; } used_t;'
        dangerous, _, _, _ = aud.audit_structs(cdef, self.C_TEXT,
                                               'n = ffi.sizeof("used_t")')
        assert [row[0] for row in dangerous] == ['used_t']

    def test_a_reordered_field_is_reported_as_order(self):
        cdef = ('typedef struct { bool alloc; size_t refs; int b; int a; } used_t;')
        _, latent, _, _ = aud.audit_structs(cdef, self.C_TEXT, '')
        assert 'ORDER' in aud.describe_field_drift(latent[0][1], latent[0][2])

    def test_an_extra_cdef_field_is_reported(self):
        cdef = ('typedef struct { bool alloc; size_t refs; int a; int b; '
                'int ghost; } used_t;')
        _, latent, _, _ = aud.audit_structs(cdef, self.C_TEXT, '')
        assert 'extra ghost' in aud.describe_field_drift(latent[0][1], latent[0][2])

    def test_a_cdef_only_struct_is_listed_separately_not_as_drift(self):
        cdef = 'typedef struct { int only; } shim_t;'
        dangerous, latent, unmirrored, _ = aud.audit_structs(cdef, self.C_TEXT, '')
        assert unmirrored == ['shim_t']
        assert (dangerous, latent) == ([], [])

    def test_aliased_spellings_do_not_read_as_drift(self):
        c_text = 'typedef struct { unsigned char private[64]; } signature_t;'
        cdef = 'typedef struct { unsigned char private_key[64]; } signature_t;'
        dangerous, latent, _, _ = aud.audit_structs(cdef, c_text, '')
        assert (dangerous, latent) == ([], [])

    def test_an_unknown_macro_inside_a_struct_is_warned_about(self):
        c_text = ('typedef struct { int a;\n#ifdef AT_FUTURE_FLAG\nint f;\n'
                  '#endif\n } s_t;')
        cdef = 'typedef struct { int a; } s_t;'
        _, _, _, warnings = aud.audit_structs(cdef, c_text, '')
        assert any('AT_FUTURE_FLAG' in w for w in warnings)


class TestTheRealTree:
    """Run against the checked-in cdef and headers: this is the gate itself."""

    def test_the_cdef_mirrors_the_c_structs(self):
        cdef = aud.cdef_blob()
        headers = aud.collect(['src/c/**/*.h'])
        pynative = aud.collect_py()
        dangerous, latent, _, _ = aud.audit_structs(cdef, headers, pynative)
        assert dangerous == [], [
            (name, aud.describe_field_drift(mine, theirs))
            for name, mine, theirs, _ in dangerous]
        assert latent == [], [
            (name, aud.describe_field_drift(mine, theirs))
            for name, mine, theirs, _ in latent]

    def test_the_structs_python_allocates_are_all_mirrored(self):
        """A struct Python allocates but the cdef does not mirror from C would be
        invisible to this check -- the one blind spot worth asserting against."""
        cdef = aud.cdef_blob()
        headers = aud.collect(['src/c/**/*.h'])
        _, _, unmirrored, _ = aud.audit_structs(cdef, headers, aud.collect_py())
        allocated = [name for name in unmirrored
                     if "ffi.new('%s" % name in aud.collect_py()]
        assert allocated == []
