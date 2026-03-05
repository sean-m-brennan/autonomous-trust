# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""
Python wrapper for the C ``data_t`` type abstraction.

``Data`` wraps an opaque ``data_t*`` pointer and provides Pythonic
access to the stored value via ``.type`` and ``.value`` properties.
"""

from .._ffi import ffi, lib


# Map C enum values to human-readable names
class DataType:
    NONE = 0
    INT = 1
    UINT = 2
    FLOAT = 3
    BOOL = 4
    STRING = 5
    BYTES = 6
    OBJECT = 7


class Data:
    """Wrapper around C ``data_t*`` providing automatic type conversion."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, value=None, *, _ptr=None, _owned=True):
        """Create a Data wrapper.

        Args:
            value: A Python value (int, float, bool, str, bytes) to wrap.
            _ptr:  An existing ``data_t*`` CFFI pointer (for internal use).
            _owned: Whether this wrapper owns the pointer (calls free on del).
        """
        if _ptr is not None:
            self._ptr = _ptr
            self._owned = _owned
            return

        self._owned = True
        if value is None:
            self._ptr = ffi.NULL
        elif isinstance(value, bool):
            self._ptr = lib.boolean_data(value)
        elif isinstance(value, int):
            if value < 0:
                self._ptr = lib.l_integer_data(value)
            else:
                self._ptr = lib.ul_integer_data(value)
        elif isinstance(value, float):
            self._ptr = lib.floating_pt_dbl_data(value)
        elif isinstance(value, str):
            encoded = value.encode('utf-8')
            buf = ffi.new('char[]', encoded)
            self._ptr = lib.string_data(buf, len(encoded))
        elif isinstance(value, (bytes, bytearray)):
            buf = ffi.new('unsigned char[]', bytes(value))
            self._ptr = lib.bytes_data(buf, len(value))
        else:
            raise TypeError(f"Cannot wrap {type(value).__name__} as Data")

    @property
    def value(self):
        """Extract the stored value as a Python object."""
        if self._ptr == ffi.NULL:
            return None
        # Try each type in order
        val = ffi.new('bool *')
        if lib.data_boolean(self._ptr, val) == 0:
            return val[0]

        ival = ffi.new('long *')
        if lib.data_l_integer(self._ptr, ival) == 0:
            return ival[0]

        uval = ffi.new('unsigned long *')
        if lib.data_ul_integer(self._ptr, uval) == 0:
            return uval[0]

        dval = ffi.new('double *')
        if lib.data_floating_pt_dbl(self._ptr, dval) == 0:
            return dval[0]

        sptr = ffi.new('char **')
        if lib.data_string_ptr(self._ptr, sptr) == 0:
            return ffi.string(sptr[0]).decode('utf-8')

        bptr = ffi.new('unsigned char **')
        if lib.data_bytes_ptr(self._ptr, bptr) == 0:
            # Need length — not directly available from API
            # Return the raw pointer info
            return bytes(ffi.buffer(bptr[0]))

        return None

    @property
    def int_value(self):
        """Extract as int (raises on type mismatch)."""
        val = ffi.new('int *')
        rc = lib.data_integer(self._ptr, val)
        if rc != 0:
            raise TypeError("Data does not contain an integer")
        return val[0]

    @property
    def float_value(self):
        """Extract as float."""
        val = ffi.new('double *')
        rc = lib.data_floating_pt_dbl(self._ptr, val)
        if rc != 0:
            raise TypeError("Data does not contain a float")
        return val[0]

    @property
    def str_value(self):
        """Extract as str."""
        sptr = ffi.new('char **')
        rc = lib.data_string_ptr(self._ptr, sptr)
        if rc != 0:
            raise TypeError("Data does not contain a string")
        return ffi.string(sptr[0]).decode('utf-8')

    @property
    def bool_value(self):
        """Extract as bool."""
        val = ffi.new('bool *')
        rc = lib.data_boolean(self._ptr, val)
        if rc != 0:
            raise TypeError("Data does not contain a boolean")
        return val[0]

    def __eq__(self, other):
        if isinstance(other, Data):
            return lib.data_equal(self._ptr, other._ptr)
        return NotImplemented

    def __repr__(self):
        try:
            v = self.value
        except Exception:
            v = '<error>'
        return f'Data({v!r})'

    def __del__(self):
        if self._owned and self._ptr != ffi.NULL:
            lib.smrt_deref(self._ptr)
