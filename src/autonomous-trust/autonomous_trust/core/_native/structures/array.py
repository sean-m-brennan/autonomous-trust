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

"""
Python wrapper for the C ``array_t`` dynamic array.

``Array`` wraps an opaque ``array_t*`` and implements
``collections.abc.MutableSequence`` so it behaves like a Python list.
"""

import collections.abc

from .._ffi import ffi, lib
from .data import Data


class Array(collections.abc.MutableSequence):
    """Wrapper around C ``array_t*`` implementing MutableSequence."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, iterable=None, *, _ptr=None, _owned=True):
        if _ptr is not None:
            self._ptr = _ptr
            self._owned = _owned
            return

        self._owned = True
        arr_ptr = ffi.new('array_t **')
        # Workaround: array_create checks *arr_ptr != NULL
        arr_ptr[0] = ffi.cast('array_t *', 0x1)
        rc = lib.array_create(arr_ptr)
        if rc != 0:
            raise MemoryError(f"array_create failed with rc={rc}")
        self._ptr = arr_ptr[0]

        if iterable is not None:
            for item in iterable:
                self.append(item)

    @staticmethod
    def _to_data_ptr(value):
        """Convert a Python value to a data_t* for the C API.

        The returned pointer must outlive this call because C array_append
        does not increment the reference count.  We bump the ref count here;
        the Data's __del__ will later decrement it back, leaving count >= 1.
        """
        if isinstance(value, Data):
            lib.smrt_ref(value._ptr)
            return value._ptr
        d = Data(value)
        # Bump ref while d is alive (before GC can run __del__)
        lib.smrt_ref(d._ptr)
        ptr = d._ptr
        # d.__del__ will smrt_deref, bringing count from 2→1.
        return ptr

    def __len__(self):
        return lib.array_size(self._ptr)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError(f"array index {index} out of range")
        elem = ffi.new('data_t **')
        rc = lib.array_get(self._ptr, index, elem)
        if rc != 0:
            raise IndexError(f"array_get failed at index {index}")
        return Data(_ptr=elem[0], _owned=False).value

    def __setitem__(self, index, value):
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError(f"array index {index} out of range")
        rc = lib.array_set(self._ptr, index, self._to_data_ptr(value))
        if rc != 0:
            raise IndexError(f"array_set failed at index {index}")

    def __delitem__(self, index):
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError(f"array index {index} out of range")
        elem = ffi.new('data_t **')
        lib.array_get(self._ptr, index, elem)
        lib.array_remove(self._ptr, elem[0])

    def insert(self, index, value):
        # C array only supports append; for insert at arbitrary position,
        # we append and then shift (limited by C API).
        # For simplicity, only support append-at-end.
        if index >= len(self):
            self.append(value)
        else:
            raise NotImplementedError(
                "C array_t only supports append; insert at arbitrary "
                "index is not supported"
            )

    def append(self, value):
        rc = lib.array_append(self._ptr, self._to_data_ptr(value))
        if rc != 0:
            raise RuntimeError(f"array_append failed with rc={rc}")

    def __contains__(self, value):
        d = Data(value)
        return lib.array_contains(self._ptr, d._ptr)

    def index(self, value, start=0, stop=None):
        d = Data(value)
        idx = lib.array_find(self._ptr, d._ptr)
        if idx < 0:
            raise ValueError(f"{value!r} is not in array")
        return idx

    def __repr__(self):
        items = [self[i] for i in range(min(len(self), 10))]
        suffix = ', ...' if len(self) > 10 else ''
        return f'Array({items!r}{suffix})'

    def __del__(self):
        if self._owned and self._ptr != ffi.NULL:
            lib.array_free(self._ptr)
