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
Python wrapper for the C ``map_t`` hash map.

``Map`` wraps an opaque ``map_t*`` and implements
``collections.abc.MutableMapping`` so it behaves like a Python dict.
Keys are always strings; values are auto-converted via ``Data``.
"""

import collections.abc

from .._ffi import ffi, lib
from .data import Data


class Map(collections.abc.MutableMapping):
    """Wrapper around C ``map_t*`` implementing MutableMapping."""

    __slots__ = ('_ptr', '_owned')

    def __init__(self, mapping=None, *, _ptr=None, _owned=True, **kwargs):
        if _ptr is not None:
            self._ptr = _ptr
            self._owned = _owned
            return

        self._owned = True
        map_ptr = ffi.new('map_t **')
        map_ptr[0] = ffi.cast('map_t *', 0x1)
        rc = lib.map_create(map_ptr)
        if rc != 0:
            raise MemoryError(f"map_create failed with rc={rc}")
        self._ptr = map_ptr[0]

        if mapping is not None:
            if isinstance(mapping, dict):
                for k, v in mapping.items():
                    self[k] = v
            else:
                for k, v in mapping:
                    self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    @staticmethod
    def _encode_key(key):
        """Ensure key is bytes for the C API."""
        if isinstance(key, str):
            return key.encode('utf-8')
        if isinstance(key, bytes):
            return key
        raise TypeError(f"Map keys must be str or bytes, not {type(key).__name__}")

    def __getitem__(self, key):
        bkey = self._encode_key(key)
        val = ffi.new('data_t **')
        rc = lib.map_get(self._ptr, bkey, val)
        if rc != 0:
            raise KeyError(key)
        return Data(_ptr=val[0], _owned=False).value

    def __setitem__(self, key, value):
        bkey = self._encode_key(key)
        if isinstance(value, Data):
            d = value
        else:
            d = Data(value)
        # Bump ref while d is alive (before GC can run __del__)
        lib.smrt_ref(d._ptr)
        rc = lib.map_set(self._ptr, bkey, d._ptr)
        if rc != 0:
            raise RuntimeError(f"map_set failed with rc={rc}")

    def __delitem__(self, key):
        bkey = self._encode_key(key)
        rc = lib.map_remove(self._ptr, bkey)
        if rc != 0:
            raise KeyError(key)

    def __len__(self):
        return lib.map_size(self._ptr)

    def __iter__(self):
        keys_arr = lib.map_keys(self._ptr)
        n = lib.array_size(keys_arr)
        for i in range(n):
            elem = ffi.new('data_t **')
            rc = lib.array_get(keys_arr, i, elem)
            if rc == 0:
                sptr = ffi.new('char **')
                rc2 = lib.data_string_ptr(elem[0], sptr)
                if rc2 == 0:
                    yield ffi.string(sptr[0]).decode('utf-8')

    def __contains__(self, key):
        bkey = self._encode_key(key)
        val = ffi.new('data_t **')
        return lib.map_get(self._ptr, bkey, val) == 0

    def __repr__(self):
        items = {k: self[k] for k in list(self)[:10]}
        suffix = ', ...' if len(self) > 10 else ''
        return f'Map({items!r}{suffix})'

    def __del__(self):
        if self._owned and self._ptr != ffi.NULL:
            lib.map_free(self._ptr)
