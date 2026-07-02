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
import numpy as np
import pytest

from autonomous_trust.services.data.serialize import serialize, deserialize


class TestSerializeSafe:
    def test_roundtrip_1d(self):
        arr = np.array([1.0, 2.0, 3.0])
        data = serialize(arr, fast=False)
        result = deserialize(data, fast=False)
        np.testing.assert_array_equal(arr, result)

    def test_roundtrip_2d(self):
        arr = np.random.rand(10, 10)
        data = serialize(arr, fast=False)
        result = deserialize(data, fast=False)
        np.testing.assert_array_almost_equal(arr, result)

    def test_roundtrip_integers(self):
        arr = np.array([1, 2, 3, 4, 5], dtype=np.int32)
        data = serialize(arr, fast=False)
        result = deserialize(data, fast=False)
        np.testing.assert_array_equal(arr, result)

    def test_returns_bytes(self):
        arr = np.array([1.0])
        data = serialize(arr, fast=False)
        assert isinstance(data, bytes)

    def test_empty_array(self):
        arr = np.array([])
        data = serialize(arr, fast=False)
        result = deserialize(data, fast=False)
        np.testing.assert_array_equal(arr, result)


class TestSerializeFast:
    def test_roundtrip_1d(self):
        arr = np.array([1.0, 2.0, 3.0])
        data = serialize(arr, fast=True)
        result = deserialize(data, fast=True)
        np.testing.assert_array_equal(arr, result)

    def test_roundtrip_2d(self):
        arr = np.random.rand(10, 10)
        data = serialize(arr, fast=True)
        result = deserialize(data, fast=True)
        np.testing.assert_array_almost_equal(arr, result)

    def test_returns_bytes(self):
        arr = np.array([1.0])
        data = serialize(arr, fast=True)
        assert isinstance(data, bytes)

    def test_roundtrip_3d_image_like(self):
        arr = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
        data = serialize(arr, fast=True)
        result = deserialize(data, fast=True)
        np.testing.assert_array_equal(arr, result)


class TestSerializeCrossModes:
    def test_fast_and_safe_produce_identical_bytes(self):
        arr = np.array([1.0, 2.0, 3.0])
        fast_data = serialize(arr, fast=True)
        safe_data = serialize(arr, fast=False)
        assert fast_data == safe_data

    def test_cross_mode_roundtrip(self):
        arr = np.array([1.0, 2.0, 3.0])
        data = serialize(arr, fast=True)
        result = deserialize(data, fast=False)
        np.testing.assert_array_equal(arr, result)
