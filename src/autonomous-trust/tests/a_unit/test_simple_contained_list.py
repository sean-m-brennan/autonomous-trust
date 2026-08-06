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
import pytest

from autonomous_trust.simple.contained_list import ContainedList


class TestContainedList:
    def test_len(self):
        cl = ContainedList([1, 2, 3])
        assert len(cl) == 3

    def test_getitem(self):
        cl = ContainedList([10, 20, 30])
        assert cl[0] == 10
        assert cl[2] == 30

    def test_setitem(self):
        cl = ContainedList([1, 2, 3])
        cl[1] = 99
        assert cl[1] == 99

    def test_delitem(self):
        cl = ContainedList([1, 2, 3])
        del cl[0]
        assert len(cl) == 2
        assert cl[0] == 2

    def test_iter(self):
        cl = ContainedList([1, 2, 3])
        assert list(cl) == [1, 2, 3]

    def test_reversed(self):
        cl = ContainedList([1, 2, 3])
        assert list(reversed(cl)) == [3, 2, 1]

    def test_contains(self):
        cl = ContainedList([1, 2, 3])
        assert 2 in cl
        assert 5 not in cl

    def test_add(self):
        cl = ContainedList([1, 2])
        result = cl + [3, 4]
        assert result == [1, 2, 3, 4]

    def test_mul(self):
        cl = ContainedList([1, 2])
        result = cl * 2
        assert result == [1, 2, 1, 2]

    def test_rmul(self):
        cl = ContainedList([1, 2])
        result = 2 * cl
        assert result == [1, 2, 1, 2]

    def test_append(self):
        cl = ContainedList([1])
        cl.append(2)
        assert list(cl) == [1, 2]

    def test_insert(self):
        cl = ContainedList([1, 3])
        cl.insert(1, 2)
        assert list(cl) == [1, 2, 3]

    def test_pop(self):
        cl = ContainedList([1, 2, 3])
        val = cl.pop(1)
        assert val == 2
        assert len(cl) == 2

    def test_remove(self):
        cl = ContainedList([1, 2, 3])
        cl.remove(2)
        assert list(cl) == [1, 3]

    def test_count(self):
        cl = ContainedList([1, 2, 2, 3])
        assert cl.count(2) == 2
        assert cl.count(5) == 0

    def test_index(self):
        cl = ContainedList([10, 20, 30])
        assert cl.index(20) == 1

    def test_iadd(self):
        cl = ContainedList([1, 2])
        cl += [3, 4]
        assert 3 in cl
        assert 4 in cl

    def test_imul(self):
        cl = ContainedList([1])
        cl *= 3
        assert len(cl) == 3
