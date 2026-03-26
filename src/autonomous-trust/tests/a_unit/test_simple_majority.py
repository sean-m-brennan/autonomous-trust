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
import pytest

from autonomous_trust.simple.majority import (
    _count_elts, majority, majority_element, predominant, predominant_element,
)


class TestCountElts:
    def test_basic(self):
        counts = _count_elts([1, 2, 1, 3, 1])
        assert counts[1] == 3
        assert counts[2] == 1
        assert counts[3] == 1

    def test_empty(self):
        counts = _count_elts([])
        assert counts == {}

    def test_short_circuit(self):
        result = []
        def sc(elt, count):
            if count >= 2:
                result.append(elt)
                return True
            return False
        counts = _count_elts([1, 2, 1, 3, 3], sc)
        assert 1 in result


class TestMajority:
    def test_true_majority(self):
        assert majority([True, True, True, False]) is True

    def test_no_majority(self):
        assert majority([True, True, False, False]) is False

    def test_element_majority(self):
        assert majority('a', ['a', 'a', 'a', 'b']) is True

    def test_element_no_majority(self):
        assert majority('a', ['a', 'b', 'b', 'b']) is False

    def test_too_few_args(self):
        with pytest.raises(TypeError):
            majority()

    def test_too_many_args(self):
        with pytest.raises(TypeError):
            majority(1, 2, 3)


class TestMajorityElement:
    def test_has_majority(self):
        assert majority_element(['a', 'a', 'a', 'b', 'c']) == 'a'

    def test_no_majority(self):
        assert majority_element(['a', 'b', 'c']) is None

    def test_single_element(self):
        assert majority_element(['x']) == 'x'


class TestPredominant:
    def test_is_predominant(self):
        assert predominant('a', ['a', 'a', 'b', 'c']) is True

    def test_not_predominant(self):
        assert predominant('a', ['a', 'a', 'b', 'b', 'c']) is False


class TestPredominantElement:
    def test_has_predominant(self):
        assert predominant_element(['a', 'a', 'b', 'c']) == 'a'

    def test_no_predominant(self):
        assert predominant_element(['a', 'a', 'b', 'b']) is None
