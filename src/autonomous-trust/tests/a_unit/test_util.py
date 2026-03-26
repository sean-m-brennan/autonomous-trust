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
from autonomous_trust.core.util import ClassEnumMeta


class SampleEnum(metaclass=ClassEnumMeta):
    alpha = 'a'
    beta = 'b'
    gamma = 'c'


class TestClassEnumMeta:
    def test_contains_valid(self):
        assert 'alpha' in SampleEnum
        assert 'beta' in SampleEnum

    def test_contains_invalid(self):
        assert 'nonexistent' not in SampleEnum

    def test_contains_private(self):
        assert '__class__' not in SampleEnum

    def test_iter(self):
        attrs = list(SampleEnum)
        assert 'alpha' in attrs
        assert 'beta' in attrs
        assert 'gamma' in attrs
