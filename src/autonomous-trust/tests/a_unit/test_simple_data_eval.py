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
from uuid import uuid4

from autonomous_trust.simple.data_eval import (
    exponential_thresholds, linear_thresholds, distance_hierarchy,
)
from autonomous_trust.simple.data_service import Ident


class TestThresholds:
    def test_exponential(self):
        assert exponential_thresholds(4, 2) == 4  # 2^(4-2) = 4
        assert exponential_thresholds(2, 2) == 1  # 2^0 = 1
        assert exponential_thresholds(0, 2) == 0.25  # 2^-2

    def test_linear(self):
        assert linear_thresholds(5, 2) == 5
        assert linear_thresholds(0, 0) == 0


class TestDistanceHierarchy:
    def test_basic(self):
        p1 = Ident('p1')
        p2 = Ident('p2')
        p3 = Ident('p3')
        distances = {
            frozenset([p1.uuid, p2.uuid]): 0.1,
            frozenset([p1.uuid, p3.uuid]): 0.5,
            frozenset([p2.uuid, p3.uuid]): 0.4,
        }
        groups, thresholds = distance_hierarchy(
            distances, exponential_thresholds, 1.0, sensitivity=0, fixed=3
        )
        assert len(groups) == 3
        total_peers = sum(len(g) for g in groups)
        assert total_peers == 3
