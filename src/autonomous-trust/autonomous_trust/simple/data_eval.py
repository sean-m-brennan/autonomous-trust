# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import uuid
from collections import OrderedDict
from typing import Callable

from data_service import Ident


def exponential_thresholds(index: int, sensitivity: int) -> int:
    return 2 ** (index - sensitivity)


def linear_thresholds(index: int, sensitivity: int) -> int:
    return index


def distance_hierarchy(distances: dict[frozenset[uuid.UUID], float],
                       get_thresholds: Callable[[int, int], int],
                       max_distance: int, sensitivity: int = None,
                       fixed: int = None) -> tuple[list[set[Ident]], list[int]]:
    pairs = distances.keys()
    peers = set([p for pair in pairs for p in pair])

    thresholds = []
    groups = []
    idx = 0
    jdx = 0
    prev_dist = 0
    while True:
        grp_added = False
        if len(groups) < idx + 1 and (fixed is None or len(groups) < fixed):
            groups.append(set())
            grp_added = True
        max_dist = 0.
        threshold = get_thresholds(jdx, sensitivity)  # category threshold increases exponentially
        ascending_distances = OrderedDict({k: v for k, v in sorted(distances.items(), key=lambda item: item[1])})
        for key, dist in ascending_distances.items():
            dist_dist = abs(dist - prev_dist)
            if dist_dist <= threshold:
                if dist_dist > max_dist:
                    max_dist = dist_dist
                flattened = set([p for grp in groups for p in grp])
                for p in key:
                    if p not in flattened:
                        groups[idx].add(p)
        if grp_added and len(groups) < fixed:
            idx += 1
        if len(groups) > len(thresholds):
            thresholds.append(threshold)
        prev_dist = max_dist
        jdx += 1
        if len(set([p for grp in groups for p in grp])) >= len(peers):
            break
    if fixed is not None:
        while len(groups) < fixed:
            groups.append(set())
            thresholds.append(get_thresholds(jdx, sensitivity))
            jdx += 1

    return groups, list(map(lambda x: x / max_distance, thresholds))
