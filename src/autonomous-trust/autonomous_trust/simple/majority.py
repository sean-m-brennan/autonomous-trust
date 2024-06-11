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

from typing import Any, Callable, Union


def _count_elts(elt_list: list[Any], short_circuit: Callable[[Any, int], bool] = None) -> dict[Any, int]:
    counts = {}
    for elt in elt_list:
        if elt not in counts.keys():
            counts[elt] = 1
        else:
            counts[elt] += 1
        if short_circuit and short_circuit(elt, counts[elt]):
            break
    return counts


def majority(*args: Union[Any, list[Any]]) -> bool:
    """Element (or True) is present in the given list more often than all other elements combined"""
    elt = True
    elt_list = []
    if len(args) == 2:
        elt = args[0]
        elt_list = args[1]
    elif len(args) == 1:
        elt_list = args[0]
    elif len(args) < 1:
        raise TypeError("majority() missing 1 required positional argument: 'elt_list', " +
                        "or 2 required positional_arguments 'elt' and 'elt_list'")
    else:
        raise TypeError('majority() takes at most 2 positional arguments but %d were given' % len(args))
    counts = _count_elts(elt_list)
    if counts[elt] > sum(counts.values()) - counts[elt]:
        return True
    return False


def majority_element(elt_list: list[Any]) -> Any:
    """Find the element present in the list more often than all other elements combined (or None)"""
    result = None

    def short_circuit(elt, count):
        nonlocal result
        if count > len(elt_list) / 2:
            result = elt
            return True
        return False

    _count_elts(elt_list, short_circuit)
    return result


def predominant(elt: Any, elt_list: list[Any]) -> bool:
    """Element is present in the list more often any other single element"""
    counts = _count_elts(elt_list)
    sort_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    if sort_counts[0][1] == counts[elt] and sort_counts[0][1] != sort_counts[1][1]:
        return True
    return False


def predominant_element(elt_list: list[Any]) -> Any:
    """Find the element present in the list more often any other single element (or None)"""
    counts = {}
    for elt in elt_list:
        if elt not in counts.keys():
            counts[elt] = 1
        else:
            counts[elt] += 1
    s = sorted(_count_elts(elt_list).items(), key=lambda item: item[1], reverse=True)
    if s[0][1] > s[1][1]:
        return s[0][0]
    return None  # no predominant element
