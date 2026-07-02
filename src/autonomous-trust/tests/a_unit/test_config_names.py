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
from autonomous_trust.core.config.names import random_name


def test_random_name_default():
    name = random_name()
    assert '_' in name
    parts = name.split('_')
    assert len(parts) == 2


def test_random_name_custom_sep():
    name = random_name(sep='-')
    assert '-' in name


def test_random_name_no_sep():
    name = random_name(sep='')
    assert isinstance(name, str)
    assert len(name) > 0


def test_random_name_capitalized():
    name = random_name(sep='_', cap=True)
    parts = name.split('_')
    assert parts[0][0].isupper()
    assert parts[1][0].isupper()
