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
"""Catch-up entries marked as told (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 3,
D2 (b)).

Under an enabled join policy a joiner adopts the chain catch-up hands it, as
before, and records locally which entries it was not party to. The marks are
persisted, never sent, and nothing reads them until the told ceiling
(Phase 4). Inert, nothing is marked.
"""
import json
import os

import pytest

from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core._python.identity.join_policy import JoinPolicy
from autonomous_trust.core._python.reputation.repprocess import CATCHUP_MARKS_FILE

from tests.a_unit.test_update_pages import (ENTRIES, _deliver, _id, _receiver,
                                            _staged)

ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


def _marks_file():
    return os.path.join(Configuration.get_cfg_dir(),
                        CATCHUP_MARKS_FILE + Configuration.file_ext)


def _window(rp):
    return to_json_string(list(rp.history))


def test_entries_between_others_are_marked_told():
    ada, bob = _id('ada', 1), _id('bob', 2)
    sender, _ = _staged(ada, bob)
    rp, q = _receiver()
    rp.join_policy = ON
    _deliver(rp, q, _window(sender), ada)
    assert len(rp.history) == ENTRIES
    assert all(rp.is_told(tx.index) for tx in rp.history)
    with open(_marks_file()) as f:
        assert json.load(f) == {'': [tx.index for tx in rp.history]}


def test_an_entry_naming_us_is_not_told():
    ada, cal = _id('ada', 1), _id('cal', 3)
    sender, _ = _staged(ada, cal)
    rp, q = _receiver()                          # cal
    rp.join_policy = ON
    _deliver(rp, q, _window(sender), ada)
    assert len(rp.history) == ENTRIES
    assert not any(rp.is_told(tx.index) for tx in rp.history)
    assert not os.path.exists(_marks_file())


def test_an_inert_policy_marks_nothing():
    ada, bob = _id('ada', 1), _id('bob', 2)
    sender, _ = _staged(ada, bob)
    rp, q = _receiver()
    _deliver(rp, q, _window(sender), ada)
    assert len(rp.history) == ENTRIES
    assert rp._catchup_marks == {}
    assert not os.path.exists(_marks_file())


def test_the_marks_survive_a_restart():
    with open(_marks_file(), 'w') as f:
        json.dump({'': [3, 4], 'child': [7]}, f)
    rp, _ = _receiver()
    assert rp.is_told(3) and rp.is_told(7, 'child') and not rp.is_told(5)


def test_a_corrupt_marks_file_is_left_in_place():
    with open(_marks_file(), 'w') as f:
        json.dump({'': ['x']}, f)
    rp, _ = _receiver()
    assert rp._catchup_marks == {}
    assert os.path.exists(_marks_file())
