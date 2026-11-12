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
"""Tier hysteresis (doc/architecture/trust-tiers.md, "Hysteresis"): promotion
happens at a tier's floor and demotion at the floor less the ladder's
tier_demotion_epsilon (0.02 by default), so a peer whose score hovers on a
floor holds its tier instead of flapping across it.

Found on the Wi-Fi fleet (2026-11-11): a node failing probes settled at
0.63-0.66 and every observer, the Raspberry Pi included, moved it between tiers
1 and 2 three to six times in forty minutes. The margin was parsed from the
ladder but never applied. Mirrors the C twin, test/rep_tier_hysteresis_test.c.
"""
import json
import os
import queue
import time
from types import SimpleNamespace

import pytest

from autonomous_trust.core.system import CfgIds
from .test_peer_standing import _identity, _make_rep_process


@pytest.fixture
def root(tmp_path, monkeypatch):
    os.makedirs(tmp_path / 'etc' / 'at')
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    monkeypatch.delenv('AT_REP_MIN_TENURE_SEC', raising=False)
    monkeypatch.delenv('AT_TRUST_LADDER', raising=False)
    return tmp_path


def _node():
    rp = _make_rep_process()
    them = _identity('peer')
    rp.peers.all = [SimpleNamespace(uuid=them.uuid, signature=them.signature)]
    return rp, them


def _publish(rp, them, score):
    """Publish @p score and return the tier identity now holds for the peer."""
    rp._publish_tier_change({CfgIds.identity: queue.Queue()}, them.uuid, score)
    return rp.peer_tiers[str(them.uuid)]


def test_promotion_happens_at_the_floor(root):
    rp, them = _node()
    assert _publish(rp, them, 0.60) == 1
    assert _publish(rp, them, 0.65) == 2


def test_demotion_waits_for_the_floor_less_the_margin(root):
    rp, them = _node()
    assert _publish(rp, them, 0.70) == 2
    assert _publish(rp, them, 0.64) == 2
    assert _publish(rp, them, 0.631) == 2
    assert _publish(rp, them, 0.629) == 1


def test_a_score_hovering_on_a_floor_does_not_flap(root):
    """The Pi's own sequence for the defector, 2026-11-11."""
    rp, them = _node()
    tiers = [_publish(rp, them, s)
             for s in (0.795, 0.627, 0.660, 0.640, 0.651, 0.647, 0.629)]
    assert tiers == [2, 1, 2, 2, 2, 2, 1]


def test_the_margin_spans_several_tiers_only_as_far_as_the_score(root):
    rp, them = _node()
    assert _publish(rp, them, 0.95) == 4
    assert _publish(rp, them, 0.885) == 4
    assert _publish(rp, them, 0.79) == 3
    assert _publish(rp, them, 0.70) == 2


def test_a_tenure_hold_is_not_softened_by_the_margin(root, monkeypatch):
    """A young member is capped just under tier 3's floor, which is inside
    the margin: the hold, not the margin, decides its tier."""
    monkeypatch.setenv('AT_REP_MIN_TENURE_SEC', '600')
    rp, them = _node()
    rp._tenure_seeded = True
    rp._member_since[str(them.uuid)] = (None, time.time() - 1000)
    assert _publish(rp, them, 0.85) == 3
    rp._member_since[str(them.uuid)] = (None, time.time())
    assert _publish(rp, them, rp._tenure_bound(them.uuid, 0.85)) == 2


def test_the_ladder_sets_the_margin(root, monkeypatch, tmp_path):
    ladder = tmp_path / 'ladder.json'
    ladder.write_text(json.dumps({'tier_demotion_epsilon': 0.0}))
    monkeypatch.setenv('AT_TRUST_LADDER', str(ladder))
    rp, them = _node()
    assert _publish(rp, them, 0.70) == 2
    assert _publish(rp, them, 0.649) == 1
