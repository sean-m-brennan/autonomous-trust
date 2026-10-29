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
"""Tenure (doc/architecture/reputation.md, "Tenure"): a member this node has
held for less than AT_REP_MIN_TENURE_SEC holds at most tier 2, however well it
has answered.

Found by Stele's red team (rt-3717776, 2026-10-15): the owner's shill answered
four probes honestly, ordered placement committed them in seconds, and the
observer scored it 0.90 (tier 4) fourteen seconds after it joined, then counted
it as a replica. These assert the tier the sweep queues for publication, the
thing identity's gates read. Mirrors the C twin, test/rep_tenure_test.c.
"""
import json
import os
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from nacl.encoding import HexEncoder

from autonomous_trust.core.config import Configuration
from .test_peer_standing import _identity, _make_rep_process

TENURE = '600'
T0 = 1_000_000.0


@pytest.fixture
def root(tmp_path, monkeypatch):
    os.makedirs(tmp_path / 'etc' / 'at')
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    monkeypatch.setenv('AT_REP_MIN_TENURE_SEC', TENURE)
    return tmp_path


def _key(ident):
    return ident.signature.public.encode(encoder=HexEncoder).decode('ascii')


def _node():
    """Self and one admitted peer, four bilateral 0.9 tasks between them (a
    tier-4 record)."""
    rp = _make_rep_process()
    them = _identity('peer')
    rp.peers.all = [SimpleNamespace(uuid=them.uuid, signature=them.signature)]
    for _ in range(4):
        tid = uuid4()
        rp.history.update(tid, rp.identity.uuid, 900)
        rp.history.update(tid, them.uuid, 900)
    return rp, them


def _tier(rp, them, present=T0):
    rp.pending_tiers.clear()
    rp._rescore_sweep(present)
    scores = [s for u, s in rp.pending_tiers if str(u) == str(them.uuid)]
    assert scores, 'the sweep did not rescore the peer'
    return rp._trust_tier(scores[-1])


def _since(rp, them, ago, key=None):
    rp._tenure_seeded = True
    rp._member_since[str(them.uuid)] = (key, time.time() - ago)


def test_a_young_member_is_held_at_tier_two(root):
    rp, them = _node()
    _since(rp, them, 10)
    assert _tier(rp, them) == 2
    assert 0.79 < rp.reputations.current[str(them.uuid)] < 0.80


def test_a_member_past_its_tenure_is_not_held(root):
    rp, them = _node()
    _since(rp, them, 1000)
    assert _tier(rp, them) == 4


def test_the_gate_is_off_unless_set(root, monkeypatch):
    monkeypatch.delenv('AT_REP_MIN_TENURE_SEC')
    rp, them = _node()
    _since(rp, them, 0)
    assert _tier(rp, them) == 4


def test_a_member_first_seen_now_is_held(root):
    rp, them = _node()
    assert _tier(rp, them) == 2


def test_the_hold_lifts_once_tenure_is_served(root):
    """No new commit makes the peer due: the sweep does, once it is served."""
    rp, them = _node()
    _since(rp, them, 10)
    assert _tier(rp, them) == 2
    rp._publish_tier_change({}, str(them.uuid),
                            rp.reputations.current[str(them.uuid)])
    _since(rp, them, 1000, _key(them))
    assert _tier(rp, them, T0 + 3600) == 4


def test_first_seen_in_the_roster_survives_a_restart(root):
    rp, them = _node()
    path = os.path.join(Configuration.get_cfg_dir(), rp.ROSTER_FILE)
    with open(path, 'w') as f:
        json.dump({'members': {str(them.uuid): {
            'first_seen': int(time.time()) - 1000, 'pubkey': _key(them)}}}, f)
    assert _tier(rp, them) == 4


def test_a_changed_key_restarts_the_clock(root):
    rp, them = _node()
    _since(rp, them, 1000, 'a' * 64)
    assert _tier(rp, them) == 2


def test_the_roster_records_the_clock_it_keeps(root):
    """first_seen in roster.cfg.json is the gate's own start, not the moment of
    the write, so the file and the gate never disagree."""
    rp, them = _node()
    start = time.time() - 300
    rp._member_since[str(them.uuid)] = (_key(them), start)
    rp.peers.all = [them]
    rp._persist_roster()
    path = os.path.join(Configuration.get_cfg_dir(), rp.ROSTER_FILE)
    with open(path) as f:
        doc = json.load(f)
    assert doc['members'][str(them.uuid)]['first_seen'] == int(start)
