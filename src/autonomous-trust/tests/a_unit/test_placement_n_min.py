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
"""A group's declared N_min (RD_13.2_BYZANTINE_QUORUM_PLAN.md §0.4).

A roster entry may declare N_min, and F = (N_min - 1) // 3 then raises the
slash, checkpoint, attestation and commit-certificate bars to (M + F) // 2 + 1
of the M members. The declaration is in the entry hash only when made, a
genesis makes none, and it changes only when a strict majority of the roster
reports one value: the leader restates the roster on the reports it collects
from place_accepted, and each acceptor takes a value only if it is in force or
the one it is configured for. The bytes are pinned so the C twin
(src/c/test/rep_place_roster_test.c) produces exactly these.
"""
from uuid import UUID

import pytest

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.reputation.placement import (entry_from_dict,
                                                        entry_to_dict)
from autonomous_trust.core.reputation.reputation import (
    Transaction, byzantine_f, roster_n_min_norm, roster_task_id)
from autonomous_trust.core._python.reputation.repprocess import _env_n_min

from tests.a_unit.test_placement_sim import Sim

A = 'aaaaaaaa-0000-4000-8000-000000000001'
B = 'bbbbbbbb-0000-4000-8000-000000000002'
M2 = [[B, '22' * 32], [A, '11' * 32]]
D2 = 'c02c382b7ab59e73d577c48f3bf8b6bd8f4e010f2fd2787498004e95516fd86a'
T0 = UUID('65c0a743-5641-5b6b-b79d-d5c8a4646039')
G_HASH = b'02a57fe42cfda395872b38d4420e7d6857dd8dccb31d39e6c4f112cd7d7ce279'
# A restatement of the genesis declaring N_min 4, and the same undeclaring.
T_R4 = UUID('05b28db3-fb50-5ba5-8a24-a2f053a182fd')
T_R0 = UUID('2cbb8fdf-80d6-56f4-8038-e4547d1e00ee')
R4_HASH = b'ca90ab36ec77a141a1c4b7882d760e39fe01806ee27e585eb74ee3924c04fa7e'


def _restate(n_min=4):
    return Transaction(roster_task_id(T0, 'restate', None, D2, n_min),
                       roster_op='restate', roster_digest=D2, roster_members=M2,
                       index=1, prev_hash=G_HASH, roster_n_min=n_min)


class TestPinned:
    def test_the_task_and_bytes_are_pinned(self):
        assert roster_task_id(T0, 'restate', None, D2, 4) == T_R4
        assert roster_task_id(T0, 'restate', None, D2) == T_R0
        assert roster_task_id(T0, 'restate', None, D2, None) == T_R0
        assert _restate()._canonical_bytes() == (
            str(T_R4) + '|null|null|null|null|1|roster|restate|null|' + D2
            + '|4').encode()
        assert _restate().entry_hash() == R4_HASH

    def test_no_declaration_keeps_the_old_bytes(self):
        tx = _restate(None)
        assert tx._canonical_bytes() == (
            str(T_R0) + '|null|null|null|null|1|roster|restate|null|' + D2).encode()
        assert _restate(0).roster_n_min is None


class TestValues:
    @pytest.mark.parametrize('n_min, f', [(None, 0), (1, 0), (3, 0), (4, 1),
                                          (6, 1), (7, 2), (10, 3)])
    def test_f(self, n_min, f):
        assert byzantine_f(n_min) == f

    @pytest.mark.parametrize('bad', [-1, 1.5, '4', True])
    def test_a_malformed_declaration_is_refused(self, bad):
        with pytest.raises(ValueError):
            roster_n_min_norm(bad)

    @pytest.mark.parametrize('raw, want', [(None, None), ('', None), ('  ', None),
                                           ('0', None), ('4', 4), (' 7 ', 7)])
    def test_the_environment(self, monkeypatch, raw, want):
        if raw is None:
            monkeypatch.delenv('AT_REP_N_MIN', raising=False)
        else:
            monkeypatch.setenv('AT_REP_N_MIN', raw)
        assert _env_n_min('AT_REP_N_MIN') == want

    @pytest.mark.parametrize('raw', ['-1', 'four', '4.0'])
    def test_a_malformed_environment_is_fatal(self, monkeypatch, raw):
        monkeypatch.setenv('AT_REP_N_MIN', raw)
        with pytest.raises(ValueError):
            _env_n_min('AT_REP_N_MIN')


class TestWire:
    def test_the_placement_wire_carries_it(self):
        d = entry_to_dict(_restate())
        assert d['roster']['n_min'] == 4
        assert entry_from_dict(d).roster_n_min == 4
        assert 'n_min' not in entry_to_dict(_restate(None))['roster']

    def test_the_catchup_wire_carries_it(self):
        tx = from_json_string(to_json_string(_restate()))
        assert tx.roster_n_min == 4 and tx.entry_hash() == R4_HASH
        assert 'roster_n_min' not in to_json_string(_restate(None))


# --- the acceptor's rule ------------------------------------------------------

def _restating(rp, n_min):
    """A restatement of `rp`'s roster in force declaring `n_min`."""
    r = rp.history.latest_roster()
    return Transaction(roster_task_id(r.task_id, 'restate', None, r.roster_digest, n_min),
                       roster_op='restate', roster_digest=r.roster_digest,
                       roster_members=r.roster_members, roster_n_min=n_min)


class TestAcceptorRule:
    def test_a_change_needs_our_configuration(self, tmp_path, monkeypatch):
        sim = Sim(3, 1, tmp_path, monkeypatch)
        rp = sim.nodes[0][0]
        tx = _restating(rp, 7)
        assert rp._roster_value_ok([tx], rp.history, '') is not None
        rp.N_MIN = 7
        assert rp._roster_value_ok([tx], rp.history, '') is None
        rp.N_MIN = 4
        assert rp._roster_value_ok([tx], rp.history, '') is not None

    def test_a_carried_change_is_left_to_the_acceptors(self, tmp_path, monkeypatch):
        """A proposer carrying (or building, from the majority's reports) a
        value it is not configured for does not refuse it itself."""
        sim = Sim(3, 1, tmp_path, monkeypatch)
        rp = sim.nodes[0][0]
        tx = _restating(rp, 7)
        assert rp._roster_value_ok([tx], rp.history, '', config_check=False) is None
        assert rp._place_value_ok([tx], rp.history, None, config_check=False) is None

    def test_an_unchanged_declaration_still_waits_its_turn(self, tmp_path, monkeypatch):
        sim = Sim(3, 1, tmp_path, monkeypatch)
        rp = sim.nodes[0][0]
        rp.N_MIN = 7
        assert rp._roster_value_ok([_restating(rp, None)], rp.history, '') == \
            'a restatement too early'


# --- the trigger, end to end -------------------------------------------------

def _declared(sim):
    return [rp.history.latest_roster().roster_n_min for rp, _q in sim.nodes]


def _leader(sim):
    return min(range(len(sim.nodes)),
               key=lambda i: sim.nodes[i][0]._place_rank('', sim.nodes[i][0].history.next_index))


@pytest.mark.parametrize('seed', range(3))
def test_a_majority_configured_alike_declares_it(tmp_path, monkeypatch, seed):
    sim = Sim(5, seed, tmp_path, monkeypatch)
    for i in (0, 1, 2):
        sim.nodes[i][0].N_MIN = 4
    tasks = []
    for _ in range(4):
        tasks.append(sim.complete(*sim.rng.sample(range(5), 2)))
        sim.run(2)
    sim.settle(lambda: _declared(sim) == [4] * 5, limit=3000)
    # Placement went on, and every node holds the same chain.
    later = sim.complete(3, 4)
    sim.run(30)
    chains = sim.chains()
    assert all(c == chains[0] for c in chains)
    assert sorted(map(str, chains[0])) == sorted(map(str, tasks + [later]))


@pytest.mark.parametrize('seed', range(3))
def test_a_minority_including_the_leader_changes_nothing(tmp_path, monkeypatch,
                                                         seed):
    """The liveness case behind call 9: a leader proposing its own value
    would accept it alone, and every later proposer at that index would have
    to carry a value the majority refuses."""
    sim = Sim(5, seed, tmp_path, monkeypatch)
    first = sim.complete(0, 1)
    sim.run(10)
    lead = sim.index_of(next(iter(sim.nodes[0][0]._place_vars()['_placers'].values())))
    other = (lead + 1) % 5
    for i in (lead, other):
        sim.nodes[i][0].N_MIN = 4
    tasks = [first]
    for _ in range(4):
        tasks.append(sim.complete(*sim.rng.sample(range(5), 2)))
        sim.run(5)
    sim.run(30)
    assert _declared(sim) == [None] * 5
    chains = sim.chains()
    assert all(c == chains[0] for c in chains)
    assert sorted(map(str, chains[0])) == sorted(map(str, tasks))


def test_a_leader_configured_otherwise_still_declares_the_majoritys(tmp_path,
                                                                    monkeypatch):
    sim = Sim(5, 5, tmp_path, monkeypatch)
    first = sim.complete(0, 1)
    sim.run(10)
    lead = sim.index_of(next(iter(sim.nodes[0][0]._place_vars()['_placers'].values())))
    for i in range(5):
        if i != lead:
            sim.nodes[i][0].N_MIN = 7
    sim.complete(2, 3)
    sim.settle(lambda: _declared(sim) == [7] * 5, limit=3000)
    assert sim.nodes[lead][0].N_MIN is None
    del first
