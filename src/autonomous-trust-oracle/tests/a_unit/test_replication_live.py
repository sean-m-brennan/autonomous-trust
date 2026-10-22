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
"""Live replication end to end in process (RD_12.6_LIVE_REPLICATION_PLAN.md
§3.7): the requestor's layer (``replication.live``) against two executors
answering through the core's own ``handle_replay_request``.

The requestor is a stub negotiation process: its ``start_directed`` records
the replica, ``release_result`` records what is released and with which
score. Messages between the three are routed by hand, each stamped with its
authenticated sender, as the network process would.
"""
import hashlib
import json
import queue
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.negotiation.negprocess import NegotiationProcess
from autonomous_trust.core._python.negotiation.protocol import NegotiationProtocol
from autonomous_trust.core._python.negotiation.replay import (Replayable,
                                                              trace_chain)
from autonomous_trust.core.system import CfgIds
from autonomous_trust.oracle._python.replication import live


def _identity(tag):
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(UUID(bytes=hashlib.md5(tag.encode()).digest()), '10.0.0.1',
                    '%s.test' % tag, Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False), _public_only=False)


#: The honest computation: s0 .. s7.
COUNT = Replayable(init=lambda: 0, step=lambda s, i: s + 1 if s < 7 else None,
                   encode=lambda s: 's%d' % s, decode=lambda t: int(t[1:]))
HONEST = ['s%d' % i for i in range(8)]
CHEAT = ['s0', 's1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7']


class _Peers:
    def __init__(self, idents):
        self.by = {str(i.uuid).lower(): i for i in idents}

    def find_by_uuid(self, uuid):
        return self.by.get(str(uuid).lower())


class _Requestor:
    def __init__(self, me, others, replay=COUNT):
        self.name = CfgIds.negotiation
        self.identity = me
        self.q_cadence = 0.01
        self.peers = _Peers(others)
        self.peer_capabilities = {'demo.count': [str(o.uuid) for o in others]}
        self.capabilities = ({'demo.count': SimpleNamespace(replay=replay)}
                             if replay is not None else {})
        self.protocol = SimpleNamespace(absent_peers=set())
        self.started = []
        self.released = {}

    def start_directed(self, queues, cap, args, kwargs, peer):
        task = SimpleNamespace(uuid=uuid4())
        self.started.append((task, peer))
        return task

    def release_result(self, queues, task, score=None):
        self.released[str(task.uuid)] = score


class _Executor:
    """An executor whose trace the core keeps, answering via the core."""

    def __init__(self, ident, requestor, states, lies=None):
        self.name = CfgIds.negotiation
        self.identity = ident
        self.q_cadence = 0.01
        self.logger = SimpleNamespace(debug=lambda *a: None, error=lambda *a: None)
        self.states = states
        self.lies = lies or {}
        self._traces = {}
        self.requestor = requestor

    _expire_traces = NegotiationProcess._expire_traces

    def keep(self, task_uuid):
        self._traces[str(task_uuid)] = (list(self.states), str(self.requestor.uuid),
                                        time.monotonic() + 60)

    def answer(self, message):
        net = queue.Queue()
        NegotiationProcess.handle_replay_request(self, {CfgIds.network: net}, message)
        if net.empty():
            return None
        out = net.get_nowait()
        payload = json.loads(out.obj)
        if 'digest' in payload and payload['index'] in self.lies:
            payload['digest'] = self.lies[payload['index']]
        out.obj = json.dumps(payload)
        return out


def _result(task_uuid, executor, states, value=None):
    chain = trace_chain(states)
    return SimpleNamespace(uuid=task_uuid, executor_uuid=str(executor.uuid),
                           requested_capability_name='demo.count',
                           requested_args=(), requested_kwargs={},
                           result=value if value is not None else states[-1],
                           trace_root=chain[-1], trace_len=len(states))


@pytest.fixture
def declared(monkeypatch, tmp_path):
    path = tmp_path / 'replication.json'
    path.write_text(json.dumps({'version': 1, 'capabilities': {
        'demo.count': {'replicate_prob': 1.0, 'replay': {}}}}))
    monkeypatch.setenv('AT_REPLICATION', str(path))
    live.reset()
    yield
    live.reset()


def _play(req, executors, queues):
    """Route the requestor's questions to the executors and their answers
    back, until nobody has anything to say."""
    net = queues[CfgIds.network]
    for _ in range(64):
        moved = False
        while not net.empty():
            msg = net.get_nowait()
            target = next(e for e in executors
                          if str(e.identity.uuid) == str(msg.to_whom[0].uuid))
            msg.from_whom, msg.verified = req.identity, True
            answer = target.answer(msg)
            if answer is not None:
                answer.from_whom, answer.verified = target.identity, True
                live.handle_replay_response(req, queues, answer)
                moved = True
        if not moved:
            return


def _setup(primary_states, replica_states, lies=None, replay=COUNT):
    me, p, q = _identity('req'), _identity('primary'), _identity('replica')
    req = _Requestor(me, [p, q], replay)
    net = queue.Queue()
    queues = {CfgIds.network: net, CfgIds.reputation: queue.Queue()}
    t1 = uuid4()
    first = _result(t1, p, primary_states)
    assert live.on_result(req, queues, first, None) == 'hold'
    task, peer = req.started[0]
    replica_ex = _Executor(peer, me, replica_states, lies)
    primary_ex = _Executor(p, me, primary_states)
    primary_ex.keep(t1)
    replica_ex.keep(task.uuid)
    second = _result(task.uuid, peer, replica_states)
    assert live.on_result(req, queues, second, None) == 'consume'
    return req, queues, net, [primary_ex, replica_ex], str(t1), str(task.uuid)


def test_agreement_corroborates_both(declared):
    req, queues, net, ex, t1, t2 = _setup(HONEST, HONEST)
    assert net.empty()                           # no game
    assert req.released == {t1: (0.9, 'replication'), t2: (0.9, 'replication')}
    assert queues[CfgIds.reputation].empty()     # nothing to attest


@pytest.mark.parametrize('lies', [None, {3: trace_chain(HONEST)[3]}])
def test_the_game_convicts_the_cheater(declared, lies):
    req, queues, net, ex, t1, t2 = _setup(HONEST, CHEAT, lies)
    _play(req, ex, queues)
    assert req.released == {t1: (0.9, 'replication'), t2: (0.1, 'replication')}
    # The outvoted finding is also proposed as an attested entry (D6).
    att = queues[CfgIds.reputation].get_nowait()
    assert att.subject_uuid == str(ex[1].identity.uuid)
    assert (att.score, att.channel) == (0.1, 'replication')
    assert queues[CfgIds.reputation].empty()


def test_the_primary_can_be_the_cheater(declared):
    req, queues, net, ex, t1, t2 = _setup(CHEAT, HONEST)
    _play(req, ex, queues)
    assert req.released == {t1: (0.1, 'replication'), t2: (0.9, 'replication')}


def test_without_a_step_contract_both_go_to_the_ordinary_arms(declared):
    req, queues, net, ex, t1, t2 = _setup(HONEST, CHEAT, replay=None)
    assert net.empty()
    assert req.released == {t1: None, t2: None}


def test_an_unsampled_or_undeclared_result_is_left_alone(declared, monkeypatch):
    me, p, q = _identity('req'), _identity('primary'), _identity('replica')
    req = _Requestor(me, [p, q])
    other = _result(uuid4(), p, HONEST)
    other.requested_capability_name = 'demo.other'
    assert live.on_result(req, {}, other, None) is None
    lonely = _Requestor(me, [p])                 # no peer for a replica
    assert live.on_result(lonely, {}, _result(uuid4(), p, HONEST), None) is None


def test_a_silent_replica_releases_the_primary(declared, monkeypatch):
    me, p, q = _identity('req'), _identity('primary'), _identity('replica')
    req = _Requestor(me, [p, q])
    t1 = uuid4()
    assert live.on_result(req, {}, _result(t1, p, HONEST), None) == 'hold'
    later = time.monotonic() + live.hold_seconds() + 1
    monkeypatch.setattr(live.time, 'monotonic', lambda: later)
    live.periodic(req, {})
    assert req.released == {str(t1): None}
    # Its result, arriving after all, is consumed and not scored.
    task, peer = req.started[0]
    assert live.on_result(req, {}, _result(task.uuid, peer, HONEST), None) == 'consume'
    assert len(req.released) == 1


@pytest.mark.parametrize('talker, honest', [(0, True), (1, False)])
def test_silence_mid_game_settles_the_responsive_side_alone(declared, monkeypatch,
                                                            talker, honest):
    """Only one executor answers. Its whole trace is re-run locally: the
    honest primary is corroborated, the cheating replica outvoted; the silent
    side is not scored at all (D10)."""
    req, queues, net, ex, t1, t2 = _setup(HONEST, CHEAT)
    assert not net.empty()                       # the first challenge is out
    while not net.empty():
        msg = net.get_nowait()
        if str(msg.to_whom[0].uuid) != str(ex[talker].identity.uuid):
            continue
        msg.from_whom, msg.verified = req.identity, True
        answer = ex[talker].answer(msg)
        answer.from_whom, answer.verified = ex[talker].identity, True
        live.handle_replay_response(req, queues, answer)
    later = time.monotonic() + live.hold_seconds() + 1
    monkeypatch.setattr(live.time, 'monotonic', lambda: later)
    live.periodic(req, queues)
    assert req.released == {(t1, t2)[talker]:
                            (0.9 if honest else 0.1, 'replication')}


def test_an_answer_from_the_wrong_peer_is_not_taken(declared):
    req, queues, net, ex, t1, t2 = _setup(HONEST, CHEAT)
    msg = net.get_nowait()
    msg.from_whom, msg.verified = req.identity, True
    target = next(e for e in ex if str(e.identity.uuid) == str(msg.to_whom[0].uuid))
    answer = target.answer(msg)
    impostor = next(e for e in ex if e is not target)
    answer.from_whom, answer.verified = impostor.identity, True
    live.handle_replay_response(req, queues, answer)
    group = next(iter(live._state(req)['groups'].values()))
    side = next(k for k, v in group.sides.items()
                if v.executor == str(target.identity.uuid))
    assert side in group.owed                     # still waiting on the real one


def test_an_executor_answers_only_its_requestor():
    me, other = _identity('req'), _identity('stranger')
    ex = _Executor(_identity('ex'), me, HONEST)
    t = uuid4()
    ex.keep(t)
    from autonomous_trust.core.network import Message
    ask = Message(CfgIds.negotiation, NegotiationProtocol.replay_challenge,
                  json.dumps({'task': str(t), 'round': 1, 'index': 3}), ex.identity)
    ask.verified = True
    ask.from_whom = other
    assert ex.answer(ask) is None
    ask.from_whom = me
    reply = json.loads(ex.answer(ask).obj)
    assert reply['digest'] == trace_chain(HONEST)[3]
