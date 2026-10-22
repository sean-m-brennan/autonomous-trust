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
"""Live replication, the requestor's side (RD_12.6_LIVE_REPLICATION_PLAN.md
§3.3-3.7). The Python twin of ``replication_live.c``.

It runs in the negotiation process, through the core's hooks
(``NegotiationHooks.on_result`` / ``periodic``). When a result of a
replayable capability arrives, it draws once against the declared
probability; a sampled result's score is held while one other capable peer,
drawn uniformly, runs the same task as a replica. Agreement corroborates
both. Disagreement between two committed traces goes to the bisection game
(:class:`.bisection.ChallengeSession`), settled by re-executing one step with
this node's own step contract; anything else is released to the ordinary
arms. A held score is released by the hold deadline, twice the commit
timeout from the draw, whatever happened.
"""
from __future__ import annotations

import logging
import os
import time
import traceback
from queue import Full
from typing import Any, Optional

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.network import Message
from autonomous_trust.core.negotiation.certified import default_seed
from autonomous_trust.core.reputation.reputation import AttestedScore
from autonomous_trust.core.structures.merkle import MerkleTree
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.negotiation.protocol import NegotiationProtocol
from autonomous_trust.core._python.negotiation.replay import (replay_step,
                                                              run_trace,
                                                              trace_chain)

from .adjudication import CORROBORATED, DISPUTE, OUTVOTED, adjudicate, verify
from .bisection import ChallengeSession, settle
from .model import EMPTY_MODEL, ReplicationDeclarationError, load_replication_env
from .sampling import should_replicate

logger = logging.getLogger(__name__)

#: The process's declaration, loaded on first use (and checked at start by
#: the extension's ``check_config``).
_MODEL = None


#: Settled task ids remembered so a late reply is consumed, not scored.
BY_TASK_MAX = 1024


def _model():
    global _MODEL
    if _MODEL is None:
        try:
            _MODEL = load_replication_env()
        except (OSError, ValueError, ReplicationDeclarationError):
            logger.error('replication: declaration rejected, live replication '
                         'stays OFF: %s', traceback.format_exc())
            _MODEL = EMPTY_MODEL
    return _MODEL


def reset() -> None:
    global _MODEL
    _MODEL = None


def hold_seconds() -> float:
    """How long a sampled result's score is held: twice the commit timeout
    (RD_12.6 plan §0.1), read as the reputation process reads it."""
    try:
        commit = float(os.environ.get('AT_REP_COMMIT_TIMEOUT_SEC') or 15.0)
    except ValueError:
        commit = 15.0
    return 2.0 * commit


class _Side:
    """One executor of a replica group."""

    def __init__(self, task: str, executor: str, result=None):
        self.task = task
        self.executor = executor
        self.result = result

    @property
    def root(self) -> Optional[str]:
        return getattr(self.result, 'trace_root', None)

    @property
    def length(self) -> int:
        n = getattr(self.result, 'trace_len', None)
        return n if isinstance(n, int) and not isinstance(n, bool) else 0


class _Group:
    def __init__(self, cap, args, kwargs, primary: _Side, deadline: float):
        self.cap = cap
        self.args = tuple(args or ())
        self.kwargs = dict(kwargs or {})
        self.sides = {'a': primary}
        self.deadline = deadline
        self.phase = 'replica'          # then 'challenge', 'reveal', 'done'
        self.session: Optional[ChallengeSession] = None
        self.round = 0
        self.index = None
        self.owed: set = set()
        self.digests: dict = {}
        self.reveals: dict = {}


def _state(proc) -> dict:
    return proc.__dict__.setdefault('_replication_live',
                                    {'groups': {}, 'by_task': {}})


def _send(proc, queues, verb, payload, peer) -> None:
    try:
        queues[CfgIds.network].put(Message(
            proc.name, verb, to_json_string(payload), peer,
            from_whom=getattr(proc, 'identity', None)),
            block=True, timeout=proc.q_cadence)
    except Full:
        logger.error('replication: network queue full')


def _replica_peer(proc, cap: str, primary: str):
    """A capable peer other than the primary and this node, drawn uniformly
    from fresh verifier entropy (D5), or None."""
    me = str(getattr(getattr(proc, 'identity', None), 'uuid', '')).lower()
    absent = getattr(getattr(proc, 'protocol', None), 'absent_peers', set()) or set()
    try:
        listed = proc.peer_capabilities[cap]
    except KeyError:
        return None
    candidates = sorted({str(u).lower() for u in listed}
                        - {primary.lower(), me} - {str(a).lower() for a in absent})
    if not candidates:
        return None
    return proc.peers.find_by_uuid(candidates[default_seed() % len(candidates)])


# --- the core's hooks ---------------------------------------------------------

def on_result(proc, queues, task, tracker) -> Optional[str]:
    """Hold a sampled result, consume a replica's (RD_12.6 plan §3.7)."""
    state = _state(proc)
    tid = str(task.uuid)
    if tid in state['by_task']:
        gid = state['by_task'][tid]
        group = state['groups'].get(gid)
        if group is not None and 'b' in group.sides and group.sides['b'].task == tid:
            if group.sides['b'].result is None and group.phase == 'replica':
                group.sides['b'].result = task
                _adjudicate(proc, queues, group, gid)
        return 'consume'
    cap = getattr(task, 'requested_capability_name', None)
    executor = getattr(task, 'executor_uuid', None)
    if cap is None or executor is None:
        return None
    prob = _model().live_prob_for(cap)
    if prob <= 0.0 or not should_replicate(prob, default_seed())[0]:
        return None
    peer = _replica_peer(proc, cap, str(executor))
    if peer is None:
        logger.debug('replication: no replica peer for %s; not held', cap)
        return None
    replica = proc.start_directed(queues, cap, getattr(task, 'requested_args', ()),
                                  getattr(task, 'requested_kwargs', {}), peer)
    if replica is None:
        return None
    group = _Group(cap, getattr(task, 'requested_args', ()),
                   getattr(task, 'requested_kwargs', {}),
                   _Side(tid, str(executor), task),
                   time.monotonic() + hold_seconds())
    group.sides['b'] = _Side(str(replica.uuid), str(peer.uuid))
    state['groups'][tid] = group
    state['by_task'][tid] = tid
    state['by_task'][str(replica.uuid)] = tid
    logger.info('replication: %s by %s sampled; replica %s to %s', cap,
                str(executor)[:8], str(replica.uuid)[:8], str(peer.uuid)[:8])
    return 'hold'


def periodic(proc, queues) -> None:
    """The hold deadline (RD_12.6 plan §3.7, D10)."""
    state = _state(proc)
    clock = time.monotonic()
    for gid, group in list(state['groups'].items()):
        if clock < group.deadline or group.phase == 'done':
            continue
        if group.phase == 'replica':
            _release(proc, queues, group, gid, {'a': None})
        elif len(group.owed) == 1:
            _settle_silence(proc, queues, group, gid)
        else:
            _release(proc, queues, group, gid, {'a': None, 'b': None})


def handle_replay_response(proc, queues, message):
    """An executor's answer to one of our challenges or reveals."""
    if message.function != NegotiationProtocol.replay_response:
        return False
    if not message.verified:
        return True
    payload = message.obj
    if isinstance(payload, (str, bytes)):
        try:
            payload = from_json_string(payload)
        except ValueError:
            return True
    if not isinstance(payload, dict):
        return True
    state = _state(proc)
    gid = state['by_task'].get(str(payload.get('task')))
    group = state['groups'].get(gid) if gid is not None else None
    if group is None or group.phase not in ('challenge', 'reveal'):
        return True
    sender = str(getattr(message.from_whom, 'uuid', '')).lower()
    side = next((s for s, v in group.sides.items()
                 if v.task == payload.get('task') and v.executor.lower() == sender),
                None)
    if side is None or side not in group.owed or payload.get('round') != group.round \
            or payload.get('index') != group.index:
        return True
    if group.phase == 'challenge':
        digest = payload.get('digest')
        if not isinstance(digest, str):
            return True
        group.digests[side] = digest
    else:
        reveal = payload.get('reveal')
        if not isinstance(reveal, dict):
            return True
        group.reveals[side] = {k: reveal.get(k) if isinstance(reveal.get(k), str)
                               else None for k in ('prev', 'pre', 'state')}
    group.owed.discard(side)
    if not group.owed:
        if group.phase == 'challenge':
            try:
                group.session.answer(group.index, group.digests.get('a'),
                                     group.digests.get('b'))
            except ValueError:
                # A malformed digest is no answer: leave it to the deadline.
                group.owed = {s for s in ('a', 'b') if s in group.digests
                              and not _is_digest(group.digests[s])}
                return True
            _advance(proc, queues, group, gid)
        else:
            _settle_game(proc, queues, group, gid)
    return True


def _is_digest(text) -> bool:
    return isinstance(text, str) and len(text) == 64


# --- settling -----------------------------------------------------------------

def _adjudicate(proc, queues, group, gid) -> None:
    a, b = group.sides['a'], group.sides['b']
    tol = _model().tolerance_for(group.cap)
    verdicts = adjudicate([('a', a.result.result), ('b', b.result.result)],
                          tolerance=tol)
    if verdicts.get('a') == CORROBORATED and verdicts.get('b') == CORROBORATED:
        _release(proc, queues, group, gid, {'a': CORROBORATED, 'b': CORROBORATED})
        return
    replay = _local_replay(proc, group.cap)
    if verdicts.get('a') == DISPUTE and replay is not None and a.root and b.root \
            and a.length > 0 and b.length > 0:
        group.session = ChallengeSession(a.length, a.root, b.length, b.root)
        if group.session.disputed:
            _advance(proc, queues, group, gid)
            return
    # No commitment, no step contract, or results that differ over agreeing
    # traces: a dispute nobody settles. The ordinary arms score both.
    _release(proc, queues, group, gid, {'a': None, 'b': None})


def _advance(proc, queues, group, gid) -> None:
    """Ask the next question, or the reveal once the session is done."""
    pending = group.session.pending()
    group.round += 1
    group.digests = {}
    if pending is not None:
        group.phase, (group.index, owe) = 'challenge', pending
        verb = NegotiationProtocol.replay_challenge
    else:
        group.phase, group.index = 'reveal', group.session.divergence
        owe = ('a', 'b')
        verb = NegotiationProtocol.replay_reveal
    group.owed = set(owe)
    for side in owe:
        s = group.sides[side]
        peer = proc.peers.find_by_uuid(s.executor)
        if peer is None:
            continue                     # it stays owed: the deadline decides
        _send(proc, queues, verb, {'task': s.task, 'round': group.round,
                                   'index': group.index}, peer)


def _settle_game(proc, queues, group, gid) -> None:
    replay = _local_replay(proc, group.cap)
    spec = _model().replay_for(group.cap)
    k = group.session.divergence

    def truth(pre):
        try:
            return replay_step(replay, pre, k, group.args, group.kwargs)
        except Exception:
            logger.error('replication: re-executing step %d of %s failed: %s',
                         k, group.cap, traceback.format_exc())
            return None

    verdicts = settle(group.session, group.reveals, truth,
                      spec.max_state_bytes if spec is not None else 4096)
    logger.info('replication: %s settled at step %d: %s', group.cap, k, verdicts)
    _release(proc, queues, group, gid, verdicts)


def _settle_silence(proc, queues, group, gid) -> None:
    """One side went quiet mid-game (D10): re-run the whole computation and
    settle the side that answered alone; the silent side is not scored."""
    silent = next(iter(group.owed))
    live = 'b' if silent == 'a' else 'a'
    side = group.sides[live]
    replay = _local_replay(proc, group.cap)
    verdict = None
    if replay is not None:
        try:
            states = run_trace(replay, group.args, group.kwargs).states
            ok = (len(states) == side.length
                  and trace_chain(states)[-1] == side.root)
            verdict = CORROBORATED if ok else OUTVOTED
        except Exception:
            logger.error('replication: re-running %s failed: %s', group.cap,
                         traceback.format_exc())
    logger.info('replication: %s went silent; %s settled %s', silent, live, verdict)
    _release(proc, queues, group, gid, {live: verdict}, drop=(silent,))


def _release(proc, queues, group, gid, verdicts: dict, drop=()) -> None:
    """Release each side named in ``verdicts``: with its verdict's score, or
    (verdict None, or one that scores nobody) for the ordinary arms. A side in
    ``drop`` is not released at all; a side not named is left as it is."""
    group.phase = 'done'
    for side, verdict in verdicts.items():
        if side in drop:
            continue
        s = group.sides.get(side)
        if s is None or s.result is None:
            continue
        score = verify(verdict) if verdict is not None else None
        proc.release_result(queues, s.result, score)
        if verdict == OUTVOTED:
            _attest(proc, queues, group, side, score)
    state = _state(proc)
    state['groups'].pop(gid, None)
    # The task ids stay mapped to nothing, so a late reply is still consumed;
    # the oldest are forgotten past BY_TASK_MAX.
    for s in group.sides.values():
        state['by_task'][s.task] = None
    while len(state['by_task']) > BY_TASK_MAX:
        stale = next((t for t, g in state['by_task'].items() if g is None), None)
        if stale is None:
            break
        del state['by_task'][stale]


def _digest(text: str) -> str:
    return MerkleTree.get_hash(text.encode('utf-8')).decode('ascii')


def _attest(proc, queues, group, side: str, score) -> None:
    """An outvoted finding also goes out as a verifier-attested entry on the
    `replication` channel (D6 option 3), so an executor that withholds its own
    half cannot keep it off the chain. The evidence digest covers the task,
    the step the game settled at (none for a whole re-run) and the digest the
    executor committed to there; the scope is the task, so separate findings
    about one peer are not rate-capped together. A requestor below the
    verifier floor is not co-signed, and the held half stands alone."""
    s = group.sides[side]
    k = group.session.divergence if group.session is not None else None
    claimed = (group.session.claimed(side) if k is not None else s.root) or ''
    evidence = _digest('AT-REPLICATION\0%s|%s|%s|%s' % (
        s.task, '' if k is None else k, claimed, group.cap))
    try:
        queues[CfgIds.reputation].put(AttestedScore(
            subject_uuid=s.executor, score=score[0], channel=score[1],
            evidence_digest=evidence, attest_scope=_digest(s.task)),
            block=True, timeout=proc.q_cadence)
    except (Full, KeyError):
        logger.error('replication: could not propose the attestation about %s',
                     s.executor[:8])


def _local_replay(proc, cap: str):
    """This node's own step contract for ``cap``, or None (D3)."""
    try:
        return getattr(proc.capabilities[cap], 'replay', None)
    except (KeyError, TypeError, AttributeError):
        return None
