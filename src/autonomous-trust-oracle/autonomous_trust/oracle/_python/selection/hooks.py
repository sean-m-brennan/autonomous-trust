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
"""Selective assignment in a running negotiation process: the core's hooks and
the two audit verbs (RD_12.7 plan §0, §3).

The requestor side draws (:func:`select_participants`), re-draws after a
decline (:func:`on_decline`), marks every drawn result so the main process
echoes its score back (:func:`on_result`, :func:`on_score`) and answers audit
queries. The peer side checks the coin on every invitation it admits
(:func:`on_invitation`) and asks about the draws it can see it was not shown:
an index that jumps from 5 to 9 means draws 6, 7 and 8 happened without it.
Every finding is logged and counted per requestor, and nothing else happens
(§0.2): selection never touches reputation or refuses work.
"""

from __future__ import annotations

import logging
import time
from queue import Full
from typing import Optional

from autonomous_trust.core._python import _probes
from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.oracle.certificates.rng import SplitMix64

from . import chain as _chain
from . import selector as _selector
from .estimate import estimate
from .draw import seed_of, unit
from .selector import BOOTSTRAP_CAPABILITY_NAMES, Requestor, ucb_bonus

logger = logging.getLogger(__name__)

#: A requestor asks "what happened at draw n?" with this verb ...
AUDIT_QUERY = 'selection audit'
#: ... and is answered with this one. Both are answered only when verified.
AUDIT_REPLY = 'selection audit reply'

#: The most gap indices one invitation sends queries about.
AUDIT_MAX_PER_GAP = 8

#: Seconds between the estimator's slow-timer runs.
ESTIMATE_SECONDS = 300.0

_REQ_KEY = '_selection_requestor'
_PEER_KEY = '_selection_peer'


def _model_for(proc):
    """The process's own requestor's model when it has one (the conformance
    harness configures one node), else $AT_SELECTION's. Mirrors C's
    per-process configuration."""
    req = proc.__dict__.get(_REQ_KEY)
    return req.model if req is not None else _selector._model()


def configure(proc, model, root: bytes, cfg_dir: str) -> None:
    """Conformance and tests: give ``proc`` its own requestor with ``model``,
    a chain seeded from ``root`` and files in ``cfg_dir``. The C twin is
    at_selection_configure."""
    proc.__dict__[_REQ_KEY] = Requestor(getattr(proc, 'name', 'negotiation'),
                                        model, cfg_dir=cfg_dir, root=root)


def _requestor(proc) -> Requestor:
    req = proc.__dict__.get(_REQ_KEY)
    if req is None:
        req = Requestor(getattr(proc, 'name', 'negotiation'), _selector._model())
        proc.__dict__[_REQ_KEY] = req
    return req


def _peer_state(proc) -> dict:
    return proc.__dict__.setdefault(_PEER_KEY, {'chains': {}, 'findings': {}})


def findings(proc) -> dict:
    """``{requestor uuid: {reason: count}}``: what this node's audit has
    found, for the operator surface."""
    return _peer_state(proc)['findings']


def _uuid(peer) -> str:
    return str(getattr(peer, 'uuid', peer) or '').lower()


def _tier(peer) -> int:
    try:
        return int(getattr(peer, '_tier', 0) or 0)
    except (TypeError, ValueError):
        return 0


def _purpose(model, cap: str, target) -> Optional[str]:
    """``'probe'``, ``'task'``, or None when this task is not drawn."""
    if not model.declared:
        return None
    if target is not None:
        if cap in BOOTSTRAP_CAPABILITY_NAMES and model.probe_floor is not None:
            return 'probe'
        return None
    if cap in BOOTSTRAP_CAPABILITY_NAMES:
        return None     # the window-phase pairs keep their fan-out
    return 'task' if model.selects(cap) else None


def _weights(req: Requestor, purpose: str, peers: list) -> list[float]:
    if purpose == 'probe':
        return [ucb_bonus(req.probe_counts.get(_uuid(p), 0), req.probe_total)
                for p in peers]
    return [1.0 + _tier(p) for p in peers]


def _decide(req: Requestor, task, purpose: str, eligible: list, k,
            floor: float, redraw_of=None) -> list:
    uuids = [_uuid(p) for p in eligible]
    selected, field = req.decide(str(task.uuid), task.capability.name, uuids,
                                 _weights(req, purpose, eligible), k, floor,
                                 purpose, redraw_of=redraw_of)
    if purpose == 'probe':
        for pos in selected:
            req.probe_counts[uuids[pos]] = req.probe_counts.get(uuids[pos], 0) + 1
        req.probe_total += 1
        req._write_chain()
    task.draw = field
    return [eligible[pos] for pos in selected]


# --- requestor side ----------------------------------------------------------

def select_participants(proc, task, peers: list, target) -> Optional[list]:
    model = _model_for(proc)
    cap = task.capability.name
    purpose = _purpose(model, cap, target)
    if purpose is None or not peers:
        return None
    eligible = sorted(peers, key=_uuid)
    req = _requestor(proc)
    if purpose == 'probe':
        return _decide(req, task, purpose, eligible, 1, model.probe_floor)
    policy = model.policy_for(cap)
    return _decide(req, task, purpose, eligible, policy.k, policy.floor)


def on_decline(proc, task, peer_uuid, peers: list) -> Optional[list]:
    """D5(a): a decline is a non-event for reputation, and the replacement is
    a second decision over the peers not yet asked."""
    model = _model_for(proc)
    if not model.declared:
        return None
    req = _requestor(proc)
    rec = req.record_decline(str(task.uuid), _uuid(peer_uuid))
    if rec is None:
        return None
    asked = req.asked(str(task.uuid))
    eligible = sorted((p for p in peers if _uuid(p) not in asked), key=_uuid)
    if not eligible:
        return None
    floor = (model.probe_floor if rec['purpose'] == 'probe'
             else model.policy_for(task.capability.name).floor)
    return _decide(req, task, rec['purpose'], eligible, 1, floor,
                   redraw_of=rec['index'])


def on_result(proc, queues, task, tracker) -> Optional[str]:
    """Ask the main process to echo a drawn result's score back."""
    if proc.__dict__.get(_REQ_KEY) is not None \
            and getattr(tracker, 'draw', None) is not None:
        task.echo_score = True
    return None


def on_score(proc, echo) -> None:
    req = proc.__dict__.get(_REQ_KEY)
    if req is not None:
        req.record_outcome(echo.task_uuid, echo.executor_uuid.lower(), echo.score)


def periodic(proc, queues) -> None:
    req = proc.__dict__.get(_REQ_KEY)
    if req is None:
        return
    req.flush()
    now = time.monotonic()
    if now - proc.__dict__.get('_selection_estimated', 0.0) >= ESTIMATE_SECONDS:
        proc.__dict__['_selection_estimated'] = now
        report(proc)


def report(proc) -> dict:
    """Run the estimator over the log now, log one line per capability and
    publish the regrets on the probes stream (D7(a): a diagnostic only)."""
    req = proc.__dict__.get(_REQ_KEY)
    if req is None:
        return {}
    result = estimate(req.records.values())
    for cap, entry in result.items():
        logger.info('selection: %s over %d decisions (%d outcomes): value '
                    'logged %.3f uniform %.3f greedy %.3f; regret vs greedy %.3f',
                    cap, entry['decisions'], entry['observed'],
                    entry['value']['logged'], entry['value']['uniform'],
                    entry['value']['greedy'], entry['regret']['greedy'])
        _probes.emit('selection', 'estimate', capability=cap,
                     decisions=entry['decisions'], observed=entry['observed'],
                     value=entry['value'], regret=entry['regret'])
    proc.__dict__['_selection_estimate'] = result
    return result


def handle_audit_query(proc, queues, message):
    if message.function != AUDIT_QUERY:
        return False
    if not getattr(message, 'verified', False):
        return True
    payload = _payload(message)
    if payload is None or isinstance(payload.get('index'), bool) \
            or not isinstance(payload.get('index'), int):
        return True
    req = proc.__dict__.get(_REQ_KEY)
    if req is None and _model_for(proc).declared:
        req = _requestor(proc)
    answer = (req.audit_answer(payload['index'], _uuid(message.from_whom))
              if req is not None else {'index': payload['index'], 'status': 'unknown'})
    _send(proc, queues, AUDIT_REPLY, answer, message.from_whom)
    return True


# --- peer side ---------------------------------------------------------------

def _finding(proc, requestor: str, reason: str) -> None:
    per = findings(proc).setdefault(requestor, {})
    per[reason] = per.get(reason, 0) + 1
    _probes.counter('selection', 'finding', reason)
    logger.warning('selection: requestor %s, draw finding: %s', requestor[:8], reason)


_HEX = frozenset('0123456789abcdefABCDEF')


def _unhex(value, n: int = _chain.LINK_BYTES) -> bytes:
    """Exactly ``n`` bytes of hex, as C's at_sel_unhex reads them; anything
    else (``bytes.fromhex`` would also take spaces) raises ValueError."""
    if not isinstance(value, str) or len(value) != 2 * n or not set(value) <= _HEX:
        raise ValueError('not %d bytes of hex' % n)
    return bytes.fromhex(value)


def _int(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError('not an integer')
    return value


def _num(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('not a number')
    return float(value)


def check_draw(state: dict, requestor: str, draw: dict) -> tuple[Optional[str], list[int]]:
    """Check one invitation's coin against what ``state`` holds for the
    requestor. Returns ``(finding or None, gap indices)`` and updates the
    state. The rules, pinned by the corpus, are runtime-neutral."""
    try:
        head = _unhex(draw['head'])
        index = _int(draw['index'])
        link = _unhex(draw['link'])
        prev = _unhex(draw['prev_root']) if draw.get('prev_root') is not None else None
    except (KeyError, TypeError, ValueError):
        return 'malformed', []
    chains = state['chains']
    seen = chains.get(requestor)
    finding = None
    if seen is not None and seen['head'] != head:
        if prev is not None and _chain.verify_rotation(seen['head'], prev):
            seen = None
        else:
            finding = 'head_changed'
            seen = None
    if seen is None:
        seen = {'head': head, 'known': None, 'indices': set()}
        chains[requestor] = seen
    known = seen['known']
    if known is not None and index <= known[0]:
        if index in seen['indices']:
            return finding, []      # a re-announce of a draw already checked
        return finding or 'index_not_increasing', []
    if not _chain.verify_link(head, index, link, known):
        return finding or 'bad_link', []
    gap = []
    if known is not None and index > known[0] + 1:
        gap = list(range(max(known[0] + 1, index - AUDIT_MAX_PER_GAP), index))
    seen['known'] = (index, link)
    seen['indices'].add(index)
    return finding, gap


def on_invitation(proc, queues, task, sender) -> None:
    draw = getattr(task, 'draw', None)
    if not draw:
        return      # an older requestor, or a task nothing selected
    requestor = _uuid(sender)
    finding, gap = check_draw(_peer_state(proc), requestor, draw)
    if finding is not None:
        _finding(proc, requestor, finding)
    if gap:
        for index in gap:
            _send(proc, queues, AUDIT_QUERY, {'index': index}, sender)


def check_answer(state: dict, requestor: str, answer: dict) -> Optional[str]:
    """Check an audit answer against the chain the peer holds and its own
    coin. Returns a finding, or None when the answer is consistent."""
    if answer.get('status') != 'ok':
        return 'audit_unknown'
    seen = state['chains'].get(requestor)
    try:
        index = _int(answer['index'])
        link = _unhex(answer['link'])
        head = _unhex(answer['head'])
        row = answer.get('row')
        if row is not None:
            selected = row['selected'] is True
            draw_at = row.get('draw_at')
            if draw_at is not None:
                draw_at = _int(draw_at)
                lo, hi = _num(row['lo']), _num(row['hi'])
                if not 0 <= draw_at <= 1 << 20:
                    raise ValueError('draw offset out of range')
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'audit_malformed'
    if seen is None or head != seen['head'] or not _chain.verify_link(head, index, link):
        return 'audit_bad_link'
    if row is None:
        return None     # not eligible for that draw
    if draw_at is not None:
        rng = SplitMix64(seed_of(link))
        u = 0.0
        for _ in range(draw_at + 1):
            u = unit(rng)
        if (lo <= u < hi) != selected:
            return 'audit_inconsistent'
    if selected and index not in seen['indices']:
        return 'audit_selected_uninvited'
    return None


def handle_audit_reply(proc, queues, message):
    if message.function != AUDIT_REPLY:
        return False
    if not getattr(message, 'verified', False):
        return True
    answer = _payload(message)
    if answer is None:
        return True
    requestor = _uuid(message.from_whom)
    finding = check_answer(_peer_state(proc), requestor, answer)
    if finding is not None:
        _finding(proc, requestor, finding)
    return True


# --- plumbing ----------------------------------------------------------------

def _payload(message) -> Optional[dict]:
    payload = message.obj
    if isinstance(payload, (str, bytes)):
        try:
            payload = from_json_string(payload)
        except ValueError:
            return None
    return payload if isinstance(payload, dict) else None


def _send(proc, queues, verb, payload, peer) -> None:
    try:
        queues[CfgIds.network].put(Message(
            proc.name, verb, to_json_string(payload), peer,
            from_whom=getattr(proc, 'identity', None)),
            block=True, timeout=proc.q_cadence)
    except Full:
        logger.error('selection: network queue full')
