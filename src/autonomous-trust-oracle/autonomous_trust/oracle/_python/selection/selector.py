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
"""The requestor's half of selective assignment (RD_12.7 plan §3.1-§3.6).

Runs in the negotiation process, behind the core's ``select_participants`` and
``on_decline`` hooks. One seed chain and one decision log per node. Every
decision, whether a task's draw, a probe's target or the re-draw after a
decline, consumes one chain index, so the indices a peer sees are the
requestor's whole history of coins.

**Which tasks are drawn.** A capability the declaration gives a ``k``
(D1(b)), and a directed probe when the declaration has a ``probe`` block. A
probe's target is then drawn here over every capable, present peer, weighted
by the UCB1 bonus of this layer's own probe counts (D6). The prober's own
argmax choice is overridden, so the two runtimes draw from the same counts
whichever process their prober runs in. A broadcast of a bootstrap capability
(the window-phase pairs) is never drawn, and neither is a task addressed to a
peer by anything but the prober.

**Persistence (§0.2).** Two files in the node's configuration directory.
``selection-<proc>.json`` holds the chain root, the next index and the probe
counts. It is written before a link is used, so a restart never reuses one.
``selection-log-<proc>.json`` holds the last ``log_records`` decisions and is
flushed on a slow timer, so a crash loses at most that much of the log. An
index lost that way answers ``unknown`` to an audit, as an evicted one does.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from collections import OrderedDict
from typing import Optional

from autonomous_trust.core.config import Configuration, atomic_write

from . import chain as _chain
from .draw import draw as _draw, propensities, seed_of
from .model import load_selection_env

logger = logging.getLogger(__name__)

#: The capabilities the prober issues; a directed task for one is a probe.
from autonomous_trust.core._python.bootstrap_capabilities import \
    BOOTSTRAP_CAPABILITY_NAMES  # noqa: E402

#: Seconds between log flushes.
FLUSH_SECONDS = 5.0

#: Version of the policy the log records name; bumped when the draw changes.
POLICY_VERSION = 1

_STATE_KEY = '_selection_requestor'
_MODEL = None


def _model():
    global _MODEL
    if _MODEL is None:
        _MODEL = load_selection_env()
    return _MODEL


def reset() -> None:
    """Forget the cached declaration (between conformance scenarios)."""
    global _MODEL
    _MODEL = None


def set_model(model) -> None:
    """Use ``model`` instead of $AT_SELECTION (tests and the harness)."""
    global _MODEL
    _MODEL = model


def ucb_bonus(count: int, total: int) -> float:
    """The prober's UCB1 bonus, as ``BootstrapWorker._ucb_bonus`` computes it."""
    return math.sqrt(2.0 * math.log(total + 2) / (count + 1))


class Requestor:
    """One node's chain, probe counts and decision log."""

    def __init__(self, proc_name: str, model, cfg_dir: Optional[str] = None,
                 root: Optional[bytes] = None):
        self.model = model
        cfg_dir = cfg_dir if cfg_dir is not None else Configuration.get_cfg_dir()
        self.chain_path = os.path.join(cfg_dir, 'selection-%s.json' % proc_name)
        self.log_path = os.path.join(cfg_dir, 'selection-log-%s.json' % proc_name)
        self.chain: Optional[_chain.SeedChain] = None
        self.next_index = 1
        self.prev_root: Optional[bytes] = None
        self.probe_counts: dict[str, int] = {}
        self.probe_total = 0
        self.records: 'OrderedDict[int, dict]' = OrderedDict()
        self.by_task: dict[str, list[int]] = {}
        self._dirty = False
        self._last_flush = 0.0
        self._load(root)

    # --- persistence ------------------------------------------------------

    def _load(self, root: Optional[bytes]) -> None:
        state = _read_json(self.chain_path)
        if state is not None:
            self.chain = _chain.SeedChain(bytes.fromhex(state['root']))
            self.next_index = int(state['next'])
            prev = state.get('prev_root')
            self.prev_root = bytes.fromhex(prev) if prev else None
            self.probe_counts = {str(k): int(v)
                                 for k, v in state.get('probe_counts', {}).items()}
            self.probe_total = int(state.get('probe_total', 0))
        else:
            self.chain = (_chain.SeedChain(root) if root is not None
                          else _chain.SeedChain.fresh())
            self._write_chain()
        log = _read_json(self.log_path)
        if log is not None:
            for rec in log.get('records', []):
                self._index(rec)

    def _write_chain(self) -> None:
        state = {'version': 1, 'root': self.chain.root.hex(),
                 'next': self.next_index,
                 'prev_root': self.prev_root.hex() if self.prev_root else None,
                 'probe_counts': self.probe_counts,
                 'probe_total': self.probe_total}
        with atomic_write(self.chain_path) as handle:
            json.dump(state, handle, sort_keys=True)

    def flush(self, force: bool = False) -> None:
        """Write the log if it changed and the timer allows (or ``force``)."""
        now = time.monotonic()
        if not self._dirty or (not force and now - self._last_flush < FLUSH_SECONDS):
            return
        with atomic_write(self.log_path) as handle:
            json.dump({'version': 1, 'records': list(self.records.values())},
                      handle, sort_keys=True)
        self._dirty = False
        self._last_flush = now

    # --- the chain --------------------------------------------------------

    def _take_link(self) -> tuple[int, bytes, dict]:
        """The next (index, link) and the draw field the invitation carries.
        Persisted before it is returned."""
        if self.next_index > _chain.LENGTH:
            self.prev_root = self.chain.root
            self.chain = _chain.SeedChain.fresh()
            self.next_index = 1
            logger.info('selection: seed chain rotated, new head %s',
                        self.chain.head.hex()[:16])
        index = self.next_index
        self.next_index += 1
        self._write_chain()
        link = self.chain.link(index)
        field = {'head': self.chain.head.hex(), 'index': index, 'link': link.hex()}
        if self.prev_root is not None:
            field['prev_root'] = self.prev_root.hex()
        return index, link, field

    # --- the log ----------------------------------------------------------

    def _index(self, rec: dict) -> None:
        self.records[int(rec['index'])] = rec
        self.by_task.setdefault(rec['task'], []).append(int(rec['index']))
        while len(self.records) > self.model.log_records:
            _, old = self.records.popitem(last=False)
            kept = [i for i in self.by_task.get(old['task'], []) if i != old['index']]
            if kept:
                self.by_task[old['task']] = kept
            else:
                self.by_task.pop(old['task'], None)
        self._dirty = True

    # --- decisions --------------------------------------------------------

    def decide(self, task_uuid: str, capability: str, eligible: list[str],
               weights: list[float], k, floor: float, kind_hint: str,
               redraw_of: Optional[int] = None) -> tuple[list[int], dict]:
        """Draw over ``eligible`` (uuid strings, canonical order). Returns the
        selected positions and the draw field for the invitation."""
        index, link, field = self._take_link()
        result = _draw(weights, k, floor, seed_of(link))
        rows = []
        for pos, peer in enumerate(eligible):
            rows.append({'peer': peer, 'propensity': result.inclusion[pos],
                         'selected': pos in result.selected})
        rec = {'index': index, 'head': field['head'], 'task': task_uuid,
               'capability': capability, 'policy': POLICY_VERSION,
               'purpose': kind_hint, 'kind': result.kind,
               'degraded': result.degraded, 'fallback': result.fallback,
               'link': field['link'], 'k': k, 'floor': floor,
               'weights': list(weights), 'eligible': rows, 'outcome': {},
               'redraw_of': redraw_of}
        self._index(rec)
        return list(result.selected), field

    def record_decline(self, task_uuid: str, peer: str) -> Optional[dict]:
        """Mark ``peer`` declined in the task's latest decision that selected
        it; returns that record, or None when no decision selected it."""
        for index in reversed(self.by_task.get(task_uuid, [])):
            rec = self.records.get(index)
            if rec is None:
                continue
            if any(r['peer'] == peer and r['selected'] for r in rec['eligible']):
                rec['outcome'][peer] = 'declined'
                self._dirty = True
                return rec
        return None

    def record_outcome(self, task_uuid: str, peer: str, score: float) -> bool:
        """Join a scored result into the decision that selected its executor."""
        for index in reversed(self.by_task.get(task_uuid, [])):
            rec = self.records.get(index)
            if rec is not None and any(r['peer'] == peer and r['selected']
                                       for r in rec['eligible']):
                rec['outcome'][peer] = float(score)
                self._dirty = True
                return True
        return False

    def asked(self, task_uuid: str) -> set:
        """Every peer any decision for ``task_uuid`` selected."""
        out = set()
        for index in self.by_task.get(task_uuid, []):
            rec = self.records.get(index)
            if rec is not None:
                out.update(r['peer'] for r in rec['eligible'] if r['selected'])
        return out

    # --- the audit (§0.1, §0.2) -------------------------------------------

    def audit_answer(self, index: int, asker: str) -> dict:
        """The answer to "draw ``index``: was I eligible, and how did the coin
        fall for me?" Only the asker's own row; never another peer's."""
        rec = self.records.get(int(index))
        if rec is None or int(index) >= self.next_index:
            return {'index': int(index), 'status': 'unknown'}
        answer = {'index': int(index), 'status': 'ok', 'head': rec['head'],
                  'link': rec['link'], 'task': rec['task'],
                  'eligible_count': len(rec['eligible']), 'row': None}
        peers = [r['peer'] for r in rec['eligible']]
        if asker in peers:
            answer['row'] = audit_row(rec, peers.index(asker))
        return answer


def audit_row(rec: dict, pos: int) -> dict:
    """The asker's row, with what lets it check its own coin: the stream
    offset of the draw that decided it (``draw_at``) and the interval that
    draw had to fall in for it to be selected (``lo`` <= u < ``hi``)."""
    row = rec['eligible'][pos]
    weights, k, floor = rec['weights'], rec['k'], rec['floor']
    n = len(weights)
    out = {'position': pos, 'eligible': True, 'propensity': row['propensity'],
           'selected': row['selected']}
    if rec['kind'] == 'all':
        out.update(draw_at=None, lo=0.0, hi=1.0)
        return out
    probs, _ = propensities(weights, floor)
    if rec['kind'] == 'categorical':
        lo = 0.0
        for p in probs[:pos]:
            lo += p
        out.update(draw_at=0, lo=lo, hi=lo + probs[pos])
        return out
    pi = k * probs[pos]
    pi = floor if pi < floor else pi
    pi = 1.0 if pi > 1.0 else pi
    if rec.get('fallback') and row['selected']:
        # The Bernoulli round came up empty, and the categorical draw after
        # it, at stream offset n, chose this peer.
        lo = 0.0
        for p in probs[:pos]:
            lo += p
        out.update(draw_at=n, lo=lo, hi=lo + probs[pos])
    else:
        out.update(draw_at=pos, lo=0.0, hi=pi)
    return out


def _read_json(path: str):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as err:
        logger.error('selection: unreadable %s (%s); starting over', path, err)
        return None
