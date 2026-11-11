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
"""A man in the middle, live: read what one node puts on the wire, and replay
it to a peer.

A sidecar (``mitm_sidecar``) runs in ``honest-1``'s network namespace with
``NET_RAW``, from the same image as the nodes. It captures every UDP frame to
or from AT's ports, then replays everything ``honest-1`` sent ``honest-2``
point-to-point, from ``honest-1``'s own address. ``collect`` reads:

- **Confidentiality.** Each captured payload is classified. It is plaintext
  only if it *parses* as an envelope: a JSON object with non-empty
  ``process`` and ``function``, or the protobuf marker ``0xAB`` followed by a
  ``NetMessage`` with both set. Anything else is opaque (ciphertext is
  uniform bytes, and may well start with ``{`` or ``0xAB``). A plaintext
  verb outside ``allowed_plaintext()`` (the core's unencrypted verbs and
  every extension's declared plaintext verbs, imported) FAILs.
- **Replay.** ``honest-2``'s count of committed bilateral transactions with
  ``honest-1`` (its dump's ``n``) must not rise in the minute after the
  replay by more than ``REPLAY_SLACK`` beyond the most it rose for any other
  honest peer in that minute. A replay of ``honest-1``'s frames can move only
  ``honest-1``'s count, and the other peers are the control: the first
  placements of a young cohort move every count at once. The ``not above
  mark`` refusals ``honest-2`` logs are reported, in all and after the
  replay.

A run whose sidecar replayed nothing (or never logged) is NO_DATA.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from autonomous_trust.evaluation.redteam import AttackScenario
from autonomous_trust.evaluation.redteam import live

HONEST_PREFIX = 'honest-'
SIDECAR = 'mitm'
SUBNET = '10.34.0'
#: The harness puts its host directory for the run's files here.
ARTIFACTS = '{artifacts}'
#: How many more committed transactions with the replayed peer than with any
#: other honest peer the minute after the replay may add, before the replay
#: counts as acted on.
REPLAY_SLACK = 5

_NAME = re.compile(r'^[A-Za-z0-9_.\-]+$')


def allowed_plaintext() -> frozenset:
    """The verbs AT sends unencrypted by design: the core's, and each
    extension's declared plaintext verbs."""
    from autonomous_trust.core._python.identity.protocol import (
        CORE_UNENCRYPTED_VERBS)
    from autonomous_trust.core._python.extensions import all_extensions
    verbs = set(CORE_UNENCRYPTED_VERBS)
    for ext in all_extensions():
        verbs.update(ext.plaintext_verbs)
    return frozenset(verbs)


def _named(process, function) -> bool:
    return (isinstance(process, str) and isinstance(function, str)
            and bool(_NAME.match(process)) and bool(_NAME.match(function)))


def classify(frame: bytes) -> tuple:
    """('json', function), ('proto', function) or ('opaque', None)."""
    if frame[:1] == b'{':
        try:
            doc = json.loads(frame.decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            doc = None
        if isinstance(doc, dict) and _named(doc.get('process'),
                                            doc.get('function')):
            return 'json', doc['function']
    if frame[:1] == b'\xab':
        from autonomous_trust.core.protobuf.network import net_message_pb2
        pb = net_message_pb2.NetMessage()
        try:
            pb.ParseFromString(frame[1:])
        except Exception:
            pb = None
        if pb is not None and _named(pb.process, pb.function):
            return 'proto', pb.function
    return 'opaque', None


# --- the deployment ----------------------------------------------------------

def compose(honest: int = 6, *, capture_s: float = 600,
            replay_at_s: float = 660, image: str = live.DEFAULT_IMAGE,
            dump_sec: float = 5.0, policy: bool = True,
            log_level: str = 'INFO') -> dict:
    services = {}
    ips = {}
    for i in range(honest):
        name = '%s%d' % (HONEST_PREFIX, i + 1)
        ips[name] = '%s.%d' % (SUBNET, 10 + i)
        services[name] = live.honest_service(
            name, ips[name], image=image, policy=policy, dump_sec=dump_sec,
            log_level=log_level)
    target, victim = HONEST_PREFIX + '1', HONEST_PREFIX + '2'
    services[SIDECAR] = {
        'image': image,
        'container_name': SIDECAR,
        'user': 'root',
        'cap_add': ['NET_RAW'],
        'network_mode': 'service:%s' % target,
        'depends_on': [target],
        'volumes': ['%s:/capture' % ARTIFACTS],
        'environment': {
            'AUTONOMOUS_TRUST_EXE':
                '-m autonomous_trust.evaluation.redteam.mitm_sidecar',
            'MITM_TARGET': ips[target],
            'MITM_VICTIM': ips[victim],
            'MITM_CAPTURE_S': '%g' % capture_s,
            'MITM_REPLAY_AT_S': '%g' % replay_at_s,
        },
    }
    return live.deployment(services, '%s.0/24' % SUBNET)


# --- reading the result ------------------------------------------------------

_REPLAYED = re.compile(r'MITM_REPLAYED (\d+) at ([0-9.]+)')
_REFUSED = re.compile(r'not above mark')


def _n_at(series, t) -> Optional[int]:
    """The last ``n`` at or before ``t``."""
    out = None
    for ts, n in series:
        if ts <= t:
            out = n
    return out


def _rise_after(dumps: list, at: float, peer: str) -> Optional[int]:
    """How much the dumps' ``n`` for ``peer`` rose in the minute after
    ``at``; None without a dump on both sides."""
    series = []
    for rec in dumps:
        v = {live.short_nick(e): e for e in rec.get('view') or []}.get(peer)
        if v is not None:
            series.append((float(rec.get('t', 0.0)), int(v.get('n', 0))))
    start, after = _n_at(series, at), _n_at(series, at + 60)
    if start is None or after is None:
        return None
    return after - start


def replay_moved_n(dumps: list, at: float, peer: str,
                   controls: list) -> Optional[str]:
    """Why the victim's ``n`` for ``peer`` rose too much in the minute after
    ``at`` against the ``controls``' rise; '' when it did not; None when the
    dumps cannot say (no dump of ``peer`` on both sides, or no control)."""
    rise = _rise_after(dumps, at, peer)
    others = [r for r in (_rise_after(dumps, at, c) for c in controls)
              if r is not None]
    if rise is None or not others:
        return None
    if rise > max(others) + REPLAY_SLACK:
        return ('replay acted on: n for %s rose %d in the minute after the '
                'replay, at most %d for any other honest peer'
                % (peer, rise, max(others)))
    return ''


_STAMP = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) ')


def refusals_after(log_text: str, at: float) -> int:
    """The ``not above mark`` refusals logged at or after ``at``. A node logs
    in UTC."""
    import datetime
    n = 0
    for line in log_text.splitlines():
        if not _REFUSED.search(line):
            continue
        m = _STAMP.match(line)
        if m is None:
            continue
        t = datetime.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S.%f')
        if t.replace(tzinfo=datetime.timezone.utc).timestamp() >= at:
            n += 1
    return n


class MitmAttack(AttackScenario):
    """Capture-and-replay from one node's namespace, as a standalone
    scenario."""

    name = 'mitm_attack'
    description = 'Read and replay one node\'s traffic from its own namespace'

    def __init__(self, honest: int = 6, *, capture_s: float = 600,
                 replay_at_s: float = 660, image: str = live.DEFAULT_IMAGE,
                 policy: bool = True, log_level: str = 'INFO'):
        self.honest = honest
        self.capture_s = capture_s
        self.replay_at_s = replay_at_s
        self.image = image
        self.policy = policy
        self.log_level = log_level

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(
            self.honest, capture_s=self.capture_s,
            replay_at_s=self.replay_at_s, image=self.image,
            policy=self.policy, log_level=self.log_level))
        compose_config['standalone'] = True
        compose_config['artifacts'] = ARTIFACTS
        sim_config['collect_logs'] = [HONEST_PREFIX + '2', SIDECAR]

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        frames = (metrics.get('artifacts') or {}).get('frames.jsonl') or ''
        allowed = allowed_plaintext()
        verbs, opaque, total = {}, 0, 0
        failed = []
        for line in frames.splitlines():
            try:
                row = json.loads(line)
                payload = bytes.fromhex(row['hex'])
            except (ValueError, KeyError, TypeError):
                continue
            total += 1
            kind, function = classify(payload)
            if kind == 'opaque':
                opaque += 1
                continue
            verbs[function] = verbs.get(function, 0) + 1
        for verb in sorted(set(verbs) - allowed):
            failed.append('plaintext %s on the wire (%d frames)'
                          % (verb, verbs[verb]))
        victim = HONEST_PREFIX + '2'
        victim_log = logs.get(victim, '')
        dumps = live.read_dumps(victim_log)
        m = _REPLAYED.search(logs.get(SIDECAR, '') or '')
        replayed = int(m.group(1)) if m else 0
        moved = None
        controls = ['%s%d' % (HONEST_PREFIX, i) for i in range(3, self.honest + 1)]
        if m:
            moved = replay_moved_n(dumps, float(m.group(2)),
                                   HONEST_PREFIX + '1', controls)
            if moved:
                failed.append(moved)
        metrics['attack_specific'] = {
            'honest': self.honest,
            'policy': self.policy,
            'frames': total,
            'opaque': opaque,
            'plaintext_verbs': verbs,
            'replayed': replayed,
            'replay_at': float(m.group(2)) if m else None,
            'refusals': len(_REFUSED.findall(victim_log)),
            'refusals_after_replay': (refusals_after(victim_log, float(m.group(2)))
                                      if m else 0),
            'failed_checks': failed,
        }
        silent = [] if dumps else [victim]
        if not replayed or not total:
            # Nothing replayed, or nothing captured (the artifacts mount
            # failed, say): the run measured nothing.
            silent.append(SIDECAR)
        elif dumps and moved is None:
            # The victim's dumps cannot judge the replay: no dump of
            # honest-1 on both sides of it, or no control peer.
            silent.append(victim)
        live.mark_no_data(metrics, logs, silent)
        return metrics
