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
"""What every live red-team attack shares: the container side and the reading.

A live attack is a *standalone* scenario. Its ``setup`` hands the harness a
whole compose deployment, every container runs the attack's own module
(``python -m ...``) as its node, and that module prepares the node's
configuration in the container before it starts the node in the same process:

- ``base_config`` generates the identity (so it carries the container's own
  address) and grants the plaintext verbs of every enabled extension, without
  which a node refuses to start.
- ``swap_process`` replaces one of the node's processes with an attacker's
  subclass in ``subsystems.cfg.json``.
- ``run_node`` starts the node; ``RedTeamNode`` sends its capabilities (the
  bootstrap probes) to its other processes, so peers can probe it.

The reading side parses the ``AT_REPDUMP`` lines a node logs when
``AT_REP_DUMP_SEC`` is set (``read_dumps``), and ``held_since`` turns a series
of checks into the time a condition last became true and held to the end.
"""

from __future__ import annotations

import json
import os
import re
from typing import Iterable, Optional

from autonomous_trust.core import AutonomousTrust
from autonomous_trust.core._python.system import queue_cadence

#: The image every node runs; it must carry the evaluation, first-contact and
#: rendezvous packages (scripts/build-docker.sh builds it).
DEFAULT_IMAGE = 'autonomous-trust-full-devel'
#: The compose network every live attack's nodes share.
NETWORK = 'redteam'


# --- the deployment ----------------------------------------------------------

def node_service(name: str, ip: str, role: str, env: dict, *, image: str,
                 module: str, network: str = NETWORK,
                 volumes: Optional[list] = None) -> dict:
    """One compose service: a Python node named ``name`` at ``ip`` whose
    entry point is ``python -m <module>``, told its ``role``. ``env`` adds to
    (and may override) the common environment."""
    environment = {
        'AT_REDTEAM_ROLE': role,
        'AT_PEER_NAME': name,
        'AT_FIRST_CONTACT': '1',
        'AUTONOMOUS_TRUST_BACKEND': 'python',
        'AUTONOMOUS_TRUST_EXE': '-m %s' % module,
        'STARTUP_DELAY': '0',
    }
    environment.update(env)
    svc = {
        'image': image,
        'container_name': name,
        'hostname': name,
        'environment': environment,
        'networks': {network: {'ipv4_address': ip}},
    }
    if volumes:
        svc['volumes'] = list(volumes)
    return svc


def honest_service(name: str, ip: str, *, image: str = DEFAULT_IMAGE,
                   policy: bool = True, dump_sec: float = 5.0,
                   log_level: str = 'INFO', env: Optional[dict] = None,
                   network: str = NETWORK) -> dict:
    """An honest node: this module's own ``__main__``, dumping its
    reputation view every ``dump_sec`` seconds, with or without the join
    policy (no anchors: every peer earns its tier on this node's own
    evidence)."""
    e = {'AT_REDTEAM_POLICY': '1' if policy else '0',
         'AT_REDTEAM_LOG_LEVEL': log_level,
         'AT_REP_DUMP_SEC': str(dump_sec)}
    e.update(env or {})
    return node_service(name, ip, 'honest', e, image=image, module=__name__,
                        network=network)


def deployment(services: dict, subnet: str, network: str = NETWORK,
               volumes: Optional[Iterable[str]] = None) -> dict:
    """A compose document around ``services`` on one bridge ``subnet``."""
    doc = {
        'services': services,
        'networks': {network: {'ipam': {'config': [{'subnet': subnet}]}}},
    }
    if volumes:
        doc['volumes'] = {v: {} for v in volumes}
    return doc


# --- the container side ------------------------------------------------------

def base_config(cfg_dir: str, name: str):
    """Generate this node's configuration in ``cfg_dir`` as ``python -m
    autonomous_trust --live`` does, grant the plaintext verbs of every enabled
    extension (first contact's hello and request, ...), and return the
    node's identity."""
    from autonomous_trust.core.config.generate import random_config
    from autonomous_trust.core import Configuration, CfgIds
    from autonomous_trust.core._python import plaintext_verbs
    from autonomous_trust.core._python.extensions import enabled_extensions

    os.makedirs(cfg_dir, exist_ok=True)
    random_config(cfg_dir, name)
    plaintext_verbs.write(cfg_dir, [v for ext in enabled_extensions()
                                    for v in ext.plaintext_verbs])
    return Configuration.from_file(
        os.path.join(cfg_dir, CfgIds.identity + Configuration.file_ext))


def swap_process(cfg_dir: str, cfg_id: str, cls: type) -> None:
    """Run ``cls`` in place of the node's ``cfg_id`` process: rewrite that
    entry of ``subsystems.cfg.json`` to the class's dotted path. ``cls`` keeps
    the process name of the one it replaces, so every queue reaches it."""
    from autonomous_trust.core._python.processes import ProcessTracker
    path = os.path.join(cfg_dir, ProcessTracker.default_filename)
    with open(path) as f:
        subsystems = json.load(f)
    subsystems[cfg_id] = '%s.%s' % (cls.__module__, cls.__qualname__)
    with open(path, 'w') as f:
        json.dump(subsystems, f, indent=2)


def join_policy_doc(anchors: Iterable[str] = ()) -> dict:
    """A join-policy declaration with the given anchor classes and the
    defaults for the rest."""
    return {'version': 1, 'enabled': True, 'anchors': list(anchors)}


def write_join_policy(cfg_dir: str, anchors: Iterable[str] = ()) -> str:
    """Write ``join_policy_doc(anchors)`` to the node's configuration and
    return its path, for ``AT_JOIN_POLICY``."""
    path = os.path.join(cfg_dir, 'join_policy.json')
    with open(path, 'w') as f:
        json.dump(join_policy_doc(anchors), f)
    return path


def prepare_honest(cfg_dir: str, name: str, policy: bool) -> Optional[str]:
    """An honest node's configuration. Returns the join-policy path to
    export, or None."""
    base_config(cfg_dir, name)
    return write_join_policy(cfg_dir) if policy else None


class RedTeamNode(AutonomousTrust):
    """The node every container runs. It sends its capabilities (the bootstrap
    probes) to its other processes itself, as the example participants do:
    its identity process answers peers' caps queries with what it is sent,
    and a node that advertises no probes is one no peer can probe."""

    def autonomous_ability(self, queues):
        for q_name in queues:
            if q_name != self.proc_name:
                queues[q_name].put(self.capabilities, block=True,
                                   timeout=queue_cadence)


def run_node(log_level: str = 'INFO') -> None:
    """Start the node in this process and run it until it is stopped.
    ``log_level`` is a ``LogLevel`` name."""
    from autonomous_trust.core import Configuration
    from autonomous_trust.core._python.processes import LogLevel
    RedTeamNode(multiproc=True, log_level=LogLevel[log_level],
                logfile=Configuration.log_stdout).run_forever()


def honest_main() -> None:
    """An honest container's entry point: prepare, then run the node."""
    from autonomous_trust.core import Configuration
    path = prepare_honest(Configuration.get_cfg_dir(),
                          os.environ.get('AT_PEER_NAME', 'node'),
                          os.environ.get('AT_REDTEAM_POLICY') == '1')
    if path is not None:
        os.environ['AT_JOIN_POLICY'] = path
    run_node(os.environ.get('AT_REDTEAM_LOG_LEVEL', 'INFO'))


# --- reading the result ------------------------------------------------------

_DUMP = re.compile(r'AT_REPDUMP (\{.*\})')


def read_dumps(log_text: str) -> list[dict]:
    """Every ``AT_REPDUMP`` record in a node's log, in order. A line that does
    not parse (cut off when the container stopped, say) is skipped."""
    out = []
    for line in log_text.splitlines():
        m = _DUMP.search(line)
        if m is None:
            continue
        try:
            out.append(json.loads(m.group(1)))
        except ValueError:
            continue
    return out


def held_since(series: list[tuple[float, bool]]) -> Optional[float]:
    """When a condition last became true and stayed true through the last
    sample, in seconds from the first sample; None if it was false at the end
    (or there are no samples). A crossing that was later lost does not count."""
    if not series:
        return None
    t0 = series[0][0]
    since = None
    for t, ok in series:
        if not ok:
            since = None
        elif since is None:
            since = t - t0
    return since


def short_nick(view_entry: dict) -> str:
    """A dump entry's nickname without its domain: a live nickname is a full
    address (honest-2@tekfive.com)."""
    return (view_entry.get('nick') or '').split('@')[0]



def last_view(dumps: list[dict]) -> dict:
    """The last dump's view, by short nickname."""
    if not dumps:
        return {}
    return {short_nick(v): v for v in dumps[-1].get('view') or []}


def honest_pair_failures(name: str, dumps: list[dict], honest: Iterable[str],
                         tier: int = 3) -> list[str]:
    """What is wrong with how node ``name`` holds every other honest node at
    the end of its run: each one must be in its last view at ``tier`` or above
    on its own evidence (``own`` > 0). One string per honest peer that is not."""
    view = last_view(dumps)
    out = []
    for other in honest:
        if other == name:
            continue
        v = view.get(other)
        if v is None:
            out.append('%s: never saw %s' % (name, other))
        elif int(v.get('tier', 0)) < tier or not v.get('own'):
            out.append('%s: %s at tier %s with own %s' % (
                name, other, v.get('tier'), v.get('own')))
    return out


def honest_held_since(dumps: list[dict], name: str, honest: Iterable[str],
                      tier: int = 3) -> Optional[float]:
    """When node ``name`` last came to hold every other honest node at
    ``tier`` or above on its own evidence, and held them so to its last dump."""
    others = [h for h in honest if h != name]
    series = []
    for rec in dumps:
        view = {short_nick(v): v for v in rec.get('view') or []}
        ok = all(o in view and int(view[o].get('tier', 0)) >= tier
                 and view[o].get('own') for o in others)
        series.append((float(rec.get('t', 0.0)), ok))
    return held_since(series)


def mark_no_data(metrics: dict, logs: dict, silent: Iterable[str]) -> bool:
    """A node that never dumped never ran (a missing module in the image,
    say), so the run says nothing: set NO_DATA and keep the tail of each
    silent node's log, so the report says why. Returns whether it did."""
    silent = list(silent)
    if not silent:
        return False
    metrics['error'] = 'no_metrics'
    metrics.setdefault('attack_specific', {})['log_tails'] = {
        n: (logs.get(n) or '')[-2000:] for n in silent}
    return True


if __name__ == '__main__':
    honest_main()
