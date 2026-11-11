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
"""Reputation gaming, live: a gamer earns trust with right answers, then
defects.

A gamer answers AT's known-answer probes correctly until its defection time
(``AT_REDTEAM_DEFECT_AT``, epoch seconds: start-up plus ``defect_s``), then
answers every probe wrongly, with the same wrong answers as the colluding
cohort's ``fail`` adversary. The answers are module-level functions swapped
into ``BOOTSTRAP_FUNCTIONS`` before the node registers them, because the node
hands its processes to a pool that pickles them.

The deployment is standalone: ``honest`` nodes run ``live`` and dump their
reputation view, the gamers run this module and log their defection time. The
second arm sets ``AT_REP_MIN_TENURE_SEC`` on the honest nodes, so a newcomer
holds at most the tenure tier until it has been a member that long.

``collect_node`` reads, per honest node and gamer: ``t_rise``, the first time
the gamer sat at tier 3 or above on the node's own evidence (seconds from the
node's first dump); ``peak_tier_before``, its highest earned tier before it
defected; ``t_fall``, seconds from the defection until the gamer last
dropped below tier 1 on own evidence and stayed there; and ``final_tier``.

FAIL when any honest node's ``t_fall`` is None (the gamer kept trust it no
longer earns), or when an honest node ends without holding every other
honest node at tier 3 on its own evidence.
"""

from __future__ import annotations

import os
import re
import time

from autonomous_trust.evaluation.redteam import AttackScenario
from autonomous_trust.evaluation.redteam import live
from autonomous_trust.evaluation.redteam.colluding_cohort import (
    _wrong_echo_challenge, _wrong_handshake, _wrong_time_attest)

GAMER_PREFIX = 'gamer-'
HONEST_PREFIX = 'honest-'
DEFECT_ENV = 'AT_REDTEAM_DEFECT_AT'
SUBNET = '10.32.0'


# --- the switch --------------------------------------------------------------

def _defected() -> bool:
    at = os.environ.get(DEFECT_ENV)
    return at is not None and time.time() >= float(at)


# Module-level, not closures: they must pickle by reference.

def _gaming_handshake(nonce=0, **kw):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    return _wrong_handshake(nonce) if _defected() else bc.at_handshake(nonce)


def _gaming_time_attest(**kw):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    return _wrong_time_attest() if _defected() else bc.at_time_attest()


def _gaming_echo_challenge(payload='', **kw):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    return (_wrong_echo_challenge(payload) if _defected()
            else bc.at_echo_challenge(payload))


def install_switch() -> None:
    """Answer every probe correctly until ``AT_REDTEAM_DEFECT_AT``, wrongly
    after. Must run before the node registers its bootstrap capabilities."""
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    bc.BOOTSTRAP_FUNCTIONS['at.handshake'] = _gaming_handshake
    bc.BOOTSTRAP_FUNCTIONS['at.time-attest'] = _gaming_time_attest
    bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge'] = _gaming_echo_challenge


def defect_after(seconds: float) -> float:
    """Set the defection time ``seconds`` from now (inherited by the node's
    processes) and install the switch. Returns the time."""
    at = time.time() + float(seconds)
    os.environ[DEFECT_ENV] = repr(at)
    install_switch()
    return at


# --- the deployment ----------------------------------------------------------

def compose(gamers: int = 1, honest: int = 6, *, defect_s: float = 480,
            tenure_s: float = 0, image: str = live.DEFAULT_IMAGE,
            dump_sec: float = 5.0, policy: bool = True,
            log_level: str = 'INFO') -> dict:
    """The honest nodes and the gamers, all starting together. ``tenure_s``
    > 0 gives the honest nodes a minimum tenure."""
    services = {}
    extra = {'AT_REP_MIN_TENURE_SEC': '%g' % tenure_s} if tenure_s > 0 else {}
    for i in range(honest):
        name = '%s%d' % (HONEST_PREFIX, i + 1)
        services[name] = live.honest_service(
            name, '%s.%d' % (SUBNET, 10 + i), image=image, policy=policy,
            dump_sec=dump_sec, log_level=log_level, env=extra)
    for i in range(gamers):
        name = '%s%d' % (GAMER_PREFIX, i + 1)
        services[name] = live.node_service(
            name, '%s.%d' % (SUBNET, 100 + i), 'gamer',
            {'AT_REDTEAM_LOG_LEVEL': log_level,
             'AT_REDTEAM_DEFECT_S': '%g' % defect_s},
            image=image, module=__name__)
    return live.deployment(services, '%s.0/24' % SUBNET)


# --- the container side ------------------------------------------------------

def node_main():
    from autonomous_trust.core import Configuration
    live.base_config(Configuration.get_cfg_dir(),
                     os.environ.get('AT_PEER_NAME', 'node'))
    at = defect_after(float(os.environ.get('AT_REDTEAM_DEFECT_S', '480')))
    print('%s %.3f' % (DEFECT_ENV, at), flush=True)
    live.run_node(os.environ.get('AT_REDTEAM_LOG_LEVEL', 'INFO'))


# --- reading the result ------------------------------------------------------

_DEFECT = re.compile(DEFECT_ENV + r' ([0-9.]+)')


def defect_time(log_text: str):
    """The defection time a gamer logged at start, or None."""
    m = _DEFECT.search(log_text or '')
    return float(m.group(1)) if m else None


def collect_node(log_text: str, defect_at: float,
                 gamer: str = GAMER_PREFIX + '1') -> dict:
    """How one honest node held ``gamer`` before and after it defected."""
    dumps = live.read_dumps(log_text)
    t0 = float(dumps[0].get('t', 0.0)) if dumps else 0.0
    t_rise = None
    peak = final = 0
    after = [(float(defect_at), False)]
    seen = False
    for rec in dumps:
        t = float(rec.get('t', 0.0))
        v = {live.short_nick(e): e for e in rec.get('view') or []}.get(gamer)
        tier = int(v.get('tier', 0)) if v else 0
        own = bool(v and v.get('own'))
        seen = seen or v is not None
        final = tier
        if t < defect_at:
            if own:
                peak = max(peak, tier)
                if tier >= 3 and t_rise is None:
                    t_rise = t - t0
        else:
            after.append((t, own and tier < 1))
    return {'dumps': len(dumps), 't_rise': t_rise, 'peak_tier_before': peak,
            'final_tier': final, 'seen': seen,
            't_fall': live.held_since(after) if len(after) > 1 else None}


class ReputationGamingAttack(AttackScenario):
    """Gamers that build trust and then defect, as a standalone scenario."""

    name = 'reputation_gaming'
    description = 'Nodes that earn trust with right answers, then defect'

    def __init__(self, gamers: int = 1, honest: int = 6, *,
                 defect_s: float = 480, tenure_s: float = 0,
                 image: str = live.DEFAULT_IMAGE, policy: bool = True,
                 log_level: str = 'INFO'):
        self.gamers = gamers
        self.honest = honest
        self.defect_s = defect_s
        self.tenure_s = tenure_s
        self.image = image
        self.policy = policy
        self.log_level = log_level

    @property
    def honest_names(self) -> list:
        return ['%s%d' % (HONEST_PREFIX, i + 1) for i in range(self.honest)]

    @property
    def gamer_names(self) -> list:
        return ['%s%d' % (GAMER_PREFIX, i + 1) for i in range(self.gamers)]

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        compose_config.clear()
        compose_config.update(compose(
            self.gamers, self.honest, defect_s=self.defect_s,
            tenure_s=self.tenure_s, image=self.image, policy=self.policy,
            log_level=self.log_level))
        compose_config['standalone'] = True
        sim_config['collect_logs'] = self.honest_names + self.gamer_names

    def collect(self, metrics: dict) -> dict:
        logs = metrics.get('logs') or {}
        defects = {g: defect_time(logs.get(g, '')) for g in self.gamer_names}
        nodes, failed = {}, []
        for n in self.honest_names:
            text = logs.get(n, '')
            nodes[n] = {g: collect_node(text, at, g)
                        for g, at in defects.items() if at is not None}
            for g, r in nodes[n].items():
                if r['t_fall'] is None:
                    failed.append('%s: %s kept trust after defecting' % (n, g))
            failed += live.honest_pair_failures(
                n, live.read_dumps(text), self.honest_names)
        metrics['attack_specific'] = {
            'gamers': self.gamers,
            'honest': self.honest,
            'defect_s': self.defect_s,
            'tenure_s': self.tenure_s,
            'policy': self.policy,
            'defect_at': defects,
            'nodes': nodes,
            'failed_checks': failed,
        }
        silent = [n for n in self.honest_names
                  if not live.read_dumps(logs.get(n, ''))]
        # A gamer that logged no defection time never started either; one
        # no honest node held as a peer never ran; one that never rose to
        # tier 3 on any honest node's evidence before it defected never
        # exercised the attack.
        silent += [g for g, at in defects.items() if at is None]
        for g in self.gamer_names:
            runs = [nodes[n][g] for n in self.honest_names if g in nodes[n]]
            if runs and not any(r['seen'] for r in runs):
                silent.append(g)
            elif runs and all(r['t_rise'] is None for r in runs):
                silent.append(g)
                metrics['attack_specific']['not_exercised'] = sorted(
                    set(metrics['attack_specific'].get('not_exercised', [])) | {g})
        live.mark_no_data(metrics, logs, silent)
        return metrics


if __name__ == '__main__':
    node_main()
