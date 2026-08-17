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

"""Dependency-light entrypoints for the multi-agency disaster-response demo.

Two modes, neither of which runs an AutonomousTrust node itself:

    # 1. Replay a recorded scenario event log (captured by a live run's
    #    coordinator.py --record FILE):
    python -m examples.multi_agency --playback FILE [--port 8050]

    # 2. LOG-HARVEST debug lens: reconstruct the observer->subject
    #    reputation matrix by tailing the logs of a running mesh whose
    #    nodes were started with AT_REP_DUMP_SEC=<sec>, and serve the
    #    dashboard from that reconstruction:
    python -m examples.multi_agency --log-harvest \
        [--runtime docker|k8s] [--namespace NS] [--containers a,b,c] \
        [--port 8050]

LIVE (in-mesh) hosting still lives in coordinator.py, which is itself an
AT node and serves this same dashboard in-thread. The --log-harvest mode
is the deliberately out-of-band alternative: it needs no coordinator and
trusts nothing relayed over the mesh — every score is read straight from
the node that computed it. See log_harvest.py.
"""

import argparse
import logging
import sys

from autonomous_trust.core import LogLevel
from autonomous_trust.core import LOG_FORMAT, LOG_DATEFMT


_LOG_LEVEL_BY_NAME = {
    "debug":    LogLevel.DEBUG,
    "info":     LogLevel.INFO,
    "warning":  LogLevel.WARNING,
    "error":    LogLevel.ERROR,
    "critical": LogLevel.CRITICAL,
}


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="python -m examples.multi_agency",
        description="Multi-agency disaster-response dashboard. Choose a "
                    "playback replay or the log-harvest debug lens. For a "
                    "live in-mesh run use coordinator.py "
                    "(scripts/run-demo.sh --variant=multi-agency).",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--playback", metavar="FILE",
                      help="Replay a recorded scenario event log JSON file "
                           "(captured by 'coordinator.py --record FILE'). "
                           "Runs no AT runtime.")
    mode.add_argument("--log-harvest", action="store_true",
                      help="Reconstruct the reputation matrix by tailing a "
                           "running mesh's container/pod logs (nodes must run "
                           "with AT_REP_DUMP_SEC set). Runs no AT runtime.")
    mode.add_argument("--triage", action="store_true",
                      help="One-shot: read current logs, print a per-subject "
                           "exclusion triage table (why the graph paints nodes "
                           "'excluded': real AT exclusion vs cold-start "
                           "baseline vs earned decline), and exit. No dashboard.")
    p.add_argument("--runtime", choices=["docker", "k8s"], default="docker",
                   help="Log source for --log-harvest (default: docker).")
    p.add_argument("--namespace", default=None,
                   help="Kubernetes namespace for --runtime k8s.")
    p.add_argument("--containers", default=None,
                   help="Comma-separated container/pod names to tail "
                        "(default: the scenario's peer names).")
    p.add_argument("--tail", type=int, default=0,
                   help="Lines of prior log history to include on attach "
                        "(default: 0 = only new lines).")
    p.add_argument("--port", type=int, default=8050,
                   help="Port to serve the Dash app on (default: 8050).")
    p.add_argument("--log-level", default="info",
                   choices=list(_LOG_LEVEL_BY_NAME),
                   help="Log level (default: info).")
    return p.parse_args(argv)


def _resolve_nodes(args, scenario):
    """Container/pod names to read: explicit --containers, else the
    scenario's peer names (which match the generated compose/k8s names)."""
    if args.containers:
        return [n.strip() for n in args.containers.split(",") if n.strip()]
    return list(scenario.peers)


def _run_triage(args, scenario_cls):
    """One-shot exclusion triage. Deliberately imports neither Dash nor
    demo.py — a read-only lens over the current logs."""
    from .log_harvest import collect_once, format_triage_table

    scenario = scenario_cls()
    nodes = _resolve_nodes(args, scenario)
    matrix = collect_once(nodes, runtime=args.runtime,
                          namespace=args.namespace, tail=args.tail)
    print(format_triage_table(matrix.triage_table()))


def _run_playback(args, scenario_cls, PlaybackInterface, MultiAgencyDemo):
    iface = PlaybackInterface(scenario_cls(), playback_file=args.playback)
    MultiAgencyDemo(iface, port=args.port).run()


def _run_log_harvest(args, scenario_cls, PlaybackInterface, MultiAgencyDemo):
    import queue as _queue
    from .log_harvest import LogHarvester

    scenario = scenario_cls()
    # Container / pod names match the scenario peer names in the demo's
    # compose + k8s manifests, so the roster is the default node list.
    nodes = _resolve_nodes(args, scenario)

    bridge_queue = _queue.Queue()
    harvester = LogHarvester(
        bridge_queue, nodes,
        runtime=args.runtime, namespace=args.namespace, tail=args.tail)
    harvester.start()

    # LIVE mode (no playback_file): the scenario clock advances at wall rate
    # while the harvester feeds real observations onto bridge_queue.
    iface = PlaybackInterface(scenario, bridge_queue=bridge_queue)
    try:
        MultiAgencyDemo(iface, port=args.port).run()
    finally:
        harvester.stop()


def main(argv=None):
    # Root handler so demo.py's module-level logging reaches stderr; without
    # it Python's lastResort filters everything below WARNING.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format=LOG_FORMAT, datefmt=LOG_DATEFMT,
    )

    args = _parse_args(argv if argv is not None else sys.argv[1:])

    # Scenario is needed by every mode (for the default node roster / phase
    # axis) and is light; Dash + demo.py are pulled only when we actually
    # serve, so --triage stays dependency-light.
    from autonomous_trust.evaluation.scenarios.disaster_response import (
        DisasterResponseScenario,
    )

    if args.triage:
        _run_triage(args, DisasterResponseScenario)
        return

    from autonomous_trust.evaluation.scenarios.playback_iface import (
        PlaybackInterface,
    )
    from .demo import MultiAgencyDemo

    if args.log_harvest:
        _run_log_harvest(args, DisasterResponseScenario,
                         PlaybackInterface, MultiAgencyDemo)
    else:
        _run_playback(args, DisasterResponseScenario,
                      PlaybackInterface, MultiAgencyDemo)


if __name__ == '__main__':
    main()
