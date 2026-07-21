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

"""Canned-playback entrypoint for the multi-agency disaster-response demo.

    python -m examples.multi_agency --playback FILE [--port 8050]
                                    [--log-level info]

This replays a recorded scenario event log (produced by a live run's
``coordinator.py --record FILE``) with NO AutonomousTrust runtime — a
lightweight, dependency-light way to review or present a captured session.

LIVE mode no longer lives here. A live run is hosted by the coordinator
(``examples/multi_agency/coordinator.py``), which is itself an AT mesh node
and serves this same ``MultiAgencyDemo`` dashboard in-thread, feeding it the
mesh observations directly (no separate bridge/observer node). See
``run-demo.sh --variant=multi-agency`` and the DoD-mission demo for the same
coordinator-hosted pattern.
"""

import argparse
import logging
import sys

from autonomous_trust.core import LogLevel


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
        description="Multi-agency disaster-response dashboard (canned "
                    "playback). For a live run use coordinator.py "
                    "(scripts/run-demo.sh --variant=multi-agency).",
    )
    p.add_argument("--playback", metavar="FILE", required=True,
                   help="Replay a recorded scenario event log JSON file "
                        "(captured by 'coordinator.py --record FILE'). "
                        "Runs no AT runtime.")
    p.add_argument("--port", type=int, default=8050,
                   help="Port to serve the Dash app on (default: 8050).")
    p.add_argument("--log-level", default="info",
                   choices=list(_LOG_LEVEL_BY_NAME),
                   help="Log level (default: info).")
    return p.parse_args(argv)


def main(argv=None):
    # Root handler so demo.py's module-level logging reaches stderr; without
    # it Python's lastResort filters everything below WARNING.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    args = _parse_args(argv if argv is not None else sys.argv[1:])

    # Lazy imports: pulling in evaluation + Dash up front is only needed once
    # we actually serve.
    from autonomous_trust.evaluation.scenarios.disaster_response import (
        DisasterResponseScenario,
    )
    from autonomous_trust.evaluation.scenarios.playback_iface import (
        PlaybackInterface,
    )
    from .demo import MultiAgencyDemo

    iface = PlaybackInterface(
        DisasterResponseScenario(),
        playback_file=args.playback,
    )
    MultiAgencyDemo(iface, port=args.port).run()


if __name__ == '__main__':
    main()
