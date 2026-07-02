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

"""Entrypoint for the multi-agency disaster-response demo.

    python -m examples.multi_agency [--playback FILE | --record FILE]
                                    [--port 8050] [--namespace NS]
                                    [--log-level info]

Live mode (no --playback) joins the AT mesh via an InspectorBridge and
streams real peer observations into the dashboard. --playback replays
a captured event log without an AT runtime. --record captures the
scripted scenario timeline to JSON for later --playback.
"""

import argparse
import atexit
import logging
import os
import signal as _signal
import sys
import time

from autonomous_trust.core import LogLevel
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import random_config


_LOG_LEVEL_BY_NAME = {
    "debug":    LogLevel.DEBUG,
    "info":     LogLevel.INFO,
    "warning":  LogLevel.WARNING,
    "error":    LogLevel.ERROR,
    "critical": LogLevel.CRITICAL,
}


def _install_subprocess_cleanup(manager=None):
    """Reap the bridge's child-process tree on exit/signal.

    The multi-agency demo spawns a multiprocessing Manager plus an AT
    worker pool inside a daemon thread (the bridge). Daemon threads
    die abruptly when the main thread exits, so the pool's `__exit__`
    and the Manager's shutdown never run, and the workers — which all
    share argv — orphan to init. Repeated runs accumulate them and OOM
    the host. This handler walks our descendants via psutil and
    terminates the lot.
    """
    import psutil

    cleaned = [False]

    def _cleanup():
        if cleaned[0]:
            return
        cleaned[0] = True
        if manager is not None:
            try:
                manager.shutdown()
            except Exception:
                pass
        try:
            me = psutil.Process(os.getpid())
            children = me.children(recursive=True)
        except psutil.NoSuchProcess:
            return
        for c in children:
            try:
                c.terminate()
            except psutil.NoSuchProcess:
                continue
            except Exception:
                pass
        _gone, alive = psutil.wait_procs(children, timeout=3)
        for c in alive:
            try:
                c.kill()
            except (psutil.NoSuchProcess, Exception):
                pass

    atexit.register(_cleanup)

    def _handler(signum, _frame):
        _cleanup()
        # 128+N convention so $? is recognizable.
        os._exit(128 + signum)

    for sig in (_signal.SIGINT, _signal.SIGTERM, _signal.SIGHUP):
        try:
            _signal.signal(sig, _handler)
        except (ValueError, AttributeError, OSError):
            # Not in main thread or signal not supported on this platform.
            pass


def _await_peers():
    """Honor STARTUP_DELAY before joining the AT mesh.

    The peer-image's entrypoint.sh exposes STARTUP_DELAY for compose /
    k8s; the inspector container overrides `command:` and bypasses
    that script, so we re-implement it here. The single request_access
    multicast at T+0 otherwise races peers' bind() and is lost.
    """
    delay = (os.environ.get('STARTUP_DELAY')
             or os.environ.get('AT_STARTUP_DELAY'))
    try:
        secs = int(delay) if delay else 0
    except ValueError:
        secs = 0
    if secs > 0:
        print('multi-agency: waiting %ds for peers to bind...' % secs,
              flush=True)
        time.sleep(secs)


def _ensure_inspector_config():
    """Generate / locate the inspector AT config dir.

    The bridge is an AutonomousTrust subclass and needs the same
    on-disk config (identity, network, etc.) the stock inspector uses.
    Reads/writes under the installed inspector package so a single set
    of credentials is shared across runs.
    """
    import autonomous_trust.inspector as _inspector_pkg
    inspector_dir = os.path.dirname(_inspector_pkg.__file__)
    cfg_dir = os.path.join(inspector_dir, 'inspector', Configuration.CFG_PATH)
    if Configuration.ROOT_VARIABLE_NAME in os.environ:
        cfg_dir = Configuration.get_cfg_dir()
    has_config = os.path.isdir(cfg_dir) and any(
        f.endswith(Configuration.file_ext) for f in os.listdir(cfg_dir))
    if not has_config:
        random_config(inspector_dir, 'inspector')
    # random_config sets ROOT when it runs; set here too so repeat
    # invocations (has_config already True) don't fall back to /etc.
    os.environ.setdefault(Configuration.ROOT_VARIABLE_NAME, cfg_dir)
    return cfg_dir


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="python -m examples.multi_agency",
        description="Multi-agency disaster-response dashboard.",
    )
    p.add_argument("--port", type=int, default=8050,
                   help="Port to serve the Dash app on (default: 8050).")
    p.add_argument("--log-level", default="info",
                   choices=list(_LOG_LEVEL_BY_NAME),
                   help="Log level (default: info).")
    p.add_argument("--playback", metavar="FILE", default=None,
                   help="Replay a recorded scenario event log JSON file. "
                        "Skips the AT runtime entirely.")
    p.add_argument("--record", metavar="FILE", default=None,
                   help="Record the live scenario event stream to FILE "
                        "(JSON; consumable by --playback). Mutually "
                        "exclusive with --playback.")
    p.add_argument("--namespace", default=os.environ.get("AT_K8S_NAMESPACE"),
                   help="Kubernetes namespace the peers run in. Defaults "
                        "to $AT_K8S_NAMESPACE if set. Republished to env "
                        "so the bridge subprocess inherits it.")
    return p.parse_args(argv)


def main(argv=None):
    # Install a root handler so demo.py's module-level `logger.info(...)`
    # (and anything else in this dashboard-host process) actually reaches
    # stderr.  Without it, Python's lastResort handler filters everything
    # below WARNING.  See examples/dod_mission/coordinator.py:main() for
    # the AT-side rationale (Automaton only handler-binds its own class
    # logger); this process isn't an Automaton, but the same getLogger
    # trap applies because no other handler gets attached to root.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    args = _parse_args(argv if argv is not None else sys.argv[1:])
    log_level = _LOG_LEVEL_BY_NAME[args.log_level]

    if args.record and args.playback:
        print("Error: --record and --playback are mutually exclusive.",
              file=sys.stderr)
        sys.exit(2)

    if args.namespace:
        os.environ["AT_K8S_NAMESPACE"] = args.namespace
        print(f'multi-agency: k8s namespace = {args.namespace}', flush=True)

    # Lazy imports: pulling in evaluation/inspector + Dash up front
    # would surprise --playback users who don't need the full stack.
    from autonomous_trust.evaluation.scenarios.disaster_response import (
        DisasterResponseScenario,
    )
    from autonomous_trust.evaluation.scenarios.playback_iface import (
        PlaybackInterface,
    )
    from .demo import MultiAgencyDemo

    bridge_queue = None
    bridge_mgr = None
    if args.playback is None:
        # Live mode: only wait for peers + spawn the bridge.
        _await_peers()
        _ensure_inspector_config()

        import multiprocessing as _mp
        from .bridge import spawn_bridge, BRIDGE_QUEUE_MAX
        # Manager queue so the bridge's BridgeDataRcvr (a forkserver
        # child of the bridge's AT pool) can put reading events into
        # this same queue from a different process without smuggling
        # a raw mp.Queue across the spawn boundary.
        bridge_mgr = _mp.Manager()
        bridge_queue = bridge_mgr.Queue(maxsize=BRIDGE_QUEUE_MAX)
        spawn_bridge(bridge_queue, log_level=log_level)

    _install_subprocess_cleanup(manager=bridge_mgr)

    iface = PlaybackInterface(
        DisasterResponseScenario(),
        playback_file=args.playback,
        bridge_queue=bridge_queue,
        record_file=args.record,
    )
    MultiAgencyDemo(iface, port=args.port).run()


if __name__ == '__main__':
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
