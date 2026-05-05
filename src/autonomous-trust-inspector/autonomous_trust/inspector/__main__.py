# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

import argparse
import atexit
import os
import signal as _signal
import sys
import time

from autonomous_trust.core import LogLevel
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import random_config

from .inspector import Inspector


def _install_subprocess_cleanup(manager=None):
    """Reap the inspector's child-process tree on exit/signal.

    The civilian inspector spawns a multiprocessing Manager plus an AT
    worker pool inside a daemon thread (the bridge). Daemon threads die
    abruptly when the main thread exits, so the pool's `__exit__` and
    the Manager's shutdown never run, and the workers — which all show
    up as `python3 -m autonomous_trust.inspector` because they inherit
    argv — orphan to init. Repeated runs accumulate them and OOM the
    host. This handler walks our descendants via psutil and terminates
    the lot.
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
        # Mirror the default exit code for this signal so callers that
        # check $? still see a recognizable value (128+N convention).
        os._exit(128 + signum)

    for sig in (_signal.SIGINT, _signal.SIGTERM, _signal.SIGHUP):
        try:
            _signal.signal(sig, _handler)
        except (ValueError, AttributeError, OSError):
            # Not in main thread or signal not supported on this platform.
            pass


_LOG_LEVEL_BY_NAME = {
    "debug":    LogLevel.DEBUG,
    "info":     LogLevel.INFO,
    "warning":  LogLevel.WARNING,
    "error":    LogLevel.ERROR,
    "critical": LogLevel.CRITICAL,
}


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="python -m autonomous_trust.inspector",
        description="AutonomousTrust inspector — stock UI or civilian demo.",
    )
    p.add_argument("--port", type=int, default=None,
                   help="Port to serve on. Default: stock 8000, demo 8050.")
    p.add_argument("--log-level", default="debug",
                   choices=list(_LOG_LEVEL_BY_NAME),
                   help="Log level (default: debug).")
    p.add_argument("--demo-civilian", action="store_true",
                   help="Launch the civilian disaster-response dashboard "
                        "(Dash) instead of the stock force-graph UI.")
    p.add_argument("--playback", metavar="FILE", default=None,
                   help="Replay a recorded scenario event log JSON file. "
                        "Implies --demo-civilian and skips the AT runtime.")
    p.add_argument("--namespace", default=os.environ.get("AT_K8S_NAMESPACE"),
                   help="Kubernetes namespace the peers run in. Defaults to "
                        "$AT_K8S_NAMESPACE if set (k8s downward-API can "
                        "populate it). Exported back to env so the bridge "
                        "subprocess and any downstream consumer can read it.")
    return p.parse_args(argv)


def _run_stock(port, log_level):
    # Use existing config if available; only generate when none exists.
    cfg_dir = os.path.join(os.path.dirname(__file__),
                           'inspector', Configuration.CFG_PATH)
    if Configuration.ROOT_VARIABLE_NAME in os.environ:
        cfg_dir = Configuration.get_cfg_dir()
    has_config = os.path.isdir(cfg_dir) and any(
        f.endswith(Configuration.file_ext) for f in os.listdir(cfg_dir))
    if not has_config:
        random_config(os.path.join(os.path.dirname(__file__)), 'inspector')
    # random_config sets ROOT when it runs; set it here too so repeat
    # invocations (has_config already True) don't fall back to /etc.
    os.environ.setdefault(Configuration.ROOT_VARIABLE_NAME, cfg_dir)
    _install_subprocess_cleanup()
    Inspector(log_level=log_level, port=port).run_forever()


def _run_civilian(port, playback_file, log_level):
    # Lazy import — evaluation pulls in Dash deps we don't need in stock mode.
    from .civilian import CivilianDemo

    bridge_queue = None
    bridge_mgr = None
    if playback_file is None:
        # Live mode: spawn a CivilianInspectorBridge in a daemon thread
        # to observe real AT peers and pipe events to the Dash callback.
        # The bridge is an AutonomousTrust subclass and needs the same
        # config-dir setup as the stock inspector (_run_stock).
        cfg_dir = os.path.join(os.path.dirname(__file__),
                               'inspector', Configuration.CFG_PATH)
        if Configuration.ROOT_VARIABLE_NAME in os.environ:
            cfg_dir = Configuration.get_cfg_dir()
        has_config = os.path.isdir(cfg_dir) and any(
            f.endswith(Configuration.file_ext) for f in os.listdir(cfg_dir))
        if not has_config:
            random_config(os.path.join(os.path.dirname(__file__)),
                          'inspector')
        os.environ.setdefault(Configuration.ROOT_VARIABLE_NAME, cfg_dir)

        import multiprocessing as _mp
        from .civilian_bridge import spawn_bridge, BRIDGE_QUEUE_MAX
        # Manager queue so the bridge's BridgeDataRcvr (a forkserver
        # child of the bridge's AT pool) can put reading events into
        # this same queue from a different process without smuggling a
        # raw mp.Queue across the spawn boundary.
        bridge_mgr = _mp.Manager()
        bridge_queue = bridge_mgr.Queue(maxsize=BRIDGE_QUEUE_MAX)
        spawn_bridge(bridge_queue, log_level=log_level)

    _install_subprocess_cleanup(manager=bridge_mgr)
    CivilianDemo(port=port, playback_file=playback_file,
                 bridge_queue=bridge_queue).run()


def _await_peers():
    # Inspector's compose entry overrides `command:` and bypasses
    # entrypoint.sh, so the peer-image's STARTUP_DELAY plumbing doesn't
    # apply. Honor the same env var here so the inspector can be held
    # back until peer TCP listeners are bound — otherwise its single
    # request_access multicast at T+0 races peers' bind() and is lost,
    # leaving peers' accept_peer_message rejecting every later TCP frame.
    delay = os.environ.get('STARTUP_DELAY') or os.environ.get('AT_STARTUP_DELAY')
    try:
        secs = int(delay) if delay else 0
    except ValueError:
        secs = 0
    if secs > 0:
        print('Inspector: waiting %ds for peers to bind...' % secs, flush=True)
        time.sleep(secs)


if __name__ == '__main__':
    args = _parse_args(sys.argv[1:])
    log_level = _LOG_LEVEL_BY_NAME[args.log_level]

    # Republish namespace into env so the bridge subprocess (and any
    # downstream code that needs it for service-name resolution / log
    # context) inherits the same value the operator passed on the CLI.
    if args.namespace:
        os.environ["AT_K8S_NAMESPACE"] = args.namespace
        print(f'Inspector: k8s namespace = {args.namespace}', flush=True)

    civilian = args.demo_civilian or args.playback is not None
    port = args.port if args.port is not None else (8050 if civilian else 8000)

    if args.playback is None:
        _await_peers()

    if civilian:
        _run_civilian(port=port, playback_file=args.playback,
                      log_level=log_level)
    else:
        _run_stock(port=port, log_level=log_level)
