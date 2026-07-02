# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Entrypoint for the stock inspector force-graph UI.

    python -m autonomous_trust.inspector [--port 8000] [--log-level info]

Scenario-specific dashboards (e.g. the multi-agency demo) live under
``examples/`` and have their own entrypoints; see
``examples/README.md`` for the architecture.
"""

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


def _install_subprocess_cleanup():
    """Reap the inspector's child-process tree on exit/signal.

    The inspector spawns AT worker subprocesses; without this handler
    they orphan to init when the main thread exits unexpectedly and
    accumulate across runs.
    """
    import psutil

    cleaned = [False]

    def _cleanup():
        if cleaned[0]:
            return
        cleaned[0] = True
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
        os._exit(128 + signum)

    for sig in (_signal.SIGINT, _signal.SIGTERM, _signal.SIGHUP):
        try:
            _signal.signal(sig, _handler)
        except (ValueError, AttributeError, OSError):
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
        description="AutonomousTrust stock inspector (force-graph UI).",
    )
    p.add_argument("--port", type=int, default=8000,
                   help="Port to serve on (default: 8000).")
    p.add_argument("--log-level", default="debug",
                   choices=list(_LOG_LEVEL_BY_NAME),
                   help="Log level (default: debug).")
    return p.parse_args(argv)


def _await_peers():
    """Honor STARTUP_DELAY before joining the AT mesh.

    Compose/k8s set STARTUP_DELAY on peer images via entrypoint.sh; the
    inspector container overrides `command:` and bypasses that script,
    so honor the same env var here.
    """
    delay = os.environ.get('STARTUP_DELAY') or os.environ.get('AT_STARTUP_DELAY')
    try:
        secs = int(delay) if delay else 0
    except ValueError:
        secs = 0
    if secs > 0:
        print(f'Inspector: waiting {secs}s for peers to bind...', flush=True)
        time.sleep(secs)


def _run_stock(port, log_level):
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


if __name__ == '__main__':
    args = _parse_args(sys.argv[1:])
    log_level = _LOG_LEVEL_BY_NAME[args.log_level]
    _await_peers()
    _run_stock(port=args.port, log_level=log_level)
