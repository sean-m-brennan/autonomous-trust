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
"""
Optional debug-probes facade.

DESIGN
------
Probe call sites in production code go through this module. When the
AT_PROBES env var is unset (default), every public function is bound
to a no-op at import time, so call sites pay near-zero cost.

When AT_PROBES is truthy, the package writes structured JSONL to a
shared directory; counters aggregate (layer, event, reason) tuples
and emit deltas every few seconds.

PRUNING
-------
This subpackage is removable as a unit. To strip probe call sites
from production code:

    grep -rln '_probes\\.' src/autonomous-trust/.../core/_python/ \\
        | xargs sed -i -E '/[^a-zA-Z0-9_]_probes\\./d'

then delete any `from .. import _probes` / `from . import _probes`
imports and this directory.

DEPLOYMENT (shared volume)
--------------------------
The default output directory is `/var/at-probes`. All AT processes
across all containers must write to the same path, so mount one
named volume across every service in compose / kustomize. Override
the path with AT_PROBES_DIR.
"""
import os


_ENABLED = os.environ.get('AT_PROBES', '').strip().lower() in ('1', 'true', 'yes', 'on')


def enabled() -> bool:
    return _ENABLED


def _noop(*_args, **_kwargs):
    return None


if _ENABLED:
    from . import _writer as _w
    from . import counters as _c

    def flush() -> None:
        # Drain counter bag first so its snapshot lands in the JSONL.
        _c.flush_bag()
        _w.flush()

    def trace_msg(msg, hook: str, **ctx) -> None:
        # Pull trace_id off a Message-shaped object; fall back to no-op
        # if the caller passed something else (defensive — never crash a
        # production hook over a probe).
        tid = getattr(msg, 'trace_id', None)
        if tid is None:
            return
        proc = getattr(msg, 'process', None)
        fn = getattr(msg, 'function', None)
        _w.emit('msg', hook, trace_id=tid, process=proc, function=fn, **ctx)

    emit = _w.emit
    counter = _c.counter
else:
    emit = _noop
    flush = _noop
    counter = _noop
    trace_msg = _noop
