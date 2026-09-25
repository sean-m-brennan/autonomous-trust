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
"""How the core finds the verification layers (see
``autonomous_trust.core.extensions``).

Named by the ``autonomous_trust.extensions`` entry point when installed, and
found by file name in a source tree. Importing the five packages is what
registers them with ``autonomous_trust.core.oracles``; the extension itself
attaches no process handlers.
"""
from autonomous_trust.core import oracles
from autonomous_trust.core.extensions import Extension

from autonomous_trust.oracle import (calibration, certificates,  # noqa: F401
                                     physics, prequential, replication)


def _enabled() -> bool:
    # Always: each layer speaks only once its declaration names a model.
    return True


def _register_handlers(proc, proc_name: str) -> None:
    # The layers score in the main process, through the registry; no core
    # process needs a handler from them.
    return None


EXTENSION = Extension(name='oracle', enabled=_enabled,
                      register_handlers=_register_handlers,
                      reset=oracles.reset)
