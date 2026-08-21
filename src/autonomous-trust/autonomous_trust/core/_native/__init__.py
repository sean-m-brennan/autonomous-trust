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

"""
Native (C/CFFI) backend for autonomous_trust.core.

This module wraps libautonomous_trust.so via CFFI, providing the same
public API as the pure-Python implementation in autonomous_trust.core._python.

Raises ImportError if the native library or CFFI is not available.
"""

try:
    from ._ffi import lib as _lib  # noqa - validates that the C lib loads
except Exception as exc:
    raise ImportError(
        f"Native backend unavailable: {exc}. "
        f"Set AUTONOMOUS_TRUST_BACKEND=python to use pure-Python fallback."
    ) from exc

# Config — reuses Python Configuration with C-backed helpers
from .config import (Configuration, InitializableConfig, EmptyObject,
                     to_json_string, from_json_string,
                     to_yaml_string, from_yaml_string)

# Automate — re-exports Python AutonomousTrust
from .._python.automate import AutonomousTrust  # noqa: F401
# NativeAutonomousTrust available via ._automate_native if needed

# Processes, system — delegate to Python (not yet C-backed)
from .._python.processes import (ProcessTracker, Process, ProcMeta, LogLevel,
                                LOG_FORMAT, LOG_DATEFMT)
from .._python.system import CfgIds, QueueType
