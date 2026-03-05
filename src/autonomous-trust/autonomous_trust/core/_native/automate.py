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
Native AutonomousTrust orchestrator.

The Python ``AutonomousTrust`` class is re-exported for full API
compatibility.  ``NativeAutonomousTrust`` provides a thin wrapper around
the C ``run_autonomous_trust()`` entry point for future use when the
C library is built with ``-DFORK=0`` (no daemonization).
"""

from ._ffi import ffi, lib

# Re-export the Python AutonomousTrust as the default — downstream
# packages (services, inspector, simulator) subclass it and rely on
# multiprocessing.Queue-based IPC which the C side doesn't support yet.
from .._python.automate import AutonomousTrust  # noqa: F401

# Re-export LogLevel mapping
from .._python.processes import LogLevel


# C log_level_t values (must match utilities/logger.h)
_LOG_LEVEL_MAP = {
    LogLevel.DEBUG: 1,
    LogLevel.INFO: 2,
    LogLevel.WARNING: 3,
    LogLevel.ERROR: 4,
    LogLevel.CRITICAL: 5,
}


class NativeAutonomousTrust:
    """Thin wrapper around the C ``run_autonomous_trust()`` entry point.

    This is a low-level interface that runs the C daemon loop directly.
    It requires the C library to be built with ``-DFORK=0`` to avoid
    double-forking, which would orphan the Python process.

    For normal use, prefer the re-exported ``AutonomousTrust`` class
    which provides full Python-level process orchestration.
    """

    def __init__(self, q_in: str = 'at_in', q_out: str = 'at_out',
                 log_level: LogLevel = LogLevel.INFO,
                 log_file: str | None = None):
        self.q_in = q_in
        self.q_out = q_out
        self.log_level = log_level
        self.log_file = log_file

    def run(self) -> int:
        """Run the C autonomous trust daemon loop.

        Returns the C function's return code (0 = success).

        Warning:
            This calls the C ``run_autonomous_trust()`` which may
            daemonize (double-fork) unless built with ``-DFORK=0``.
        """
        q_in_buf = ffi.new('char[]', self.q_in.encode('utf-8'))
        q_out_buf = ffi.new('char[]', self.q_out.encode('utf-8'))
        c_level = _LOG_LEVEL_MAP.get(self.log_level, 2)

        if self.log_file is not None:
            log_buf = ffi.new('char[]', self.log_file.encode('utf-8'))
        else:
            log_buf = ffi.NULL

        rc = lib.run_autonomous_trust(
            q_in_buf, q_out_buf,
            ffi.NULL, 0,  # capabilities (not yet supported from Python)
            c_level, log_buf,
        )
        return rc
