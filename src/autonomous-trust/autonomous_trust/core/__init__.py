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

try:
    import importlib.metadata  # noqa
    __version__ = importlib.metadata.version("autonomous_trust")
except ImportError:
    __version__ = 0

from .processes import yaml, ProcessTracker, Process, ProcMeta, LogLevel
from .config import Configuration, InitializableConfig, EmptyObject, to_yaml_string, from_yaml_string
from .system import CfgIds, QueueType


def __getattr__(name):
    """Lazy import for AutonomousTrust to avoid circular imports in subprocess unpickling."""
    if name == 'AutonomousTrust':
        from .automate import AutonomousTrust
        return AutonomousTrust
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
