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

# Load order matters: automate imports from .processes at module
# scope, so .processes must be fully loaded before .automate runs.
# When multiprocessing.Manager's spawned server subprocess re-imports
# autonomous_trust.core to unpickle queue payloads, automate's
# module-level `from .processes import Process` would otherwise hit
# a partially-initialized .processes (cycle).
from .config import Configuration, InitializableConfig, EmptyObject, \
    to_json_string, from_json_string, to_yaml_string, from_yaml_string
from .system import CfgIds, QueueType
from .processes import ProcessTracker, Process, ProcMeta, LogLevel
from .automate import AutonomousTrust  # noqa
