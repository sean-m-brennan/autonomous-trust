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
Native config module — reuses Python Configuration for serialization,
adds C-backed directory/loading helpers.
"""

# Configuration serialization is pure Python — reuse it directly
from ..._python.config import (
    Configuration,
    InitializableConfig,
    EmptyObject,
    SerializeMode,
    WireFormat,
    to_json_string,
    from_json_string,
    to_yaml_string,
    from_yaml_string,
    ConfigMap,
)

from .configuration import get_cfg_dir, get_data_dir, load_all_configs
