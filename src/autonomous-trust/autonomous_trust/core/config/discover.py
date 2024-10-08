# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import os

from autonomous_trust.core.processes import Process
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config import ConfigMap


def get_cfg_type(path: str):
    if path.endswith(Configuration.file_ext):
        return os.path.basename(path).removesuffix(Configuration.file_ext)
    return path


def load_configs():
    configs: ConfigMap = {}
    cfg_dir = Configuration.get_cfg_dir()
    config_files = [x for x in os.listdir(cfg_dir) if x.endswith(Configuration.file_ext)]
    config_paths = list(map(lambda x: os.path.join(cfg_dir, x), config_files))
    for cfg_file in config_paths:
        configs[get_cfg_type(cfg_file)] = Configuration.from_file(cfg_file)
    configs[Process.key] = []
    return configs
