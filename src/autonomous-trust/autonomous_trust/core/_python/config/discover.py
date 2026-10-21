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

import os

from ..config import Configuration
from ..config import ConfigMap

# NB: ..processes.Process is imported lazily below. Eagerly importing
# at module scope creates a cycle when multiprocessing.Manager spawns
# a server subprocess: pickle re-imports autonomous_trust.core, which
# triggers _python/__init__.py → automate.py → here → ..processes,
# but ..processes hasn't finished loading yet, raising ImportError.


def get_cfg_type(path: str):
    if path.endswith(Configuration.file_ext):
        return os.path.basename(path).removesuffix(Configuration.file_ext)
    return path


def load_configs():
    from ..processes import Process  # deferred; see top-of-module note
    configs: ConfigMap = {}
    cfg_dir = Configuration.get_cfg_dir()
    config_files = [x for x in os.listdir(cfg_dir) if x.endswith(Configuration.file_ext)]
    config_paths = list(map(lambda x: os.path.join(cfg_dir, x), config_files))
    for cfg_file in config_paths:
        cfg_type = get_cfg_type(cfg_file)
        cfg = Configuration.from_file(cfg_file)
        if cfg_type == _GROUP_CFG and isinstance(cfg, (list, tuple)):
            # identity saves its group as (Group, history) -- the history is
            # rebuilt at startup, never read back -- and every consumer wants
            # the Group. Handing on the pair made each restarted process's
            # protocol.group a list (reputation then failed every proposal on
            # `'list' object has no attribute 'uuid'`), and identity's "is this
            # still our saved group?" check could never match.
            cfg = cfg[0] if cfg else None
        configs[cfg_type] = cfg
    configs[Process.key] = []
    return configs


#: The group config's file stem (CfgIds.group; not imported, to keep this
#: module free of the cycle its deferred imports avoid).
_GROUP_CFG = 'group'
