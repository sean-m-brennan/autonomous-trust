#!/usr/bin/env -S python3 -m
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
import sys
from ..system import dev_root_dir
from .configuration import Configuration
from .generate import generate_identity


if __name__ == '__main__':
    silent = True
    randomize = False
    if '--random' in sys.argv:
        randomize = True
    if '--verbose' in sys.argv:
        silent = False
    if Configuration.ROOT_VARIABLE_NAME in os.environ:
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.abspath(os.path.join(dev_root_dir, Configuration.CFG_PATH))
    generate_identity(cfg_dir, randomize, silent=silent)
