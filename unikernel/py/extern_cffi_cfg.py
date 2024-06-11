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
import subprocess
import shutil
from glob import glob


def fetch_build (extern_dir, build_dir):
    repo_url = 'https://foss.heptapod.net/pypy/cffi'
    if not os.path.isdir(os.path.join(extern_dir, 'cffi')):
        subprocess.run(['hg', 'clone', repo_url], cwd=extern_dir)
    os.makedirs(os.path.join(build_dir, 'cffi'), exist_ok=True)
    print("Acquire cffi code")
    src_dir = os.path.join(extern_dir, 'cffi')
    sources = glob(os.path.join(src_dir, 'c', '*.[ch]')) + glob(os.path.join(src_dir, 'cffi', '*.*'))
    for file in sources:
        shutil.copy(file, os.path.join(build_dir, 'cffi'))
