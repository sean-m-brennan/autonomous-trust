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
from ..config import conda_environ_name


def conda_present():
    if subprocess.call(['which', 'conda'], stdout=subprocess.DEVNULL) == 0:
        return subprocess.getoutput('which conda')
    return None


def conda_env_present(env_name):
    conda_base = subprocess.getoutput('conda info --base')
    if not os.path.isdir(os.path.join(conda_base, 'envs', env_name)):
        return False
    envs_list = subprocess.getoutput('conda env list')
    for line in envs_list.split('\n'):
        if line and line.split()[0] == env_name:
            return True
    return False


def init(conda_only=False, environ_only=False, no_virt=False, env_cfg=None):
    if not conda_present():
        from .conda import install_conda
        install_conda()  # this may restart the script
        if conda_only:
            return
    elif not conda_env_present(conda_environ_name):
        from .conda import init_conda_env
        init_conda_env(env_cfg=env_cfg)  # this may restart the script
        if environ_only:
            return
    elif not conda_only and not environ_only:
        from .rust import install_rust
        install_rust()
        if not no_virt:
            from .docker import install_docker
            install_docker()
            # Advanced options
            from .unikraft import get_kraft, get_qemu
            get_kraft()
            get_qemu()


def update():
    from .conda import update_env
    update_env()
