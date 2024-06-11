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
import shutil
import subprocess
from ..util import which, sudo_command, GREEN, RESET
from ..config import qemu_user_prefix, docker_multiarch


def install_docker():
    if which('docker') is None:
        raise RuntimeError('Docker installation not detected')
    if docker_multiarch:
        install_multi_arch_docker()


def install_multi_arch_docker():
    if not os.path.isdir(os.path.join(qemu_user_prefix, 'bin', 'qemu-aarch64-static')):
        tmp_dir = '/tmp'
        subprocess.run(['conda', 'install', '-n', 'base', 'conda-build', 'ninja', 'git'])
        print(GREEN + 'Build/install qemu-user-static to %s' % qemu_user_prefix + RESET)
        subprocess.run(['git', 'clone', 'https://gitlab.com/qemu-project/qemu.git'], cwd=tmp_dir, check=True)
        # FIXME is the following really necessary? (very, very slow)
        subprocess.run(['git', 'submodule', 'update', '--init', '--recursive'],
                       cwd=os.path.join(tmp_dir, 'qemu'), check=True)
        build_dir = os.path.join(tmp_dir, 'qemu', 'build')
        os.makedirs(build_dir, exist_ok=True)
        # FIXME compilers required here
        subprocess.run(['../configure', '--prefix=' + qemu_user_prefix,
                        '--static', '--disable-system', '--enable-linux-user'], cwd=build_dir, check=True)
        subprocess.run(['make', '-j8'], cwd=build_dir, check=True)
        sudo_command(['make', 'install'], cwd=build_dir)
        for file in os.listdir(os.path.join(qemu_user_prefix, 'bin')):
            shutil.move(file, file + '-static')

    subprocess.run(['docker', 'run', '--privileged', '--rm', 'tonistiigi/binfmt', '--install', 'all'])
    subprocess.run(['docker', 'buildx', 'create', '--name', 'builder', '--driver', 'docker-container',
                    '--driver-opt', 'network=host', '--use'])
    subprocess.run(['docker', 'buildx', 'inspect', 'builder', '--bootstrap'])
