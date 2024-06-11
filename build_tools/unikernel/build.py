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
from pathlib import Path

from ..config import base_dir, ARCH, default_cpu_count, default_initrd_fs
from ..util import GREEN, RESET, sed_on_file
from ..devel.unikraft import get_kraft, update_kraft
from .cfg import default_platform, default_implementation, Kraft, unikernel_dir, kraft_tool
from .libraries import config_ext_libs, get_ext_sources
from .patches import apply_uk_patches


def get_kernel(implementation=default_implementation, platform=default_platform, debuggable=False):
    src_dir = os.path.join(base_dir, 'unikernel', implementation)

    target = 'autonomoustrust_' + implementation
    if implementation == 'c':
        target = 'autonomoustrust'

    kernel = target + '_' + platform + '-' + ARCH
    if debuggable:
        kernel += '.dbg'

    return src_dir, kernel


def build_unikernel(implementation=default_implementation, platform=default_platform, cpu_count=default_cpu_count,
                    initrdfs=default_initrd_fs, do_clean=False, pristine=False, debuggable=False, force=False):

    src_dir, kernel = get_kernel(implementation, platform, debuggable)

    kraft = get_kraft()
    update_kraft(kraft)

    if do_clean or pristine:
        clean(kraft, implementation, pristine)

    # Prep libraries
    config_ext_libs(['libffi', 'libzmq'], kraft)
    get_ext_sources(implementation)

    impl_dir = os.path.join(unikernel_dir, implementation)

    # Initialize
    if not os.path.exists(os.path.join(impl_dir, '.init')):
        subprocess.run([kraft, 'init'], cwd=impl_dir)
        Path(os.path.join(impl_dir, '.init')).touch()
    # Patch
    apply_uk_patches(implementation)

    # Build
    if kraft_tool == Kraft.pykraft:
        shutil.copy(os.path.join(impl_dir, 'Kraftfile.9pfs'), os.path.join(impl_dir, 'kraft.yaml'))
        if initrdfs:
            shutil.copy(os.path.join(impl_dir, 'Kraftfile.initrd'), os.path.join(impl_dir, 'kraft.yaml'))
        # For SMP multiprocessing increase CPU count
        sed_on_file(os.path.join(impl_dir, 'kraft.yaml'),
                    'CONFIG_UKPLAT_LCPU_MAXCOUNT=1', 'CONFIG_UKPLAT_LCPU_MAXCOUNT=%d' % cpu_count)
        print(GREEN + 'Configure unikraft for %s' % implementation + RESET)
        options = ['-m', ARCH, '-p', platform, '-t', kernel]
        if force:
            options += ['-F']
        subprocess.run([kraft, 'configure'] + options)
        print(GREEN + 'Build unikraft for %s' % implementation + RESET)
        subprocess.run([kraft, 'build'])
    elif kraft_tool == Kraft.kraftkit:
        shutil.copy(os.path.join(impl_dir, 'Kraftfile.9pfs'), os.path.join(impl_dir, 'Kraft'))
        if initrdfs:
            shutil.copy(os.path.join(impl_dir, 'Kraftfile.initrd'), os.path.join(impl_dir, 'Kraft'))
        options = ['-m', ARCH, '-p', platform, '--log-type', 'simple']
        if force:
            options += ['-F']
        subprocess.run([kraft, 'build'] + options)

    return os.path.join(src_dir, kernel)


def clean(kraft, impl, pristine=False):
    impl_dir = os.path.join(unikernel_dir, impl)
    if pristine:
        subprocess.run(['git', 'clean', '-f', '-xd', impl_dir])
    else:
        subprocess.run([kraft, 'clean'], cwd=impl_dir)
