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

from ..config import qemu_system
from .build import build_unikernel, get_kernel
from .cfg import UPlatform, default_platform, default_implementation


def actuate(num_nodes: int = 2, implementation: str = default_implementation, platform: str = default_platform,
            initrdfs: bool = False, debuggable: bool = False, quick: bool = False):
    src_dir, kernel = get_kernel(implementation, platform, debuggable)
    kernel_path = os.path.join(src_dir, kernel)
    if not quick:
        build_unikernel(implementation, platform, initrdfs=initrdfs, debuggable=debuggable)

    command = []
    if platform == UPlatform.linuxu:
        command = [kernel_path]
    elif platform == UPlatform.kvm:
        print("To exit QEMU, press ctrl-a x")
        options = ['-nographic', '-vga', 'none', '-device', 'sga', '-m', '1G']
        fs_img_dir = os.path.join(src_dir, 'fs0')
        if os.path.isdir(fs_img_dir):
            subprocess.call('/bin/sh ./correct_filesystem.sh', cwd=src_dir)  # FIXME should be in build
            if initrdfs:
                subprocess.call('/bin/sh ./create_fs_image.sh', cwd=src_dir)
                options += ['-initrd', os.path.join(src_dir, 'initramfz')]
            else:
                options += ['-fsdev', 'local,id=myid,path=' + os.path.join(src_dir, 'fs0') + ',security_model=none',
                            '-device', 'virtio-9p-pci,fsdev=myid,mount_tag=fs0']
        command = [qemu_system] + options + ['-k', kernel_path]
    elif platform == UPlatform.xen:
        raise NotImplementedError

    for _ in range(1, num_nodes + 1):  # FIXME separate terminals
        subprocess.Popen(command)
