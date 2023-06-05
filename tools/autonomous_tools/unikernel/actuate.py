import os
import subprocess

from ..config import qemu_system
from .build import build_unikernel
from .cfg import UPlatform, default_platform, default_implementation


def actuate(num_nodes: int = 2, implementation=default_implementation, platform=default_platform, initrdfs=False):
    kernel_path = build_unikernel(implementation, platform)
    src_dir = os.path.dirname(kernel_path)

    command = []
    if platform == UPlatform.linuxu:
        command = [kernel_path]
    elif platform == UPlatform.kvm:
        print("To exit QEMU, press ctrl-a x")
        options = ['-nographic', '-vga', 'none', '-device', 'sga', '-m', '1G']
        fs_img_dir = os.path.join(src_dir, 'fs0')
        if os.path.isdir(fs_img_dir):
            subprocess.call('/bin/sh ./correct_filesystem.sh', cwd=src_dir)  #FIXME should be in build
            if initrdfs:
                subprocess.call('/bin/sh ./create_fs_image.sh', cwd=src_dir)
                options += ['-initrd', os.path.join(src_dir, 'initramfz')]
            else:
                options += ['-fsdev', 'local,id=myid,path=' + os.path.join(src_dir, 'fs0') + ',security_model=none',
                            '-device', 'virtio-9p-pci,fsdev=myid,mount_tag=fs0']
        command = [qemu_system] + options + ['-k', kernel_path]
    elif platform == UPlatform.xen:
        raise NotImplementedError

    for n in range(1, num_nodes + 1):
        subprocess.Popen(command)
