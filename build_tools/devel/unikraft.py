import os
import sys
import subprocess
import urllib.request
from pathlib import Path
from datetime import datetime

from ..unikernel.cfg import Kraft, unikernel_dir, kraft_tool, uk_workdir
from ..config import kraft_update_freq_days, ARCH
from ..util import which


def get_kraft():
    kraft = None

    os.environ['UK_WORKDIR'] = uk_workdir
    os.environ['KRAFTRC'] = os.path.join(unikernel_dir, '.kraftrc')

    # Find existing kraft tool
    kpath_alt = which('kraft', True)[-1]
    kpath_default = which('kraft')
    conda_prefix = os.environ['CONDA_PREFIX']
    if kpath_default is not None:
        if kraft_tool == Kraft.pykraft and conda_prefix in kpath_default:
            kraft = kpath_default
        elif kraft_tool == Kraft.kraftkit:
            if conda_prefix in kpath_default:
                kraft = kpath_default
            else:
                kraft = kpath_alt

    # Install kraft, if missing
    if kraft is None:
        if kraft_tool == Kraft.pykraft:
            # install pykraft under conda
            subprocess.run([sys.executable, "-m", "pip", "install",
                            'git+https://github.com/unikraft/pykraft.git'], check=True)
        elif kraft_tool == Kraft.kraftkit:
            # install KraftKit
            kraftkit_url = 'https://get.kraftkit.sh'
            install_sh = 'kraftkit.sh'
            urllib.request.urlretrieve(kraftkit_url, install_sh)
            subprocess.run(['bin/sh', install_sh, '-y'], check=True)
        kraft = which('kraft')
    return kraft


def update_kraft(kraft):
    update_file = os.path.join(unikernel_dir, '.update')
    if not os.path.isdir(os.path.join(unikernel_dir, '.unikraft')) or \
            not os.path.exists(update_file) or \
            (datetime.now() - datetime.fromtimestamp(os.path.getmtime(update_file))).days > kraft_update_freq_days:
        if kraft_tool == Kraft.pykraft:
            subprocess.run([kraft, 'list', 'update'])
        elif kraft_tool == Kraft.kraftkit:
            subprocess.run([kraft, 'pkg', 'update'])
        Path(update_file).touch()


def get_qemu():
    qemu = which('qemu-system-' + ARCH)
    if qemu is None:
        qemu = which('qemu-kvm')
        if qemu is None:
            qemu = '/usr/libexec/qemu-kvm'
            if not os.path.exists(qemu):
                raise RuntimeError('QEMU installation not found')
    return qemu
