import os
import subprocess
from glob import glob
from pathlib import Path
import shutil

from ..config import base_dir
from ..util import GREEN, RESET
from .cfg import uk_workdir


def apply_uk_patches(impl=None):
    if impl is None:
        impl = '*'
    patch_dir = os.path.join(base_dir, 'unikernel', 'uk_patches')
    if not os.path.exists(os.path.join(uk_workdir, '.patched')):
        print(GREEN + "Patch unikraft" + RESET)
        # main patch first
        subprocess.run(['patch', '-p1', '--forward', '--input', os.path.join(patch_dir, 'unikraft.patch')],
                       cwd=uk_workdir)
        for pfile in glob(os.path.join(patch_dir, 'unikraft.%s.patch' % impl)):
            subprocess.run(['patch', '-p1', '--forward', '--input', pfile], cwd=uk_workdir)

        # Cannot create a patch with patches in it, so copy instead
        for patch_info in glob(os.path.join(patch_dir, '%s_patch_*_*' % impl)):
            lib_dir = patch_info.split('_')[2]
            patch_file = patch_info.split('_')[3]
            shutil.copy(patch_info, os.path.join(uk_workdir, 'libs', lib_dir, 'patches', patch_file))

        Path(os.path.join(uk_workdir, '.patched')).touch()
