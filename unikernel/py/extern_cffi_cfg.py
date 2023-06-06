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
