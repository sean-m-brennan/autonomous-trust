import os
import subprocess
import shutil
import sys


def fetch_build (extern_dir, build_dir):
    repo_url = 'https://github.com/pyca/pynacl.git'
    if not os.path.isdir(os.path.join(extern_dir, 'pynacl')):
        subprocess.run(['git', 'clone', repo_url], cwd=extern_dir)
    print("Building sodium module from pynacl (see pynacl/build.log)")
    env = os.environ.copy()
    env['PYNACL_SODIUM_STATIC'] = 1
    env['SODIUM_INSTALL_MINIMAL'] = 1
    with open(os.path.join(extern_dir, 'pynacl', 'build.log'), 'w') as log:
        subprocess.run([sys.executable, 'setup.py', 'build'], env=env, cwd=os.path.join(extern_dir, 'pynacl'),
                       stdout=log, stderr=log)
    for root, _, files in os.walk(os.path.join(extern_dir, 'pynacl')):
        for x in files:
            if x == '_sodium.c':
                c_file = os.path.join(root, x)
                break
    shutil.copy(c_file, build_dir)
