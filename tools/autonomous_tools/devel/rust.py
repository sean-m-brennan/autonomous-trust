import os
import subprocess
import json
import urllib.request
from ..config import conda_environ_name


def install_rust(env_name=conda_environ_name):
    cargo_home = None
    json_info = json.loads(subprocess.getoutput('conda info --json'))
    for path in json_info['envs']:
        if env_name in path:
            cargo_home = path
    if cargo_home is None:
        raise RuntimeError('Installing Rust, but Conda env %s is not installed' % env_name)
    print('Cargo ', cargo_home)
    os.environ['RUSTUP_HOME'] = cargo_home
    os.environ['CARGO_HOME'] = cargo_home
    os.environ['PATH'] += ':' + os.path.join(cargo_home, 'bin')
    rustup_url = 'https://sh.rustup.rs'
    install_sh = '/tmp/rustup.sh'
    urllib.request.urlretrieve(rustup_url, install_sh)
    subprocess.run(['/bin/sh', install_sh, '-y'], check=True)
    subprocess.run(['rustup', 'install', 'nightly'], check=True)
    subprocess.run(['rustup', 'default', 'nightly'])

    active_dir = os.path.join(cargo_home, 'etc', 'conda', 'activate.d')
    os.makedirs(active_dir, exist_ok=True)
    active_file = os.path.join(active_dir, 'rust_activate.sh')
    with open(active_file, 'w') as act:
        lines = ['#!/bin/sh', 'export RUSTUP_HOME=' + cargo_home, 'export CARGO_HOME=' + cargo_home]
        act.writelines(lines)
    os.chmod(active_file, 0o775)

    deactive_dir = os.path.join(cargo_home, 'etc', 'conda', 'deactivate.d')
    os.makedirs(deactive_dir, exist_ok=True)
    deactive_file = os.path.join(deactive_dir, 'rust_deactivate.sh')
    with open(deactive_file, 'w') as deact:
        lines = ['#!/bin/sh', 'unset RUSTUP_HOME', 'unset CARGO_HOME']
        deact.writelines(lines)
    os.chmod(deactive_file, 0o775)
