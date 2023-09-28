import os
import sys
import subprocess
import urllib.request
from ..config import OS, ARCH, conda_home, conda_environ_name
from . import conda_env_present, conda_present
from .. import program

wrap_script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'bin', program))  # FIXME find bin dir
cfg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cfg'))


def install_conda(dest=conda_home):
    if not conda_present():
        conda_url = 'https://repo.anaconda.com/miniconda/Miniconda3-latest-%s-%s.sh' % (OS.capitalize(), ARCH)
        install_sh = '/tmp/miniconda3-latest.sh'
        print('Retrieve %s' % conda_url)
        urllib.request.urlretrieve(conda_url, install_sh)
        subprocess.run(['/bin/sh', install_sh, '-b', '-p', dest])
    print("Utilizing conda")
    os.execl(wrap_script, wrap_script, *sys.argv[1:])  # activate base environ (see trust script)


def init_conda_env(env_name=conda_environ_name, env_cfg=None):
    if not env_cfg:
        env_cfg = os.path.join(cfg_dir, 'environment.yaml')
    else:
        print('Using non-default environ config: %s' % env_cfg)
    if not conda_env_present(env_name):
        subprocess.run(['conda', 'config', '--add', 'channels', 'conda-forge'])
        subprocess.run(['conda', 'update', '-n', 'base', 'conda'], check=True)
        subprocess.run(['conda', 'install', '-n', 'base', 'docker-py'], check=True)
        subprocess.run(['conda', 'env', 'create', '-n', env_name, '--file', env_cfg], check=True)
        subprocess.run(['conda', 'env', 'update', '-n', env_name, '--file', os.path.join(cfg_dir, 'devel_environ.yaml')], check=True)
        print("Activating conda environment")
        os.execl(wrap_script, wrap_script, *sys.argv[1:])  # activate target environ (see trust script)


def update_env(env_name=conda_environ_name, env_cfg=None):
    if not env_cfg:
        env_cfg = os.path.join(cfg_dir, 'environment.yaml')
    else:
        print('Using non-default environ config: %s' % env_cfg)
    if not conda_present():
        install_conda()
    if not conda_env_present(env_name):
        init_conda_env(env_name, env_cfg=env_cfg)
    subprocess.run(['conda', 'update', '-n', 'base', 'conda'], check=True)
    subprocess.run(['conda', 'update', '-n', env_name, '--all'], check=True)
    subprocess.run(['conda', 'env', 'update', '-n', env_name, '--file', env_cfg], check=True)
