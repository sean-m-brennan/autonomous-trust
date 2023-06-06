import os
import sys
import subprocess
import urllib.request
from ..config import OS, ARCH, conda_home, conda_environ_name
from . import conda_env_present, conda_present

wrap_script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'trust'))
cfg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config'))


def install_conda(dest=conda_home):
    if not conda_present():
        conda_url = 'https://repo.anaconda.com/miniconda/Miniconda3-latest-%s-%s.sh' % (OS.capitalize(), ARCH)
        install_sh = '/tmp/miniconda3-latest.sh'
        print('Retrieve %s' % conda_url)
        urllib.request.urlretrieve(conda_url, install_sh)
        subprocess.run(['/bin/sh', install_sh, '-b', '-p', dest])
    print("Utilizing conda")
    os.execl(wrap_script, wrap_script, *sys.argv)  # activate base environ


def init_conda_env(env_name=conda_environ_name):
    if not conda_env_present(env_name):
        from conda.cli import python_api as anaconda  # noqa

        anaconda.run_command(anaconda.Commands.CONFIG, '--add', 'channels', 'conda-forge', stdout=None)
        anaconda.run_command(anaconda.Commands.UPDATE, '-n', 'base', 'conda', stdout=None)
        anaconda.run_command(anaconda.Commands.INSTALL, '-n', 'base', 'docker-py')
        anaconda.run_command(anaconda.Commands.CREATE, '-n', env_name, '--file', os.path.join(cfg_dir, 'environment.yml'))
        anaconda.run_command(anaconda.Commands.UPDATE, '-n', env_name, '--file', os.path.join(cfg_dir, 'dev_env.yml'))
        print("Activating conda environment")
        os.execl(wrap_script, wrap_script, *sys.argv)  # activate target environ
