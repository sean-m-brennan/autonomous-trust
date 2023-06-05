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
        subprocess.run([install_sh, '-b', '-p', dest])
    print("Utilizing conda")
    os.execl(wrap_script, wrap_script, *sys.argv)  # activate base environ


def init_conda_env(env_name=conda_environ_name):
    if not conda_env_present(env_name):
        from conda.cli import python_api as anaconda

        anaconda.run_command(anaconda.Commands.CONFIG, '--add', 'channels', 'conda-forge', stdout=None)
        anaconda.run_command(anaconda.Commands.UPDATE, '-n', 'base', 'conda', stdout=None)
        anaconda.run_command(anaconda.Commands.INSTALL, '-n', 'base', 'docker-py')
        anaconda.run_command(anaconda.Commands.CREATE, '-n', env_name, '--file', os.path.join(cfg_dir, 'environment.yml'))
        anaconda.run_command(anaconda.Commands.UPDATE, '-n', env_name, '--file', os.path.join(cfg_dir, 'dev_env.yml'))
        print("Activating conda environment")
        os.execl(wrap_script, wrap_script, *sys.argv)  # activate target environ


# FIXME package creation?
#print('%s-%s' % (sys.platform, platform.architecture()[0][:-3]))
"""
populate_env () {
    local env=${1:-$environment}
    local use_pip=${2:-false}
    local my_conda_base=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

    if [ "$use_pip" != "" ]; then
        pip install -r ${my_conda_base}/environment.recipes.txt
    else
        python_version=$(grep "\- python.*=" ${my_conda_base}/environment.yaml | awk -F"=" '{print $NF}' )
        for pkg in ${my_conda_base}/recipes/*; do
            prebuilt=false
            for arch in noarch $(conda run -n $env python3 ${my_conda_base}/getarch.py); do
                conda mambabuild --python ${python_version} $pkg
            done
        done
        #conda index $CONDA_PREFIX_1/conda-bld
        conda config --add channels local
        conda install -y -n $env -c local --file ${my_conda_base}/environment.recipes.txt
    fi
}
"""

# FIXME compiler installation?
"""
    local env_dir=$(conda env list | grep "/${env}$" | awk '{print $NF}')
    local platform=$(conda info | grep platform | awk '{print $NF}')
    if [ "$(which gcc)" = "" ] && [ -e ${my_conda_base}/$platform ]; then
        conda env update -n $env --file ${my_conda_base}/${platform}/platform.yaml --prune

        shopt -s nullglob
        local cc=${env_dir}/bin/*gcc
        local cpp=${env_dir}/bin/*g++
        if [ "$cc" = "" ] || [ "$cpp" = "" ]; then
            echo "GCC/G++ not found"
            exit 1
        fi
        mkdir -p ${env_dir}/etc/conda/activate.d
        cat << EOF > ${env_dir}/etc/conda/activate.d/gcc_activate.sh
#!/bin/sh
export CC=$cc
export CXX=$cpp
EOF

        mkdir -p ${env_dir}/etc/conda/deactivate.d
        cat << EOF > ${env_dir}/etc/conda/deactivate.d/gcc_deactivate.sh
#!/bin/sh
unset CC
unset CXX
EOF

    fi
"""