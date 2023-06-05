import subprocess
from ..config import conda_environ_name


def conda_present():
    if subprocess.call(['which', 'conda'], stdout=subprocess.DEVNULL) == 0:
        return subprocess.getoutput('which conda')
    return None


def conda_env_present(env_name):
    envs_list = subprocess.getoutput('conda env list')
    for line in envs_list.split('\n'):
        if line and line.split()[0] == env_name:
            return True
    return False


def init():
    if not conda_present():
        from .conda import install_conda
        install_conda()  # this may restart the script
    elif not conda_env_present(conda_environ_name):
        from .conda import init_conda_env
        init_conda_env()  # this may restart the script
    else:
        from .rust import install_rust
        install_rust()
        from .docker import install_docker
        install_docker()
        # FIXME may need to signal requirements for compilers

        # Advanced options
        from .unikraft import install_unikraft
        install_unikraft()
        # FIXME detect/signal kvm/qemu
