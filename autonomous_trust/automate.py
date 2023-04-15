import os
import time

from .configuration import Configuration
from .identity import Identity, Peers


def banner():
    print("")
    print("You are using\033[94m AutonomousTrust\033[00m from\033[96m TekFive\033[00m.")
    print("")


def configure():
    configs = {}
    cfg_dir = os.environ.get(Configuration.VARIABLE_NAME, Configuration.PATH_DEFAULT)

    def get_cfg_type(path):
        return os.path.splitext(os.path.basename(path))[0]

    config_files = os.listdir(cfg_dir)
    cfg_types = map(get_cfg_type, config_files)
    if 'identity' not in cfg_types:
        Identity.initialize('myself', '127.0.0.1').to_file(os.path.join(cfg_dir, 'identity.yaml'))
    if 'peers' not in cfg_types:
        Peers().to_file(os.path.join(cfg_dir, 'peers.yaml'))
    # TODO etc
    config_files = os.listdir(cfg_dir)
    config_paths = map(lambda x: os.path.join(cfg_dir, x), config_files)
    for cfg_file in config_paths:
        configs[get_cfg_type(cfg_file)] = Configuration.from_file(cfg_file)
    # TODO domain?:
    print("Configuring %s at %s for %s" %
          (configs['identity'].nickname, configs['identity'].address, '(unknown domain)'))
    # TODO this is fake:
    configs['processes'] = ['communications', 'reputation', 'computing services', 'data services']
    return configs


def main():
    banner()
    procs = configure()['processes']
    for proc in procs:
        # TODO start child processes (comms, sensors, data-processing, etc)
        print("Starting %s ..." % proc)
    try:
        print('                                        Ready.')
        i = 0
        while True:
            # TODO run forever unless signalled
            if i > 1000:
                break
            time.sleep(0.1)
            i += 1
    except KeyboardInterrupt:
        pass
    for proc in reversed(procs):
        # TODO clean up
        print("Halting %s" % proc)
    print("Shutdown")
