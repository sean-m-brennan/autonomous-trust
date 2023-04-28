#!/usr/bin/env -S python3 -m

import os
import sys
from . import dev_root_dir
from .automate import main
from .config.configuration import Configuration
from .processes import LogLevel
from .config.generate import generate_identity


if __name__ == '__main__':
    ident = None
    if len(sys.argv) > 1:
        ident = sys.argv[1]
    if Configuration.VARIABLE_NAME in os.environ.keys():
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.join(dev_root_dir, Configuration.CFG_PATH)
        if ident is not None:
            cfg_dir = os.path.join(dev_root_dir, ident, Configuration.CFG_PATH)
    if not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True, seed=ident)
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir
    main(multiproc=True, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
