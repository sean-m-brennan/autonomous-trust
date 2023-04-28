#!/usr/bin/env -S python3 -m

import os
import sys
from .. import dev_root_dir
from .configuration import Configuration
from .generate import generate_identity


if __name__ == '__main__':
    silent = True
    randomize = False
    if '--random' in sys.argv:
        randomize = True
    if '--verbose' in sys.argv:
        silent = False
    if Configuration.VARIABLE_NAME in os.environ.keys():
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.abspath(os.path.join(dev_root_dir, Configuration.CFG_PATH))
    generate_identity(cfg_dir, randomize, silent=silent)
