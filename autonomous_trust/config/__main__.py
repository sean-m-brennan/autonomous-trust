#!/usr/bin/env -S python3 -m

import os
import sys
from config.configuration import Configuration
from autonomous_trust.config.generate_config import generate_identity


if __name__ == '__main__':
    randomize = False
    if '--random' in sys.argv:
        randomize = True
    this_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    cfg_dir = os.path.join(this_dir, Configuration.CFG_PATH)
    generate_identity(cfg_dir, randomize)
