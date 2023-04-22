#!/usr/bin/env -S python3 -m

import os
import sys
from autonomous_trust.automate import main
from autonomous_trust.configuration import Configuration
from autonomous_trust.processes import LogLevel
from autonomous_trust.generate_config import generate_identity


if __name__ == '__main__':
    ident = None
    if len(sys.argv) > 1:
        ident = sys.argv[1]
    this_dir = os.path.abspath(os.path.dirname(__file__))
    cfg_dir = os.path.join(this_dir, Configuration.CFG_PATH)
    if ident is not None:
        os.path.join(this_dir, ident, Configuration.CFG_PATH)
    if not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True, seed=id)
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir
    main(multiproc=True, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
